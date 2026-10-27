use async_trait::async_trait;
use secretspec::{
    Address, AsyncProvider, AsyncProviderAdapter, DiscoveryContext, NativeAddress, Provider,
    ProviderBase, ProviderValue, Result, Secret, SecretBytes, SecretSpecError, SyncProviderAdapter,
};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn native(item: &str) -> NativeAddress {
    NativeAddress {
        item: item.into(),
        field: None,
        vault: None,
        section: None,
        version: None,
    }
}

#[derive(Default)]
struct NativeAsync {
    reads: AtomicUsize,
    values: Mutex<HashMap<String, SecretBytes>>,
    write_only: bool,
}

fn key(addr: Address<'_>) -> String {
    match addr {
        Address::Native(addr) => addr.item.clone(),
        Address::Convention {
            project,
            profile,
            key,
        } => format!("{project}/{profile}/{key}"),
    }
}

#[async_trait]
impl AsyncProvider for NativeAsync {
    async fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
        assert!(!self.write_only, "write-only stores must not read values");
        tokio::task::yield_now().await;
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.values.lock().unwrap().get(&key(addr)).cloned())
    }

    async fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()> {
        self.values.lock().unwrap().insert(key(addr), value.clone());
        Ok(())
    }

    async fn exists(&self, addr: Address<'_>) -> Result<bool> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.values.lock().unwrap().contains_key(&key(addr)))
    }
}

#[tokio::test]
async fn native_async_trait_objects_accept_borrowed_addresses_and_binary_values() {
    let provider: Box<dyn AsyncProvider> = Box::new(NativeAsync::default());
    let reference = native("binary");
    let addr = Address::Native(&reference);
    let bytes = SecretBytes::from(vec![0, 255, 128, 10]);
    provider.set(addr, &bytes).await.unwrap();
    assert!(provider.exists(addr).await.unwrap());
    let value = provider.get_with_metadata(addr).await.unwrap().unwrap();
    assert_eq!(value.value.expose_secret(), bytes.expose_secret());
    assert!(value.expires_at_unix_ms.is_none());
    assert!(value.revision.is_none());
    assert!(
        provider
            .get(Address::Native(&native("missing")))
            .await
            .unwrap()
            .is_none()
    );
    assert!(!provider.supports_delete());
    let delete = provider.delete(addr).await.unwrap_err();
    let preflight = provider.check_deletable(addr).await.unwrap_err();
    assert_eq!(delete.to_string(), preflight.to_string());
    assert!(
        provider
            .reflect(DiscoveryContext::new("app", "dev"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn default_batches_deduplicate_and_omit_missing_values() {
    let provider = NativeAsync::default();
    let addr = Address::convention("app", "dev", "KEY");
    provider
        .set(addr, &SecretBytes::from("value"))
        .await
        .unwrap();
    let requests = [
        ("first", addr),
        ("alias", addr),
        ("missing", Address::Native(&native("missing"))),
    ];
    let values = provider.get_many(&requests).await.unwrap();
    assert_eq!(provider.reads.load(Ordering::SeqCst), 2);
    assert_eq!(values.len(), 2);
    assert_eq!(
        values["first"].expose_secret(),
        values["alias"].expose_secret()
    );
    let metadata = provider.get_many_with_metadata(&requests).await.unwrap();
    assert_eq!(metadata.len(), 2);
    assert!(metadata["first"].expires_at_unix_ms.is_none());
    assert_eq!(
        provider.exists_many(&requests).await.unwrap(),
        HashSet::from(["first".into(), "alias".into()])
    );
}

#[tokio::test]
async fn write_only_batch_presence_does_not_read_values() {
    let provider = NativeAsync {
        write_only: true,
        ..Default::default()
    };
    let addr = Address::convention("app", "dev", "KEY");
    provider
        .set(addr, &SecretBytes::from("value"))
        .await
        .unwrap();
    let requests = [
        ("first", addr),
        ("alias", addr),
        ("missing", Address::Native(&native("missing"))),
    ];
    assert_eq!(provider.exists_many(&requests).await.unwrap().len(), 2);
    assert_eq!(provider.reads.load(Ordering::SeqCst), 2);
}

struct BlockingRead {
    started: Mutex<Option<tokio::sync::oneshot::Sender<std::thread::ThreadId>>>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl Provider for BlockingRead {
    fn convention_address(&self, _: &str, _: &str, key: &str) -> Result<NativeAddress> {
        Ok(native(key))
    }
    fn name(&self) -> &str {
        "blocking"
    }
    fn uri(&self) -> String {
        "blocking://".into()
    }
    fn get(&self, _: Address<'_>) -> Result<Option<SecretBytes>> {
        self.started
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .send(std::thread::current().id())
            .unwrap();
        self.release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        Ok(Some("value".into()))
    }
    fn set(&self, _: Address<'_>, _: &SecretBytes) -> Result<()> {
        unreachable!()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn adapter_allows_other_tasks_to_progress_on_a_current_thread_runtime() {
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let provider: Arc<dyn AsyncProvider> =
        Arc::new(AsyncProviderAdapter::new(Arc::new(BlockingRead {
            started: Mutex::new(Some(started_tx)),
            release: Mutex::new(release_rx),
        })));
    let task =
        tokio::spawn(async move { provider.get(Address::convention("app", "dev", "KEY")).await });
    let worker_id = tokio::time::timeout(Duration::from_secs(5), started_rx)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(worker_id, std::thread::current().id());
    release_tx.send(()).unwrap();
    assert_eq!(
        task.await.unwrap().unwrap().unwrap().expose_secret(),
        b"value"
    );
}

struct Overrides;

impl Provider for Overrides {
    fn convention_address(&self, _: &str, _: &str, key: &str) -> Result<NativeAddress> {
        Ok(native(key))
    }
    fn name(&self) -> &str {
        "overrides"
    }
    fn uri(&self) -> String {
        "overrides://".into()
    }
    fn get(&self, _: Address<'_>) -> Result<Option<SecretBytes>> {
        panic!("batch and metadata overrides must be forwarded")
    }
    fn set(&self, _: Address<'_>, _: &SecretBytes) -> Result<()> {
        panic!("expiry override must be forwarded")
    }
    fn supports_delete(&self) -> bool {
        true
    }
    fn get_with_metadata(&self, addr: Address<'_>) -> Result<Option<ProviderValue>> {
        assert_eq!(key(addr), "remote");
        Ok(Some(
            ProviderValue::new(vec![0, 255].into(), Some(1234)).with_revision(Some(
                secretspec_ipc::Revision::new("remote:v3".into()).unwrap(),
            )),
        ))
    }
    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretBytes>> {
        assert_eq!(key(requests[0].1), "remote");
        Ok(HashMap::from([(requests[0].0.into(), "batch".into())]))
    }
    fn get_many_with_metadata(
        &self,
        requests: &[(&str, Address<'_>)],
    ) -> Result<HashMap<String, ProviderValue>> {
        Ok(HashMap::from([(
            requests[0].0.into(),
            self.get_with_metadata(requests[0].1)?.unwrap(),
        )]))
    }
    fn exists(&self, _: Address<'_>) -> Result<bool> {
        Ok(true)
    }
    fn exists_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashSet<String>> {
        Ok(requests.iter().map(|(name, _)| (*name).into()).collect())
    }
    fn set_expiring(
        &self,
        addr: Address<'_>,
        value: &SecretBytes,
        max_age: Duration,
    ) -> Result<()> {
        assert_eq!(key(addr), "remote");
        assert_eq!(value.expose_secret(), &[0, 255]);
        assert_eq!(max_age, Duration::from_secs(30));
        Ok(())
    }
    fn check_writable(&self, _: Address<'_>) -> Result<()> {
        Err(SecretSpecError::ProviderOperationFailed(
            "read-only address".into(),
        ))
    }
    fn check_deletable(&self, _: Address<'_>) -> Result<()> {
        Err(SecretSpecError::ProviderOperationFailed(
            "protected address".into(),
        ))
    }
    fn delete(&self, _: Address<'_>) -> Result<bool> {
        Ok(false)
    }
    fn reflect(&self, context: DiscoveryContext<'_>) -> Result<HashMap<String, Secret>> {
        assert_eq!(context, DiscoveryContext::new("app", "dev"));
        Ok(HashMap::from([("KEY".into(), Secret::required("key"))]))
    }
}

#[tokio::test]
async fn adapter_preserves_batch_metadata_expiry_and_policy_overrides() {
    let provider = AsyncProviderAdapter::new(Arc::new(Overrides));
    let reference = native("remote");
    let addr = Address::Native(&reference);
    let requests = [("KEY", addr)];
    assert_eq!(provider.name(), "overrides");
    assert_eq!(provider.uri(), "overrides://");
    assert!(provider.supports_read());
    assert!(provider.supports_delete());
    let value = provider.get_with_metadata(addr).await.unwrap().unwrap();
    assert_eq!(value.expires_at_unix_ms, Some(1234));
    assert_eq!(value.revision.unwrap().as_str(), "remote:v3");
    assert_eq!(value.value.expose_secret(), &[0, 255]);
    assert_eq!(
        provider.get_many(&requests).await.unwrap()["KEY"].expose_secret(),
        b"batch"
    );
    let metadata = provider.get_many_with_metadata(&requests).await.unwrap();
    assert_eq!(metadata["KEY"].expires_at_unix_ms, Some(1234));
    assert_eq!(
        metadata["KEY"].revision.as_ref().unwrap().as_str(),
        "remote:v3"
    );
    assert!(provider.exists(addr).await.unwrap());
    assert_eq!(
        provider.exists_many(&requests).await.unwrap(),
        HashSet::from(["KEY".into()])
    );
    provider
        .set_expiring(addr, &vec![0, 255].into(), Duration::from_secs(30))
        .await
        .unwrap();
    assert!(
        provider
            .check_writable(addr)
            .await
            .unwrap_err()
            .to_string()
            .contains("read-only address")
    );
    assert!(
        provider
            .check_deletable(addr)
            .await
            .unwrap_err()
            .to_string()
            .contains("protected address")
    );
    assert!(!provider.delete(addr).await.unwrap());
    assert_eq!(
        provider
            .reflect(DiscoveryContext::new("app", "dev"))
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn adapter_resumes_provider_panics_in_the_awaiting_task() {
    let provider = AsyncProviderAdapter::new(Arc::new(Overrides));
    let task = tokio::spawn(async move { provider.get(Address::Native(&native("panic"))).await });
    assert!(task.await.unwrap_err().is_panic());
}

#[tokio::test]
async fn existing_dotenv_provider_round_trips_through_async_factory() {
    let directory = tempfile::tempdir().unwrap();
    let provider = Box::<dyn AsyncProvider>::try_from(format!(
        "dotenv://{}",
        directory.path().join(".env").display()
    ))
    .unwrap();
    let addr = Address::convention("app", "dev", "KEY");
    provider.check_writable(addr).await.unwrap();
    provider.set(addr, &"hello".into()).await.unwrap();
    assert_eq!(
        provider.get(addr).await.unwrap().unwrap().expose_secret(),
        b"hello"
    );
    assert!(provider.delete(addr).await.unwrap());
    assert!(!provider.exists(addr).await.unwrap());
}

// Policy checks finish before I/O. Polling outside a runtime also detects an
// accidental fallback to spawn_blocking instead of a native async registration.
macro_rules! native_sdk_factory {
    ($test:ident, $feature:literal, $uri:literal) => {
        #[cfg(feature = $feature)]
        #[test]
        fn $test() {
            use futures_util::FutureExt;
            let provider = Box::<dyn AsyncProvider>::try_from($uri).unwrap();
            let mut reference = native("test-secret");
            reference.field = Some("unsupported".into());
            reference.version = Some("3".into());
            let addr = Address::Native(&reference);
            let preflight = provider
                .check_writable(addr)
                .now_or_never()
                .unwrap()
                .unwrap_err();
            let value = "replacement".into();
            let write = provider
                .set(addr, &value)
                .now_or_never()
                .unwrap()
                .unwrap_err();
            assert_eq!(preflight.to_string(), write.to_string());
        }

        #[cfg(not(feature = $feature))]
        #[test]
        fn $test() {
            let Err(error) = Box::<dyn AsyncProvider>::try_from($uri) else {
                panic!("disabled SDK was constructed");
            };
            assert!(matches!(
                error,
                SecretSpecError::ProviderFeatureDisabled {
                    feature: $feature,
                    ..
                }
            ));
        }
    };
}

native_sdk_factory!(aac_factory, "aac", "aac://payments-production");
native_sdk_factory!(akv_factory, "akv", "akv://myvault");
native_sdk_factory!(awssm_factory, "awssm", "awssm://us-east-1");
native_sdk_factory!(awsps_factory, "awsps", "awsps://us-east-1");
native_sdk_factory!(gcsm_factory, "gcsm", "gcsm://my-gcp-project");
native_sdk_factory!(
    kubernetes_secret_factory,
    "kubernetes",
    "k8s+secret://db-config"
);
native_sdk_factory!(
    kubernetes_configmap_factory,
    "kubernetes",
    "k8s+configmap://db-config@default"
);
native_sdk_factory!(
    cloudflare_factory,
    "cloudflare",
    "cloudflare://STORE_ID?account_id=ACCOUNT_ID"
);
native_sdk_factory!(doppler_factory, "doppler", "doppler://myapp/prd");
native_sdk_factory!(
    infisical_factory,
    "infisical",
    "infisical://app.infisical.com/11111111-2222-4333-8444-555555555555"
);
native_sdk_factory!(scaleway_factory, "scaleway", "scaleway://fr-par");
native_sdk_factory!(setec_factory, "setec", "setec://secrets.example.ts.net");
native_sdk_factory!(
    vault_factory,
    "vault",
    "vault://vault.example.com:8200/secret"
);
native_sdk_factory!(
    openbao_factory,
    "openbao",
    "openbao://bao.example.com:8200/secret"
);

#[test]
fn async_factory_rejects_uri_passwords_without_echoing_them() {
    let Err(error) = Box::<dyn AsyncProvider>::try_from("awsps://user:private-password@us-east-1")
    else {
        panic!("credential-bearing URI was accepted");
    };
    assert!(!format!("{error:?}: {error}").contains("private-password"));
}

impl ProviderBase for NativeAsync {
    fn supports_read(&self) -> bool {
        !self.write_only
    }
    fn name(&self) -> &str {
        "native-async"
    }
    fn uri(&self) -> String {
        "native-async://".into()
    }
}

#[test]
fn sync_adapter_runs_native_async_storage_and_preserves_batch_deduplication() {
    let provider = SyncProviderAdapter::from_async(NativeAsync::default());
    let addr = Address::Native(&native("binary"));
    let value = SecretBytes::from(vec![0, 255]);
    provider.set(addr, &value).unwrap();
    assert_eq!(
        provider.get(addr).unwrap().unwrap().expose_secret(),
        &[0, 255]
    );
    let values = provider
        .get_many(&[("first", addr), ("alias", addr)])
        .unwrap();
    assert_eq!(values.len(), 2);
    assert_eq!(provider.as_async().reads.load(Ordering::SeqCst), 2);
    assert_eq!(provider.name(), "native-async");
    assert_eq!(provider.uri(), "native-async://");
    assert_eq!(
        provider.delete(addr).unwrap_err().to_string(),
        provider.check_deletable(addr).unwrap_err().to_string()
    );
}

#[test]
fn adapters_preserve_overrides_in_both_directions() {
    let backend: Box<dyn AsyncProvider> = Box::new(AsyncProviderAdapter::new(Arc::new(Overrides)));
    let provider = SyncProviderAdapter::from_async(backend);
    let reference = native("remote");
    let addr = Address::Native(&reference);
    let requests = [("KEY", addr)];
    let value = provider.get_with_metadata(addr).unwrap().unwrap();
    assert_eq!(value.value.expose_secret(), &[0, 255]);
    assert_eq!(value.expires_at_unix_ms, Some(1234));
    assert_eq!(value.revision.unwrap().as_str(), "remote:v3");
    assert_eq!(
        provider.get_many(&requests).unwrap()["KEY"].expose_secret(),
        b"batch"
    );
    let values = provider.get_many_with_metadata(&requests).unwrap();
    assert_eq!(
        values["KEY"].revision.as_ref().unwrap().as_str(),
        "remote:v3"
    );
    assert!(provider.exists(addr).unwrap());
    assert!(provider.exists_many(&requests).unwrap().contains("KEY"));
    provider
        .set_expiring(addr, &vec![0, 255].into(), Duration::from_secs(30))
        .unwrap();
    assert!(provider.supports_delete());
    assert!(!provider.delete(addr).unwrap());
    assert!(
        provider
            .check_deletable(addr)
            .unwrap_err()
            .to_string()
            .contains("protected address")
    );
    assert!(
        provider
            .check_writable(addr)
            .unwrap_err()
            .to_string()
            .contains("read-only address")
    );
    assert_eq!(
        provider
            .reflect(DiscoveryContext::new("app", "dev"))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn boxed_async_factory_composes_with_sync_adapter_and_forwards_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let backend = Box::<dyn AsyncProvider>::try_from("dotenv://.env").unwrap();
    let mut provider = SyncProviderAdapter::from_async(backend);
    Provider::with_base_dir(&mut provider, directory.path());
    let addr = Address::convention("app", "default", "TOKEN");
    Provider::set(&provider, addr, &"value".into()).unwrap();
    assert_eq!(
        Provider::get(&provider, addr)
            .unwrap()
            .unwrap()
            .expose_secret(),
        b"value"
    );
    assert!(directory.path().join(".env").exists());
}
