use secretspec::{
    Address, AsyncProvider, DiscoveryContext, ExternalProvider, Provider, ProviderCredentialBroker,
    ProviderCredentialPrincipal, ProviderCredentialRequest, ProviderEndpoint, RetryPolicy,
    SecretBytes, SecretSpecError,
};
use secretspec_ipc::error::ErrorKind;
use std::cell::Cell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct NoHostCredentials;
impl ProviderCredentialBroker for NoHostCredentials {
    fn get(
        &self,
        _principal: &ProviderCredentialPrincipal,
        _request: &ProviderCredentialRequest,
    ) -> secretspec::Result<Option<SecretBytes>> {
        Ok(None)
    }
}

fn provider(attempts: u32) -> (Option<tempfile::TempDir>, ExternalProvider) {
    let endpoint = PathBuf::from(env!("CARGO_BIN_EXE_ipc-provider-endpoint-rust"));
    #[cfg(windows)]
    let (endpoint, directory) = {
        let directory = tempfile::tempdir().unwrap();
        secretspec::windows_security::make_path_private(directory.path()).unwrap();
        let staged = directory.path().join(endpoint.file_name().unwrap());
        std::fs::copy(&endpoint, &staged).unwrap();
        (staged, Some(directory))
    };
    #[cfg(not(windows))]
    let directory = None;
    let mut provider = ExternalProvider::new(
        ProviderEndpoint {
            scheme: "memory".into(),
            executable: endpoint,
            arguments: Vec::new(),
            environment: Vec::new(),
        },
        "memory://conformance",
    )
    .unwrap();
    provider.with_credential_broker(Arc::new(NoHostCredentials));
    Provider::set_retry_policy(&mut provider, RetryPolicy::new(attempts).unwrap());
    (directory, provider)
}

fn address(key: &str) -> Address<'_> {
    Address::convention("async-tests", "default", key)
}

async fn counts(provider: &dyn AsyncProvider) -> HashMap<String, usize> {
    let value = provider
        .get(address("__ASYNC_COUNTS__"))
        .await
        .unwrap()
        .unwrap();
    serde_json::from_slice(value.expose_secret()).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn native_ipc_crud_batches_and_metadata() {
    let (_directory, provider) = provider(3);
    provider.initialize_async().await.unwrap();
    let provider: &dyn AsyncProvider = provider.as_async();
    assert!(provider.supports_read());
    assert!(provider.supports_delete());
    let token = address("TOKEN");
    assert!(provider.get(token).await.unwrap().is_none());
    provider.check_writable(token).await.unwrap();
    provider.set(token, &"value".into()).await.unwrap();
    assert!(provider.exists(token).await.unwrap());
    assert_eq!(
        provider.get(token).await.unwrap().unwrap().expose_secret(),
        b"value"
    );
    let requests = [
        ("first", token),
        ("alias", token),
        ("missing", address("MISSING")),
    ];
    let batch = provider.get_many(&requests).await.unwrap();
    assert_eq!(batch.len(), 2);
    assert_eq!(batch["first"].expose_secret(), b"value");
    assert_eq!(batch["alias"].expose_secret(), b"value");
    let present = provider.exists_many(&requests).await.unwrap();
    assert_eq!(present.len(), 2);
    assert!(present.contains("first") && present.contains("alias"));

    let expiry = address("SECRET_EXPIRY");
    provider.set(expiry, &"expiring".into()).await.unwrap();
    let metadata = provider.get_with_metadata(expiry).await.unwrap().unwrap();
    assert!(metadata.expires_at_unix_ms.is_some());
    assert!(metadata.revision.is_some());
    let batch = provider
        .get_many_with_metadata(&[("expiry", expiry)])
        .await
        .unwrap();
    assert_eq!(batch["expiry"].revision, metadata.revision);
    assert_eq!(
        batch["expiry"].expires_at_unix_ms,
        metadata.expires_at_unix_ms
    );
    provider
        .set_expiring(token, &"retained".into(), Duration::from_secs(60))
        .await
        .unwrap();
    let retained = provider.get_with_metadata(token).await.unwrap().unwrap();
    assert_eq!(retained.value.expose_secret(), b"retained");
    assert!(retained.expires_at_unix_ms.is_none());
    assert!(
        provider
            .reflect(DiscoveryContext::new("async-tests", "default"))
            .await
            .unwrap()
            .contains_key("TOKEN")
    );
    provider.check_deletable(token).await.unwrap();
    assert!(provider.delete(token).await.unwrap());
    assert!(!provider.delete(token).await.unwrap());
    assert!(!provider.exists(token).await.unwrap());
}

#[tokio::test(flavor = "current_thread")]
async fn native_ipc_can_switch_between_async_and_sync_calls() {
    let (_directory, provider) = provider(1);
    let token = address("TOKEN");
    provider
        .as_async()
        .set(token, &"async".into())
        .await
        .unwrap();
    assert_eq!(
        Provider::get(&provider, token)
            .unwrap()
            .unwrap()
            .expose_secret(),
        b"async"
    );
    Provider::set(&provider, token, &"sync".into()).unwrap();
    assert_eq!(
        provider
            .as_async()
            .get(token)
            .await
            .unwrap()
            .unwrap()
            .expose_secret(),
        b"sync"
    );
}

#[test]
fn native_ipc_session_survives_the_initial_callers_runtime() {
    let (_directory, provider) = provider(1);
    let token = address("TOKEN");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(provider.as_async().set(token, &"persistent session".into()))
        .unwrap();
    drop(runtime);
    assert_eq!(
        Provider::get(&provider, token)
            .unwrap()
            .unwrap()
            .expose_secret(),
        b"persistent session"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn native_ipc_retry_backoff_yields_to_the_callers_runtime() {
    let (_directory, provider) = provider(3);
    provider.initialize_async().await.unwrap();
    let provider: &dyn AsyncProvider = provider.as_async();
    // The endpoint requests one second of backoff. A blocking sleep would keep
    // this current-thread runtime from polling the heartbeat until it finishes.
    let started = Instant::now();
    let finished = Cell::new(false);
    let read = async {
        let result = provider.get(address("__ASYNC_RETRY_ONCE__")).await;
        finished.set(true);
        result
    };
    let heartbeat = async {
        let mut previous = started;
        loop {
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert!(previous.elapsed() < Duration::from_millis(750));
            previous = Instant::now();
            if finished.get() {
                break;
            }
        }
    };
    let (value, ()) = tokio::join!(read, heartbeat);
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert_eq!(value.unwrap().unwrap().expose_secret(), b"recovered");
    assert_eq!(counts(provider).await["get/__ASYNC_RETRY_ONCE__"], 2);
}

#[tokio::test(flavor = "current_thread")]
async fn native_ipc_obeys_retry_budget_and_does_not_retry_permission_errors() {
    for attempts in [1, 3] {
        let (_directory, provider) = provider(attempts);
        let provider: &dyn AsyncProvider = provider.as_async();
        let error = provider
            .get(address("__ASYNC_RETRY_ALWAYS__"))
            .await
            .unwrap_err();
        assert_eq!(error.protocol_kind(), Some(ErrorKind::Unavailable));
        assert!(matches!(
            error,
            SecretSpecError::ProviderTransient {
                exhausted: true,
                ..
            }
        ));
        let error = provider.get(address("__ASYNC_DENIED__")).await.unwrap_err();
        assert_eq!(error.protocol_kind(), Some(ErrorKind::PermissionDenied));
        let counts = counts(provider).await;
        assert_eq!(counts["get/__ASYNC_RETRY_ALWAYS__"], attempts as usize);
        assert_eq!(counts["get/__ASYNC_DENIED__"], 1);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn native_ipc_does_not_replay_mutations_after_lost_acknowledgements() {
    let (_directory, provider) = provider(3);
    let provider: &dyn AsyncProvider = provider.as_async();
    let value = "stored once".into();
    let set = address("__ASYNC_SET__");
    let error = provider.set(set, &value).await.unwrap_err();
    assert_eq!(error.protocol_kind(), Some(ErrorKind::Unavailable));
    assert_eq!(
        provider.get(set).await.unwrap().unwrap().expose_secret(),
        b"stored once"
    );
    let expiring = address("__ASYNC_SET_EXPIRING__");
    let error = provider
        .set_expiring(expiring, &value, Duration::from_secs(60))
        .await
        .unwrap_err();
    assert_eq!(error.protocol_kind(), Some(ErrorKind::Unavailable));
    assert!(provider.exists(expiring).await.unwrap());
    let delete = address("__ASYNC_DELETE__");
    provider.set(delete, &value).await.unwrap();
    let error = provider.delete(delete).await.unwrap_err();
    assert_eq!(error.protocol_kind(), Some(ErrorKind::Unavailable));
    assert!(!provider.exists(delete).await.unwrap());
    let counts = counts(provider).await;
    for operation in [
        "set/__ASYNC_SET__",
        "set_expiring/__ASYNC_SET_EXPIRING__",
        "delete/__ASYNC_DELETE__",
    ] {
        assert_eq!(counts[operation], 1, "replayed {operation}");
    }
}
