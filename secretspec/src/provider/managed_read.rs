//! Explicit opt-in to the cancellable read contract (0.22+).
//!
//! Register only factories whose constructors, credentials, reads and drops
//! own all their work. Async factories must stay on the supplied runtime;
//! synchronous factories must join every thread/child they start. Merely
//! implementing AsyncProvider does not opt a provider in.
use super::{Address, Provider, ProviderCredentials, ProviderUrl, ProviderValue};
use crate::request::RequestContext;
use crate::{NativeAddress, Result, SecretBytes};
use std::borrow::Cow;
use std::collections::HashMap;

pub(crate) struct Registration {
    pub schemes: &'static [&'static str],
    pub batch: bool,
    pub factory:
        fn(&ProviderUrl, ProviderCredentials, &RequestContext) -> Result<Box<dyn Provider>>,
}

#[linkme::distributed_slice]
pub(crate) static REGISTRY: [Registration];

/// Validate before credential I/O. The registry gate precedes URL parsing so
/// unknown and unregistered schemes never execute an external provider probe.
pub(crate) fn check(spec: &str) -> Result<(&'static Registration, ProviderUrl)> {
    let (scheme, _) = super::registry::split_spec(spec);
    let registration = REGISTRY
        .iter()
        .find(|entry| entry.schemes.contains(&scheme))
        .ok_or_else(|| crate::request::unsupported(format!("provider '{scheme}'")))?;
    let url = super::provider_url_from_spec(spec)?;
    super::reject_uri_credential(&url)?;
    Ok((registration, url))
}

pub(crate) fn from_spec(
    spec: &str,
    credentials: ProviderCredentials,
    request: &RequestContext,
) -> Result<Box<dyn Provider>> {
    request.checkpoint()?;
    let (registration, url) = check(spec)?;
    let inner = (registration.factory)(&url, credentials, request)?;
    Ok(Box::new(ReadOnly {
        inner: Box::new(super::RetryingProvider::for_request(inner, request.clone())),
        request: request.clone(),
        batch: registration.batch,
    }))
}

pub(crate) fn preflight<P: Provider + 'static>(
    mut provider: P,
    request: &RequestContext,
    check: fn(&P) -> Result<()>,
) -> Box<dyn Provider> {
    provider.set_retry_policy(super::RetryPolicy::default());
    let provider = std::sync::Arc::new(provider);
    let probe = std::sync::Arc::clone(&provider);
    Box::new(super::preflight::PreflightGuard::for_request(
        super::ProviderWithPreflight {
            provider: Box::new(provider),
            preflight: Some(Box::new(move || check(&probe))),
        },
        request.clone(),
    ))
}

/// The resolver sees only reads. This wrapper neither exposes Deref nor lets
/// a future resolver change turn a managed read into an unmanaged write.
struct ReadOnly {
    inner: Box<dyn Provider>,
    request: RequestContext,
    batch: bool,
}

impl Provider for ReadOnly {
    fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
        self.request.checkpoint()?;
        let result = self.inner.get(addr);
        self.request.checkpoint()?;
        result
    }
    fn get_with_metadata(&self, addr: Address<'_>) -> Result<Option<ProviderValue>> {
        self.request.checkpoint()?;
        let result = self.inner.get_with_metadata(addr);
        self.request.checkpoint()?;
        result
    }
    fn get_many_with_metadata(
        &self,
        requests: &[(&str, Address<'_>)],
    ) -> Result<HashMap<String, ProviderValue>> {
        self.request.checkpoint()?;
        // These providers have no batch I/O; admit each environment read
        // separately instead of the legacy thread fan-out default.
        if !self.batch {
            let mut values = HashMap::new();
            for (name, address) in requests {
                if let Some(value) = self.get_with_metadata(*address)? {
                    values.insert((*name).to_string(), value);
                }
            }
            return Ok(values);
        }
        let result = self.inner.get_many_with_metadata(requests);
        self.request.checkpoint()?;
        result
    }
    fn set(&self, _: Address<'_>, _: &SecretBytes) -> Result<()> {
        Err(crate::request::unsupported("provider writes"))
    }
    fn check_writable(&self, _: Address<'_>) -> Result<()> {
        Err(crate::request::unsupported("provider writes"))
    }
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn uri(&self) -> String {
        self.inner.uri()
    }
    fn supports_read(&self) -> bool {
        self.inner.supports_read()
    }
    fn retry_ownership(&self) -> super::RetryOwnership {
        self.inner.retry_ownership()
    }
    fn retry_safe(&self, operation: super::RetryOperation, addr: Address<'_>) -> bool {
        self.inner.retry_safe(operation, addr)
    }
    fn storage_identity(&self) -> String {
        self.inner.storage_identity()
    }
    fn entry_container_identity(&self) -> String {
        self.inner.entry_container_identity()
    }
    fn physical_store_path(&self) -> Option<&std::path::Path> {
        self.inner.physical_store_path()
    }
    fn configured_physical_store_path(&self) -> Option<&std::path::Path> {
        self.inner.configured_physical_store_path()
    }
    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
        self.request.checkpoint()?;
        self.inner.convention_address(project, profile, key)
    }
    fn supported_coords(&self) -> &'static [&'static str] {
        self.inner.supported_coords()
    }
    fn supports_coord(&self, name: &str) -> bool {
        self.inner.supports_coord(name)
    }
    fn resolve_coords<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, NativeAddress>> {
        self.request.checkpoint()?;
        self.inner.resolve_coords(addr)
    }
    fn configured_entry_coordinates<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<Cow<'a, NativeAddress>> {
        self.inner.configured_entry_coordinates(addr)
    }
    fn entry_coordinates<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, NativeAddress>> {
        self.request.checkpoint()?;
        self.inner.entry_coordinates(addr)
    }
    fn generated_value_persistence(&self) -> super::ProducedValuePersistence {
        self.inner.generated_value_persistence()
    }
    fn prompted_value_persistence(&self) -> super::ProducedValuePersistence {
        self.inner.prompted_value_persistence()
    }
    fn with_base_dir(&mut self, base: &std::path::Path) {
        self.inner.with_base_dir(base);
    }
    fn set_retry_policy(&mut self, policy: super::RetryPolicy) {
        self.inner.set_retry_policy(policy);
    }
    fn set_reason(&self, reason: Option<String>) {
        self.inner.set_reason(reason);
    }
    fn set_requested_authorization_duration(&self, duration: Option<std::time::Duration>) {
        self.inner.set_requested_authorization_duration(duration);
    }
    fn set_caller(&self, caller: Option<crate::CallerContext>) {
        self.inner.set_caller(caller);
    }
    fn set_project(&self, project: &str) {
        self.inner.set_project(project);
    }
    fn set_profile(&self, profile: &str) {
        self.inner.set_profile(profile);
    }
}

/// Kept next to each provider's implementation so adding a provider defaults
/// to unsupported. Its factory must explicitly receive the request context.
macro_rules! register {
    ([$($scheme:literal),+ $(,)?], $factory:expr $(, batch: $batch:literal)?) => {
        const _: () = {
            #[linkme::distributed_slice(crate::provider::managed_read::REGISTRY)]
            static REGISTRATION: crate::provider::managed_read::Registration = crate::provider::managed_read::Registration {
                schemes: &[$($scheme),+], factory: $factory,
                batch: crate::provider::declared_read_capability(&[$($batch,)?]),
            };
        };
    };
}
pub(crate) use register;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_schemes_are_unique_and_have_builtin_metadata() {
        let mut schemes = std::collections::HashSet::new();
        for registration in REGISTRY {
            for scheme in registration.schemes {
                assert!(schemes.insert(scheme), "duplicate managed scheme: {scheme}");
                assert!(
                    super::super::registry::registration_for_scheme(scheme).is_some(),
                    "managed URL validation must not discover external providers: {scheme}"
                );
            }
        }
    }

    #[cfg(any(
        feature = "vault",
        feature = "openbao",
        feature = "infisical",
        feature = "setec"
    ))]
    async fn cancel_http(
        spec: String,
        credentials: ProviderCredentials,
        partial_body: bool,
    ) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let spec = spec.replace("ENDPOINT", &listener.local_addr().unwrap().to_string());
        let (started, start) = tokio::sync::oneshot::channel();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut headers = Vec::new();
            let mut byte = [0];
            while !headers.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                headers.push(byte[0]);
            }
            if partial_body {
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10000\r\n\r\n{")
                    .unwrap();
            }
            started.send(()).unwrap();
            let mut bytes = [0; 4096];
            loop {
                match socket.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                    Err(error) => panic!("HTTP connection outlived the request: {error}"),
                }
            }
            String::from_utf8(headers)
                .unwrap()
                .lines()
                .next()
                .unwrap()
                .to_string()
        });
        let cancellation = crate::CancellationHandle::new();
        let handle = cancellation.clone();
        let task = tokio::spawn(async move {
            crate::request::run(&handle, move |context| {
                let provider = from_spec(&spec, credentials, &context)?;
                provider.get_many_with_metadata(&[(
                    "TOKEN",
                    Address::convention("project", "default", "TOKEN"),
                )])
            })
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), start)
            .await
            .expect("provider did not start HTTP")
            .unwrap();
        cancellation.cancel();
        let error = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .err()
            .expect("expected cancellation");
        assert_eq!(error.kind(), "cancelled");
        server.join().unwrap()
    }

    #[cfg(feature = "setec")]
    #[tokio::test]
    async fn cancellation_during_response_body_closes_transport() {
        cancel_http(
            "setec://ENDPOINT?tls=false".into(),
            ProviderCredentials::new(),
            true,
        )
        .await;
    }

    #[cfg(any(feature = "vault", feature = "openbao"))]
    #[tokio::test]
    async fn cancellation_during_approle_login_closes_transport() {
        let products = [
            #[cfg(feature = "vault")]
            "vault",
            #[cfg(feature = "openbao")]
            "openbao",
        ];
        for product in products {
            let credentials = ProviderCredentials::from([
                ("role_id".into(), SecretBytes::from_utf8("test-role")),
                ("secret_id".into(), SecretBytes::from_utf8("test-secret")),
            ]);
            let line = cancel_http(
                format!("{product}://ENDPOINT/secret?tls=false&auth=approle"),
                credentials,
                false,
            )
            .await;
            assert!(line.starts_with("POST /v1/auth/approle/login "), "{line}");
        }
    }

    #[cfg(feature = "infisical")]
    #[tokio::test]
    async fn cancellation_during_infisical_read_closes_transport() {
        let credentials =
            ProviderCredentials::from([("token".into(), SecretBytes::from_utf8("test-token"))]);
        cancel_http(
            "infisical://ENDPOINT/11111111-1111-4111-8111-111111111111?tls=false&env=prod".into(),
            credentials,
            true,
        )
        .await;
    }
}
