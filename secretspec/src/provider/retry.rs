//! Transport-independent, bounded retries for provider operations (0.22+).
use super::{
    Address, DiscoveryContext, ProducedValuePersistence, Provider, ProviderCredentials,
    ProviderValue,
};
use crate::config::NativeAddress;
use crate::{Result, SecretBytes, SecretSpecError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    time::Duration,
};

/// A bounded retry policy. Attempt counts include the original call (0.22+).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetryPolicy {
    #[serde(default = "default_attempts")]
    #[schemars(range(min = 1, max = 10))]
    max_attempts: u32,
}
const fn default_attempts() -> u32 {
    3
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { max_attempts: 3 }
    }
}
impl<'de> Deserialize<'de> for RetryPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Policy {
            #[serde(default = "default_attempts")]
            max_attempts: u32,
        }
        fn default_attempts() -> u32 {
            3
        }
        let value = Policy::deserialize(deserializer)?;
        Self::new(value.max_attempts).map_err(serde::de::Error::custom)
    }
}
impl RetryPolicy {
    /// Creates a policy with 1 to 10 total attempts. One disables retries.
    pub fn new(max_attempts: u32) -> Result<Self> {
        if !(1..=10).contains(&max_attempts) {
            return Err(SecretSpecError::InvalidSpec(
                "retry max_attempts must be between 1 and 10".into(),
            ));
        }
        Ok(Self { max_attempts })
    }
    pub const fn max_attempts(self) -> u32 {
        self.max_attempts
    }
    pub(crate) fn delay(self, attempt: u32, hint: Option<Duration>) -> Option<Duration> {
        if attempt >= self.max_attempts {
            return None;
        }
        Some(
            hint.unwrap_or(Duration::from_millis(250) * (1 << (attempt - 1)))
                .min(Duration::from_secs(10)),
        )
    }
    #[cfg(any(
        feature = "aac",
        feature = "cloudflare",
        feature = "doppler",
        feature = "infisical",
        feature = "scaleway",
        feature = "setec"
    ))]
    pub(crate) async fn run_async<T, F, Fut>(self, provider: &str, mut call: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        for attempt in 1..=self.max_attempts {
            match call().await {
                Ok(value) => return Ok(value),
                Err(error) => {
                    let error = classify_error(provider, error);
                    let Some(hint) = retry_hint(&error) else {
                        return Err(error);
                    };
                    let Some(delay) = self.delay(attempt, hint) else {
                        return Err(SecretSpecError::ProviderTransient {
                            source: Box::new(error),
                            retry_after: None,
                            exhausted: true,
                        });
                    };
                    tokio::time::sleep(delay).await;
                }
            }
        }
        unreachable!("validated policy has at least one attempt")
    }
    pub(crate) fn run<T>(self, provider: &str, call: impl FnMut() -> Result<T>) -> Result<T> {
        self.run_with(provider, call, std::thread::sleep)
    }
    fn run_with<T>(
        self,
        provider: &str,
        mut call: impl FnMut() -> Result<T>,
        mut sleep: impl FnMut(Duration),
    ) -> Result<T> {
        for attempt in 1..=self.max_attempts {
            match call() {
                Ok(value) => return Ok(value),
                Err(error) => {
                    let error = classify_error(provider, error);
                    let Some(hint) = retry_hint(&error) else {
                        return Err(error);
                    };
                    let Some(delay) = self.delay(attempt, hint) else {
                        return Err(SecretSpecError::ProviderTransient {
                            source: Box::new(error),
                            retry_after: None,
                            exhausted: true,
                        });
                    };
                    sleep(delay);
                }
            }
        }
        unreachable!("validated policy has at least one attempt")
    }
}

/// Selects one retry owner, avoiding nested provider/SDK loops (0.22+).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryOwnership {
    Shared,
    Managed,
}
/// Mutations need an explicit replay-safety guarantee (0.22+).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryOperation {
    Set,
    SetExpiring,
    Delete,
}

#[cfg(feature = "infisical")]
pub(crate) fn terminal(error: SecretSpecError) -> SecretSpecError {
    if retry_hint(&error).is_some() {
        SecretSpecError::ProviderTransient {
            source: Box::new(error),
            retry_after: None,
            exhausted: true,
        }
    } else {
        error
    }
}

pub(crate) fn transient(error: SecretSpecError, retry_after: Option<Duration>) -> SecretSpecError {
    SecretSpecError::ProviderTransient {
        source: Box::new(error),
        retry_after,
        exhausted: false,
    }
}
pub(crate) fn retry_hint(error: &SecretSpecError) -> Option<Option<Duration>> {
    match error {
        SecretSpecError::ProviderTransient {
            retry_after,
            exhausted: false,
            ..
        } => Some(*retry_after),
        SecretSpecError::SharedProvider(source) => retry_hint(source),
        _ => None,
    }
}

pub(crate) fn temporary_io(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut source = Some(error);
    while let Some(cause) = source {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::Interrupted
            );
        }
        source = cause.source();
    }
    false
}

/// Conservative fallback for CLI diagnostics. Only failed operations enter here.
/// Unknown messages, local errors, authentication and malformed output stay permanent.
pub(crate) fn classify_error(provider: &str, error: SecretSpecError) -> SecretSpecError {
    if matches!(&error, SecretSpecError::Io(_)) && temporary_io(&error) {
        return transient(error, None);
    }
    let SecretSpecError::ProviderOperationFailed(message) = &error else {
        return error;
    };
    let network_cli = matches!(
        provider,
        "bws"
            | "bw"
            | "onepassword"
            | "lastpass"
            | "dashlane"
            | "protonpass"
            | "passbolt"
            | "fly"
            | "cloudflare"
            | "pass"
            | "gopass"
            | "keeper"
    );
    if network_cli && cli_transient(message) {
        transient(error, None)
    } else {
        error
    }
}
fn cli_transient(message: &str) -> bool {
    let text = message.to_ascii_lowercase();
    // Never infer retryability from a parser, credential or local-process error.
    if [
        "authentication",
        "unauthorized",
        "forbidden",
        "permission denied",
        "not installed",
        "failed to start",
        "failed to parse",
        "could not parse",
        "invalid json",
        "not found",
        "does not exist",
        "non-utf-8",
        "certificate",
        "invalid token",
        "not signed in",
        "not logged in",
    ]
    .iter()
    .any(|word| text.contains(word))
    {
        return false;
    }
    [
        "[429 too many requests]",
        "[500 internal server error]",
        "[502 bad gateway]",
        "[503 service unavailable]",
        "[504 gateway timeout]",
        "http 429",
        "http 500",
        "http 502",
        "http 503",
        "http 504",
        "status code: 429",
        "status code: 500",
        "status code: 502",
        "status code: 503",
        "status code: 504",
        "connection reset by peer",
        "connection refused",
        "connection timed out",
        "connection timeout",
        "temporary failure in name resolution",
        "network is unreachable",
    ]
    .iter()
    .any(|signature| text.contains(signature))
}

/// Applies shared retries while preserving every provider capability (0.22+).
/// URI factories install this automatically; custom providers can wrap explicitly.
pub struct RetryingProvider {
    inner: Box<dyn Provider>,
    policy: RetryPolicy,
}
impl RetryingProvider {
    pub fn new(mut inner: Box<dyn Provider>, policy: RetryPolicy) -> Self {
        inner.set_retry_policy(policy);
        Self { inner, policy }
    }
    fn read<T>(&self, mut call: impl FnMut() -> Result<T>) -> Result<T> {
        if self.inner.retry_ownership() == RetryOwnership::Managed {
            return (call)();
        }
        self.policy.run(self.inner.name(), call)
    }
    fn mutate<T>(
        &self,
        operation: RetryOperation,
        addr: Address<'_>,
        mut call: impl FnMut() -> Result<T>,
    ) -> Result<T> {
        if self.inner.retry_safe(operation, addr) {
            self.read(call)
        } else {
            call()
        }
    }
}
impl Provider for RetryingProvider {
    fn set_retry_policy(&mut self, policy: RetryPolicy) {
        self.policy = policy;
        self.inner.set_retry_policy(policy);
    }
    fn retry_ownership(&self) -> RetryOwnership {
        RetryOwnership::Managed
    }
    fn retry_safe(&self, operation: RetryOperation, addr: Address<'_>) -> bool {
        self.inner.retry_safe(operation, addr)
    }

    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
        // Pure naming, no I/O: needs no auth preflight.
        self.inner.convention_address(project, profile, key)
    }

    fn supported_coords(&self) -> &'static [&'static str] {
        self.inner.supported_coords()
    }

    fn supports_coord(&self, name: &str) -> bool {
        self.inner.supports_coord(name)
    }

    fn resolve_coords<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, NativeAddress>> {
        // Pure naming, no I/O: needs no auth preflight.
        self.inner.resolve_coords(addr)
    }

    fn configured_entry_coordinates<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<Cow<'a, NativeAddress>> {
        self.inner.configured_entry_coordinates(addr)
    }

    fn entry_coordinates<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, NativeAddress>> {
        self.read(|| self.inner.entry_coordinates(addr))
    }

    fn entry_coordinates_many(&self, addrs: &[Address<'_>]) -> Result<Vec<NativeAddress>> {
        self.read(|| self.inner.entry_coordinates_many(addrs))
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
        self.read(|| self.inner.get(addr))
    }

    fn get_with_metadata(&self, addr: Address<'_>) -> Result<Option<ProviderValue>> {
        self.read(|| self.inner.get_with_metadata(addr))
    }

    fn supports_read(&self) -> bool {
        self.inner.supports_read()
    }

    fn exists(&self, addr: Address<'_>) -> Result<bool> {
        self.read(|| self.inner.exists(addr))
    }

    fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()> {
        self.mutate(RetryOperation::Set, addr, || self.inner.set(addr, value))
    }

    /// Forwarded rather than left to the trait default, which would call
    /// `self.set` and drop the expiry the inner provider can honor.
    fn set_expiring(
        &self,
        addr: Address<'_>,
        value: &SecretBytes,
        max_age: std::time::Duration,
    ) -> Result<()> {
        self.mutate(RetryOperation::SetExpiring, addr, || {
            self.inner.set_expiring(addr, value, max_age)
        })
    }

    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        self.mutate(RetryOperation::Delete, addr, || self.inner.delete(addr))
    }

    fn supports_delete(&self) -> bool {
        self.inner.supports_delete()
    }

    fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
        self.read(|| self.inner.check_deletable(addr))
    }

    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        self.read(|| self.inner.check_writable(addr))
    }

    fn generated_value_persistence(&self) -> ProducedValuePersistence {
        // Capability inspection is pure and must not trigger authentication.
        self.inner.generated_value_persistence()
    }

    fn prompted_value_persistence(&self) -> ProducedValuePersistence {
        // Capability inspection is pure and must not trigger authentication.
        self.inner.prompted_value_persistence()
    }

    fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
        self.read(|| self.inner.describe_write_target(addr))
    }

    fn auth_scope_key(&self) -> Option<String> {
        self.inner.auth_scope_key()
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    fn uri(&self) -> String {
        self.inner.uri()
    }

    fn same_entry(&self, other: &dyn Provider, addr: Address<'_>) -> Result<bool> {
        self.inner.same_entry(other, addr)
    }

    fn same_entries(
        &self,
        self_addr: Address<'_>,
        other: &dyn Provider,
        other_addr: Address<'_>,
    ) -> Result<bool> {
        self.inner.same_entries(self_addr, other, other_addr)
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

    fn with_base_dir(&mut self, base_dir: &std::path::Path) {
        self.inner.with_base_dir(base_dir);
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.inner.with_credentials(credentials);
    }

    fn reflect(&self, context: DiscoveryContext<'_>) -> Result<HashMap<String, crate::Secret>> {
        self.read(|| self.inner.reflect(context))
    }

    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretBytes>> {
        self.read(|| self.inner.get_many(requests))
    }

    fn get_many_with_metadata(
        &self,
        requests: &[(&str, Address<'_>)],
    ) -> Result<HashMap<String, ProviderValue>> {
        self.read(|| self.inner.get_many_with_metadata(requests))
    }

    fn exists_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashSet<String>> {
        self.read(|| self.inner.exists_many(requests))
    }
}

/// Serializes fallible initialization and remembers only successful attempts.
#[cfg(feature = "bw")]
pub(crate) struct SuccessCell<T> {
    value: std::sync::OnceLock<T>,
    lock: std::sync::Mutex<()>,
}
#[cfg(feature = "bw")]
impl<T> Default for SuccessCell<T> {
    fn default() -> Self {
        Self {
            value: std::sync::OnceLock::new(),
            lock: std::sync::Mutex::new(()),
        }
    }
}
#[cfg(feature = "bw")]
impl<T> SuccessCell<T> {
    pub(crate) fn get_or_try_init(
        &self,
        build: impl FnOnce() -> std::result::Result<T, String>,
    ) -> std::result::Result<&T, String> {
        if let Some(value) = self.value.get() {
            return Ok(value);
        }
        let _guard = self
            .lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(value) = self.value.get() {
            return Ok(value);
        }
        let value = build()?;
        Ok(self.value.get_or_init(|| value))
    }
    #[cfg(test)]
    pub(crate) fn set(&self, value: std::result::Result<T, String>) -> std::result::Result<(), T> {
        self.value
            .set(value.expect("fixture initializes successfully"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    fn failure() -> SecretSpecError {
        transient(
            SecretSpecError::ProviderOperationFailed("temporary service failure".into()),
            None,
        )
    }
    #[test]
    fn exponential_backoff_and_hint_cap_are_bounded() {
        let policy = RetryPolicy::default();
        let mut calls = 0;
        let mut waits = Vec::new();
        let value = policy
            .run_with(
                "custom",
                || {
                    calls += 1;
                    if calls < 3 { Err(failure()) } else { Ok(42) }
                },
                |delay| waits.push(delay),
            )
            .unwrap();
        assert_eq!(value, 42);
        assert_eq!(calls, 3);
        assert_eq!(
            waits,
            [Duration::from_millis(250), Duration::from_millis(500)]
        );
        assert_eq!(
            policy.delay(1, Some(Duration::from_secs(60))),
            Some(Duration::from_secs(10))
        );
        assert_eq!(policy.delay(1, Some(Duration::ZERO)), Some(Duration::ZERO));
        assert_eq!(policy.delay(3, None), None);
        assert_eq!(
            RetryPolicy::new(10).unwrap().delay(9, None),
            Some(Duration::from_secs(10))
        );
    }
    #[test]
    fn exhaustion_preserves_diagnostics_and_cannot_be_retried_again() {
        let mut calls = 0;
        let error = RetryPolicy::default()
            .run_with::<()>(
                "custom",
                || {
                    calls += 1;
                    Err(failure())
                },
                |_| {},
            )
            .unwrap_err();
        assert_eq!(calls, 3);
        assert_eq!(
            error.to_string(),
            "Provider operation failed: temporary service failure"
        );
        assert_eq!(error.kind(), "provider_operation_failed");
        assert_eq!(retry_hint(&error), None);
        let mut error = Some(error);
        RetryPolicy::default()
            .run_with::<()>(
                "custom",
                || Err(error.take().unwrap()),
                |_| panic!("outer retry multiplied the budget"),
            )
            .unwrap_err();
    }
    #[test]
    fn disabling_and_permanent_errors_make_one_call() {
        let mut calls = 0;
        RetryPolicy::new(1)
            .unwrap()
            .run_with::<()>(
                "custom",
                || {
                    calls += 1;
                    Err(failure())
                },
                |_| panic!("disabled retry slept"),
            )
            .unwrap_err();
        assert_eq!(calls, 1);
        RetryPolicy::default()
            .run_with::<()>(
                "bws",
                || {
                    Err(SecretSpecError::ProviderOperationFailed(
                        "authentication failed".into(),
                    ))
                },
                |_| panic!("permanent error slept"),
            )
            .unwrap_err();
    }
    #[test]
    fn configuration_rejects_bad_counts_and_unknown_fields() {
        for invalid in [
            "max_attempts = 0",
            "max_attempts = 11",
            "max_attempts = -1",
            "max_attempts = 1.5",
            "backoff = 20",
        ] {
            assert!(toml::from_str::<RetryPolicy>(invalid).is_err(), "{invalid}");
        }
        assert_eq!(
            toml::from_str::<RetryPolicy>("").unwrap(),
            RetryPolicy::default()
        );
        assert!(RetryPolicy::new(0).is_err());
        assert!(RetryPolicy::new(11).is_err());
    }
    #[test]
    fn cli_classification_is_conservative_and_only_for_network_providers() {
        for diagnostic in [
            "[503 Service Unavailable] upstream connect error: connection timeout",
            "HTTP 429 Too Many Requests",
            "connection reset by peer",
        ] {
            assert!(
                retry_hint(&classify_error(
                    "bws",
                    SecretSpecError::ProviderOperationFailed(diagnostic.into())
                ))
                .is_some()
            );
        }
        for diagnostic in [
            "authentication failed: HTTP 503",
            "could not parse HTTP 503 response",
            "invalid certificate: connection refused",
            "request failed",
            "secret timeout is not found",
        ] {
            assert!(
                retry_hint(&classify_error(
                    "bws",
                    SecretSpecError::ProviderOperationFailed(diagnostic.into())
                ))
                .is_none(),
                "{diagnostic}"
            );
        }
        assert!(
            retry_hint(&classify_error(
                "file",
                SecretSpecError::ProviderOperationFailed("HTTP 503".into())
            ))
            .is_none()
        );
    }
    struct Backend {
        calls: Arc<AtomicUsize>,
        safe: bool,
        managed: bool,
    }
    impl Provider for Backend {
        fn convention_address(&self, _: &str, _: &str, key: &str) -> Result<NativeAddress> {
            Ok(NativeAddress {
                item: key.into(),
                ..Default::default()
            })
        }
        fn get(&self, _: Address<'_>) -> Result<Option<SecretBytes>> {
            panic!("batch override was lost")
        }
        fn set(&self, _: Address<'_>, _: &SecretBytes) -> Result<()> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(transient(
                    SecretSpecError::ProviderOperationFailed("write failed".into()),
                    Some(Duration::ZERO),
                ))
            } else {
                Ok(())
            }
        }
        fn name(&self) -> &str {
            "custom"
        }
        fn uri(&self) -> String {
            "custom://".into()
        }
        fn retry_safe(&self, op: RetryOperation, _: Address<'_>) -> bool {
            self.safe && op == RetryOperation::Set
        }
        fn retry_ownership(&self) -> RetryOwnership {
            if self.managed {
                RetryOwnership::Managed
            } else {
                RetryOwnership::Shared
            }
        }
        fn get_many_with_metadata(
            &self,
            _: &[(&str, Address<'_>)],
        ) -> Result<HashMap<String, ProviderValue>> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(transient(
                    SecretSpecError::ProviderOperationFailed("read failed".into()),
                    Some(Duration::ZERO),
                ));
            }
            Ok(HashMap::from([(
                "KEY".into(),
                ProviderValue::new(SecretBytes::from_utf8("value"), Some(1234)),
            )]))
        }
    }
    #[test]
    fn wrapper_preserves_optimized_batch_and_metadata() {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = RetryingProvider::new(
            Box::new(Backend {
                calls: calls.clone(),
                safe: false,
                managed: false,
            }),
            RetryPolicy::default(),
        );
        let result = provider
            .get_many_with_metadata(&[("KEY", Address::convention("p", "default", "KEY"))])
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(result["KEY"].value.expose_secret(), b"value");
        assert_eq!(result["KEY"].expires_at_unix_ms, Some(1234));
    }
    #[test]
    fn writes_require_opt_in_and_managed_retries_have_no_outer_loop() {
        let addr = Address::convention("p", "default", "KEY");
        for (safe, managed, expected) in [(false, false, 1), (true, false, 2), (true, true, 1)] {
            let calls = Arc::new(AtomicUsize::new(0));
            let provider = RetryingProvider::new(
                Box::new(Backend {
                    calls: calls.clone(),
                    safe,
                    managed,
                }),
                RetryPolicy::default(),
            );
            assert_eq!(
                provider.set(addr, &SecretBytes::from_utf8("new")).is_ok(),
                expected == 2
            );
            assert_eq!(calls.load(Ordering::SeqCst), expected);
        }
    }
}
