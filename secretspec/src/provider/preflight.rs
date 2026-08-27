use super::{
    Address, DiscoveryContext, ProducedValuePersistence, Provider, ProviderCredentials,
    ProviderValue,
};
use crate::config::NativeAddress;
use crate::{Result, SecretSpecError};
use secrecy::SecretString;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

/// Return type from provider factories that pairs a provider with an
/// optional preflight check (e.g. authentication verification).
pub(crate) struct ProviderWithPreflight {
    pub provider: Box<dyn Provider>,
    pub preflight: Option<Box<dyn Fn() -> Result<()> + Send + Sync>>,
}

/// Process-wide deduplication of provider auth probes.
///
/// Caching the preflight check per provider *instance* was enough when one
/// instance served every secret, but a secret's `providers` fallback chain
/// builds a fresh instance per (secret, URI) pair, so N secrets would run N
/// identical auth probes (each a CLI round-trip). Providers whose auth state is
/// shared across instances advertise that via [`Provider::auth_scope_key`], and
/// [`PreflightGuard`] keys their probe here instead: the first caller per key
/// runs it, concurrent callers block on the same cell, and later callers
/// reuse the result.
///
/// Failures are returned to every caller waiting on the in-flight probe but
/// are not cached beyond that: the user may fix auth mid-process (e.g. unlock
/// the desktop app in a long-lived SDK process), so the next check re-probes.
type AuthCheckResult = std::result::Result<(), String>;
type AuthCheckCell = Arc<OnceLock<AuthCheckResult>>;

pub(crate) struct AuthCheckCache<K> {
    cells: Mutex<HashMap<K, AuthCheckCell>>,
}

impl<K> Default for AuthCheckCache<K> {
    fn default() -> Self {
        Self {
            cells: Mutex::new(HashMap::new()),
        }
    }
}

impl<K: std::hash::Hash + Eq + Clone> AuthCheckCache<K> {
    pub(crate) fn check(
        &self,
        key: K,
        probe: impl FnOnce() -> std::result::Result<(), String>,
    ) -> std::result::Result<(), String> {
        let cell = self
            .cells
            .lock()
            .unwrap()
            .entry(key.clone())
            .or_default()
            .clone();
        let result = cell.get_or_init(probe).clone();
        if result.is_err() {
            // Drop the failed cell so a later retry re-probes, but only if it
            // is still ours: another thread may have already replaced it.
            let mut cells = self.cells.lock().unwrap();
            if let Some(existing) = cells.get(&key)
                && Arc::ptr_eq(existing, &cell)
            {
                cells.remove(&key);
            }
        }
        result
    }
}

/// Auth probes shared across provider instances (see
/// [`Provider::auth_scope_key`]), keyed by provider name plus scope.
static PREFLIGHT_AUTH_CACHE: LazyLock<AuthCheckCache<(String, String)>> =
    LazyLock::new(AuthCheckCache::default);

/// Wrapper that runs a preflight check exactly once before any provider
/// operation, caching the result for all subsequent calls.
pub(super) struct PreflightGuard {
    inner: Box<dyn Provider>,
    preflight: Option<Box<dyn Fn() -> Result<()> + Send + Sync>>,
    result: OnceLock<std::result::Result<(), String>>,
}

impl PreflightGuard {
    pub(super) fn new(pwp: ProviderWithPreflight) -> Self {
        Self {
            inner: pwp.provider,
            preflight: pwp.preflight,
            result: OnceLock::new(),
        }
    }

    fn check(&self) -> Result<()> {
        let Some(f) = &self.preflight else {
            return Ok(());
        };
        // A provider with a shared auth scope dedupes the probe process-wide
        // in PREFLIGHT_AUTH_CACHE, so the per-instance providers that a
        // secret's `providers` chain creates all reuse one probe.
        if let Some(scope) = self.inner.auth_scope_key() {
            return PREFLIGHT_AUTH_CACHE
                .check((self.inner.name().to_string(), scope), || {
                    f().map_err(|e| crate::error::display_error_chain(&e))
                })
                .map_err(SecretSpecError::ProviderOperationFailed);
        }
        let result = self
            .result
            .get_or_init(|| f().map_err(|e| crate::error::display_error_chain(&e)));
        match result {
            Ok(()) => Ok(()),
            Err(msg) => Err(SecretSpecError::ProviderOperationFailed(msg.clone())),
        }
    }
}

impl Provider for PreflightGuard {
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

    fn entry_coordinates<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, NativeAddress>> {
        // Pure naming, no I/O: needs no auth preflight.
        self.inner.entry_coordinates(addr)
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        self.check()?;
        self.inner.get(addr)
    }

    fn get_with_metadata(&self, addr: Address<'_>) -> Result<Option<ProviderValue>> {
        self.check()?;
        self.inner.get_with_metadata(addr)
    }

    fn supports_read(&self) -> bool {
        self.inner.supports_read()
    }

    fn exists(&self, addr: Address<'_>) -> Result<bool> {
        self.check()?;
        self.inner.exists(addr)
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        self.check()?;
        self.inner.set(addr, value)
    }

    /// Forwarded rather than left to the trait default, which would call
    /// `self.set` and drop the expiry the inner provider can honor.
    fn set_expiring(
        &self,
        addr: Address<'_>,
        value: &SecretString,
        max_age: std::time::Duration,
    ) -> Result<()> {
        self.check()?;
        self.inner.set_expiring(addr, value, max_age)
    }

    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        self.check()?;
        self.inner.delete(addr)
    }

    fn supports_delete(&self) -> bool {
        self.inner.supports_delete()
    }

    fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
        self.inner.check_deletable(addr)
    }

    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        self.inner.check_writable(addr)
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
        self.inner.describe_write_target(addr)
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
        self.check()?;
        self.inner.reflect(context)
    }

    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        self.check()?;
        self.inner.get_many(requests)
    }

    fn get_many_with_metadata(
        &self,
        requests: &[(&str, Address<'_>)],
    ) -> Result<HashMap<String, ProviderValue>> {
        self.check()?;
        self.inner.get_many_with_metadata(requests)
    }

    fn exists_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashSet<String>> {
        self.check()?;
        self.inner.exists_many(requests)
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthCheckCache, PreflightGuard, ProviderWithPreflight};
    use crate::Result;
    use crate::config::NativeAddress;
    use crate::provider::{Address, Provider};
    use secrecy::SecretString;
    use std::cell::Cell;
    use std::sync::{Arc, Mutex};

    struct ProfileRecordingProvider {
        profile: Arc<Mutex<Option<String>>>,
    }

    impl Provider for ProfileRecordingProvider {
        fn convention_address(
            &self,
            _project: &str,
            _profile: &str,
            key: &str,
        ) -> Result<NativeAddress> {
            Ok(NativeAddress {
                item: key.to_string(),
                ..Default::default()
            })
        }

        fn get(&self, _addr: Address<'_>) -> Result<Option<SecretString>> {
            Ok(None)
        }

        fn set(&self, _addr: Address<'_>, _value: &SecretString) -> Result<()> {
            Ok(())
        }

        fn name(&self) -> &str {
            "profile-recording"
        }

        fn uri(&self) -> String {
            "profile-recording://".to_string()
        }

        fn set_profile(&self, profile: &str) {
            *self.profile.lock().unwrap() = Some(profile.to_string());
        }
    }

    #[test]
    fn success_probes_once_per_key() {
        let cache = AuthCheckCache::default();
        let probes = Cell::new(0);
        for _ in 0..3 {
            let result = cache.check("key", || {
                probes.set(probes.get() + 1);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }
        assert_eq!(probes.get(), 1);
    }

    #[test]
    fn failure_is_not_cached() {
        let cache = AuthCheckCache::default();
        assert_eq!(
            cache.check("key", || Err("not signed in".to_string())),
            Err("not signed in".to_string())
        );
        assert_eq!(cache.check("key", || Ok(())), Ok(()));

        let probes = Cell::new(0);
        assert_eq!(
            cache.check("key", || {
                probes.set(probes.get() + 1);
                Ok(())
            }),
            Ok(())
        );
        assert_eq!(probes.get(), 0);
    }

    #[test]
    fn keys_are_independent() {
        let cache = AuthCheckCache::default();
        assert_eq!(cache.check("a", || Ok(())), Ok(()));
        assert_eq!(
            cache.check("b", || Err("nope".to_string())),
            Err("nope".to_string())
        );
        assert_eq!(cache.check("a", || Err("unused".to_string())), Ok(()));
    }

    #[test]
    fn set_profile_reaches_the_provider_through_preflight_guard() {
        let profile = Arc::new(Mutex::new(None));
        let guard = PreflightGuard::new(ProviderWithPreflight {
            provider: Box::new(ProfileRecordingProvider {
                profile: Arc::clone(&profile),
            }),
            preflight: Some(Box::new(|| panic!("set_profile must not run preflight"))),
        });

        guard.set_profile("production");

        assert_eq!(profile.lock().unwrap().as_deref(), Some("production"));
    }
}
