use crate::Result;
use crate::provider::{Address, DiscoveryContext, Provider};
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(test)]
use tempfile::TempDir;

/// Mock provider for testing
pub struct MockProvider {
    storage: Arc<Mutex<HashMap<String, String>>>,
}

impl MockProvider {
    pub fn new() -> Self {
        Self {
            storage: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Provider for MockProvider {
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: format!("{}/{}/{}", project, profile, key),
            ..Default::default()
        })
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let full_key = super::flat_item(self, addr)?;
        let storage = self.storage.lock().unwrap();
        Ok(storage
            .get(&*full_key)
            .map(|v| SecretString::new(v.clone().into())))
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        let full_key = super::flat_item(self, addr)?.into_owned();
        let mut storage = self.storage.lock().unwrap();
        storage.insert(full_key, value.expose_secret().to_string());
        Ok(())
    }

    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        let item = super::flat_item(self, addr)?.into_owned();
        Ok(self.storage.lock().unwrap().remove(&item).is_some())
    }

    fn name(&self) -> &'static str {
        "mock"
    }

    fn uri(&self) -> String {
        "mock://".to_string()
    }
}

/// Provider that records how many times `get` runs for each resolved `item`,
/// so the shared [`get_each`](crate::provider::get_each) contract — identical
/// addresses fetched once, missing secrets omitted — can be asserted. Every
/// known item returns its stored value; anything else is `None`.
struct CountingProvider {
    values: HashMap<String, String>,
    gets: Arc<Mutex<HashMap<String, usize>>>,
}

impl CountingProvider {
    fn new(values: &[(&str, &str)]) -> Self {
        Self {
            values: values
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            gets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn get_count(&self, item: &str) -> usize {
        self.gets.lock().unwrap().get(item).copied().unwrap_or(0)
    }
}

impl Provider for CountingProvider {
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: format!("{}/{}/{}", project, profile, key),
            ..Default::default()
        })
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let item = super::flat_item(self, addr)?.into_owned();
        *self.gets.lock().unwrap().entry(item.clone()).or_insert(0) += 1;
        Ok(self
            .values
            .get(&item)
            .map(|v| SecretString::new(v.clone().into())))
    }

    fn set(&self, _addr: Address<'_>, _value: &SecretString) -> Result<()> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "counting"
    }

    fn uri(&self) -> String {
        "counting://".to_string()
    }
}

/// Process-global store backing [`MemTestProvider`], so a freshly built instance
/// observes writes made through an earlier one — required to exercise
/// store-then-resolve of a provider credential across separate `Secrets`.
static MEM_STORE: std::sync::LazyLock<Mutex<HashMap<String, String>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Registered, writable, profile-namespacing in-memory provider (`memtest://`).
/// Unlike `dotenv` (which ignores project/profile), this keys secrets by
/// `{project}/{profile}/{key}`, so tests can prove whether a store location
/// depends on the active profile.
pub(crate) struct MemTestProvider;
pub(crate) struct MemTestConfig;

impl TryFrom<&super::ProviderUrl> for MemTestConfig {
    type Error = crate::SecretSpecError;
    fn try_from(_url: &super::ProviderUrl) -> Result<Self> {
        Ok(Self)
    }
}

impl MemTestProvider {
    fn new(_config: MemTestConfig) -> Self {
        Self
    }
}

crate::register_provider! {
    struct: MemTestProvider,
    config: MemTestConfig,
    name: "memtest",
    description: "In-memory provider for tests",
    schemes: ["memtest"],
    examples: ["memtest://"],
    credential_names: ["test_token"],
    deletes: true,
}

impl Provider for MemTestProvider {
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: format!("{}/{}/{}", project, profile, key),
            ..Default::default()
        })
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let item = super::flat_item(self, addr)?.into_owned();
        Ok(MEM_STORE
            .lock()
            .unwrap()
            .get(&item)
            .map(|v| SecretString::new(v.clone().into())))
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        let item = super::flat_item(self, addr)?.into_owned();
        MEM_STORE
            .lock()
            .unwrap()
            .insert(item, value.expose_secret().to_string());
        Ok(())
    }

    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        let item = super::flat_item(self, addr)?.into_owned();
        Ok(MEM_STORE.lock().unwrap().remove(&item).is_some())
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        "memtest://".to_string()
    }
}

/// Peak in-flight reads for [`SlowTestProvider`], used to prove fallback-chain
/// resolution shares the provider and fans reads out under the configured cap.
static SLOW_CURRENT: AtomicUsize = AtomicUsize::new(0);
static SLOW_PEAK: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn reset_slow_peak() {
    SLOW_CURRENT.store(0, Ordering::SeqCst);
    SLOW_PEAK.store(0, Ordering::SeqCst);
}

pub(crate) fn slow_peak() -> usize {
    SLOW_PEAK.load(Ordering::SeqCst)
}

/// Registered in-memory provider whose reads pause long enough for fallback
/// concurrency to be observed (`slowtest://`).
pub(crate) struct SlowTestProvider;
pub(crate) struct SlowTestConfig;

impl TryFrom<&super::ProviderUrl> for SlowTestConfig {
    type Error = crate::SecretSpecError;

    fn try_from(_url: &super::ProviderUrl) -> Result<Self> {
        Ok(Self)
    }
}

impl SlowTestProvider {
    fn new(_config: SlowTestConfig) -> Self {
        Self
    }
}

crate::register_provider! {
    struct: SlowTestProvider,
    config: SlowTestConfig,
    name: "slowtest",
    description: "Slow in-memory provider for fallback concurrency tests",
    schemes: ["slowtest"],
    examples: ["slowtest://"],
    deletes: true,
}

impl Provider for SlowTestProvider {
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        MemTestProvider.convention_address(project, profile, key)
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let item = super::flat_item(self, addr)?.into_owned();
        let current = SLOW_CURRENT.fetch_add(1, Ordering::SeqCst) + 1;
        SLOW_PEAK.fetch_max(current, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(50));
        SLOW_CURRENT.fetch_sub(1, Ordering::SeqCst);
        Ok(MEM_STORE
            .lock()
            .unwrap()
            .get(&item)
            .map(|value| SecretString::new(value.clone().into())))
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        MemTestProvider.set(addr, value)
    }

    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        MemTestProvider.delete(addr)
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        "slowtest://".to_string()
    }
}

/// Registered in-memory provider whose first read snapshots [`MEM_STORE`].
///
/// This models providers such as BWS that cache a remote listing on the provider
/// instance: sharing one instance within a resolution is desirable, but reusing
/// it for a later resolution would return stale secret data. Reads also record
/// the session reason so tests can verify rebuilt providers receive reason
/// changes made between operations.
pub(crate) struct StatefulTestProvider {
    snapshot: std::sync::OnceLock<HashMap<String, String>>,
    reason: Mutex<Option<String>>,
    caller: Mutex<Option<crate::CallerContext>>,
}
pub(crate) struct StatefulTestConfig;

static STATEFUL_REASON_READS: std::sync::LazyLock<Mutex<HashMap<String, Vec<Option<String>>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));
static STATEFUL_CALLER_READS: std::sync::LazyLock<
    Mutex<HashMap<String, Vec<Option<crate::CallerContext>>>>,
> = std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

impl TryFrom<&super::ProviderUrl> for StatefulTestConfig {
    type Error = crate::SecretSpecError;

    fn try_from(_url: &super::ProviderUrl) -> Result<Self> {
        Ok(Self)
    }
}

impl StatefulTestProvider {
    fn new(_config: StatefulTestConfig) -> Self {
        Self {
            snapshot: std::sync::OnceLock::new(),
            reason: Mutex::new(None),
            caller: Mutex::new(None),
        }
    }
}

crate::register_provider! {
    struct: StatefulTestProvider,
    config: StatefulTestConfig,
    name: "statefultest",
    description: "Stateful in-memory provider for provider-lifetime tests",
    schemes: ["statefultest"],
    examples: ["statefultest://"],
    deletes: true,
}

impl Provider for StatefulTestProvider {
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        MemTestProvider.convention_address(project, profile, key)
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let item = super::flat_item(self, addr)?.into_owned();
        STATEFUL_REASON_READS
            .lock()
            .unwrap()
            .entry(item.clone())
            .or_default()
            .push(self.reason.lock().unwrap().clone());
        STATEFUL_CALLER_READS
            .lock()
            .unwrap()
            .entry(item.clone())
            .or_default()
            .push(self.caller.lock().unwrap().clone());
        let snapshot = self
            .snapshot
            .get_or_init(|| MEM_STORE.lock().unwrap().clone());
        Ok(snapshot
            .get(&item)
            .map(|value| SecretString::new(value.clone().into())))
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        MemTestProvider.set(addr, value)
    }

    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        MemTestProvider.delete(addr)
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        "statefultest://".to_string()
    }

    fn set_reason(&self, reason: Option<String>) {
        *self.reason.lock().unwrap() = reason;
    }

    fn set_caller(&self, caller: Option<crate::CallerContext>) {
        *self.caller.lock().unwrap() = caller;
    }
}

pub(crate) fn take_stateful_reason_reads(item: &str) -> Vec<Option<String>> {
    STATEFUL_REASON_READS
        .lock()
        .unwrap()
        .remove(item)
        .unwrap_or_default()
}

pub(crate) fn take_stateful_caller_reads(item: &str) -> Vec<Option<crate::CallerContext>> {
    STATEFUL_CALLER_READS
        .lock()
        .unwrap()
        .remove(item)
        .unwrap_or_default()
}

/// Registered provider that reads and deletes [`MEM_STORE`] like `memtest://`
/// but always fails to write (`failwrite://`).
///
/// Cache refreshes are best-effort, so tests need a store where a write can fail
/// while the entry it was meant to replace is still readable and removable —
/// exactly the situation a superseded cache entry must not survive.
pub(crate) struct FailWriteProvider;
pub(crate) struct FailWriteConfig;

impl TryFrom<&super::ProviderUrl> for FailWriteConfig {
    type Error = crate::SecretSpecError;
    fn try_from(_url: &super::ProviderUrl) -> Result<Self> {
        Ok(Self)
    }
}

impl FailWriteProvider {
    fn new(_config: FailWriteConfig) -> Self {
        Self
    }
}

crate::register_provider! {
    struct: FailWriteProvider,
    config: FailWriteConfig,
    name: "failwrite",
    description: "In-memory provider for tests whose writes always fail",
    schemes: ["failwrite"],
    examples: ["failwrite://"],
    deletes: true,
}

impl Provider for FailWriteProvider {
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: format!("{}/{}/{}", project, profile, key),
            ..Default::default()
        })
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        MemTestProvider.get(addr)
    }

    fn set(&self, _addr: Address<'_>, _value: &SecretString) -> Result<()> {
        Err(crate::SecretSpecError::ProviderOperationFailed(
            "failwrite always fails to write".to_string(),
        ))
    }

    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        MemTestProvider.delete(addr)
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        "failwrite://".to_string()
    }
}

/// Registered provider that reads and writes [`MEM_STORE`] like `memtest://` but
/// always fails to delete (`faildelete://`).
///
/// Declaring the delete capability and then failing at runtime is the case a
/// declared capability cannot rule out — a locked keychain, an unreachable
/// store — so cache invalidation still has to degrade sanely.
pub(crate) struct FailDeleteProvider;
pub(crate) struct FailDeleteConfig;

impl TryFrom<&super::ProviderUrl> for FailDeleteConfig {
    type Error = crate::SecretSpecError;
    fn try_from(_url: &super::ProviderUrl) -> Result<Self> {
        Ok(Self)
    }
}

impl FailDeleteProvider {
    fn new(_config: FailDeleteConfig) -> Self {
        Self
    }
}

crate::register_provider! {
    struct: FailDeleteProvider,
    config: FailDeleteConfig,
    name: "faildelete",
    description: "In-memory provider for tests whose deletes always fail",
    schemes: ["faildelete"],
    examples: ["faildelete://"],
    deletes: true,
}

impl Provider for FailDeleteProvider {
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        MemTestProvider.convention_address(project, profile, key)
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        MemTestProvider.get(addr)
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        MemTestProvider.set(addr, value)
    }

    fn delete(&self, _addr: Address<'_>) -> Result<bool> {
        Err(crate::SecretSpecError::ProviderOperationFailed(
            "faildelete always fails to delete".to_string(),
        ))
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        "faildelete://".to_string()
    }
}

/// The freshness window each `expiring://` write was asked for, keyed by
/// resolved item.
static EXPIRING_TTLS: std::sync::LazyLock<Mutex<HashMap<String, std::time::Duration>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// What `set_expiring` was last asked to bound `item` to, if anything.
pub(crate) fn recorded_expiry(item: &str) -> Option<std::time::Duration> {
    EXPIRING_TTLS.lock().unwrap().get(item).copied()
}

/// Registered provider that stores into [`MEM_STORE`] like `memtest://` and
/// records the expiry each write asked for (`expiring://`).
///
/// A store-side expiry is invisible from the outside — the value is simply
/// written — so this is how a test proves the requested window reaches the
/// provider instead of being dropped somewhere in the stack.
pub(crate) struct ExpiringProvider;
pub(crate) struct ExpiringConfig;

impl TryFrom<&super::ProviderUrl> for ExpiringConfig {
    type Error = crate::SecretSpecError;
    fn try_from(_url: &super::ProviderUrl) -> Result<Self> {
        Ok(Self)
    }
}

impl ExpiringProvider {
    fn new(_config: ExpiringConfig) -> Self {
        Self
    }
}

crate::register_provider! {
    struct: ExpiringProvider,
    config: ExpiringConfig,
    name: "expiring",
    description: "In-memory provider for tests that records requested expiries",
    schemes: ["expiring"],
    examples: ["expiring://"],
    deletes: true,
}

impl Provider for ExpiringProvider {
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        MemTestProvider.convention_address(project, profile, key)
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        MemTestProvider.get(addr)
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        MemTestProvider.set(addr, value)
    }

    fn set_expiring(
        &self,
        addr: Address<'_>,
        value: &SecretString,
        max_age: std::time::Duration,
    ) -> Result<()> {
        let item = super::flat_item(self, addr)?.into_owned();
        EXPIRING_TTLS.lock().unwrap().insert(item, max_age);
        self.set(addr, value)
    }

    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        MemTestProvider.delete(addr)
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        "expiring://".to_string()
    }
}

/// A single distinct address (the common case: one secret, or several sharing
/// one `ref`) is fetched once and its value shared, via the inline fast path.
#[test]
fn get_each_dedupes_one_address_across_names() {
    let p = CountingProvider::new(&[("svc", "val")]);
    let coords = crate::config::NativeAddress {
        item: "svc".into(),
        ..Default::default()
    };
    let addr = Address::Native(&coords);
    let out = super::get_each(&p, &[("FIRST", addr), ("SECOND", addr)]).unwrap();

    assert_eq!(out["FIRST"].expose_secret(), "val");
    assert_eq!(out["SECOND"].expose_secret(), "val");
    assert_eq!(p.get_count("svc"), 1, "one address must be fetched once");
}

/// Distinct addresses take the threaded path; each is fetched once, results map
/// back to the right names, and a secret that does not exist is omitted rather
/// than surfaced as an empty value.
#[test]
fn get_each_fetches_distinct_addresses_and_omits_missing() {
    let p = CountingProvider::new(&[("one", "v1"), ("two", "v2")]);
    let a1 = crate::config::NativeAddress {
        item: "one".into(),
        ..Default::default()
    };
    let a2 = crate::config::NativeAddress {
        item: "two".into(),
        ..Default::default()
    };
    let a3 = crate::config::NativeAddress {
        item: "absent".into(),
        ..Default::default()
    };
    let out = super::get_each(
        &p,
        &[
            ("A", Address::Native(&a1)),
            ("B", Address::Native(&a2)),
            ("C", Address::Native(&a3)),
        ],
    )
    .unwrap();

    assert_eq!(out["A"].expose_secret(), "v1");
    assert_eq!(out["B"].expose_secret(), "v2");
    assert!(!out.contains_key("C"), "a missing secret is omitted");
    assert_eq!(p.get_count("one"), 1);
    assert_eq!(p.get_count("two"), 1);
    assert_eq!(p.get_count("absent"), 1);
}

/// Provider that sleeps inside `get` so peak in-flight concurrency is observable.
struct PeakConcurrencyProvider {
    delay: Duration,
    current: AtomicUsize,
    peak: AtomicUsize,
}

impl PeakConcurrencyProvider {
    fn new(delay: Duration) -> Self {
        Self {
            delay,
            current: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }

    fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }
}

impl Provider for PeakConcurrencyProvider {
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: format!("{project}/{profile}/{key}"),
            ..Default::default()
        })
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let item = super::flat_item(self, addr)?.into_owned();
        let now = self.current.fetch_add(1, Ordering::SeqCst) + 1;
        // Record peak without a CAS loop: sequential max under SeqCst is enough
        // for this test's purpose (assert peak ≤ cap, not a tight race metric).
        let mut peak = self.peak.load(Ordering::SeqCst);
        while now > peak {
            match self
                .peak
                .compare_exchange(peak, now, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break,
                Err(observed) => peak = observed,
            }
        }
        std::thread::sleep(self.delay);
        self.current.fetch_sub(1, Ordering::SeqCst);
        Ok(Some(SecretString::new(item.into())))
    }

    fn set(&self, _addr: Address<'_>, _value: &SecretString) -> Result<()> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "peak"
    }

    fn uri(&self) -> String {
        "peak://".to_string()
    }
}

#[test]
fn get_each_concurrency_defaults_and_parses_env() {
    let _lock = crate::tests::scrub_resolution_env();

    let _clear = crate::tests::EnvVarGuard::remove(super::GET_EACH_CONCURRENCY_ENV);
    assert_eq!(super::get_each_concurrency(), 8);

    let _set = crate::tests::EnvVarGuard::set(super::GET_EACH_CONCURRENCY_ENV, "4");
    assert_eq!(super::get_each_concurrency(), 4);

    drop(_set);
    let _zero = crate::tests::EnvVarGuard::set(super::GET_EACH_CONCURRENCY_ENV, "0");
    assert_eq!(
        super::get_each_concurrency(),
        8,
        "zero is invalid and must fall back"
    );

    drop(_zero);
    let _bad = crate::tests::EnvVarGuard::set(super::GET_EACH_CONCURRENCY_ENV, "nope");
    assert_eq!(super::get_each_concurrency(), 8);
}

/// `SECRETSPEC_PROVIDER_CONCURRENCY` must cap in-flight unique-address fetches.
/// Without the cap, `get_each` used to spawn one thread per address and open
/// one connection each — the Vault/OpenBao reverse-proxy storm.
#[test]
fn get_each_respects_concurrency_cap() {
    let _lock = crate::tests::scrub_resolution_env();
    let _env = crate::tests::EnvVarGuard::set(super::GET_EACH_CONCURRENCY_ENV, "3");

    let p = PeakConcurrencyProvider::new(Duration::from_millis(80));
    // Keep NativeAddress values alive for the Address::Native borrows.
    let coords: Vec<crate::config::NativeAddress> = (0..10)
        .map(|i| crate::config::NativeAddress {
            item: format!("item-{i}"),
            ..Default::default()
        })
        .collect();
    let requests: Vec<(&str, Address<'_>)> = coords
        .iter()
        .enumerate()
        .map(|(i, c)| {
            // Leak names into static-ish storage via coords item for simplicity:
            // use a fixed name table.
            (
                // names only need to be unique keys in the result map
                ["n0", "n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8", "n9"][i],
                Address::Native(c),
            )
        })
        .collect();

    let out = super::get_each(&p, &requests).unwrap();
    assert_eq!(out.len(), 10);
    assert!(
        p.peak() <= 3,
        "peak in-flight gets {} exceeded concurrency cap 3",
        p.peak()
    );
    // Sanity: with a real sleep and 10 items, we should have seen more than 1.
    assert!(
        p.peak() >= 2,
        "expected some concurrency, peak={}",
        p.peak()
    );
}

#[test]
fn test_create_from_string_with_full_uris() {
    // Test basic onepassword URI
    let provider = Box::<dyn Provider>::try_from("onepassword://Private").unwrap();
    assert_eq!(provider.name(), "onepassword");

    // Test onepassword with account
    let provider = Box::<dyn Provider>::try_from("onepassword://work@Production").unwrap();
    assert_eq!(provider.name(), "onepassword");

    // Test onepassword with the service account scheme; the token comes from a
    // credential or the environment, never from the URI.
    let provider = Box::<dyn Provider>::try_from("onepassword+token://Private").unwrap();
    assert_eq!(provider.name(), "onepassword");
}

/// A URL password is always a credential, and a URI is the one place a
/// credential must never live: it reaches committed manifests, shell history,
/// and CI logs, where no amount of terminal redaction can retract it. Enforce
/// for *every* registered scheme that such a URI builds nothing and that the
/// refusal does not repeat the secret back.
///
/// The username, host, and path positions are intentionally untouched: they
/// hold non-secret attribution (1Password accounts, AWS profiles, Vault
/// namespaces). A scheme whose username *was* a credential rejects it itself,
/// which `try_from_token_scheme_rejects_a_token_in_the_uri` covers.
#[test]
fn every_scheme_rejects_a_userinfo_password() {
    const SECRET: &str = "leaked_pw_DO_NOT_ECHO";

    for reg in super::PROVIDER_REGISTRY {
        for &scheme in reg.metadata.schemes {
            let source = format!("{scheme}://attribution:{SECRET}@host/path");
            let Err(error) = Box::<dyn Provider>::try_from(source.as_str()) else {
                panic!("provider scheme {scheme:?} accepted a URL password");
            };
            let message = error.to_string();
            assert!(
                !message.contains(SECRET),
                "provider scheme {scheme:?} echoed a URL password into its error: {message:?}"
            );
            // The refusal has to be actionable, so it names the credentials this
            // provider accepts instead. Driven by the registration, so a new
            // provider gets the same quality without touching this test.
            for credential in reg.metadata.credential_names {
                assert!(
                    message.contains(credential),
                    "provider scheme {scheme:?} refused a URL password without naming its \
                     {credential:?} credential: {message:?}"
                );
            }
        }
    }
}

/// A profile is runtime context for resolving native addresses, not part of a
/// provider's name for its store. If one of these identities changed after
/// `set_profile`, cache planning (which constructs providers without a
/// profile) could no longer match the provider used during resolution.
#[test]
fn set_profile_preserves_provider_identities_across_the_registry() {
    for reg in super::PROVIDER_REGISTRY {
        assert!(
            !reg.metadata.info.examples.is_empty(),
            "provider {:?} has no registered example for the set_profile identity invariant",
            reg.metadata.info.name
        );

        for &example in reg.metadata.info.examples {
            let provider = Box::<dyn Provider>::try_from(example).unwrap_or_else(|error| {
                panic!(
                    "provider {:?} registered an example that could not be built ({example:?}): \
                     {error}",
                    reg.metadata.info.name
                )
            });
            let uri = provider.uri();
            let storage_identity = provider.storage_identity();
            let entry_container_identity = provider.entry_container_identity();

            provider.set_profile("set-profile-identity-invariant");

            assert_eq!(
                provider.uri(),
                uri,
                "provider {:?} changed uri() after set_profile (example {example:?})",
                reg.metadata.info.name
            );
            assert_eq!(
                provider.storage_identity(),
                storage_identity,
                "provider {:?} changed storage_identity() after set_profile (example \
                 {example:?})",
                reg.metadata.info.name
            );
            assert_eq!(
                provider.entry_container_identity(),
                entry_container_identity,
                "provider {:?} changed entry_container_identity() after set_profile (example \
                 {example:?})",
                reg.metadata.info.name
            );
        }
    }
}

#[test]
fn test_create_from_string_with_plain_names() {
    // Test plain provider names
    let provider = Box::<dyn Provider>::try_from("env").unwrap();
    assert_eq!(provider.name(), "env");

    let provider = Box::<dyn Provider>::try_from("systemd-credential").unwrap();
    assert_eq!(provider.name(), "systemd-credential");

    let provider = Box::<dyn Provider>::try_from("keyring").unwrap();
    assert_eq!(provider.name(), "keyring");

    let provider = Box::<dyn Provider>::try_from("dotenv").unwrap();
    assert_eq!(provider.name(), "dotenv");

    let Err(error) = Box::<dyn Provider>::try_from("file") else {
        panic!("file should require an explicit directory");
    };
    assert!(
        error
            .to_string()
            .contains("requires an explicit relative or absolute directory path")
    );

    // Test onepassword separately to debug the issue
    match Box::<dyn Provider>::try_from("onepassword") {
        Ok(provider) => assert_eq!(provider.name(), "onepassword"),
        Err(e) => panic!("Failed to create onepassword provider: {}", e),
    }

    let provider = Box::<dyn Provider>::try_from("lastpass").unwrap();
    assert_eq!(provider.name(), "lastpass");

    let provider = Box::<dyn Provider>::try_from("dashlane").unwrap();
    assert_eq!(provider.name(), "dashlane");

    let provider = Box::<dyn Provider>::try_from("gopass").unwrap();
    assert_eq!(provider.name(), "gopass");

    let provider = Box::<dyn Provider>::try_from("pass").unwrap();
    assert_eq!(provider.name(), "pass");

    let provider = Box::<dyn Provider>::try_from("protonpass").unwrap();
    assert_eq!(provider.name(), "protonpass");
}

#[test]
fn test_create_from_string_with_colon() {
    // Test provider names with colon
    let provider = Box::<dyn Provider>::try_from("env:").unwrap();
    assert_eq!(provider.name(), "env");

    let provider = Box::<dyn Provider>::try_from("keyring:").unwrap();
    assert_eq!(provider.name(), "keyring");
}

#[test]
fn test_invalid_onepassword_scheme() {
    // Test that '1password' scheme gives proper error suggesting 'onepassword'
    let result = Box::<dyn Provider>::try_from("1password");
    match result {
        Err(err) => assert!(err.to_string().contains("Use 'onepassword' instead")),
        Ok(_) => panic!("Expected error for '1password' scheme"),
    }

    let result = Box::<dyn Provider>::try_from("1password:");
    match result {
        Err(err) => assert!(err.to_string().contains("Use 'onepassword' instead")),
        Ok(_) => panic!("Expected error for '1password:' scheme"),
    }

    let result = Box::<dyn Provider>::try_from("1password://Private");
    match result {
        Err(err) => assert!(err.to_string().contains("Use 'onepassword' instead")),
        Ok(_) => panic!("Expected error for '1password://' scheme"),
    }
}

#[test]
fn test_dotenv_with_custom_path() {
    // Test dotenv provider with relative path - host part becomes first folder
    let provider = Box::<dyn Provider>::try_from("dotenv://custom/path/to/.env").unwrap();
    assert_eq!(provider.name(), "dotenv");

    // Test with absolute path format
    let provider = Box::<dyn Provider>::try_from("dotenv:///custom/path/.env").unwrap();
    assert_eq!(provider.name(), "dotenv");
}

#[test]
fn test_unknown_provider() {
    let result = Box::<dyn Provider>::try_from("unknown");
    assert!(result.is_err());
    match result {
        Err(crate::SecretSpecError::ProviderNotFound(scheme)) => {
            assert_eq!(scheme, "unknown");
        }
        _ => panic!("Expected ProviderNotFound error"),
    }
}

#[test]
fn test_dotenv_shorthand_from_docs() {
    // Test the example from line 187 of registry.rs
    let provider = Box::<dyn Provider>::try_from("dotenv:.env.production").unwrap();
    assert_eq!(provider.name(), "dotenv");
}

#[test]
fn test_documentation_examples() {
    // Test examples from the documentation

    // From line 102: onepassword://work@Production
    let provider = Box::<dyn Provider>::try_from("onepassword://work@Production").unwrap();
    assert_eq!(provider.name(), "onepassword");

    // From line 107: dotenv:/path/to/.env
    let provider = Box::<dyn Provider>::try_from("dotenv:/path/to/.env").unwrap();
    assert_eq!(provider.name(), "dotenv");

    // From line 115: lastpass://folder
    let provider = Box::<dyn Provider>::try_from("lastpass://folder").unwrap();
    assert_eq!(provider.name(), "lastpass");

    // Test dotenv examples from provider list
    let provider = Box::<dyn Provider>::try_from("dotenv://path").unwrap();
    assert_eq!(provider.name(), "dotenv");

    // File provider examples
    let provider = Box::<dyn Provider>::try_from("file:./.secrets").unwrap();
    assert_eq!(provider.name(), "file");
    assert_eq!(provider.uri(), "file://./.secrets");

    // Test pass examples
    let provider = Box::<dyn Provider>::try_from("pass://").unwrap();
    assert_eq!(provider.name(), "pass");

    // dashlane://note pins the Dashlane content type searched
    let provider = Box::<dyn Provider>::try_from("dashlane://note").unwrap();
    assert_eq!(provider.name(), "dashlane");
    assert_eq!(provider.uri(), "dashlane://note");
}

#[test]
fn test_edge_cases_and_normalization() {
    // Test scheme-only format (mentioned in docs line 151)
    let provider = Box::<dyn Provider>::try_from("keyring:").unwrap();
    assert_eq!(provider.name(), "keyring");

    // Test dotenv special case without authority (line 152-153)
    let provider = Box::<dyn Provider>::try_from("dotenv:/absolute/path").unwrap();
    assert_eq!(provider.name(), "dotenv");

    // env takes no authority: a variable is addressed via `ref`, not the URI.
    let Err(err) = Box::<dyn Provider>::try_from("env://localhost") else {
        panic!("env authority must be rejected");
    };
    assert!(err.to_string().contains("ref = { item ="), "{err}");
}

#[test]
fn test_onepassword_uri_forms() {
    // Vault-only form
    let provider = Box::<dyn Provider>::try_from("onepassword://Production").unwrap();
    assert_eq!(provider.name(), "onepassword");

    // op:// URIs (1Password's own reference syntax) are no longer provider
    // addresses: the error spells out the exact `ref` table translation.
    let Err(err) = Box::<dyn Provider>::try_from("op://Production/db/password") else {
        panic!("op:// provider spec must be rejected");
    };
    assert!(
        err.to_string()
            .contains("ref = { vault = \"Production\", item = \"db\", field = \"password\" }"),
        "{err}"
    );

    // Any item path on the provider URI fails loudly instead of being
    // silently discarded.
    assert!(Box::<dyn Provider>::try_from("onepassword://vault/Production").is_err());
}

#[test]
fn test_url_parsing_behavior() {
    use url::Url;

    // Test how URLs are actually parsed
    let url = "onepassword://vault/Production".parse::<Url>().unwrap();
    assert_eq!(url.scheme(), "onepassword");
    assert_eq!(url.host_str(), Some("vault"));
    assert_eq!(url.path(), "/Production");

    // Test dotenv URL parsing - host part becomes part of the path
    let url = "dotenv://path/to/.env".parse::<Url>().unwrap();
    assert_eq!(url.scheme(), "dotenv");
    assert_eq!(url.host_str(), Some("path"));
    assert_eq!(url.path(), "/to/.env");
}

#[test]
fn test_onepassword_vault_name_with_spaces() {
    // Vault names can contain spaces (e.g., "Home Lab")
    // Users should be able to write them with percent-encoding
    let provider = Box::<dyn Provider>::try_from("onepassword://Home%20Lab").unwrap();
    assert_eq!(provider.name(), "onepassword");
    assert_eq!(provider.uri(), "onepassword://Home%20Lab");

    // Users should also be able to write them with raw spaces
    let provider = Box::<dyn Provider>::try_from("onepassword://Home Lab").unwrap();
    assert_eq!(provider.name(), "onepassword");
    assert_eq!(provider.uri(), "onepassword://Home%20Lab");

    // With account@vault format
    let provider = Box::<dyn Provider>::try_from("onepassword://work@Home Lab").unwrap();
    assert_eq!(provider.name(), "onepassword");
    assert_eq!(provider.uri(), "onepassword://work@Home%20Lab");
}

#[test]
fn test_provider_names_with_special_characters() {
    // Pass provider with spaces in folder prefix
    let provider = Box::<dyn Provider>::try_from("pass://My Secrets/app").unwrap();
    assert_eq!(provider.name(), "pass");

    // Keyring provider with spaces in folder prefix
    let provider = Box::<dyn Provider>::try_from("keyring://My App/{profile}/{key}").unwrap();
    assert_eq!(provider.name(), "keyring");

    // LastPass provider with spaces in folder name
    let provider = Box::<dyn Provider>::try_from("lastpass://Shared Items/dev").unwrap();
    assert_eq!(provider.name(), "lastpass");

    // Pre-encoded values should also work
    let provider = Box::<dyn Provider>::try_from("pass://My%20Secrets/app").unwrap();
    assert_eq!(provider.name(), "pass");
}

// Integration tests for all providers
#[cfg(test)]
mod integration_tests {
    use super::*;
    #[cfg(feature = "ejson")]
    use crate::config::{CredentialSource, NativeAddress};

    fn generate_test_project_name() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros();
        let suffix = timestamp % 100000;
        format!("secretspec_test_{}", suffix)
    }

    fn get_test_providers() -> Vec<String> {
        std::env::var("SECRETSPEC_TEST_PROVIDERS")
            .unwrap_or_else(|_| String::new())
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().to_string())
            .collect()
    }

    #[cfg(feature = "ejson")]
    fn create_ejson_provider() -> (Box<dyn Provider>, Option<TempDir>) {
        let temp_dir = TempDir::new().expect("Create EJSON integration directory");
        let keygen = std::process::Command::new("ejson")
            .arg("keygen")
            .output()
            .expect("Testing ejson requires the official CLI on PATH");
        assert!(keygen.status.success(), "ejson keygen failed");
        let output = String::from_utf8(keygen.stdout).expect("ejson keygen output must be UTF-8");
        let keys: Vec<&str> = output
            .lines()
            .filter(|line| line.len() == 64 && line.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .collect();
        assert_eq!(
            keys.len(),
            2,
            "ejson keygen must print one public and private key"
        );

        let encrypted = temp_dir.path().join("integration.ejson");
        std::fs::write(
            &encrypted,
            serde_json::to_vec_pretty(&serde_json::json!({
                "_public_key": keys[0],
                "TOKEN": "official-cli-value",
            }))
            .unwrap(),
        )
        .unwrap();
        let encrypt = std::process::Command::new("ejson")
            .arg("encrypt")
            .arg(&encrypted)
            .output()
            .expect("run ejson encrypt");
        assert!(encrypt.status.success(), "ejson encrypt failed");

        let key_file = temp_dir.path().join("keys.env");
        std::fs::write(&key_file, format!("PRIVATE_KEY={}\n", keys[1])).unwrap();
        let target =
            crate::provider::ejson::EjsonProvider::new(crate::provider::ejson::EjsonConfig {
                path: encrypted,
            });
        let target_uri = crate::provider::Provider::uri(&target);
        let key_source =
            crate::provider::dotenv::DotEnvProvider::new(crate::provider::dotenv::DotEnvConfig {
                path: key_file,
            });
        let secrets = crate::tests::secrets_with_credential_alias(
            &target_uri,
            HashMap::from([(
                "private_key".to_string(),
                CredentialSource {
                    provider: crate::provider::Provider::uri(&key_source),
                    reference: Some(NativeAddress {
                        item: "PRIVATE_KEY".to_string(),
                        ..Default::default()
                    }),
                },
            )]),
        );
        let provider = secrets
            .get_provider(Some("target"), Some("default"))
            .expect("the sourced private key should build the EJSON provider");
        (provider, Some(temp_dir))
    }

    fn create_provider_with_temp_path(provider_name: &str) -> (Box<dyn Provider>, Option<TempDir>) {
        match provider_name {
            "dotenv" => {
                let temp_dir = TempDir::new().expect("Create temp directory");
                let dotenv_path = temp_dir.path().join(".env");
                let provider_spec = format!("dotenv:{}", dotenv_path.to_str().unwrap());
                let provider = Box::<dyn Provider>::try_from(provider_spec.as_str())
                    .expect("Should create dotenv provider with path");
                (provider, Some(temp_dir))
            }
            "file" => {
                let temp_dir = TempDir::new().expect("Create temp directory");
                let provider_spec = format!("file:{}", temp_dir.path().display());
                let provider = Box::<dyn Provider>::try_from(provider_spec.as_str())
                    .expect("Should create file provider with path");
                (provider, Some(temp_dir))
            }
            #[cfg(feature = "ejson")]
            "ejson" => create_ejson_provider(),
            "pass" => {
                let provider =
                    Box::<dyn Provider>::try_from("pass").expect("Should create pass provider");
                (provider, None)
            }
            #[cfg(feature = "vault")]
            // "vault" tests KV v2 (default), "vault-kv1" tests KV v1.
            // Set VAULT_TOKEN and run a Vault-compatible dev server.
            // For KV v1: vault secrets enable -path=kv1 -version=1 kv
            "vault" | "vault-kv1" => {
                let provider_spec = if provider_name == "vault-kv1" {
                    "vault://127.0.0.1:8200/kv1?tls=false&kv=1"
                } else {
                    "vault://127.0.0.1:8200?tls=false"
                };
                let provider = Box::<dyn Provider>::try_from(provider_spec)
                    .expect("Should create vault provider");
                (provider, None)
            }
            #[cfg(feature = "openbao")]
            // "openbao" tests KV v2 (default), "openbao-kv1" tests KV v1.
            // Set BAO_TOKEN and run `bao server -dev`.
            // For KV v1: bao secrets enable -path=kv1 -version=1 kv
            "openbao" | "openbao-kv1" => {
                let provider_spec = if provider_name == "openbao-kv1" {
                    "openbao://127.0.0.1:8200/kv1?tls=false&kv=1"
                } else {
                    "openbao://127.0.0.1:8200?tls=false"
                };
                let provider = Box::<dyn Provider>::try_from(provider_spec)
                    .expect("Should create openbao provider");
                (provider, None)
            }
            #[cfg(feature = "infisical")]
            // Bare "infisical" names no project, so route it through a real
            // one instead of failing to parse in the generic `_` branch below.
            // Set INFISICAL_TEST_PROJECT to a project UUID, INFISICAL_TEST_HOST
            // to reach a self-hosted instance (default: Infisical Cloud), and
            // authenticate with INFISICAL_CLIENT_ID/INFISICAL_CLIENT_SECRET or
            // INFISICAL_TOKEN. Prefer the former, and exercise both: only the
            // client_id/client_secret path logs in, so a token alone leaves
            // that request untested. The environment is pinned (INFISICAL_TEST_ENV,
            // default `dev`, which every new project has) because these tests
            // run under profiles no Infisical environment is named after;
            // profiles still separate, by folder.
            "infisical" => {
                let project = std::env::var("INFISICAL_TEST_PROJECT").expect(
                    "Testing the infisical provider requires a real project: set INFISICAL_TEST_PROJECT to a project UUID (and authenticate via INFISICAL_CLIENT_ID/INFISICAL_CLIENT_SECRET or INFISICAL_TOKEN).",
                );
                let host = std::env::var("INFISICAL_TEST_HOST")
                    .unwrap_or_else(|_| "app.infisical.com".to_string());
                let env = std::env::var("INFISICAL_TEST_ENV").unwrap_or_else(|_| "dev".to_string());
                // A self-hosted instance is commonly served over plain HTTP.
                let tls = if host.starts_with("localhost") || host.starts_with("127.0.0.1") {
                    "&tls=false"
                } else {
                    ""
                };
                let provider_spec = format!("infisical://{host}/{project}?env={env}{tls}");
                let provider = Box::<dyn Provider>::try_from(provider_spec.as_str())
                    .expect("Should create infisical provider");
                (provider, None)
            }
            #[cfg(feature = "akv")]
            // Bare "akv" has no vault name, so route it through a real
            // AKV_TEST_VAULT instead of falling into the generic `_` branch
            // below, where `try_from("akv")` fails to parse and panics with
            // a misleading "akv provider should exist" instead of pointing
            // at the missing configuration. Set AKV_TEST_VAULT to a real Key
            // Vault name and authenticate via AZURE_TENANT_ID/AZURE_CLIENT_ID/
            // AZURE_CLIENT_SECRET or `az login` to exercise this provider.
            "akv" => {
                let vault = std::env::var("AKV_TEST_VAULT").expect(
                    "Testing the akv provider requires a real Key Vault: set AKV_TEST_VAULT to a vault name (and authenticate via AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET or `az login`).",
                );
                let provider_spec = format!("akv://{vault}");
                let provider = Box::<dyn Provider>::try_from(provider_spec.as_str())
                    .expect("Should create akv provider");
                (provider, None)
            }
            #[cfg(feature = "aac")]
            // Set AAC_TEST_STORE to a real store name and authenticate
            // with an App Configuration Data Owner identity. An optional
            // AAC_TEST_LABEL keeps live fixtures in one exact label.
            "aac" => {
                let store = std::env::var("AAC_TEST_STORE").expect(
                    "Testing the aac provider requires a real store: set AAC_TEST_STORE to a store name (and authenticate via AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET or `az login`).",
                );
                let mut provider_spec = format!("aac://{store}");
                if let Ok(label) = std::env::var("AAC_TEST_LABEL")
                    && !label.is_empty()
                {
                    provider_spec.push_str("?label=");
                    provider_spec.push_str(&crate::provider::ProviderUrl::encode_query(&label));
                }
                let provider = Box::<dyn Provider>::try_from(provider_spec.as_str())
                    .expect("Should create aac provider");
                (provider, None)
            }
            _ => {
                let provider = Box::<dyn Provider>::try_from(provider_name)
                    .unwrap_or_else(|_| panic!("{} provider should exist", provider_name));
                (provider, None)
            }
        }
    }

    // Generic test function that tests a provider implementation
    fn test_provider_basic_workflow(provider: &dyn Provider, provider_name: &str) {
        let project_name = generate_test_project_name();

        // Test 1: Get non-existent secret
        let result = provider.get(Address::convention(
            &project_name,
            "default",
            "TEST_PASSWORD",
        ));
        match result {
            Ok(None) => {
                // Expected: key doesn't exist
            }
            Ok(Some(_)) => {
                panic!("[{}] Should not find non-existent secret", provider_name);
            }
            Err(_) => {
                // Some providers may return error instead of None
            }
        }

        // Test 2: Try to set a secret (may fail for read-only providers)
        let test_value = SecretString::new(format!("test_password_{}", provider_name).into());

        let writable = provider
            .check_writable(Address::convention("proj", "default", "KEY"))
            .is_ok();
        if writable {
            // Provider claims to support set, so it should work
            provider
                .set(
                    Address::convention(&project_name, "default", "TEST_PASSWORD"),
                    &test_value,
                )
                .unwrap_or_else(|_| {
                    panic!(
                        "[{}] Provider claims to support set but failed",
                        provider_name
                    )
                });

            // Verify we can retrieve it
            let retrieved = provider
                .get(Address::convention(
                    &project_name,
                    "default",
                    "TEST_PASSWORD",
                ))
                .unwrap_or_else(|_| {
                    panic!(
                        "[{}] Should not error when getting after set",
                        provider_name
                    )
                });

            match retrieved {
                Some(value) => {
                    assert_eq!(
                        value.expose_secret(),
                        test_value.expose_secret(),
                        "[{}] Retrieved value should match set value",
                        provider_name
                    );
                }
                None => {
                    panic!("[{}] Should find secret after setting it", provider_name);
                }
            }
        } else {
            // Provider is read-only, verify set fails
            match provider.set(
                Address::convention(&project_name, "default", "TEST_PASSWORD"),
                &test_value,
            ) {
                Ok(_) => {
                    panic!(
                        "[{}] Read-only provider should not allow set operations",
                        provider_name
                    );
                }
                Err(_) => {
                    println!(
                        "[{}] Read-only provider correctly rejected set",
                        provider_name
                    );
                }
            }
        }

        // Test 3: Deleting reports whether it removed anything and is
        // idempotent. Cache invalidation runs over secrets that may never have
        // been cached, so an absent entry is a no-op rather than an error — the
        // one behavior a provider is easiest to get wrong by matching the
        // not-found message of a different subcommand.
        let addr = Address::convention(&project_name, "default", "TEST_PASSWORD");
        match provider.delete(addr) {
            Ok(removed) => {
                assert_eq!(
                    removed, writable,
                    "[{provider_name}] delete must report whether an entry was removed"
                );
                assert!(
                    provider.get(addr).unwrap_or(None).is_none(),
                    "[{provider_name}] the secret must be gone after delete"
                );
                assert!(
                    !provider.delete(addr).unwrap_or_else(|error| panic!(
                        "[{provider_name}] deleting an absent entry must not fail: {error}"
                    )),
                    "[{provider_name}] deleting an absent entry removes nothing"
                );
            }
            // Deletion is opt-in; a provider that has not opted in says so.
            Err(error) => assert!(
                error.to_string().contains("does not support deleting"),
                "[{provider_name}] unexpected delete failure: {error}"
            ),
        }
    }

    #[cfg(feature = "ejson")]
    #[test]
    fn test_ejson_official_cli_and_sourced_credential() {
        if !get_test_providers()
            .iter()
            .any(|provider| provider == "ejson")
        {
            eprintln!("skipping: SECRETSPEC_TEST_PROVIDERS does not name ejson");
            return;
        }
        let (provider, _temp_dir) = create_ejson_provider();
        let value = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".to_string(),
                ..Default::default()
            }))
            .expect("official EJSON decrypt should succeed")
            .expect("the encrypted TOKEN should exist");
        assert_eq!(value.expose_secret(), "official-cli-value");
    }

    #[test]
    fn test_all_providers_basic_workflow() {
        // Test with our internal providers directly
        println!("Testing MockProvider");
        let mock = MockProvider::new();
        test_provider_basic_workflow(&mock, "mock");

        // Test actual providers if environment variable is set
        let providers = get_test_providers();
        for provider_name in providers {
            println!("Testing provider: {}", provider_name);
            let (provider, _temp_dir) = create_provider_with_temp_path(&provider_name);
            test_provider_basic_workflow(provider.as_ref(), &provider_name);
        }
    }

    /// A value Infisical withholds surfaces as a refusal, never as a secret.
    ///
    /// An identity permitted to see that a secret exists, but not to read it,
    /// still gets HTTP 200: the value is replaced with a placeholder and
    /// `secretValueHidden` is set. Handing that on would export a literal
    /// `<hidden-by-infisical>` to the process SecretSpec runs, and reporting it
    /// absent would read as an unset secret.
    ///
    /// Telling those identities apart needs a custom role, which Infisical
    /// gates behind a paid tier, so this runs only where one exists: set
    /// `INFISICAL_TEST_NOREAD_CLIENT_ID` and `INFISICAL_TEST_NOREAD_CLIENT_SECRET`
    /// to an identity holding that role, alongside the usual
    /// `INFISICAL_TEST_PROJECT` and a writable identity to plant the secret
    /// with. The refusal itself is covered without any of that by
    /// `provider::infisical::tests::a_withheld_value_is_refused`; this test is
    /// what proves the placeholder still looks like Infisical says it does.
    #[cfg(feature = "infisical")]
    #[test]
    fn test_infisical_refuses_a_withheld_value() {
        let (Ok(client_id), Ok(client_secret)) = (
            std::env::var("INFISICAL_TEST_NOREAD_CLIENT_ID"),
            std::env::var("INFISICAL_TEST_NOREAD_CLIENT_SECRET"),
        ) else {
            eprintln!(
                "skipping: set INFISICAL_TEST_NOREAD_CLIENT_ID/SECRET to an identity that may \
                 see a secret exists but not read it (needs an Infisical custom role)"
            );
            return;
        };
        if !get_test_providers().iter().any(|p| p == "infisical") {
            eprintln!("skipping: SECRETSPEC_TEST_PROVIDERS does not name infisical");
            return;
        }
        // A ready-made token outranks the credentials below, so the reader
        // would authenticate as whoever minted it -- read the value, and fail
        // for the wrong reason. The restricted identity has to be the only way
        // in.
        if std::env::var("INFISICAL_TOKEN").is_ok() {
            eprintln!(
                "skipping: INFISICAL_TOKEN outranks the restricted identity's credentials. \
                 Unset it and authenticate with INFISICAL_CLIENT_ID/INFISICAL_CLIENT_SECRET \
                 to exercise a withheld value."
            );
            return;
        }

        // Plant a secret the restricted identity is allowed to know about.
        let project_name = generate_test_project_name();
        let (writer, _t) = create_provider_with_temp_path("infisical");
        writer
            .set(
                Address::convention(&project_name, "default", "HIDDEN_KEY"),
                &SecretString::new("plaintext".into()),
            )
            .expect("the writing identity should store a secret");

        // The same store, read by an identity that may not see values.
        let (mut restricted, _t) = create_provider_with_temp_path("infisical");
        let mut credentials = crate::provider::ProviderCredentials::new();
        credentials.insert("client_id".to_string(), SecretString::new(client_id.into()));
        credentials.insert(
            "client_secret".to_string(),
            SecretString::new(client_secret.into()),
        );
        restricted.with_credentials(credentials);

        let err = restricted
            .get(Address::convention(&project_name, "default", "HIDDEN_KEY"))
            .expect_err("a withheld value must not read as a secret");
        assert!(
            err.to_string().contains("withheld"),
            "the refusal should say the value was withheld, got: {err}"
        );
        // The placeholder must never reach the caller.
        assert!(
            !err.to_string().contains("plaintext"),
            "the error must not carry the value"
        );
    }

    /// One key, many profiles: each profile keeps its own value.
    ///
    /// A store that folds the profile into its naming can map two profiles
    /// onto one secret, where a write under one profile silently overwrites
    /// another's. That is invisible to a single-profile test, so every store
    /// is asked to keep the profiles apart.
    #[test]
    fn test_all_providers_isolate_profiles() {
        let mock = MockProvider::new();
        test_provider_profile_isolation(&mock, "mock");

        for provider_name in get_test_providers() {
            println!("Testing provider: {}", provider_name);
            let (provider, _temp_dir) = create_provider_with_temp_path(&provider_name);
            test_provider_profile_isolation(provider.as_ref(), &provider_name);
        }
    }

    /// Stores that hold one flat namespace, where every profile reads the same
    /// value by design. Named rather than detected: a store that has collapsed
    /// its profiles by accident looks exactly like one that never had them,
    /// which is the bug this test exists to catch.
    const FLAT_PROVIDERS: &[&str] = &["dotenv", "env"];

    fn test_provider_profile_isolation(provider: &dyn Provider, provider_name: &str) {
        if FLAT_PROVIDERS.contains(&provider_name)
            || provider
                .check_writable(Address::convention("proj", "default", "KEY"))
                .is_err()
        {
            return;
        }

        let project_name = generate_test_project_name();
        let profiles = ["dev", "staging", "prod"];

        for profile in profiles {
            let value = SecretString::new(format!("value_for_{profile}").into());
            provider
                .set(
                    Address::convention(&project_name, profile, "API_KEY"),
                    &value,
                )
                .unwrap_or_else(|e| panic!("[{provider_name}] set under '{profile}': {e}"));
        }

        // Written last, so a store that collapses the profiles hands "prod"
        // back for every one of them.
        for profile in profiles {
            let found = provider
                .get(Address::convention(&project_name, profile, "API_KEY"))
                .unwrap_or_else(|e| panic!("[{provider_name}] get under '{profile}': {e}"))
                .unwrap_or_else(|| panic!("[{provider_name}] '{profile}' lost its secret"));
            assert_eq!(
                found.expose_secret(),
                format!("value_for_{profile}"),
                "[{provider_name}] profile '{profile}' reads another profile's value"
            );
        }
    }

    #[test]
    fn test_provider_special_characters() {
        let test_cases = vec![
            ("SPACED_VALUE", "value with spaces"),
            ("NEWLINE_VALUE", "value\nwith\nnewlines"),
            ("SPECIAL_CHARS", "!@#%^&*()_+-=[]{}|;',./<>?"),
            ("UNICODE_VALUE", "🔐 Secret with émojis and ñ"),
        ];

        // Test with MockProvider
        let provider = MockProvider::new();
        let project_name = generate_test_project_name();

        for (key, value) in &test_cases {
            let secret_value = SecretString::new(value.to_string().into());
            provider
                .set(
                    Address::convention(&project_name, "default", key),
                    &secret_value,
                )
                .expect("Mock provider should handle all characters");

            let result = provider
                .get(Address::convention(&project_name, "default", key))
                .expect("Should not error when getting");

            assert_eq!(
                result.map(|s| s.expose_secret().to_string()),
                Some(value.to_string()),
                "Special characters should be preserved"
            );
        }
    }

    #[test]
    fn test_provider_profile_support() {
        let provider = MockProvider::new();
        let project_name = generate_test_project_name();
        let profiles = vec!["dev", "staging", "prod"];
        let test_key = "API_KEY";

        for profile in &profiles {
            let value = SecretString::new(format!("key_for_{}", profile).into());
            provider
                .set(
                    Address::convention(&project_name, profile, test_key),
                    &value,
                )
                .expect("Should set with profile");

            let result = provider
                .get(Address::convention(&project_name, profile, test_key))
                .expect("Should get with profile");

            assert_eq!(
                result.map(|s| s.expose_secret().to_string()),
                Some(value.expose_secret().to_string()),
                "Profile-specific value should match"
            );
        }

        // Verify isolation between profiles
        for profile in profiles {
            let result = provider
                .get(Address::convention(&project_name, profile, test_key))
                .expect("Should not error");
            let expected_value = format!("key_for_{}", profile);
            assert_eq!(
                result.map(|s| s.expose_secret().to_string()),
                Some(expected_value),
                "Should find profile-specific value"
            );
        }
    }

    #[test]
    fn test_default_reflect_returns_error() {
        // Test that the default reflection implementation returns an error
        let provider = MockProvider::new();
        let result = provider.reflect(DiscoveryContext::new("project", "default"));
        assert!(
            result.is_err(),
            "Default reflect implementation should return an error"
        );

        let error = result.unwrap_err();
        let error_msg = error.to_string();
        assert!(
            error_msg.contains("does not support reflection"),
            "Error message should indicate reflection is not supported"
        );
    }

    #[test]
    fn test_pass_provider_creation() {
        // Test pass provider can be created from various URI formats
        let provider = Box::<dyn Provider>::try_from("pass").unwrap();
        assert_eq!(provider.name(), "pass");
        assert_eq!(provider.uri(), "pass");

        let provider = Box::<dyn Provider>::try_from("pass://").unwrap();
        assert_eq!(provider.name(), "pass");
        assert_eq!(provider.uri(), "pass");
    }

    #[test]
    fn test_keyring_with_folder_prefix() {
        let provider =
            Box::<dyn Provider>::try_from("keyring://secretspec/shared/{profile}/{key}").unwrap();
        assert_eq!(provider.name(), "keyring");
        assert_eq!(
            provider.uri(),
            "keyring://secretspec/shared/{profile}/{key}"
        );

        // Without folder_prefix, should use default URI
        let provider = Box::<dyn Provider>::try_from("keyring://").unwrap();
        assert_eq!(provider.name(), "keyring");
        assert_eq!(provider.uri(), "keyring");
    }

    #[test]
    fn test_lastpass_with_folder_prefix() {
        let provider =
            Box::<dyn Provider>::try_from("lastpass://Work/SecretSpec/{profile}/{key}").unwrap();
        assert_eq!(provider.name(), "lastpass");
        assert_eq!(provider.uri(), "lastpass://Work/SecretSpec/{profile}/{key}");

        // Without folder_prefix, should use default URI
        let provider = Box::<dyn Provider>::try_from("lastpass://").unwrap();
        assert_eq!(provider.name(), "lastpass");
        assert_eq!(provider.uri(), "lastpass");
    }

    #[test]
    fn test_pass_with_folder_prefix() {
        let provider =
            Box::<dyn Provider>::try_from("pass://secretspec/shared/{profile}/{key}").unwrap();
        assert_eq!(provider.name(), "pass");
        assert_eq!(provider.uri(), "pass://secretspec/shared/{profile}/{key}");

        // Without folder_prefix, should use default URI
        let provider = Box::<dyn Provider>::try_from("pass://").unwrap();
        assert_eq!(provider.name(), "pass");
        assert_eq!(provider.uri(), "pass");
    }

    #[test]
    fn test_pass_provider_is_writable() {
        let provider = Box::<dyn Provider>::try_from("pass").unwrap();
        assert!(
            provider
                .check_writable(Address::convention("proj", "default", "KEY"))
                .is_ok(),
            "Pass provider should support write operations"
        );
    }

    #[test]
    fn test_protonpass_provider_creation() {
        let provider = Box::<dyn Provider>::try_from("protonpass").unwrap();
        assert_eq!(provider.name(), "protonpass");
        assert_eq!(provider.uri(), "protonpass");

        let provider = Box::<dyn Provider>::try_from("protonpass://").unwrap();
        assert_eq!(provider.name(), "protonpass");
        assert_eq!(provider.uri(), "protonpass");

        let provider = Box::<dyn Provider>::try_from("protonpass://Work").unwrap();
        assert_eq!(provider.name(), "protonpass");
        assert_eq!(provider.uri(), "protonpass://Work");

        let provider =
            Box::<dyn Provider>::try_from("protonpass://Work/{project}/{profile}/{key}").unwrap();
        assert_eq!(provider.name(), "protonpass");
        assert_eq!(
            provider.uri(),
            "protonpass://Work/{project}/{profile}/{key}"
        );
    }

    #[test]
    fn test_protonpass_provider_is_writable() {
        let provider = Box::<dyn Provider>::try_from("protonpass").unwrap();
        assert!(
            provider
                .check_writable(Address::convention("proj", "default", "KEY"))
                .is_ok(),
            "ProtonPass provider should support write operations"
        );
    }

    #[cfg(feature = "awssm")]
    #[test]
    fn test_awssm_batch_get() {
        let providers = get_test_providers();
        if !providers.contains(&"awssm".to_string()) {
            return;
        }

        let (provider, _temp_dir) = create_provider_with_temp_path("awssm");
        let project_name = generate_test_project_name();
        let profile = "default";

        // Set up test secrets
        let test_secrets = vec![
            ("BATCH_TEST_1", "value1"),
            ("BATCH_TEST_2", "value2"),
            ("BATCH_TEST_3", "value3"),
        ];
        for (key, value) in &test_secrets {
            provider
                .set(
                    Address::convention(&project_name, profile, key),
                    &SecretString::new(value.to_string().into()),
                )
                .unwrap();
        }

        // Batch get including a key that doesn't exist
        let keys = [
            "BATCH_TEST_1",
            "BATCH_TEST_2",
            "BATCH_TEST_3",
            "NONEXISTENT",
        ];
        let requests: Vec<(&str, Address<'_>)> = keys
            .iter()
            .map(|key| (*key, Address::convention(&project_name, profile, key)))
            .collect();
        let result = provider.get_many(&requests).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result["BATCH_TEST_1"].expose_secret(), "value1");
        assert_eq!(result["BATCH_TEST_2"].expose_secret(), "value2");
        assert_eq!(result["BATCH_TEST_3"].expose_secret(), "value3");
        assert!(!result.contains_key("NONEXISTENT"));
    }

    #[cfg(feature = "awsps")]
    #[test]
    fn test_awsps_batch_get() {
        let providers = get_test_providers();
        if !providers.contains(&"awsps".to_string()) {
            return;
        }

        let (provider, _temp_dir) = create_provider_with_temp_path("awsps");
        let project_name = generate_test_project_name();
        let profile = "default";

        let test_parameters = [
            ("BATCH_TEST_1", "value1"),
            ("BATCH_TEST_2", "value2"),
            ("BATCH_TEST_3", "value3"),
        ];
        for (key, value) in test_parameters {
            provider
                .set(
                    Address::convention(&project_name, profile, key),
                    &SecretString::new(value.to_string().into()),
                )
                .unwrap();
        }

        let keys = [
            "BATCH_TEST_1",
            "BATCH_TEST_2",
            "BATCH_TEST_3",
            "NONEXISTENT",
        ];
        let requests: Vec<(&str, Address<'_>)> = keys
            .iter()
            .map(|key| (*key, Address::convention(&project_name, profile, key)))
            .collect();
        let result = provider.get_many(&requests).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result["BATCH_TEST_1"].expose_secret(), "value1");
        assert_eq!(result["BATCH_TEST_2"].expose_secret(), "value2");
        assert_eq!(result["BATCH_TEST_3"].expose_secret(), "value3");
        assert!(!result.contains_key("NONEXISTENT"));
    }

    #[cfg(feature = "awssm")]
    #[test]
    fn test_awssm_provider_creation() {
        // Test AWSSM provider can be created with a region
        let provider = Box::<dyn Provider>::try_from("awssm://us-east-1").unwrap();
        assert_eq!(provider.name(), "awssm");
        assert_eq!(provider.uri(), "awssm://us-east-1");
    }

    #[cfg(feature = "awssm")]
    #[test]
    fn test_awssm_provider_creation_without_region() {
        // Test AWSSM provider can be created without a region (uses SDK default)
        let provider = Box::<dyn Provider>::try_from("awssm://").unwrap();
        assert_eq!(provider.name(), "awssm");
        assert_eq!(provider.uri(), "awssm");

        let provider = Box::<dyn Provider>::try_from("awssm").unwrap();
        assert_eq!(provider.name(), "awssm");
        assert_eq!(provider.uri(), "awssm");
    }

    #[cfg(feature = "awssm")]
    #[test]
    fn test_awssm_provider_with_aws_profile() {
        // Test AWSSM provider with AWS profile: awssm://profile@region
        let provider = Box::<dyn Provider>::try_from("awssm://production@us-east-1").unwrap();
        assert_eq!(provider.name(), "awssm");
        assert_eq!(provider.uri(), "awssm://production@us-east-1");

        // Different profile
        let provider = Box::<dyn Provider>::try_from("awssm://staging@eu-west-1").unwrap();
        assert_eq!(provider.name(), "awssm");
        assert_eq!(provider.uri(), "awssm://staging@eu-west-1");
    }

    #[cfg(feature = "awssm")]
    #[test]
    fn test_awssm_provider_with_prefix() {
        let provider = Box::<dyn Provider>::try_from("awssm://us-east-1?prefix=myteam").unwrap();
        assert_eq!(provider.name(), "awssm");
        assert_eq!(provider.uri(), "awssm://us-east-1?prefix=myteam");
    }

    #[cfg(feature = "awssm")]
    #[test]
    fn test_awssm_provider_with_prefix_and_profile() {
        let provider =
            Box::<dyn Provider>::try_from("awssm://production@us-east-1?prefix=myteam").unwrap();
        assert_eq!(provider.name(), "awssm");
        assert_eq!(provider.uri(), "awssm://production@us-east-1?prefix=myteam");
    }

    #[cfg(feature = "awssm")]
    #[test]
    fn test_awssm_provider_with_prefix_no_region() {
        let provider = Box::<dyn Provider>::try_from("awssm://?prefix=myteam").unwrap();
        assert_eq!(provider.name(), "awssm");
        assert_eq!(provider.uri(), "awssm://?prefix=myteam");
    }

    #[cfg(feature = "awsps")]
    #[test]
    fn test_awsps_provider_creation() {
        let provider = Box::<dyn Provider>::try_from("awsps://us-east-1").unwrap();
        assert_eq!(provider.name(), "awsps");
        assert_eq!(provider.uri(), "awsps://us-east-1");
    }

    #[cfg(feature = "awsps")]
    #[test]
    fn test_awsps_provider_creation_without_region() {
        let provider = Box::<dyn Provider>::try_from("awsps://").unwrap();
        assert_eq!(provider.name(), "awsps");
        assert_eq!(provider.uri(), "awsps");

        let provider = Box::<dyn Provider>::try_from("awsps").unwrap();
        assert_eq!(provider.name(), "awsps");
        assert_eq!(provider.uri(), "awsps");
    }

    #[cfg(feature = "awsps")]
    #[test]
    fn test_awsps_provider_with_profile_and_options() {
        let provider = Box::<dyn Provider>::try_from(
            "awsps://production@us-east-1?prefix=/team&kms_key_id=alias/parameters&tier=advanced",
        )
        .unwrap();
        assert_eq!(provider.name(), "awsps");
        assert_eq!(
            provider.uri(),
            "awsps://production@us-east-1?prefix=/team&kms_key_id=alias/parameters&tier=advanced"
        );
    }

    #[cfg(feature = "vault")]
    #[test]
    fn test_vault_provider_creation() {
        // Test Vault provider with host, port, and mount
        let provider =
            Box::<dyn Provider>::try_from("vault://vault.example.com:8200/secret").unwrap();
        assert_eq!(provider.name(), "vault");
    }

    #[cfg(feature = "vault")]
    #[test]
    fn test_vault_provider_default_mount() {
        // Test Vault provider without explicit mount (defaults to "secret")
        let provider = Box::<dyn Provider>::try_from("vault://vault.example.com:8200").unwrap();
        assert_eq!(provider.name(), "vault");
    }

    #[cfg(feature = "vault")]
    #[test]
    fn test_vault_provider_custom_mount() {
        // Test Vault provider with a custom KV mount
        let provider =
            Box::<dyn Provider>::try_from("vault://vault.example.com:8200/custom-kv").unwrap();
        assert_eq!(provider.name(), "vault");
    }

    #[cfg(feature = "vault")]
    #[test]
    fn test_vault_provider_kv_v1() {
        // Test Vault provider with KV v1 via query parameter
        let provider =
            Box::<dyn Provider>::try_from("vault://vault.example.com:8200/secret?kv=1").unwrap();
        assert_eq!(provider.name(), "vault");
    }

    #[cfg(feature = "vault")]
    #[test]
    fn test_vault_provider_with_namespace() {
        // Test Vault provider with namespace in username position
        let provider =
            Box::<dyn Provider>::try_from("vault://ns1@vault.example.com:8200/secret").unwrap();
        assert_eq!(provider.name(), "vault");
    }

    #[cfg(feature = "vault")]
    #[test]
    fn test_vault_provider_tls_false() {
        // Test Vault provider with TLS disabled (for dev mode)
        let provider =
            Box::<dyn Provider>::try_from("vault://127.0.0.1:8200/secret?tls=false").unwrap();
        assert_eq!(provider.name(), "vault");
    }

    #[cfg(feature = "openbao")]
    #[test]
    fn test_openbao_provider_creation() {
        let provider = Box::<dyn Provider>::try_from("openbao://bao.internal:8200/secret").unwrap();
        assert_eq!(provider.name(), "openbao");
        assert_eq!(provider.uri(), "openbao://bao.internal:8200/secret");
    }

    #[cfg(feature = "vault")]
    #[test]
    fn test_vault_provider_requires_address() {
        // Test that Vault provider requires an address when VAULT_ADDR is not set
        let had_vault_addr = std::env::var("VAULT_ADDR").ok();
        unsafe {
            std::env::remove_var("VAULT_ADDR");
        }

        let result = Box::<dyn Provider>::try_from("vault://");
        assert!(result.is_err(), "Vault provider should require an address");

        if let Some(addr) = had_vault_addr {
            unsafe {
                std::env::set_var("VAULT_ADDR", addr);
            }
        }
    }

    #[cfg(feature = "gcsm")]
    #[test]
    fn test_gcsm_provider_creation() {
        // Test GCSM provider can be created from URI format
        let provider = Box::<dyn Provider>::try_from("gcsm://my-project").unwrap();
        assert_eq!(provider.name(), "gcsm");
        assert_eq!(provider.uri(), "gcsm://my-project");
    }

    #[cfg(feature = "gcsm")]
    #[test]
    fn test_gcsm_provider_requires_project_id() {
        // Test that GCSM provider requires a project ID
        let result = Box::<dyn Provider>::try_from("gcsm://");
        assert!(result.is_err(), "GCSM provider should require project ID");

        let result = Box::<dyn Provider>::try_from("gcsm");
        assert!(result.is_err(), "GCSM provider should require project ID");
    }

    #[cfg(feature = "bws")]
    #[test]
    fn test_bws_provider_creation() {
        let provider =
            Box::<dyn Provider>::try_from("bws://a9230ec4-5507-4870-b8b5-b3f500587e4c").unwrap();
        assert_eq!(provider.name(), "bws");
        assert_eq!(provider.uri(), "bws://a9230ec4-5507-4870-b8b5-b3f500587e4c");
    }

    #[cfg(feature = "bws")]
    #[test]
    fn test_bws_provider_requires_project_id() {
        let result = Box::<dyn Provider>::try_from("bws://");
        assert!(result.is_err());

        let result = Box::<dyn Provider>::try_from("bws");
        assert!(result.is_err());
    }

    #[cfg(feature = "bws")]
    #[test]
    fn test_bws_provider_validates_uuid_format() {
        let result = Box::<dyn Provider>::try_from("bws://not-a-uuid");
        assert!(result.is_err());

        let result = Box::<dyn Provider>::try_from("bws://12345");
        assert!(result.is_err());
    }

    #[cfg(feature = "bw")]
    #[test]
    fn test_bw_provider_creation() {
        let provider = Box::<dyn Provider>::try_from("bw://").unwrap();
        assert_eq!(provider.name(), "bw");
        assert_eq!(provider.uri(), "bw://");
    }

    #[cfg(feature = "bw")]
    #[test]
    fn test_bw_provider_with_collection() {
        let provider = Box::<dyn Provider>::try_from("bw://my-collection").unwrap();
        assert_eq!(provider.name(), "bw");
        assert_eq!(provider.uri(), "bw://my-collection");
    }

    #[cfg(feature = "bw")]
    #[test]
    fn test_bw_provider_with_org_collection() {
        let provider = Box::<dyn Provider>::try_from("bw://myorg@dev-secrets").unwrap();
        assert_eq!(provider.name(), "bw");
        assert_eq!(provider.uri(), "bw://myorg@dev-secrets");
    }

    #[cfg(feature = "bw")]
    #[test]
    fn test_bw_provider_rejects_bws_scheme() {
        use crate::provider::bw::BitwardenConfig;
        let url = crate::provider::ProviderUrl::new(url::Url::parse("bws://project-id").unwrap());
        let result = BitwardenConfig::try_from(&url);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("Invalid scheme"));
    }

    #[cfg(feature = "gcsm")]
    #[test]
    fn test_gcsm_provider_validates_project_id_format() {
        // Too short (< 6 chars)
        let result = Box::<dyn Provider>::try_from("gcsm://short");
        assert!(result.is_err(), "Should reject project ID < 6 chars");

        // Must start with lowercase letter
        let result = Box::<dyn Provider>::try_from("gcsm://123456");
        assert!(
            result.is_err(),
            "Should reject project ID starting with number"
        );

        let result = Box::<dyn Provider>::try_from("gcsm://My-Project-123");
        assert!(result.is_err(), "Should reject project ID with uppercase");

        // Cannot end with hyphen
        let result = Box::<dyn Provider>::try_from("gcsm://my-project-");
        assert!(
            result.is_err(),
            "Should reject project ID ending with hyphen"
        );

        // Invalid characters
        let result = Box::<dyn Provider>::try_from("gcsm://my_project");
        assert!(result.is_err(), "Should reject project ID with underscore");

        // Valid project IDs
        let provider = Box::<dyn Provider>::try_from("gcsm://my-project-123").unwrap();
        assert_eq!(provider.name(), "gcsm");

        let provider = Box::<dyn Provider>::try_from("gcsm://project123").unwrap();
        assert_eq!(provider.name(), "gcsm");
    }

    /// Provider credentials must reach a preflight-wrapped provider. onepassword
    /// is built as `Box<Arc<OnePasswordProvider>>` behind a `PreflightGuard`, so a
    /// `&mut self` hook applied post-construction would be swallowed by the `Arc`
    /// layer (which cannot forward `&mut self`); this passes only because the
    /// credentials are injected inside the factory, before wrapping. The delivered
    /// token folds into `auth_scope_key` as a hash, so injection shows up as a
    /// scope-key difference while the plaintext never reaches the
    /// process-lifetime preflight cache.
    #[test]
    fn credentials_reach_preflight_wrapped_provider() {
        use crate::provider::{ProviderCredentials, ProviderUrl, provider_from_url};
        use url::Url;

        // Clear any ambient token under the env lock: with one exported, every
        // instance would resolve the same effective token and the scope keys
        // below could not tell injection from a silent no-op.
        let _lock = crate::tests::scrub_resolution_env();
        let _env = crate::tests::EnvVarGuard::remove("OP_SERVICE_ACCOUNT_TOKEN");

        let scope_with = |token: Option<&str>| {
            let mut credentials = ProviderCredentials::new();
            if let Some(token) = token {
                credentials.insert(
                    "service_account_token".to_string(),
                    SecretString::new(token.into()),
                );
            }
            let url = ProviderUrl::new(Url::parse("onepassword://Private").unwrap());
            provider_from_url(&url, credentials)
                .unwrap()
                .auth_scope_key()
                .expect("onepassword advertises an auth scope")
        };

        let without_token = scope_with(None);
        let with_token = scope_with(Some("tok-xyz"));
        assert_ne!(
            with_token, without_token,
            "provider credential should be injected before Arc-wrapping"
        );
        // Same token, same scope; different tokens probe auth separately.
        assert_eq!(with_token, scope_with(Some("tok-xyz")));
        assert_ne!(with_token, scope_with(Some("tok-other")));
        // The scope key carries a hash of the token, never its plaintext.
        assert!(
            !with_token.contains("tok-xyz"),
            "auth scope key must not embed the plaintext token: {with_token}"
        );
    }
}

/// Item names a store may or may not be able to represent, drawn from the
/// dotenv corruption incident (a dash smuggled in by a `ref` item) plus other
/// shapes env-style formats reject.
#[cfg(test)]
const HOSTILE_ITEMS: &[&str] = &[
    "CACHIX_SIGNING_KEY_cache-a",
    "with space",
    "1LEADING_DIGIT",
    "dotted.name",
    "sla/sh",
    "_VALID_UNDERSCORE",
    "PLAIN_VALID_1",
];

/// The write/read symmetry contract every writable provider must keep: a `set`
/// that reports success is readable back by `get`, and a name the store cannot
/// represent is rejected up front, never written in a form that breaks later
/// reads of other secrets. Each provider is free to accept or reject any given
/// name; what it may not do is accept a write it cannot serve back.
#[cfg(test)]
fn assert_write_read_symmetry(provider: &dyn Provider) {
    use secrecy::ExposeSecret;

    // A convention secret written first must stay readable throughout.
    provider
        .set(
            Address::convention("proj", "default", "KEEP"),
            &SecretString::new("kept".into()),
        )
        .unwrap();

    for item in HOSTILE_ITEMS {
        let addr = crate::config::NativeAddress {
            item: (*item).to_string(),
            ..Default::default()
        };
        let wrote = provider
            .set(Address::Native(&addr), &SecretString::new("v".into()))
            .is_ok();
        if wrote {
            let got = provider.get(Address::Native(&addr)).unwrap();
            assert_eq!(
                got.map(|s| s.expose_secret().to_string()),
                Some("v".to_string()),
                "provider `{}` accepted a write of `{item}` it cannot read back",
                provider.name(),
            );
        }
        // Accepted or rejected, the write must not have damaged the store.
        let kept = provider
            .get(Address::convention("proj", "default", "KEEP"))
            .unwrap();
        assert_eq!(
            kept.map(|s| s.expose_secret().to_string()),
            Some("kept".to_string()),
            "provider `{}`: a write of `{item}` corrupted other secrets",
            provider.name(),
        );
    }
}

#[test]
fn dotenv_write_read_symmetry() {
    use super::dotenv::{DotEnvConfig, DotEnvProvider};

    let dir = TempDir::new().unwrap();
    let provider = DotEnvProvider::new(DotEnvConfig {
        path: dir.path().join(".env"),
    });
    assert_write_read_symmetry(&provider);
}

#[test]
fn file_write_read_symmetry() {
    use super::file::{FileConfig, FileProvider};

    let dir = TempDir::new().unwrap();
    let provider = FileProvider::new(FileConfig {
        directory: dir.path().to_path_buf(),
    });
    assert_write_read_symmetry(&provider);
}

#[test]
fn mock_provider_write_read_symmetry() {
    assert_write_read_symmetry(&MockProvider::new());
}

/// A provider that opts into deletion, as the real ones do.
struct DeletingProvider;

impl Provider for DeletingProvider {
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: format!("{}/{}/{}", project, profile, key),
            ..Default::default()
        })
    }

    fn get(&self, _addr: Address<'_>) -> Result<Option<SecretString>> {
        Ok(None)
    }

    fn set(&self, _addr: Address<'_>, _value: &SecretString) -> Result<()> {
        Ok(())
    }

    fn delete(&self, _addr: Address<'_>) -> Result<bool> {
        Ok(true)
    }

    fn supports_delete(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "deleting"
    }

    fn uri(&self) -> String {
        "deleting://".to_string()
    }
}

#[test]
fn check_deletable_refuses_a_provider_that_cannot_delete() {
    // The regression. `CountingProvider` inherits the default `delete`, which
    // errors, so the preflight must refuse it. Previously the default
    // `check_deletable` only resolved coordinates and returned Ok, so every
    // such provider passed preflight and failed later in the deletion phase --
    // after `import --delete-source` had already written the destination.
    let provider = CountingProvider::new(&[]);
    let addr = Address::convention("proj", "default", "API_KEY");

    let err = provider
        .check_deletable(addr)
        .expect_err("a provider without delete must not pass the deletion preflight");

    assert!(
        err.to_string()
            .contains("does not support deleting secrets"),
        "got: {err}"
    );
}

#[test]
fn check_deletable_and_delete_refuse_with_the_same_reason() {
    // The preflight's promise is that it predicts the operation. If the two
    // disagreed, the preflight would be reporting on something else.
    let provider = CountingProvider::new(&[]);
    let addr = Address::convention("proj", "default", "API_KEY");

    let preflight = provider.check_deletable(addr).unwrap_err().to_string();
    let attempted = provider.delete(addr).unwrap_err().to_string();

    assert_eq!(preflight, attempted);
}

#[test]
fn check_deletable_admits_a_provider_that_opts_in() {
    // Control: the guard rejects on capability, not unconditionally.
    let provider = DeletingProvider;
    let addr = Address::convention("proj", "default", "API_KEY");

    provider
        .check_deletable(addr)
        .expect("a provider that implements delete must pass preflight");
}

#[test]
fn providers_do_not_support_deletion_unless_they_say_so() {
    // `supports_delete` defaults to false in lockstep with `delete`, so adding
    // the method cannot silently make destructive behaviour available.
    assert!(!CountingProvider::new(&[]).supports_delete());
    assert!(DeletingProvider.supports_delete());
}
