use crate::Result;
use crate::provider::{Address, Provider};
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};

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

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        "memtest://".to_string()
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

#[test]
fn test_create_from_string_with_full_uris() {
    // Test basic onepassword URI
    let provider = Box::<dyn Provider>::try_from("onepassword://Private").unwrap();
    assert_eq!(provider.name(), "onepassword");

    // Test onepassword with account
    let provider = Box::<dyn Provider>::try_from("onepassword://work@Production").unwrap();
    assert_eq!(provider.name(), "onepassword");

    // Test onepassword with token
    let provider =
        Box::<dyn Provider>::try_from("onepassword+token://:ops_abc123@Private").unwrap();
    assert_eq!(provider.name(), "onepassword");
}

/// The audit log and the fallback-chain warnings persist a provider's `uri()`
/// and rely on it never echoing a credential the user embedded in the source
/// URI (see `Provider::uri`). Enforce that contract for every registered scheme:
/// build the provider from a URI carrying a recognizable secret in the
/// *password* position and assert the reconstructed `uri()` does not contain it.
///
/// The username/host/path positions hold non-secret attribution (1Password
/// accounts, AWS profiles, Vault namespaces) and are intentionally preserved; a
/// URL *password* is always a credential and must never resurface. A scheme that
/// rejects this URI shape simply builds nothing, which leaks nothing.
#[test]
fn uri_never_echoes_a_userinfo_password() {
    const SECRET: &str = "leaked_pw_DO_NOT_ECHO";

    for reg in super::PROVIDER_REGISTRY {
        for &scheme in reg.schemes {
            let source = format!("{scheme}://attribution:{SECRET}@host/path");
            // Only assert on schemes that build; a parse failure echoes nothing.
            let Ok(provider) = Box::<dyn Provider>::try_from(source.as_str()) else {
                continue;
            };
            let uri = provider.uri();
            assert!(
                !uri.contains(SECRET),
                "provider scheme {scheme:?} echoed a URL password into uri(): {uri:?}"
            );
        }
    }
}

#[test]
fn test_create_from_string_with_plain_names() {
    // Test plain provider names
    let provider = Box::<dyn Provider>::try_from("env").unwrap();
    assert_eq!(provider.name(), "env");

    let provider = Box::<dyn Provider>::try_from("keyring").unwrap();
    assert_eq!(provider.name(), "keyring");

    let provider = Box::<dyn Provider>::try_from("dotenv").unwrap();
    assert_eq!(provider.name(), "dotenv");

    // Test onepassword separately to debug the issue
    match Box::<dyn Provider>::try_from("onepassword") {
        Ok(provider) => assert_eq!(provider.name(), "onepassword"),
        Err(e) => panic!("Failed to create onepassword provider: {}", e),
    }

    let provider = Box::<dyn Provider>::try_from("lastpass").unwrap();
    assert_eq!(provider.name(), "lastpass");

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

    // Test pass examples
    let provider = Box::<dyn Provider>::try_from("pass://").unwrap();
    assert_eq!(provider.name(), "pass");
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
            "pass" => {
                let provider =
                    Box::<dyn Provider>::try_from("pass").expect("Should create pass provider");
                (provider, None)
            }
            #[cfg(feature = "vault")]
            // "vault" tests KV v2 (default), "vault-kv1" tests KV v1.
            // Set VAULT_TOKEN and run a dev server (bao server -dev).
            // For KV v1: bao secrets enable -path=kv1 -version=1 kv
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

        if provider
            .check_writable(Address::convention("proj", "default", "KEY"))
            .is_ok()
        {
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
        // Test that the default reflect implementation returns an error
        let provider = MockProvider::new();
        let result = provider.reflect();
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

    #[cfg(feature = "vault")]
    #[test]
    fn test_openbao_scheme() {
        // Test OpenBao URI scheme
        let provider = Box::<dyn Provider>::try_from("openbao://bao.internal:8200/secret").unwrap();
        assert_eq!(provider.name(), "vault");
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
        let provider = Box::<dyn Provider>::try_from("bitwarden://").unwrap();
        assert_eq!(provider.name(), "bitwarden");
        assert_eq!(provider.uri(), "bitwarden://");
    }

    #[cfg(feature = "bw")]
    #[test]
    fn test_bw_provider_with_collection() {
        let provider = Box::<dyn Provider>::try_from("bitwarden://my-collection").unwrap();
        assert_eq!(provider.name(), "bitwarden");
        assert_eq!(provider.uri(), "bitwarden://my-collection");
    }

    #[cfg(feature = "bw")]
    #[test]
    fn test_bw_provider_with_org_collection() {
        let provider = Box::<dyn Provider>::try_from("bitwarden://myorg@dev-secrets").unwrap();
        assert_eq!(provider.name(), "bitwarden");
        assert_eq!(provider.uri(), "bitwarden://myorg@dev-secrets");
    }

    #[cfg(feature = "bw")]
    #[test]
    fn test_bw_provider_rejects_bws_scheme() {
        use crate::provider::bitwarden::BitwardenConfig;
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
