use super::{Address, Provider, ProviderUrl};
use crate::SecretBytes;
use crate::{Result, SecretSpecError};
use keyring::Entry;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
mod macos {
    //! Legacy macOS keychain items are bound to the code signature of the
    //! build that created them. A new ad hoc signed build may need the user's
    //! approval to read or modify an existing item. A per-query silent lookup
    //! identifies this case without changing the process-wide interaction
    //! setting or deleting the item during a read.
    use keyring::{Entry, Error};
    use security_framework::item::{ItemClass, ItemSearchOptions, SearchResult};
    use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};

    /// `errSecInvalidOwnerEdit`: modifying an item another build owns.
    const INVALID_OWNER_EDIT: i32 = -25244;
    /// `errSecDuplicateItem`: the write could not see the item it collided with.
    const DUPLICATE_ITEM: i32 = -25299;

    fn os_status(err: &Error) -> Option<i32> {
        let inner = match err {
            Error::PlatformFailure(inner) | Error::NoStorageAccess(inner) => inner,
            _ => return None,
        };
        inner
            .downcast_ref::<security_framework::base::Error>()
            .map(|err| err.code())
    }

    /// Whether this build could not update an item it does not yet control.
    pub(super) fn access_refused(err: &Error) -> bool {
        matches!(os_status(err), Some(DUPLICATE_ITEM | INVALID_OWNER_EDIT))
    }

    /// What to do about a prompt that keeps coming back.
    pub(super) const ALWAYS_ALLOW_HINT: &str =
        "choose \"Always Allow\" in the keychain dialog so this build keeps access";

    /// A lookup that skips items needing authentication, without changing
    /// keychain interaction state for any other thread or provider.
    pub(super) fn read_without_prompt(service: &str, account: &str) -> Option<Vec<u8>> {
        let keychain = SecKeychain::default_for_domain(SecPreferencesDomain::User).ok()?;
        let mut options = ItemSearchOptions::new();
        options
            .keychains(&[keychain])
            .class(ItemClass::generic_password())
            .service(service)
            .account(account)
            .load_data(true)
            .skip_authenticated_items(true);
        match options.search().ok()?.into_iter().next()? {
            SearchResult::Data(secret) => Some(secret),
            _ => None,
        }
    }

    /// Reads without a dialog if access is already granted. An interactive
    /// fallback never modifies the item, including entries addressed by `ref`.
    pub(super) fn read(entry: &Entry, service: &str, account: &str) -> keyring::Result<Vec<u8>> {
        if let Some(secret) = read_without_prompt(service, account) {
            return Ok(secret);
        }
        let secret = entry.get_secret()?;
        eprintln!(
            "{} keychain item {} needed access from this build; if macOS asked whether to allow access, {}",
            colored::Colorize::yellow("warning:"),
            service,
            ALWAYS_ALLOW_HINT
        );
        Ok(secret)
    }

    /// A failed lookup inside the keyring crate can make a write try to add
    /// a duplicate item. Reading with a dialog grants access before retrying
    /// the in-place update. The existing item is never deleted.
    pub(super) fn write(entry: &Entry, secret: &[u8]) -> keyring::Result<()> {
        match entry.set_secret(secret) {
            Ok(()) => Ok(()),
            Err(err) if access_refused(&err) => {
                let _existing = match entry.get_secret() {
                    Ok(existing) => secrecy::zeroize::Zeroizing::new(existing),
                    Err(_) => return Err(err),
                };
                entry.set_secret(secret)
            }
            Err(err) => Err(err),
        }
    }
}

// An unpaired UTF-16 low surrogate cannot begin a legacy Windows password.
// Keep the discriminator in the same blob so overwrites are atomic.
#[cfg(any(windows, test))]
const WINDOWS_BINARY_PREFIX: &[u8] = b"\x00\xdcSecretSpec\x00bytes\x01";

#[cfg(any(windows, test))]
fn encode_windows_secret(value: &SecretBytes) -> SecretBytes {
    let bytes = match std::str::from_utf8(value.expose_secret()) {
        Ok(text) => text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        Err(_) => [WINDOWS_BINARY_PREFIX, value.expose_secret()].concat(),
    };
    SecretBytes::from_vec(bytes)
}

#[cfg(any(windows, test))]
fn decode_windows_secret(value: SecretBytes) -> Result<SecretBytes> {
    use secrecy::zeroize::Zeroizing;

    let bytes = value.expose_secret();
    if let Some(binary) = bytes.strip_prefix(WINDOWS_BINARY_PREFIX) {
        return Ok(SecretBytes::from_slice(binary));
    }
    let invalid_password = || {
        SecretSpecError::ProviderOperationFailed(
            "keyring password is not valid UTF-16LE".to_string(),
        )
    };
    if !bytes.len().is_multiple_of(2) {
        return Err(invalid_password());
    }
    let words = Zeroizing::new(
        bytes
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect::<Vec<_>>(),
    );
    String::from_utf16(&words)
        .map(SecretBytes::from_utf8)
        .map_err(|_| invalid_password())
}

/// Configuration for the keyring provider.
///
/// This struct holds configuration options for the keyring provider,
/// which stores secrets in the system's native keychain service.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct KeyringConfig {
    /// Optional folder prefix format string for organizing secrets in the keyring.
    ///
    /// Supports placeholders: {project}, {profile}, and {key}.
    /// Defaults to "secretspec/{project}/{profile}/{key}" if not specified.
    pub folder_prefix: Option<String>,
}

impl TryFrom<&ProviderUrl> for KeyringConfig {
    type Error = SecretSpecError;

    /// Creates a new KeyringConfig from a URL.
    ///
    /// The URL must have the scheme "keyring" (e.g., "keyring://" or
    /// "keyring://secretspec/shared/{profile}/{key}"). One specific
    /// `(service, account)` entry is addressed with a secret's
    /// `ref = { item = "<service>", field = "<account>" }`, not in the URI.
    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "keyring" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for keyring provider",
                url.scheme()
            )));
        }

        let mut config = Self::default();

        if let Some(host) = url.host() {
            config.folder_prefix = Some(format!("{}{}", host, url.path()));
        }

        Ok(config)
    }
}

/// Provider for storing secrets in the system keychain.
///
/// The KeyringProvider uses the operating system's native secure credential
/// storage mechanism:
/// - macOS: Keychain
/// - Windows: Credential Manager
/// - Linux: Secret Service API (via libsecret)
///
/// Secrets are stored with a hierarchical key structure using a configurable
/// format string that defaults to: `secretspec/{project}/{profile}/{key}`.
///
/// This ensures secrets are properly namespaced by project and profile,
/// preventing conflicts between different projects or environments.
pub struct KeyringProvider {
    config: KeyringConfig,
}

crate::register_provider! {
    struct: KeyringProvider,
    config: KeyringConfig,
    metadata: &super::catalog::KEYRING,
}

impl KeyringProvider {
    /// Creates a new KeyringProvider with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the keyring provider
    ///
    /// # Returns
    ///
    /// A new instance of KeyringProvider
    pub fn new(config: KeyringConfig) -> Self {
        Self { config }
    }

    /// Formats the service name for a secret in the keyring.
    ///
    /// Uses folder_prefix as a format string with {project}, {profile}, and {key} placeholders.
    /// Defaults to "secretspec/{project}/{profile}/{key}" if not configured.
    fn format_service(&self, project: &str, profile: &str, key: &str) -> String {
        let format_string = self
            .config
            .folder_prefix
            .as_deref()
            .unwrap_or("secretspec/{project}/{profile}/{key}");

        format_string
            .replace("{project}", project)
            .replace("{profile}", profile)
            .replace("{key}", key)
    }

    /// Resolves the `(service, account)` an operation targets: `item` is the
    /// service, `field` the account, defaulting to the current system
    /// username (the account convention entries live under).
    fn entry_target(&self, addr: Address<'_>) -> Result<(String, String)> {
        let coords = self.entry_coordinates(addr)?;
        let account = coords
            .field
            .clone()
            .expect("entry coordinates always contain the keyring account");
        Ok((coords.item.clone(), account))
    }

    /// The current system username, the account convention entries live under.
    fn current_username() -> Result<String> {
        whoami::username().map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to determine the current username for keyring storage: {}",
                crate::error::display_error_chain(&e)
            ))
        })
    }
}

impl KeyringProvider {
    /// Reads the entry's bytes. macOS uses a per-query silent lookup before
    /// allowing an interactive read.
    fn read_entry(entry: &Entry, service: &str, account: &str) -> keyring::Result<Vec<u8>> {
        #[cfg(target_os = "macos")]
        {
            macos::read(entry, service, account)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (service, account);
            entry.get_secret()
        }
    }

    /// Writes the entry's bytes. macOS retries an in-place update after an
    /// interactive read when another build's item hid from the first lookup.
    fn write_entry(entry: &Entry, secret: &[u8], service: &str) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            macos::write(entry, secret).map_err(|err| {
                if macos::access_refused(&err) {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "macOS refused to change keychain item {service}: {err}; {}, or review \
                         the item's access settings in Keychain Access",
                        macos::ALWAYS_ALLOW_HINT
                    ))
                } else {
                    err.into()
                }
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = service;
            Ok(entry.set_secret(secret)?)
        }
    }
}

impl Provider for KeyringProvider {
    /// Convention entries use the folder-prefix format string as the service
    /// name, `secretspec/{project}/{profile}/{key}` by default; the account
    /// (the `field` coordinate) is resolved at operation time.
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: self.format_service(project, profile, key),
            ..Default::default()
        })
    }

    /// `field` is the keyring account within the service entry.
    fn supported_coords(&self) -> &'static [&'static str] {
        &["field"]
    }

    fn configured_entry_coordinates<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<std::borrow::Cow<'a, crate::config::NativeAddress>> {
        let mut coords = self.resolve_coords(addr)?.into_owned();
        if coords.field.is_none() {
            coords.field = Some(Self::current_username()?);
        }
        Ok(std::borrow::Cow::Owned(coords))
    }

    fn name(&self) -> &str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        if let Some(ref prefix) = self.config.folder_prefix {
            format!("keyring://{}", ProviderUrl::encode(prefix))
        } else {
            "keyring".to_string()
        }
    }

    /// The configured prefix selects a service entry inside the current user's
    /// keyring; it does not select another keyring store.
    fn entry_container_identity(&self) -> String {
        "keyring".to_string()
    }

    /// Retrieves a secret from the system keychain.
    ///
    /// The secret is looked up using a hierarchical key structure determined
    /// by the folder_prefix format string (defaults to `secretspec/{project}/{profile}/{key}`).
    ///
    /// The current system username is used as the account identifier.
    fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
        let (service, username) = self.entry_target(addr)?;
        let entry = Entry::new(&service, &username)?;
        match Self::read_entry(&entry, &service, &username) {
            Ok(secret) => {
                let secret = SecretBytes::from_vec(secret);
                #[cfg(windows)]
                let secret = decode_windows_secret(secret)?;
                Ok(Some(secret))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Stores a secret in the system keychain.
    ///
    /// The secret is stored with a hierarchical key structure determined
    /// by the folder_prefix format string (defaults to `secretspec/{project}/{profile}/{key}`).
    ///
    /// The current system username is used as the account identifier.
    /// If a secret already exists with the same key, it will be overwritten.
    fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()> {
        let (service, username) = self.entry_target(addr)?;
        let entry = Entry::new(&service, &username)?;
        #[cfg(windows)]
        let value = &encode_windows_secret(value);
        Self::write_entry(&entry, value.expose_secret(), &service)?;
        Ok(())
    }

    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        let (service, username) = self.entry_target(addr)?;
        let entry = Entry::new(&service, &username)?;
        match entry.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn supports_delete(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use url::Url;

    proptest! {
        #[test]
        fn windows_arbitrary_bytes_round_trip(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let value = SecretBytes::from_vec(bytes);
            let decoded = decode_windows_secret(encode_windows_secret(&value)).unwrap();
            prop_assert_eq!(decoded.expose_secret(), value.expose_secret());
        }

        #[test]
        fn windows_legacy_unicode_never_matches_binary_marker(text in any::<String>()) {
            let legacy = SecretBytes::from_vec(
                text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            );
            prop_assert!(!legacy.expose_secret().starts_with(WINDOWS_BINARY_PREFIX));
            let decoded = decode_windows_secret(legacy).unwrap();
            prop_assert_eq!(decoded.expose_secret(), text.as_bytes());
        }
    }

    #[test]
    fn windows_legacy_passwords_remain_readable() {
        for text in ["", "password", "héllo 🔑", "a\0b", "YWJjZA==", "line\r\n"] {
            let legacy =
                SecretBytes::from_vec(text.encode_utf16().flat_map(u16::to_le_bytes).collect());
            assert_eq!(
                decode_windows_secret(legacy).unwrap().expose_secret(),
                text.as_bytes()
            );
            let value = SecretBytes::from_utf8(text);
            assert_eq!(
                encode_windows_secret(&value).expose_secret(),
                text.encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>(),
            );
        }
    }

    #[test]
    fn windows_binary_values_round_trip_without_legacy_ambiguity() {
        for bytes in [b"\xff\0\xfe".as_slice(), WINDOWS_BINARY_PREFIX, b"\x00\xdc"] {
            let value = SecretBytes::from_slice(bytes);
            let stored = encode_windows_secret(&value);
            assert!(stored.expose_secret().starts_with(WINDOWS_BINARY_PREFIX));
            assert_eq!(
                decode_windows_secret(stored).unwrap().expose_secret(),
                bytes
            );
        }
    }

    #[test]
    fn windows_invalid_legacy_passwords_are_rejected() {
        for bytes in [b"\xff".as_slice(), b"\x00\xdc", b"\x00\xd8"] {
            assert!(decode_windows_secret(SecretBytes::from_slice(bytes)).is_err());
        }
    }

    fn provider_url(s: &str) -> ProviderUrl {
        ProviderUrl::new(Url::parse(s).unwrap())
    }

    #[test]
    fn format_service_default_pattern() {
        let provider = KeyringProvider::new(KeyringConfig::default());
        assert_eq!(
            provider.format_service("myproj", "prod", "API_KEY"),
            "secretspec/myproj/prod/API_KEY"
        );
    }

    #[test]
    fn format_service_custom_prefix() {
        let provider = KeyringProvider::new(KeyringConfig {
            folder_prefix: Some("vault/{profile}/{key}".to_string()),
        });
        assert_eq!(
            provider.format_service("myproj", "prod", "API_KEY"),
            "vault/prod/API_KEY"
        );
    }

    #[test]
    fn try_from_sets_folder_prefix_from_host_and_path() {
        let config =
            KeyringConfig::try_from(&provider_url("keyring://secretspec/shared/{profile}/{key}"))
                .unwrap();
        assert_eq!(
            config.folder_prefix.as_deref(),
            Some("secretspec/shared/{profile}/{key}")
        );
    }

    #[test]
    fn try_from_without_host_has_no_prefix() {
        let config = KeyringConfig::try_from(&provider_url("keyring://")).unwrap();
        assert_eq!(config.folder_prefix, None);
    }

    #[test]
    fn try_from_rejects_wrong_scheme() {
        let err = KeyringConfig::try_from(&provider_url("pass://x")).unwrap_err();
        assert!(err.to_string().contains("Invalid scheme"));
    }

    #[test]
    fn uri_round_trips_default_and_prefix() {
        assert_eq!(
            KeyringProvider::new(KeyringConfig::default()).uri(),
            "keyring"
        );
        let provider = KeyringProvider::new(KeyringConfig {
            folder_prefix: Some("my vault/{key}".to_string()),
        });
        // The space must be percent-encoded.
        assert_eq!(provider.uri(), "keyring://my%20vault/{key}");
    }

    /// A native address maps `item` to the service and `field` to the account.
    #[test]
    fn native_address_maps_item_and_field_to_service_and_account() {
        let p = KeyringProvider::new(KeyringConfig::default());
        let addr = crate::config::NativeAddress {
            item: "com.example.app".into(),
            field: Some("alice".into()),
            ..Default::default()
        };
        assert_eq!(
            p.entry_target(Address::Native(&addr)).unwrap(),
            ("com.example.app".to_string(), "alice".to_string())
        );
    }

    /// Without a `field`, the account defaults to the current system username,
    /// matching where convention entries are stored.
    #[test]
    fn native_address_account_defaults_to_current_username() {
        let p = KeyringProvider::new(KeyringConfig::default());
        let addr = crate::config::NativeAddress {
            item: "com.example.app".into(),
            ..Default::default()
        };
        let (service, account) = p.entry_target(Address::Native(&addr)).unwrap();
        assert_eq!(service, "com.example.app");
        assert_eq!(account, whoami::username().unwrap());
    }

    #[test]
    fn same_entries_treats_the_implicit_account_as_the_current_username() {
        let provider = KeyringProvider::new(KeyringConfig::default());
        let implicit = crate::config::NativeAddress {
            item: "com.example.app".into(),
            ..Default::default()
        };
        let explicit = crate::config::NativeAddress {
            item: "com.example.app".into(),
            field: Some(whoami::username().unwrap()),
            ..Default::default()
        };

        assert!(
            provider
                .same_entries(
                    Address::Native(&implicit),
                    &provider,
                    Address::Native(&explicit),
                )
                .unwrap(),
            "addresses that operations send to one keyring entry must compare equal"
        );
    }

    /// Keyring entries have no versions; the coordinate is rejected.
    #[test]
    fn native_address_rejects_version() {
        let p = KeyringProvider::new(KeyringConfig::default());
        let addr = crate::config::NativeAddress {
            item: "com.example.app".into(),
            version: Some("3".into()),
            ..Default::default()
        };
        let err = p.entry_target(Address::Native(&addr)).unwrap_err();
        assert!(err.to_string().contains("`version`"), "{err}");
    }
}

/// Keychain tests need a real keychain. Enable them with
/// `SECRETSPEC_TEST_PROVIDERS=keyring`. None of them shows a dialog.
#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::macos;
    use keyring::Entry;
    use std::process::Command;

    fn keyring_tests_enabled() -> bool {
        std::env::var("SECRETSPEC_TEST_PROVIDERS")
            .map(|list| list.split(',').any(|name| name.trim() == "keyring"))
            .unwrap_or(false)
    }

    const ACCOUNT: &str = "secretspec-test";

    fn test_entry(name: &str) -> (Entry, String) {
        let service = format!("secretspec-test/{}/{name}", std::process::id());
        (Entry::new(&service, ACCOUNT).unwrap(), service)
    }

    /// The keychain the keyring crate writes to, named explicitly because
    /// `security` does not always resolve the default keychain the same way.
    fn default_keychain() -> String {
        let output = Command::new("/usr/bin/security")
            .args(["default-keychain", "-d", "user"])
            .output()
            .unwrap();
        String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .trim_matches('"')
            .to_string()
    }

    /// Runs `security` against the default keychain and returns its stdout.
    fn security(args: &[&str]) -> Option<String> {
        let output = Command::new("/usr/bin/security")
            .args(args)
            .arg(default_keychain())
            .output()
            .unwrap();
        output
            .status
            .success()
            .then(|| String::from_utf8(output.stdout).unwrap())
    }

    /// Creates the entry's item through Apple's `security` tool, so this
    /// test binary is in neither its access control list nor its partition
    /// list, exactly like an item written by an earlier SecretSpec build.
    fn create_foreign_item(service: &str, value: &str) {
        security(&[
            "add-generic-password",
            "-s",
            service,
            "-a",
            ACCOUNT,
            "-w",
            value,
        ])
        .unwrap();
    }

    #[test]
    fn own_items_round_trip_without_prompting() {
        if !keyring_tests_enabled() {
            eprintln!("skipping: SECRETSPEC_TEST_PROVIDERS does not name keyring");
            return;
        }
        let (entry, service) = test_entry("own");
        macos::write(&entry, b"first").unwrap();
        macos::write(&entry, b"second").unwrap();
        assert_eq!(
            macos::read_without_prompt(&service, ACCOUNT),
            Some(b"second".to_vec())
        );
        assert_eq!(macos::read(&entry, &service, ACCOUNT).unwrap(), b"second");
        entry.delete_credential().unwrap();
    }

    /// Skipping authentication leaves an item from another signer intact.
    #[test]
    fn foreign_item_is_kept_by_silent_lookup() {
        if !keyring_tests_enabled() {
            eprintln!("skipping: SECRETSPEC_TEST_PROVIDERS does not name keyring");
            return;
        }
        let (_entry, service) = test_entry("foreign");
        create_foreign_item(&service, "theirs");

        assert!(macos::read_without_prompt(&service, ACCOUNT).is_none());

        let kept = security(&["find-generic-password", "-s", &service, "-a", ACCOUNT, "-w"]);
        assert_eq!(kept.as_deref().map(str::trim), Some("theirs"));
        security(&["delete-generic-password", "-s", &service, "-a", ACCOUNT]).unwrap();
    }
}
