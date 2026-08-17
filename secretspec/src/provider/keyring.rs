use super::{Address, Provider, ProviderUrl};
use crate::{Result, SecretSpecError};
use keyring::Entry;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

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
    name: "keyring",
    description: "Uses system keychain (Recommended)",
    schemes: ["keyring"],
    examples: ["keyring://", "keyring://secretspec/shared/{profile}/{key}"],
    deletes: true,
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

    fn entry_coordinates<'a>(
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
    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let (service, username) = self.entry_target(addr)?;
        let entry = Entry::new(&service, &username)?;
        match entry.get_password() {
            Ok(password) => Ok(Some(SecretString::new(password.into()))),
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
    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        let (service, username) = self.entry_target(addr)?;
        let entry = Entry::new(&service, &username)?;
        entry.set_password(value.expose_secret())?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

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
