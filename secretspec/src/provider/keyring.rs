use super::Provider;
use crate::{Result, SecretSpecError};
use keyring::Entry;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use url::Url;

/// Configuration for the keyring provider.
///
/// This struct holds configuration options for the keyring provider,
/// which stores secrets in the system's native keychain service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyringConfig {
    /// Optional folder prefix format string for organizing secrets in the keyring.
    ///
    /// Supports placeholders: {project}, {profile}, and {key}.
    /// Defaults to "secretspec/{project}/{profile}/{key}" if not specified.
    pub folder_prefix: Option<String>,
}

impl Default for KeyringConfig {
    fn default() -> Self {
        Self {
            folder_prefix: None,
        }
    }
}

impl TryFrom<&Url> for KeyringConfig {
    type Error = SecretSpecError;

    /// Creates a new KeyringConfig from a URL.
    ///
    /// The URL must have the scheme "keyring" (e.g., "keyring://" or
    /// "keyring://secretspec/shared/{profile}/{key}").
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use url::Url;
    /// # use secretspec::provider::keyring::KeyringConfig;
    /// let url = Url::parse("keyring://").unwrap();
    /// let config: KeyringConfig = (&url).try_into().unwrap();
    /// ```
    fn try_from(url: &Url) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "keyring" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for keyring provider",
                url.scheme()
            )));
        }

        let mut config = Self::default();

        if let Some(host) = url.host_str() {
            let path = url.path();
            // Percent-decode so placeholders like {profile} and {key} survive URL parsing
            let raw = format!("{}{}", host, path);
            let decoded = raw.replace("%7B", "{").replace("%7D", "}");
            config.folder_prefix = Some(decoded);
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
}

impl Provider for KeyringProvider {
    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        if let Some(ref prefix) = self.config.folder_prefix {
            format!("keyring://{}", prefix)
        } else {
            "keyring".to_string()
        }
    }

    /// Retrieves a secret from the system keychain.
    ///
    /// The secret is looked up using a hierarchical key structure determined
    /// by the folder_prefix format string (defaults to `secretspec/{project}/{profile}/{key}`).
    ///
    /// The current system username is used as the account identifier.
    fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<SecretString>> {
        let service = self.format_service(project, profile, key);
        let username = whoami::username()
            .map_err(|e| SecretSpecError::ProviderOperationFailed(e.to_string()))?;
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
    fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()> {
        let service = self.format_service(project, profile, key);
        let username = whoami::username()
            .map_err(|e| SecretSpecError::ProviderOperationFailed(e.to_string()))?;
        let entry = Entry::new(&service, &username)?;
        entry.set_password(value.expose_secret())?;
        Ok(())
    }
}
