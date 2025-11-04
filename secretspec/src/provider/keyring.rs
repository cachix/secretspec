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
/// Currently, no additional configuration is required as the provider
/// uses sensible defaults for all platforms.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyringConfig {}

impl TryFrom<&Url> for KeyringConfig {
    type Error = SecretSpecError;

    /// Creates a new KeyringConfig from a URL.
    ///
    /// The URL must have the scheme "keyring" (e.g., "keyring://").
    /// Currently, no additional parameters are supported in the URL.
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

        Ok(Self::default())
    }
}

impl KeyringConfig {}

/// Provider for storing secrets in the system keychain.
///
/// The KeyringProvider uses the operating system's native secure credential
/// storage mechanism:
/// - macOS: Keychain
/// - Windows: Credential Manager
/// - Linux: Secret Service API (via libsecret)
///
/// Secrets are stored with a hierarchical key structure:
/// `secretspec/{project}/{profile}/{key}`
///
/// This ensures secrets are properly namespaced by project and profile,
/// preventing conflicts between different projects or environments.
pub struct KeyringProvider {
    #[allow(dead_code)]
    config: KeyringConfig,
}

crate::register_provider! {
    struct: KeyringProvider,
    config: KeyringConfig,
    name: "keyring",
    description: "Uses system keychain (Recommended)",
    schemes: ["keyring"],
    examples: ["keyring://"],
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
}

impl Provider for KeyringProvider {
    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }
    
    fn uri(&self) -> String {
        // Keyring can be just "keyring" or "keyring://"
        "keyring".to_string()
    }

    /// Retrieves a secret from the system keychain.
    ///
    /// The secret is looked up using a hierarchical key structure:
    /// `secretspec/{project}/{profile}/{key}`
    ///
    /// The current system username is used as the account identifier.
    ///
    /// # Arguments
    ///
    /// * `project` - The project name
    /// * `key` - The secret key to retrieve
    /// * `profile` - The profile/environment name
    ///
    /// # Returns
    ///
    /// * `Ok(Some(String))` - The secret value if found
    /// * `Ok(None)` - If the secret doesn't exist
    /// * `Err` - If there was an error accessing the keychain
    fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<SecretString>> {
        let service = format!("secretspec/{}/{}/{}", project, profile, key);

        let entry = Entry::new(&service, &whoami::username())?;
        match entry.get_password() {
            Ok(password) => Ok(Some(SecretString::new(password.into()))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Stores a secret in the system keychain.
    ///
    /// The secret is stored with a hierarchical key structure:
    /// `secretspec/{project}/{profile}/{key}`
    ///
    /// The current system username is used as the account identifier.
    /// If a secret already exists with the same key, it will be overwritten.
    ///
    /// # Arguments
    ///
    /// * `project` - The project name
    /// * `key` - The secret key to store
    /// * `value` - The secret value to store
    /// * `profile` - The profile/environment name
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the secret was stored successfully
    /// * `Err` - If there was an error accessing the keychain
    fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()> {
        let service = format!("secretspec/{}/{}/{}", project, profile, key);

        let entry = Entry::new(&service, &whoami::username())?;
        entry.set_password(value.expose_secret())?;
        Ok(())
    }
}
