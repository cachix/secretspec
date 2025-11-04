use super::Provider;
use crate::{Result, SecretSpecError};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::env;
use url::Url;

/// Configuration for the environment variables provider.
///
/// This struct represents the configuration for the read-only environment
/// variables provider. It contains no fields as the provider reads directly
/// from the process environment without additional configuration.
///
/// # Example
///
/// ```ignore
/// # use secretspec::provider::env::EnvConfig;
/// let config = EnvConfig::default();
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvConfig {}

impl TryFrom<&Url> for EnvConfig {
    type Error = SecretSpecError;

    /// Creates an `EnvConfig` from a URL.
    ///
    /// This method validates that the URL has the correct scheme ("env")
    /// and returns an `EnvConfig` instance. The environment provider
    /// doesn't require any additional configuration from the URL.
    ///
    /// # Example
    ///
    /// ```ignore
    /// # use url::Url;
    /// # use secretspec::provider::env::EnvConfig;
    /// let url = Url::parse("env://").unwrap();
    /// let config: EnvConfig = (&url).try_into().unwrap();
    /// ```
    fn try_from(url: &Url) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "env" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for env provider",
                url.scheme()
            )));
        }

        Ok(Self::default())
    }
}

impl EnvConfig {}

/// A read-only provider that reads secrets from environment variables.
///
/// The `EnvProvider` reads secrets directly from the process environment
/// variables. This provider is **read-only** and cannot persist values
/// across process boundaries. Attempts to set values will return an error.
///
/// # Read-only Nature
///
/// This provider is intentionally read-only because:
/// - Environment variables set at runtime only affect the current process
/// - Changes don't persist after the process exits
/// - Child processes inherit a copy of the parent's environment
///
/// To set environment variables, use your shell, process manager, or
/// container orchestration system.
///
/// # Example
///
/// ```ignore
/// # use secretspec::provider::env::{EnvProvider, EnvConfig};
/// let provider = EnvProvider::new(EnvConfig::default());
/// // Can only read values, not set them
/// ```
pub struct EnvProvider {
    #[allow(dead_code)]
    config: EnvConfig,
}

crate::register_provider! {
    struct: EnvProvider,
    config: EnvConfig,
    name: "env",
    description: "Read-only environment variables",
    schemes: ["env"],
    examples: ["env://"],
}

impl EnvProvider {
    /// Creates a new `EnvProvider` with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the provider (currently unused)
    ///
    /// # Example
    ///
    /// ```ignore
    /// # use secretspec::provider::env::{EnvProvider, EnvConfig};
    /// let config = EnvConfig::default();
    /// let provider = EnvProvider::new(config);
    /// ```
    pub fn new(config: EnvConfig) -> Self {
        Self { config }
    }
}

impl Provider for EnvProvider {
    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }
    
    fn uri(&self) -> String {
        // Env can be "env", "env:", or "env://"
        "env".to_string()
    }

    /// Retrieves a secret value from environment variables.
    ///
    /// This method reads the value directly from the process environment
    /// using the provided key. The project and profile parameters are
    /// ignored as environment variables are global to the process.
    ///
    /// # Arguments
    ///
    /// * `_project` - Project name (ignored)
    /// * `key` - The environment variable name to read
    /// * `_profile` - Profile name (ignored)
    ///
    /// # Returns
    ///
    /// * `Ok(Some(String))` - If the environment variable exists
    /// * `Ok(None)` - If the environment variable doesn't exist
    /// * `Err` - Never returns an error in practice
    ///
    /// # Example
    ///
    /// ```ignore
    /// # use secretspec::provider::{Provider, env::{EnvProvider, EnvConfig}};
    /// # unsafe { std::env::set_var("MY_SECRET", "value123"); }
    /// let provider = EnvProvider::new(EnvConfig::default());
    /// let value = provider.get("myproject", "MY_SECRET", "production").unwrap();
    /// assert_eq!(value, Some("value123".to_string()));
    /// ```
    fn get(&self, _project: &str, key: &str, _profile: &str) -> Result<Option<SecretString>> {
        Ok(env::var(key).ok().map(|v| SecretString::new(v.into())))
    }

    /// Attempts to set a secret value (always fails).
    ///
    /// This method always returns an error because the environment provider
    /// is read-only. Environment variables set at runtime don't persist
    /// across process boundaries and would create confusing behavior.
    ///
    /// # Arguments
    ///
    /// * `_project` - Project name (ignored)
    /// * `_key` - Environment variable name (ignored)
    /// * `_value` - Value to set (ignored)
    /// * `_profile` - Profile name (ignored)
    ///
    /// # Returns
    ///
    /// Always returns `Err(SecretSpecError::ProviderOperationFailed)` with
    /// an explanatory message about the read-only nature of this provider.
    ///
    /// # Example
    ///
    /// ```ignore
    /// # use secretspec::provider::{Provider, env::{EnvProvider, EnvConfig}};
    /// let provider = EnvProvider::new(EnvConfig::default());
    /// let result = provider.set("myproject", "MY_SECRET", "value", "production");
    /// assert!(result.is_err());
    /// ```
    fn set(&self, _project: &str, _key: &str, _value: &SecretString, _profile: &str) -> Result<()> {
        // Environment variables are read-only in this backend
        // Setting environment variables at runtime doesn't persist across processes
        Err(crate::SecretSpecError::ProviderOperationFailed(
            "Environment variable provider is read-only. Set variables in your shell or process environment.".to_string()
        ))
    }

    /// Indicates whether this provider supports setting values.
    ///
    /// Always returns `false` for the environment provider since it's
    /// a read-only provider. This allows the CLI and other consumers
    /// to check capabilities before attempting operations.
    ///
    /// # Returns
    ///
    /// Always returns `false`
    fn allows_set(&self) -> bool {
        false
    }
}
