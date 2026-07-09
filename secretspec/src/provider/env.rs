use super::{Address, Provider, ProviderUrl};
use crate::{Result, SecretSpecError};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::env;

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

impl TryFrom<&ProviderUrl> for EnvConfig {
    type Error = SecretSpecError;

    /// Creates an `EnvConfig` from a URL.
    ///
    /// Validates the scheme is "env" and that the URI carries no authority:
    /// the provider reads the variable named after each secret, and a specific
    /// variable is addressed with `ref = { item = "VARNAME" }`, not in the URI.
    ///
    /// # Example
    ///
    /// ```ignore
    /// # use url::Url;
    /// # use secretspec::provider::env::EnvConfig;
    /// let url = Url::parse("env://").unwrap();
    /// let config: EnvConfig = (&url).try_into().unwrap();
    /// ```
    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "env" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for env provider",
                url.scheme()
            )));
        }

        if let Some(host) = url.host().filter(|h| !h.is_empty()) {
            let hint = crate::config::ref_table_hint(None, &host, None, None);
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "env:// takes no authority: to read one specific variable, use \
                 {hint} on the secret instead"
            )));
        }
        Ok(Self {})
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
pub struct EnvProvider;

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
    /// * `_config` - The configuration for the provider; the process
    ///   environment is global, so there is nothing to configure.
    ///
    /// # Example
    ///
    /// ```ignore
    /// # use secretspec::provider::env::{EnvProvider, EnvConfig};
    /// let config = EnvConfig::default();
    /// let provider = EnvProvider::new(config);
    /// ```
    pub fn new(_config: EnvConfig) -> Self {
        Self
    }
}

impl Provider for EnvProvider {
    /// Convention names map straight to the environment variable named by the
    /// secret key; project and profile don't exist in a process environment.
    fn convention_address(
        &self,
        _project: &str,
        _profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: key.to_string(),
            ..Default::default()
        })
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        // Env can be "env", "env:", or "env://".
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
    /// let value = provider.get(Address::convention("myproject", "production", "MY_SECRET")).unwrap();
    /// assert_eq!(value, Some("value123".to_string()));
    /// ```
    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let var = super::flat_item(self, addr)?;
        Ok(env::var(&*var).ok().map(|v| SecretString::new(v.into())))
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
    /// let result = provider.set(Address::convention("myproject", "production", "MY_SECRET"), "value");
    /// assert!(result.is_err());
    /// ```
    fn set(&self, addr: Address<'_>, _value: &SecretString) -> Result<()> {
        self.check_writable(addr)
    }

    /// Always read-only: setting environment variables at runtime doesn't
    /// persist across processes. Stating the reason here lets the CLI refuse
    /// the write before prompting for a value, with the same message `set`
    /// would return.
    fn check_writable(&self, _addr: Address<'_>) -> Result<()> {
        Err(crate::SecretSpecError::ProviderOperationFailed(
            "Environment variable provider is read-only. Set variables in your shell or process environment.".to_string()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    /// A native address reads the variable its `item` names, regardless of any
    /// instance configuration.
    #[test]
    fn native_address_reads_the_named_variable() {
        let p = EnvProvider::new(EnvConfig::default());
        let addr = crate::config::NativeAddress {
            item: "PATH".into(),
            ..Default::default()
        };
        // PATH is set in every test environment.
        assert!(p.get(Address::Native(&addr)).unwrap().is_some());
    }

    /// The authority form (`env://VARNAME`) from earlier iterations is
    /// rejected with a pointer at the `ref` table, instead of being silently
    /// ignored and reading the wrong variable.
    #[test]
    fn authority_is_rejected_with_ref_hint() {
        let err = EnvConfig::try_from(&ProviderUrl::new(Url::parse("env://SOME_VAR").unwrap()))
            .unwrap_err();
        assert!(
            err.to_string().contains("ref = { item = \"SOME_VAR\" }"),
            "{err}"
        );
    }

    /// Environment variables have no sub-components, so a `field` coordinate is
    /// rejected instead of silently reading the wrong thing.
    #[test]
    fn native_address_rejects_field() {
        let p = EnvProvider::new(EnvConfig::default());
        let addr = crate::config::NativeAddress {
            item: "PATH".into(),
            field: Some("x".into()),
            ..Default::default()
        };
        let err = p.get(Address::Native(&addr)).unwrap_err();
        assert!(err.to_string().contains("`field`"), "{err}");
    }
}
