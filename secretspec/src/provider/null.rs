use super::{Address, Provider, ProviderUrl};
use crate::{Result, SecretSpecError};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// Configuration for the null provider.
///
/// The provider takes no options because it never reads or stores values. It
/// exists to let SecretSpec continue to a declaration's `default` value.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NullConfig {}

impl TryFrom<&ProviderUrl> for NullConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "null" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for null provider",
                url.scheme()
            )));
        }

        let path = url.path();
        if !url.username().is_empty()
            || url.password().is_some()
            || url.host().is_some_and(|host| !host.is_empty())
            || !path.trim_matches('/').is_empty()
            || url.has_query()
        {
            return Err(SecretSpecError::ProviderOperationFailed(
                "null:// takes no authority, path, or query".to_string(),
            ));
        }

        Ok(Self {})
    }
}

/// A provider that never contains a value.
///
/// A miss lets normal resolution continue to the secret's committed `default`,
/// making this provider useful for non-sensitive environment configuration that
/// belongs in `secretspec.toml` but should not be stored in a secret backend.
pub struct NullProvider;

crate::register_provider! {
    struct: NullProvider,
    config: NullConfig,
    name: "null",
    description: "Use manifest defaults without storage (0.19+)",
    schemes: ["null"],
    examples: ["null://"],
}

impl NullProvider {
    pub fn new(_config: NullConfig) -> Self {
        Self
    }
}

impl Provider for NullProvider {
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

    /// Address coordinates cannot affect an always-missing lookup. Advertising
    /// every current coordinate keeps `null` usable as an override for any
    /// declaration without pretending that it maps to a storage concept.
    fn supported_coords(&self) -> &'static [&'static str] {
        &["field", "vault", "section", "version"]
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        // Resolve the address so native coordinates receive the same validation
        // as every other flat provider, even though no storage is consulted.
        let _ = super::flat_item(self, addr)?;
        Ok(None)
    }

    fn set(&self, addr: Address<'_>, _value: &SecretString) -> Result<()> {
        self.check_writable(addr)
    }

    fn check_writable(&self, _addr: Address<'_>) -> Result<()> {
        Err(SecretSpecError::ProviderOperationFailed(
            "null provider never stores values; configure a manifest default or choose a writable provider"
                .to_string(),
        ))
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        "null://".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Secret;
    use secrecy::ExposeSecret;
    use std::collections::HashMap;

    #[test]
    fn always_misses_and_rejects_writes() {
        let provider = NullProvider::new(NullConfig::default());
        let addr = Address::convention("project", "development", "LOCAL_PORT");

        assert!(provider.get(addr).unwrap().is_none());
        let error = provider
            .set(addr, &SecretString::new("8090".into()))
            .unwrap_err();
        assert!(error.to_string().contains("never stores values"), "{error}");
    }

    #[test]
    fn native_coordinates_do_not_change_the_miss() {
        let provider = NullProvider::new(NullConfig::default());
        let addr = crate::config::NativeAddress {
            item: "remote-name".to_string(),
            field: Some("password".to_string()),
            vault: Some("Production".to_string()),
            section: Some("database".to_string()),
            version: Some("latest".to_string()),
        };

        assert!(provider.get(Address::Native(&addr)).unwrap().is_none());
    }

    #[test]
    fn miss_applies_the_manifest_default() {
        let _env = crate::tests::scrub_resolution_env();
        let config = crate::tests::resolve_test_config(HashMap::from([(
            "LOCAL_PORT".to_string(),
            Secret {
                description: Some("Local server port".to_string()),
                default: Some("8090".to_string()),
                providers: Some(vec!["null".to_string()]),
                ..Default::default()
            },
        )]));
        let spec = crate::Secrets::new(config, None, None, None);

        let resolved = spec.validate().unwrap().unwrap();
        assert_eq!(
            resolved.resolved.secrets["LOCAL_PORT"].expose_secret(),
            "8090"
        );
        assert_eq!(
            resolved.with_defaults,
            vec![("LOCAL_PORT".to_string(), "8090".to_string())]
        );
    }

    #[test]
    fn rejects_uri_configuration() {
        let error = Box::<dyn Provider>::try_from("null://unexpected")
            .err()
            .expect("authority must be rejected");
        assert!(error.to_string().contains("takes no authority"), "{error}");
    }
}
