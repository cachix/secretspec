use std::sync::Once;

use keyring_core::Entry;
use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::Deserialize;
use serde::Serialize;

use super::Provider;
use super::ProviderUrl;
use crate::MonosecretError;
use crate::Result;

static SET_CREDENTIAL_STORE: Once = Once::new();

/// Configuration for the keyring provider.
///
/// This struct holds configuration options for the keyring provider,
/// which stores secrets in the system's native keychain service.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct KeyringConfig {
	/// Optional folder prefix format string for organizing secrets in the keyring.
	///
	/// Supports placeholders: {project}, {profile}, and {key}.
	/// Defaults to "monosecret/{project}/{profile}/{key}" if not specified.
	pub folder_prefix: Option<String>,
}

impl TryFrom<&ProviderUrl> for KeyringConfig {
	type Error = MonosecretError;

	/// Creates a new `KeyringConfig` from a URL.
	///
	/// The URL must have the scheme "keyring" (e.g., "keyring://" or
	/// "<keyring://monosecret/shared/{profile}/{key>}").
	fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
		if url.scheme() != "keyring" {
			return Err(MonosecretError::ProviderOperationFailed(format!(
				"Invalid scheme '{}' for keyring provider",
				url.scheme()
			)));
		}

		let mut config = Self::default();

		if let Some(host) = url.host() {
			let path = url.path();
			config.folder_prefix = Some(format!("{host}{path}"));
		}

		Ok(config)
	}
}

/// Provider for storing secrets in the system keychain.
///
/// The `KeyringProvider` uses the operating system's native secure credential
/// storage mechanism:
/// - macOS: Keychain
/// - Windows: Credential Manager
/// - Linux/Unix: Secret Service API
///
/// Secrets are stored with a hierarchical key structure using a configurable
/// format string that defaults to: `monosecret/{project}/{profile}/{key}`.
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
	examples: ["keyring://", "keyring://monosecret/shared/{profile}/{key}"],
}

impl KeyringProvider {
	/// Creates a new `KeyringProvider` with the given configuration.
	///
	/// # Arguments
	///
	/// * `config` - The configuration for the keyring provider
	///
	/// # Returns
	///
	/// A new instance of `KeyringProvider`
	pub fn new(config: KeyringConfig) -> Self {
		Self { config }
	}

	fn entry(service: &str, username: &str) -> Result<Entry> {
		SET_CREDENTIAL_STORE.call_once(set_credential_store);
		Entry::new(service, username).map_err(Into::into)
	}

	/// Formats the service name for a secret in the keyring.
	///
	/// Uses `folder_prefix` as a format string with {project}, {profile}, and {key} placeholders.
	/// Defaults to "monosecret/{project}/{profile}/{key}" if not configured.
	fn format_service(&self, project: &str, profile: &str, key: &str) -> String {
		let format_string = self
			.config
			.folder_prefix
			.as_deref()
			.unwrap_or("monosecret/{project}/{profile}/{key}");

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
			format!("keyring://{}", ProviderUrl::encode(prefix))
		} else {
			"keyring".to_string()
		}
	}

	/// Retrieves a secret from the system keychain.
	///
	/// The secret is looked up using a hierarchical key structure determined
	/// by the `folder_prefix` format string (defaults to `monosecret/{project}/{profile}/{key}`).
	///
	/// The current system username is used as the account identifier.
	fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<SecretString>> {
		let service = self.format_service(project, profile, key);
		let username = whoami::username()
			.map_err(|e| MonosecretError::ProviderOperationFailed(e.to_string()))?;
		let entry = Self::entry(&service, &username)?;
		match entry.get_password() {
			Ok(password) => Ok(Some(SecretString::new(password.into()))),
			Err(keyring_core::Error::NoEntry) => Ok(None),
			Err(e) => Err(e.into()),
		}
	}

	/// Stores a secret in the system keychain.
	///
	/// The secret is stored with a hierarchical key structure determined
	/// by the `folder_prefix` format string (defaults to `monosecret/{project}/{profile}/{key}`).
	///
	/// The current system username is used as the account identifier.
	/// If a secret already exists with the same key, it will be overwritten.
	fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()> {
		let service = self.format_service(project, profile, key);
		let username = whoami::username()
			.map_err(|e| MonosecretError::ProviderOperationFailed(e.to_string()))?;
		let entry = Self::entry(&service, &username)?;
		entry.set_password(value.expose_secret())?;
		Ok(())
	}
}

fn set_credential_store() {
	#[cfg(target_os = "macos")]
	{
		if let Ok(store) = apple_native_keyring_store::keychain::Store::new() {
			keyring_core::set_default_store(store);
		}
	}

	#[cfg(target_os = "windows")]
	{
		if let Ok(store) = windows_native_keyring_store::Store::new() {
			keyring_core::set_default_store(store);
		}
	}

	#[cfg(all(
		unix,
		not(any(target_os = "macos", target_os = "ios", target_os = "android"))
	))]
	{
		if let Ok(store) = zbus_secret_service_keyring_store::Store::new() {
			keyring_core::set_default_store(store);
		}
	}
}

#[cfg(test)]
mod tests {
	use url::Url;

	use super::*;

	fn provider_url(s: &str) -> ProviderUrl {
		ProviderUrl::new(Url::parse(s).unwrap())
	}

	#[test]
	fn format_service_default_pattern() {
		let provider = KeyringProvider::new(KeyringConfig::default());
		assert_eq!(
			provider.format_service("myproj", "prod", "API_KEY"),
			"monosecret/myproj/prod/API_KEY"
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
			KeyringConfig::try_from(&provider_url("keyring://monosecret/shared/{profile}/{key}"))
				.unwrap();
		assert_eq!(
			config.folder_prefix.as_deref(),
			Some("monosecret/shared/{profile}/{key}")
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
}
