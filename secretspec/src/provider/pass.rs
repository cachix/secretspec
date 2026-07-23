use super::{Address, Provider, ProviderUrl};
use crate::{Result, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::process::Command;

/// Configuration for the pass (password-store) provider.
///
/// This struct holds configuration options for the pass provider.
/// Pass stores secrets as GPG-encrypted files using the Unix password
/// manager in a hierarchical structure.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PassConfig {
    /// Optional folder prefix format string for organizing secrets in pass.
    ///
    /// Supports placeholders: {project}, {profile}, and {key}.
    /// Defaults to "secretspec/{project}/{profile}/{key}" if not specified.
    pub folder_prefix: Option<String>,

    /// Optional password store directory.
    ///
    /// When set, exported as `PASSWORD_STORE_DIR` for every `pass` invocation,
    /// overriding the default `~/.password-store`. Configured via the
    /// `store_dir` query parameter (e.g. `pass://?store_dir=/path/to/store`).
    pub store_dir: Option<String>,
}

impl TryFrom<&ProviderUrl> for PassConfig {
    type Error = SecretSpecError;

    /// Creates a PassConfig from a URL.
    ///
    /// The URL must have the scheme "pass" (e.g., "pass://" or
    /// "pass://secretspec/shared/{profile}/{key}").
    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "pass" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for pass provider",
                url.scheme()
            )));
        }

        let mut config = Self {
            store_dir: url.query_value("store_dir"),
            ..Self::default()
        };

        if let Some(host) = url.host() {
            let path = url.path();
            config.folder_prefix = Some(format!("{}{}", host, path));
        }

        Ok(config)
    }
}

/// Provider for managing secrets with pass (password-store).
///
/// The PassProvider uses the Unix password manager `pass`, which stores
/// secrets as GPG-encrypted files in a hierarchical structure.
///
/// # Storage Format
///
/// Secrets are stored with a hierarchical path structure:
/// `secretspec/{project}/{profile}/{key}`
///
/// This ensures secrets are properly namespaced by project and profile,
/// preventing conflicts between different projects or environments.
///
/// # Requirements
///
/// - The `pass` command must be available in PATH
/// - GPG must be configured with appropriate keys
/// - The password store must be initialized (`pass init`)
pub struct PassProvider {
    config: PassConfig,
}

crate::register_provider! {
    struct: PassProvider,
    config: PassConfig,
    name: "pass",
    description: "Unix password manager with GPG encryption",
    schemes: ["pass"],
    examples: ["pass://", "pass://secretspec/shared/{profile}/{key}", "pass://?store_dir=/path/to/store"],
}

impl PassProvider {
    /// Creates a new PassProvider with the given configuration.
    pub fn new(config: PassConfig) -> Self {
        Self { config }
    }

    /// Formats the entry name for a secret.
    ///
    /// Uses folder_prefix as a format string with {project}, {profile}, and {key} placeholders.
    /// Defaults to "secretspec/{project}/{profile}/{key}" if not configured.
    fn format_entry_name(&self, project: &str, profile: &str, key: &str) -> String {
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

    /// Creates a `pass` command, applying `PASSWORD_STORE_DIR` when a custom
    /// store directory is configured.
    fn command(&self) -> Command {
        let mut command = Command::new("pass");
        if let Some(ref store_dir) = self.config.store_dir {
            command.env("PASSWORD_STORE_DIR", store_dir);
        }
        command
    }
}

impl Provider for PassProvider {
    /// Convention entries live under the folder-prefix format string,
    /// `secretspec/{project}/{profile}/{key}` by default.
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: self.format_entry_name(project, profile, key),
            ..Default::default()
        })
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let prefix = self
            .config
            .folder_prefix
            .as_deref()
            .map(ProviderUrl::encode)
            .unwrap_or_default();
        match self.config.store_dir {
            Some(ref store_dir) => {
                format!(
                    "pass://{}?store_dir={}",
                    prefix,
                    ProviderUrl::encode_query(store_dir)
                )
            }
            None if prefix.is_empty() => "pass".to_string(),
            None => format!("pass://{}", prefix),
        }
    }

    /// Retrieves a secret from the password store.
    ///
    /// # Arguments
    ///
    /// * `project` - The project name
    /// * `key` - The secret key to retrieve
    /// * `profile` - The profile name
    ///
    /// # Returns
    ///
    /// * `Ok(Some(SecretString))` - The secret value if found
    /// * `Ok(None)` - If the secret doesn't exist in the password store
    /// * `Err` - If there was an error executing `pass` or reading the output
    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let entry_name = super::flat_item(self, addr)?;

        let output = self
            .command()
            .arg("show")
            .arg(&*entry_name)
            .output()
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to execute 'pass' command: {}. Is pass installed?",
                    e
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Entry doesn't exist
            if output.status.code() == Some(1) && stderr.contains("is not in the password store") {
                return Ok(None);
            }

            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "pass command failed: {}",
                stderr
            )));
        }

        let content = String::from_utf8(output.stdout)
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to parse pass output as UTF-8: {}",
                    e
                ))
            })?
            .trim()
            .to_string();

        Ok(Some(SecretString::new(content.into())))
    }

    /// Sets a secret value in the password store.
    ///
    /// # Arguments
    ///
    /// * `project` - The project name
    /// * `key` - The secret key to set
    /// * `value` - The value to store
    /// * `profile` - The profile name
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the value was successfully written
    /// * `Err(SecretSpecError)` - If writing the pass entry fails
    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        let entry_name = super::flat_item(self, addr)?;

        let mut child = self
            .command()
            .args(["insert", "-m", "-f", &entry_name])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to execute pass command: {}",
                    e
                ))
            })?;

        let mut stdin = child.stdin.take().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "Failed to obtain stdin for pass command".to_string(),
            )
        })?;

        use std::io::Write;
        stdin
            .write_all(value.expose_secret().as_bytes())
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to write to pass stdin: {}",
                    e
                ))
            })?;

        // Drop stdin to close the pipe so pass process receives EOF
        drop(stdin);

        let output = child.wait_with_output().map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to wait for pass command: {}",
                e
            ))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "pass command failed: {}",
                stderr
            )));
        }

        Ok(())
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
    fn format_entry_name_default_pattern() {
        let provider = PassProvider::new(PassConfig::default());
        assert_eq!(
            provider.format_entry_name("myproj", "prod", "API_KEY"),
            "secretspec/myproj/prod/API_KEY"
        );
    }

    #[test]
    fn format_entry_name_custom_prefix() {
        let provider = PassProvider::new(PassConfig {
            folder_prefix: Some("vault/{profile}/{key}".to_string()),
            store_dir: None,
        });
        assert_eq!(
            provider.format_entry_name("myproj", "prod", "API_KEY"),
            "vault/prod/API_KEY"
        );
    }

    #[test]
    fn try_from_parses_store_dir_query() {
        let config =
            PassConfig::try_from(&provider_url("pass://?store_dir=/custom/store")).unwrap();
        assert_eq!(config.folder_prefix, None);
        assert_eq!(config.store_dir.as_deref(), Some("/custom/store"));
    }

    #[test]
    fn try_from_parses_store_dir_with_folder_prefix() {
        let config = PassConfig::try_from(&provider_url(
            "pass://secretspec/{profile}/{key}?store_dir=/custom/store",
        ))
        .unwrap();
        assert_eq!(
            config.folder_prefix.as_deref(),
            Some("secretspec/{profile}/{key}")
        );
        assert_eq!(config.store_dir.as_deref(), Some("/custom/store"));
    }

    #[test]
    fn try_from_sets_folder_prefix_from_host_and_path() {
        let config =
            PassConfig::try_from(&provider_url("pass://secretspec/shared/{profile}/{key}"))
                .unwrap();
        assert_eq!(
            config.folder_prefix.as_deref(),
            Some("secretspec/shared/{profile}/{key}")
        );
    }

    #[test]
    fn try_from_rejects_wrong_scheme() {
        let err = PassConfig::try_from(&provider_url("keyring://x")).unwrap_err();
        assert!(err.to_string().contains("Invalid scheme"));
    }

    #[test]
    fn uri_round_trips_default_and_prefix() {
        assert_eq!(PassProvider::new(PassConfig::default()).uri(), "pass");
        let provider = PassProvider::new(PassConfig {
            folder_prefix: Some("my vault/{key}".to_string()),
            store_dir: None,
        });
        assert_eq!(provider.uri(), "pass://my%20vault/{key}");
    }

    #[test]
    fn uri_round_trips_store_dir() {
        let store_dir_only = PassProvider::new(PassConfig {
            folder_prefix: None,
            store_dir: Some("/custom/store".to_string()),
        });
        assert_eq!(store_dir_only.uri(), "pass://?store_dir=/custom/store");

        let with_prefix = PassProvider::new(PassConfig {
            folder_prefix: Some("shared/{key}".to_string()),
            store_dir: Some("/custom/store".to_string()),
        });
        assert_eq!(
            with_prefix.uri(),
            "pass://shared/{key}?store_dir=/custom/store"
        );
    }

    #[test]
    fn uri_round_trips_store_dir_with_special_chars() {
        // Characters that are structurally significant inside a query string
        // (`&`, `+`, `#`, `%`, space) must survive uri() -> TryFrom. Plain
        // path/host encoding leaves them unescaped, which would silently corrupt
        // the store directory; encode_query escapes them so they round-trip.
        for store_dir in [
            "/custom/store",
            "/srv/store+1",
            "/data/a&b",
            "/data/a#b",
            "/has space",
            "/pct%20literal",
            "/q?x=y",
            "/all/&+#%=? mix",
        ] {
            let provider = PassProvider::new(PassConfig {
                folder_prefix: Some("shared/{key}".to_string()),
                store_dir: Some(store_dir.to_string()),
            });
            let uri = provider.uri();
            let reparsed = PassConfig::try_from(&provider_url(&uri))
                .unwrap_or_else(|e| panic!("uri {uri:?} failed to reparse: {e}"));
            assert_eq!(
                reparsed.store_dir.as_deref(),
                Some(store_dir),
                "store_dir {store_dir:?} did not round-trip via uri {uri:?}"
            );
            assert_eq!(
                reparsed.folder_prefix.as_deref(),
                Some("shared/{key}"),
                "folder_prefix corrupted by store_dir {store_dir:?} via uri {uri:?}"
            );
        }
    }

    /// A native address names the store entry directly via `item`, bypassing
    /// the folder-prefix format string.
    #[test]
    fn native_address_names_the_entry() {
        let p = PassProvider::new(PassConfig {
            folder_prefix: Some("vault/{profile}/{key}".to_string()),
            store_dir: None,
        });
        let addr = crate::config::NativeAddress {
            item: "email/work".into(),
            ..Default::default()
        };
        assert_eq!(
            crate::provider::flat_item(&p, Address::Native(&addr)).unwrap(),
            "email/work"
        );
    }

    /// Store entries have no sub-components; a `field` coordinate is rejected.
    #[test]
    fn native_address_rejects_field() {
        let p = PassProvider::new(PassConfig::default());
        let addr = crate::config::NativeAddress {
            item: "email/work".into(),
            field: Some("password".into()),
            ..Default::default()
        };
        let err = crate::provider::flat_item(&p, Address::Native(&addr)).unwrap_err();
        assert!(err.to_string().contains("`field`"), "{err}");
    }
}
