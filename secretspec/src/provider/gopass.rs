use crate::config::NativeAddress;
use crate::provider::{Address, ProviderUrl};
use crate::{Provider, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::process::Command;

/// Configuration for the gopass (gopass.pw) provider.
///
/// Gopass is a multi-user, multi-store abstraction layer on top of
/// `pass`.
/// This struct holds configuration options for the gopass provider
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GoPassConfig {
    /// Optional folder prefix format string for organizing secrets in pass.
    ///
    /// Supports placeholders: {project}, {profile}, and {key}.
    /// Defaults to "secretspec/{project}/{profile}/{key}" if not specified.
    pub folder_prefix: Option<String>,
}

impl TryFrom<&ProviderUrl> for GoPassConfig {
    type Error = SecretSpecError;

    /// Creates a GoPassConfig from a URL.
    ///
    /// The URL must have the scheme "gopass" (e.g., "gopass://" or
    /// "gopass://secretspec/shared/{profile}/{key}").
    fn try_from(url: &ProviderUrl) -> Result<Self, Self::Error> {
        if url.scheme() != "gopass" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for gopass provider",
                url.scheme(),
            )));
        }

        let mut config = Self::default();

        if let Some(host) = url.host() {
            let path = url.path();
            config.folder_prefix = Some(format!("{}{}", host, path));
        }

        Ok(config)
    }
}

pub struct GoPassProvider {
    config: GoPassConfig,
}

crate::register_provider! {
    struct: GoPassProvider,
    config: GoPassConfig,
    name: "gopass",
    description: "Multi-user and multi-store abstraction layer over pass",
    schemes: ["gopass"],
    examples: ["gopass://", "gopass://secretspec/shared/{profile}/{key}"],
}

impl GoPassProvider {
    /// Creates a new GoPassProvider with the given configuration.
    pub fn new(config: GoPassConfig) -> Self {
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

    /// Creates a `gopass` command
    fn command(&self) -> Command {
        Command::new("gopass")
    }
}

impl Provider for GoPassProvider {
    /// Convention entries live under the folder-prefix format string,
    /// `secretspec/{project}/{profile}/{key}` by default.
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> crate::Result<NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: self.format_entry_name(project, profile, key),
            ..Default::default()
        })
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
    /// * `Err` - If there was an error executing `gopass` or reading the output
    fn get(&self, addr: Address<'_>) -> crate::Result<Option<SecretString>> {
        let entry_name = super::flat_item(self, addr)?;

        let output = self
            .command()
            .arg("show")
            // auto-confirm any yes/no prompt, in case the entry doesn't exist
            .arg("-y")
            // only show the password
            // ponytail: first line only — multiline secrets truncate; switch to -n/--noparsing if that bites
            .arg("-o")
            .arg(&*entry_name)
            .output()
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to execute 'gopass' command: {}. Is gopass installed?",
                    e
                ))
            })?;

        if output.status.success() {
            let content = String::from_utf8(output.stdout)
                .map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to parse gopass output as UTF-8: {}",
                        e
                    ))
                })?
                .trim()
                .to_string();

            Ok(Some(SecretString::new(content.into())))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);

            // Entry doesn't exist. gopass exits 11 here; the message is
            // "is not in the password store" when piped.
            if output.status.code() == Some(11) && stderr.contains("is not in the password store") {
                Ok(None)
            } else {
                Err(SecretSpecError::ProviderOperationFailed(format!(
                    "gopass command failed: {}",
                    stderr
                )))
            }
        }
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
    /// * `Err(SecretSpecError)` - If writing the gopass entry fails
    fn set(&self, addr: Address<'_>, value: &SecretString) -> crate::Result<()> {
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
                    "Failed to execute gopass command: {}",
                    e
                ))
            })?;

        let mut stdin = child.stdin.take().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "Failed to obtain stdin for gopass command".to_string(),
            )
        })?;

        use std::io::Write;
        stdin
            .write_all(value.expose_secret().as_bytes())
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to write to gopass stdin: {}",
                    e
                ))
            })?;

        // Drop stdin to close the pipe so gopass process receives EOF
        drop(stdin);

        let output = child.wait_with_output().map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to wait for gopass command: {}",
                e
            ))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "gopass command failed: {}",
                stderr
            )));
        }

        Ok(())
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

        if prefix.is_empty() {
            "gopass".to_string()
        } else {
            format!("gopass://{}", prefix)
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
    fn format_entry_name_default_pattern() {
        let provider = GoPassProvider::new(GoPassConfig::default());
        assert_eq!(
            provider.format_entry_name("myproj", "prod", "API_KEY"),
            "secretspec/myproj/prod/API_KEY"
        );
    }

    #[test]
    fn format_entry_name_custom_prefix() {
        let provider = GoPassProvider::new(GoPassConfig {
            folder_prefix: Some("team-store/{profile}/{key}".to_string()),
        });
        assert_eq!(
            provider.format_entry_name("myproj", "prod", "API_KEY"),
            "team-store/prod/API_KEY"
        );
    }

    #[test]
    fn try_from_sets_folder_prefix_from_host_and_path() {
        let config =
            GoPassConfig::try_from(&provider_url("gopass://secretspec/shared/{profile}/{key}"))
                .unwrap();
        assert_eq!(
            config.folder_prefix.as_deref(),
            Some("secretspec/shared/{profile}/{key}")
        );
    }

    #[test]
    fn try_from_bare_url_leaves_prefix_unset() {
        let config = GoPassConfig::try_from(&provider_url("gopass://")).unwrap();
        assert_eq!(config.folder_prefix, None);
    }

    #[test]
    fn try_from_rejects_wrong_scheme() {
        let err = GoPassConfig::try_from(&provider_url("pass://x")).unwrap_err();
        assert!(err.to_string().contains("Invalid scheme"));
    }

    #[test]
    fn uri_round_trips_default_and_prefix() {
        assert_eq!(GoPassProvider::new(GoPassConfig::default()).uri(), "gopass");
        let provider = GoPassProvider::new(GoPassConfig {
            folder_prefix: Some("my store/{key}".to_string()),
        });
        assert_eq!(provider.uri(), "gopass://my%20store/{key}");
    }

    /// A native address names the store entry directly via `item`, bypassing
    /// the folder-prefix format string. This is what gopass logical paths
    /// (including mount-point prefixes for multi-store setups) map onto.
    #[test]
    fn native_address_names_the_entry() {
        let p = GoPassProvider::new(GoPassConfig {
            folder_prefix: Some("team-store/{profile}/{key}".to_string()),
        });
        let addr = crate::config::NativeAddress {
            item: "work-store/email/work".into(),
            ..Default::default()
        };
        assert_eq!(
            crate::provider::flat_item(&p, Address::Native(&addr)).unwrap(),
            "work-store/email/work"
        );
    }

    /// Store entries have no sub-components; a `field` coordinate is rejected.
    #[test]
    fn native_address_rejects_field() {
        let p = GoPassProvider::new(GoPassConfig::default());
        let addr = crate::config::NativeAddress {
            item: "email/work".into(),
            field: Some("password".into()),
            ..Default::default()
        };
        let err = crate::provider::flat_item(&p, Address::Native(&addr)).unwrap_err();
        assert!(err.to_string().contains("`field`"), "{err}");
    }
}
