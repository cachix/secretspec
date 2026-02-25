use super::Provider;
use crate::{Result, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::process::Command;
use url::Url;

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
}

impl TryFrom<&Url> for PassConfig {
    type Error = SecretSpecError;

    /// Creates a PassConfig from a URL.
    ///
    /// The URL must have the scheme "pass" (e.g., "pass://" or
    /// "pass://secretspec/shared/{profile}/{key}").
    fn try_from(url: &Url) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "pass" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for pass provider",
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

impl TryFrom<Url> for PassConfig {
    type Error = SecretSpecError;

    fn try_from(url: Url) -> std::result::Result<Self, Self::Error> {
        (&url).try_into()
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
    examples: ["pass://", "pass://secretspec/shared/{profile}/{key}"],
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
}

impl Provider for PassProvider {
    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        if let Some(ref prefix) = self.config.folder_prefix {
            format!("pass://{}", prefix)
        } else {
            "pass".to_string()
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
    fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<SecretString>> {
        let entry_name = self.format_entry_name(project, profile, key);

        let output = Command::new("pass")
            .arg("show")
            .arg(&entry_name)
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
    fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()> {
        let entry_name = self.format_entry_name(project, profile, key);

        let mut child = Command::new("pass")
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
