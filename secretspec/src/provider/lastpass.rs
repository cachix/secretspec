use crate::provider::Provider;
use crate::{Result, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::process::{Command, Stdio};
use url::Url;

/// Configuration for the LastPass provider.
///
/// This struct contains the configuration options for interacting with LastPass
/// through the `lpass` CLI tool.
///
/// # Examples
///
/// ```ignore
/// use secretspec::provider::lastpass::LastPassConfig;
///
/// // Create a default configuration
/// let config = LastPassConfig::default();
///
/// // Create a configuration with a folder prefix
/// let config = LastPassConfig {
///     folder_prefix: Some("my-company".to_string()),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastPassConfig {
    /// Optional folder prefix format string for organizing secrets in LastPass.
    ///
    /// Supports placeholders: {project}, {profile}, and {key}.
    /// Defaults to "secretspec/{project}/{profile}/{key}" if not specified.
    pub folder_prefix: Option<String>,
}

impl Default for LastPassConfig {
    /// Creates a default LastPassConfig with no folder prefix.
    fn default() -> Self {
        Self {
            folder_prefix: None,
        }
    }
}

impl TryFrom<&Url> for LastPassConfig {
    type Error = SecretSpecError;

    /// Creates a LastPassConfig from a URL.
    ///
    /// Parses a URL in the format `lastpass://[folder]` where the folder
    /// component is optional. The folder can be specified either as the
    /// authority or the path component of the URL.
    ///
    /// # Arguments
    ///
    /// * `url` - A URL with the `lastpass` scheme
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the parsed configuration or an error
    /// if the URL scheme is not `lastpass`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use url::Url;
    /// use secretspec::provider::lastpass::LastPassConfig;
    ///
    /// // URL without folder
    /// let url = Url::parse("lastpass://").unwrap();
    /// let config: LastPassConfig = (&url).try_into().unwrap();
    ///
    /// // URL with folder as authority
    /// let url = Url::parse("lastpass://my-folder").unwrap();
    /// let config: LastPassConfig = (&url).try_into().unwrap();
    ///
    /// // URL with folder as path
    /// let url = Url::parse("lastpass:///my-folder").unwrap();
    /// let config: LastPassConfig = (&url).try_into().unwrap();
    /// ```
    fn try_from(url: &Url) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "lastpass" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for lastpass provider",
                url.scheme()
            )));
        }

        let mut config = Self::default();

        if let Some(host) = url.host_str() {
            config.folder_prefix = Some(host.to_string() + url.path());
        }

        Ok(config)
    }
}

/// LastPass provider implementation for SecretSpec.
///
/// This provider integrates with LastPass password manager through the `lpass` CLI tool.
/// It stores secrets in a hierarchical structure within LastPass using a configurable
/// format string that defaults to: `secretspec/{project}/{profile}/{key}`.
///
/// # Requirements
///
/// The LastPass CLI (`lpass`) must be installed and the user must be logged in:
/// - macOS: `brew install lastpass-cli`
/// - Linux: Use your package manager (e.g., `apt install lastpass-cli`)
/// - NixOS: `nix-env -iA nixpkgs.lastpass-cli`
///
/// After installation, authenticate with: `lpass login <your-email>`
///
/// # Examples
///
/// ```ignore
/// use secretspec::provider::lastpass::{LastPassProvider, LastPassConfig};
///
/// // Create provider with default config
/// let provider = LastPassProvider::default();
///
/// // Create provider with custom config
/// let config = LastPassConfig {
///     folder_prefix: Some("work".to_string()),
/// };
/// let provider = LastPassProvider::new(config);
/// ```
pub struct LastPassProvider {
    #[allow(dead_code)]
    config: LastPassConfig,
}

crate::register_provider! {
    struct: LastPassProvider,
    config: LastPassConfig,
    name: "lastpass",
    description: "LastPass password manager",
    schemes: ["lastpass"],
    examples: ["lastpass://", "lastpass://Shared-SecretSpec"],
}

impl LastPassProvider {
    /// Creates a new LastPassProvider with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The LastPass configuration to use
    pub fn new(config: LastPassConfig) -> Self {
        Self { config }
    }

    /// Executes a LastPass CLI command and returns its output.
    ///
    /// This is the core method for interacting with the LastPass CLI. It handles
    /// command execution, error detection, and provides helpful error messages
    /// for common issues like missing CLI installation or authentication.
    ///
    /// # Arguments
    ///
    /// * `args` - Command line arguments to pass to `lpass`
    ///
    /// # Returns
    ///
    /// Returns the command's stdout as a String on success, or an error with
    /// detailed information about what went wrong.
    ///
    /// # Errors
    ///
    /// - Returns an error if the `lpass` CLI is not installed
    /// - Returns an error if the user is not logged in to LastPass
    /// - Returns an error if the command fails for any other reason
    fn execute_lpass_command(&self, args: &[&str]) -> Result<String> {
        let mut cmd = Command::new("lpass");
        cmd.args(args);

        let output = match cmd.output() {
            Ok(output) => output,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "LastPass CLI (lpass) is not installed.\n\nTo install it:\n  - macOS: brew install lastpass-cli\n  - Linux: Check your package manager (apt install lastpass-cli, yum install lastpass-cli, etc.)\n  - NixOS: nix-env -iA nixpkgs.lastpass-cli\n\nAfter installation, run 'lpass login <your-email>' to authenticate.".to_string(),
                ));
            }
            Err(e) => return Err(e.into()),
        };

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            if error_msg.contains("Could not find decryption key")
                || error_msg.contains("Not logged in")
            {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "LastPass authentication required. Please run 'lpass login' first.".to_string(),
                ));
            }
            return Err(SecretSpecError::ProviderOperationFailed(
                error_msg.to_string(),
            ));
        }

        String::from_utf8(output.stdout)
            .map_err(|e| SecretSpecError::ProviderOperationFailed(e.to_string()))
    }

    /// Formats the item name for storage in LastPass.
    ///
    /// Creates a hierarchical path for organizing secrets within LastPass.
    /// Uses folder_prefix as a format string with {project}, {profile}, and {key} placeholders.
    /// Defaults to "secretspec/{project}/{profile}/{key}" if not configured.
    ///
    /// # Arguments
    ///
    /// * `project` - The project name
    /// * `key` - The secret key name
    /// * `profile` - The profile name (e.g., "default", "production", "staging")
    ///
    /// # Returns
    ///
    /// A formatted string representing the full path to the secret in LastPass.
    fn format_item_name(&self, project: &str, key: &str, profile: &str) -> String {
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

    /// Verifies that the user is logged in to LastPass.
    ///
    /// This method checks the login status and returns a helpful error message
    /// if the user needs to authenticate.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if logged in, or an error with instructions on how to log in.
    ///
    /// # Errors
    ///
    /// Returns an error if the user is not logged in to LastPass.
    fn check_if_logged_in(&self) -> Result<()> {
        // Check if we're logged in first
        if !self.check_login_status()? {
            return Err(SecretSpecError::ProviderOperationFailed(
                "LastPass authentication required. Please run 'lpass login <your-email>' first."
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Checks the current LastPass login status.
    ///
    /// Executes `lpass status` to determine if the user is currently logged in.
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if logged in, `Ok(false)` if not logged in, or an error
    /// if the status check itself fails.
    fn check_login_status(&self) -> Result<bool> {
        match self.execute_lpass_command(&["status"]) {
            Ok(output) => Ok(!output.contains("Not logged in")),
            Err(SecretSpecError::ProviderOperationFailed(msg))
                if msg.contains("Not logged in")
                    || msg.contains("LastPass authentication required") =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }
}

impl Provider for LastPassProvider {
    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        // LastPass can be "lastpass" (default) or "lastpass://folder" or "lastpass://Folder/Subfolder"
        if let Some(ref prefix) = self.config.folder_prefix {
            // The folder_prefix might be something like "SecretSpec/{project}/{profile}/{key}"
            // We want to extract just the folder part for the URI
            if let Some(folder) = prefix.split('/').next() {
                if folder.is_empty() || folder == "Shared" {
                    "lastpass".to_string()
                } else {
                    format!("lastpass://{}", folder)
                }
            } else {
                "lastpass".to_string()
            }
        } else {
            "lastpass".to_string()
        }
    }

    /// Retrieves a secret from LastPass.
    ///
    /// Fetches the value of a secret stored in LastPass at the path
    /// determined by the folder_prefix format string. Uses `lpass show` with
    /// the `--sync=now` flag to ensure fresh data from the server.
    ///
    /// # Arguments
    ///
    /// * `project` - The project name
    /// * `key` - The secret key to retrieve
    /// * `profile` - The profile name
    ///
    /// # Returns
    ///
    /// - `Ok(Some(value))` if the secret exists and has a value
    /// - `Ok(None)` if the secret doesn't exist or has an empty value
    /// - `Err` if there's an error accessing LastPass
    ///
    /// # Errors
    ///
    /// - Returns an error if not logged in to LastPass
    /// - Returns an error if the LastPass CLI fails
    fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<SecretString>> {
        self.check_if_logged_in()?;

        let item_name = self.format_item_name(project, key, profile);

        match self.execute_lpass_command(&["show", "--sync=now", "--password", &item_name]) {
            Ok(output) => {
                let password = output.trim();
                if password.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(SecretString::new(password.to_string().into())))
                }
            }
            Err(SecretSpecError::ProviderOperationFailed(msg))
                if msg.contains("Could not find specified account") =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Stores a secret in LastPass.
    ///
    /// Creates or updates a secret in LastPass at the path
    /// determined by the folder_prefix format string. The method first checks if
    /// the item exists to determine whether to use `lpass edit` (for updates)
    /// or `lpass set` (for new items).
    ///
    /// # Arguments
    ///
    /// * `project` - The project name
    /// * `key` - The secret key to store
    /// * `value` - The secret value to store
    /// * `profile` - The profile name
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or an error if the operation fails.
    ///
    /// # Errors
    ///
    /// - Returns an error if not logged in to LastPass
    /// - Returns an error if the LastPass CLI command fails
    ///
    /// # Implementation Details
    ///
    /// The method uses non-interactive mode and disables pinentry to avoid
    /// GUI prompts. The secret value is passed via stdin to avoid exposing
    /// it in the process list.
    fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()> {
        self.check_if_logged_in()?;

        let item_name = self.format_item_name(project, key, profile);

        // Check if item exists
        if self.get(project, key, profile)?.is_some() {
            // Update existing item
            let args = vec![
                "edit",
                "--sync=now",
                &item_name,
                "--password",
                "--non-interactive",
            ];

            let mut cmd = Command::new("lpass");
            cmd.args(&args);
            cmd.env("LPASS_DISABLE_PINENTRY", "1");

            let mut child = cmd
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;

            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(value.expose_secret().as_bytes())?;
            }

            let output = child.wait_with_output()?;
            if !output.status.success() {
                let error_msg = String::from_utf8_lossy(&output.stderr);
                return Err(SecretSpecError::ProviderOperationFailed(
                    error_msg.to_string(),
                ));
            }
        } else {
            // Create new item using lpass set
            let args = vec![
                "set",
                "--sync=now",
                &item_name,
                "--password",
                "--non-interactive",
            ];

            let mut cmd = Command::new("lpass");
            cmd.args(&args);
            cmd.env("LPASS_DISABLE_PINENTRY", "1");

            let mut child = cmd
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;

            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(value.expose_secret().as_bytes())?;
            }

            let output = child.wait_with_output()?;
            if !output.status.success() {
                let error_msg = String::from_utf8_lossy(&output.stderr);
                return Err(SecretSpecError::ProviderOperationFailed(
                    error_msg.to_string(),
                ));
            }
        }

        Ok(())
    }
}

impl Default for LastPassProvider {
    /// Creates a LastPassProvider with default configuration.
    ///
    /// This is equivalent to calling `LastPassProvider::new(LastPassConfig::default())`.
    fn default() -> Self {
        Self::new(LastPassConfig::default())
    }
}
