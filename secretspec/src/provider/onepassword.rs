use crate::config::SecretRequest;
use crate::provider::{Provider, ProviderUrl};
use crate::{Result, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;

/// Represents a OnePassword item retrieved from the CLI.
///
/// This struct deserializes the JSON output from the `op item get` command
/// and contains an array of fields that hold the actual secret data.
#[derive(Debug, Deserialize)]
pub(crate) struct OnePasswordItem {
    /// Collection of fields within the OnePassword item.
    /// Each field represents a piece of data stored in the item.
    pub(crate) fields: Vec<OnePasswordField>,
}

/// Represents a single field within a OnePassword item.
///
/// Fields can contain various types of data such as passwords, strings,
/// or concealed values. The field's label is used to identify specific
/// data within an item.
#[derive(Debug, Deserialize)]
pub(crate) struct OnePasswordField {
    /// Unique identifier for the field within the item.
    id: String,
    /// The type of field (e.g., "STRING", "CONCEALED", "PASSWORD").
    #[serde(rename = "type")]
    field_type: String,
    /// Optional human-readable label for the field.
    /// Used to identify fields like "value", "password", etc.
    pub(crate) label: Option<String>,
    /// Optional section the field belongs to (e.g. "GitHub").
    pub(crate) section: Option<OnePasswordSection>,
    /// The actual value stored in the field.
    /// May be None for certain field types.
    pub(crate) value: Option<String>,
}

/// A section within a OnePassword item.
#[derive(Debug, Deserialize)]
pub(crate) struct OnePasswordSection {
    /// Optional label for the section (e.g. "GitHub").
    pub(crate) label: Option<String>,
}

/// Template for creating new OnePassword items via the CLI.
///
/// This struct is serialized to JSON and passed to the `op item create` command
/// using the `--template` flag. It defines the structure and metadata for
/// new secure note items that store secrets.
#[derive(Debug, Serialize)]
struct OnePasswordItemTemplate {
    /// The title of the item, formatted as "secretspec/{project}/{profile}/{key}".
    title: String,
    /// The category of the item. Always "SECURE_NOTE" for secretspec items.
    category: String,
    /// Collection of fields to include in the item.
    /// Contains project, key, and value fields.
    fields: Vec<OnePasswordFieldTemplate>,
    /// Tags to help organize and identify secretspec items.
    /// Includes "automated" and the project name.
    tags: Vec<String>,
}

/// Template for individual fields when creating OnePassword items.
///
/// Each field represents a piece of data to store in the item.
/// Used within OnePasswordItemTemplate to define the item's content.
#[derive(Debug, Serialize)]
struct OnePasswordFieldTemplate {
    /// Human-readable label for the field (e.g., "project", "key", "value").
    label: String,
    /// The type of field. Always "STRING" for secretspec fields.
    #[serde(rename = "type")]
    field_type: String,
    /// The actual value to store in the field.
    value: String,
}

/// Configuration for the OnePassword provider.
///
/// This struct contains all the necessary configuration options for
/// interacting with OnePassword CLI. It supports both interactive authentication
/// and service account tokens for automated workflows.
///
/// # Examples
///
/// ```ignore
/// # use secretspec::provider::onepassword::OnePasswordConfig;
/// // Using default configuration (interactive auth)
/// let config = OnePasswordConfig::default();
///
/// // With a specific vault
/// let config = OnePasswordConfig {
///     default_vault: Some("Development".to_string()),
///     ..Default::default()
/// };
///
/// // With service account token for CI/CD
/// let config = OnePasswordConfig {
///     service_account_token: Some("ops_eyJzaWduSW...".to_string()),
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OnePasswordConfig {
    /// Optional account shorthand (for multiple accounts).
    ///
    /// Used with the `--account` flag when you have multiple OnePassword
    /// accounts configured. This should match the shorthand shown in
    /// `op account list`.
    pub account: Option<String>,
    /// Default vault to use when profile is "default".
    ///
    /// If not set, defaults to "Private" for the default profile.
    /// For non-default profiles, the profile name is used as the vault name.
    pub default_vault: Option<String>,
    /// Service account token (alternative to interactive auth).
    ///
    /// When set, this token is passed via the OP_SERVICE_ACCOUNT_TOKEN
    /// environment variable to authenticate without user interaction.
    /// Ideal for CI/CD environments.
    pub service_account_token: Option<String>,
    /// Optional folder prefix format string for organizing SecretSpec-owned secrets in OnePassword.
    ///
    /// Supports placeholders: {project}, {profile}, and {key}.
    /// Defaults to "secretspec/{project}/{profile}/{key}" if not specified.
    pub folder_prefix: Option<String>,
    /// Whether this provider uses native 1Password secret references (`op://`).
    #[serde(default)]
    pub native_references: bool,
    /// Base path segments for native 1Password references after the vault name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reference_base_path: Vec<String>,
}

impl TryFrom<&ProviderUrl> for OnePasswordConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        let scheme = url.scheme();

        match scheme {
            "1password" => {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "Invalid scheme '1password'. Use 'onepassword' instead (e.g., onepassword://vault/path)".to_string()
                ));
            }
            "onepassword" | "onepassword+token" | "op" | "op+token" => {}
            _ => {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Invalid scheme '{}' for OnePassword provider",
                    scheme
                )));
            }
        }

        let mut config = Self {
            native_references: matches!(scheme, "op" | "op+token"),
            ..Self::default()
        };

        // Parse URL components for account@vault format, ignoring dummy localhost
        if let Some(host) = url.host()
            && host != "localhost"
        {
            let username = url.username();

            // Check if we have username (account) information
            if !username.is_empty() {
                // Handle user:token format for service account tokens
                if scheme == "onepassword+token" || scheme == "op+token" {
                    if let Some(password) = url.password() {
                        config.service_account_token = Some(password);
                    } else {
                        config.service_account_token = Some(username);
                    }
                } else {
                    config.account = Some(username);
                }
                config.default_vault = Some(host);
            } else {
                // No username, so the host is the vault
                config.default_vault = Some(host);
            }
        }

        let uri_path = url.path();
        let uri_path = uri_path.trim_matches('/');
        if !uri_path.is_empty() {
            if config.native_references {
                config.reference_base_path = uri_path
                    .split('/')
                    .filter(|segment| !segment.is_empty())
                    .map(str::to_string)
                    .collect();
            } else {
                let folder_prefix = if uri_path.contains("{key}") {
                    uri_path.to_string()
                } else {
                    format!("{}/{{key}}", uri_path.trim_end_matches('/'))
                };
                config.folder_prefix = Some(folder_prefix);
            }
        }

        Ok(config)
    }
}

/// Detects if running on Windows Subsystem for Linux 2.
///
/// Checks if the system is running on WSL2 by reading `/proc/sys/kernel/osrelease`
/// and looking for the `-microsoft-standard-WSL2` suffix.
///
/// # Returns
///
/// * `true` - Running on WSL2
/// * `false` - Not running on WSL2 or unable to determine
#[cfg(target_os = "linux")]
fn is_wsl2() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|content| content.trim().ends_with("-microsoft-standard-WSL2"))
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn is_wsl2() -> bool {
    false
}

/// Removes any `OP_SESSION_*` env vars from a spawned `op` invocation.
///
/// `op` treats `OP_SESSION_<account>` as the authoritative session and will not
/// fall back to the desktop app's biometric flow when those tokens expire,
/// returning `"account is not signed in"` instead. Stripping them lets the
/// desktop integration (Settings → Developer → Integrate with 1Password CLI)
/// handle unlock automatically. See
/// <https://github.com/cachix/secretspec/issues/80>.
const OP_NOT_INSTALLED_HELP: &str = "OnePassword CLI (op) is not installed.\n\n\
    To install it:\n  \
    - macOS: brew install 1password-cli\n  \
    - Linux: Download from https://1password.com/downloads/command-line/\n  \
    - Windows: Download from https://1password.com/downloads/command-line/\n  \
    - NixOS: nix-env -iA nixpkgs.onepassword\n\n\
    Then enable desktop integration in the 1Password app under\n  \
    Settings → Developer → \"Integrate with 1Password CLI\".";

const AUTH_REQUIRED_HELP: &str = "OnePassword authentication required.\n\n\
    Recommended: enable desktop integration in the 1Password app under\n  \
    Settings → Developer → \"Integrate with 1Password CLI\", then unlock the app.\n\n\
    Alternatives:\n  \
    - Service account (CI): set OP_SERVICE_ACCOUNT_TOKEN or use the onepassword+token:// or op+token:// scheme\n  \
    - Manual signin: run 'eval $(op signin)' (session expires after 30 minutes of inactivity)";

fn is_auth_error(error_msg: &str) -> bool {
    error_msg.contains("not currently signed in")
        || error_msg.contains("no active session")
        || error_msg.contains("could not find session token")
        || error_msg.contains("account is not signed in")
}

pub(crate) fn strip_op_session_env(cmd: &mut Command) {
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("OP_SESSION_") {
            cmd.env_remove(&key);
        }
    }
}

/// Provider implementation for OnePassword password manager.
///
/// This provider integrates with OnePassword CLI (`op`) to store and retrieve
/// secrets. It organizes secrets in a hierarchical structure within OnePassword
/// items using a configurable format string that defaults to: `secretspec/{project}/{profile}/{key}`.
///
/// # Authentication
///
/// The provider supports three authentication methods, in order of preference:
///
/// 1. **Desktop app integration** (recommended for local dev): enable
///    Settings → Developer → "Integrate with 1Password CLI" in the desktop app.
///    `op` calls are unlocked via biometrics with no shell session needed.
/// 2. **Service Account Tokens**: For CI/CD, configure a token in the config
///    or set `OP_SERVICE_ACCOUNT_TOKEN`.
/// 3. **Manual signin** (legacy): run `eval $(op signin)`. The provider strips
///    `OP_SESSION_*` env vars before spawning `op` so that expired session
///    tokens fall back to desktop integration instead of erroring.
///
/// # Storage Structure
///
/// Secrets are stored as Secure Note items in OnePassword with:
/// - Title: formatted according to folder_prefix configuration
/// - Category: SECURE_NOTE
/// - Fields: project, key, value
/// - Tags: "automated", {project}
///
/// # Example Usage
///
/// ```ignore
/// # Desktop integration (recommended): enable in 1Password app, then:
/// secretspec set MY_SECRET --provider onepassword://Development
///
/// # Service account token
/// export OP_SERVICE_ACCOUNT_TOKEN="ops_eyJzaWduSW..."
/// secretspec get MY_SECRET --provider onepassword+token://Development
/// ```
pub struct OnePasswordProvider {
    /// Configuration for the provider including auth settings and default vault.
    config: OnePasswordConfig,
    /// The OnePassword CLI command to use (either "op" or a custom path).
    op_command: String,
    /// Provider-local dependency secrets that are passed to the `op` child process.
    dependency_env: HashMap<String, SecretString>,
}

crate::register_provider! {
    struct: OnePasswordProvider,
    config: OnePasswordConfig,
    name: "onepassword",
    description: "OnePassword password manager",
    schemes: ["onepassword", "onepassword+token", "op", "op+token"],
    examples: [
        "onepassword://vault",
        "onepassword://work@Production",
        "onepassword+token://vault",
        "op://vault/item/section",
        "op+token://vault/item",
    ],
    preflight: check_auth,
}

impl OnePasswordProvider {
    /// Creates a new OnePasswordProvider with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the provider
    pub fn new(config: OnePasswordConfig) -> Self {
        let op_command = std::env::var("SECRETSPEC_OPCLI_PATH").unwrap_or_else(|_| {
            if is_wsl2() {
                "op.exe".to_string()
            } else {
                "op".to_string()
            }
        });
        Self {
            config,
            op_command,
            dependency_env: HashMap::new(),
        }
    }

    /// Executes a OnePassword CLI command with proper error handling.
    ///
    /// This method handles:
    /// - Setting up authentication (account, service token)
    /// - Executing the command
    /// - Parsing error messages for common issues
    /// - Providing helpful error messages for missing CLI
    ///
    /// # Arguments
    ///
    /// * `args` - The command arguments to pass to `op`
    /// * `stdin_data` - Optional data to write to stdin
    ///
    /// # Returns
    ///
    /// * `Result<String>` - The command output or an error
    ///
    /// # Errors
    ///
    /// Returns specific errors for:
    /// - Missing OnePassword CLI installation
    /// - Authentication required
    /// - Command execution failures
    /// - Stdin write failures
    fn execute_op_command(&self, args: &[&str], stdin_data: Option<&str>) -> Result<String> {
        use std::io::Write;
        use std::process::Stdio;

        tracing::debug!(
            command = %self.op_command,
            args = ?args,
            has_stdin = stdin_data.is_some(),
            has_service_token = self.config.service_account_token.is_some()
                || self.dependency_env.contains_key("OP_SERVICE_ACCOUNT_TOKEN"),
            account = ?self.config.account,
            vault = ?self.config.default_vault,
            "executing 1Password CLI command"
        );

        let mut cmd = Command::new(&self.op_command);
        strip_op_session_env(&mut cmd);

        // Set service account token directly on the child command. Prefer an
        // explicit token from the provider URI, then fall back to a resolved
        // provider dependency. This avoids mutating the process-global
        // environment while still giving `op` the credentials it needs.
        if let Some(token) = &self.config.service_account_token {
            cmd.env("OP_SERVICE_ACCOUNT_TOKEN", token);
        } else if let Some(token) = self.dependency_env.get("OP_SERVICE_ACCOUNT_TOKEN") {
            cmd.env("OP_SERVICE_ACCOUNT_TOKEN", token.expose_secret());
        }

        // Add account if specified
        if let Some(account) = &self.config.account {
            cmd.arg("--account").arg(account);
        }

        cmd.args(args);

        // Configure stdio based on whether we have stdin data
        if stdin_data.is_some() {
            cmd.stdin(Stdio::piped());
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());
        }

        let output = if let Some(data) = stdin_data {
            // Spawn process and write to stdin
            let mut child = match cmd.spawn() {
                Ok(child) => child,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(SecretSpecError::ProviderOperationFailed(
                        OP_NOT_INSTALLED_HELP.to_string(),
                    ));
                }
                Err(e) => return Err(e.into()),
            };

            // Write to stdin
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(data.as_bytes())?;
                drop(stdin); // Close stdin
            }

            child.wait_with_output()?
        } else {
            // No stdin data, use output() directly
            match cmd.output() {
                Ok(output) => output,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(SecretSpecError::ProviderOperationFailed(
                        OP_NOT_INSTALLED_HELP.to_string(),
                    ));
                }
                Err(e) => return Err(e.into()),
            }
        };

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            if is_auth_error(&error_msg) {
                tracing::error!(
                    status = ?output.status.code(),
                    stderr = %error_msg,
                    args = ?args,
                    "1Password CLI command failed due to authentication"
                );
                return Err(SecretSpecError::ProviderOperationFailed(
                    AUTH_REQUIRED_HELP.to_string(),
                ));
            }
            tracing::warn!(
                status = ?output.status.code(),
                stderr = %error_msg,
                args = ?args,
                "1Password CLI command failed"
            );
            return Err(SecretSpecError::ProviderOperationFailed(
                error_msg.to_string(),
            ));
        }

        String::from_utf8(output.stdout)
            .map_err(|e| SecretSpecError::ProviderOperationFailed(e.to_string()))
    }

    /// Checks if the user is authenticated with OnePassword (uncached).
    ///
    /// Uses `op vault list` rather than `op whoami` because the latter only
    /// reports the state of an explicit `op signin` session and reports
    /// `account is not signed in` under desktop-app delegated sessions even
    /// when secret reads via `op item ...` work fine. `op vault list` actually
    /// exercises the access path used for real operations.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - User is authenticated
    /// * `Ok(false)` - User is not authenticated
    /// * `Err(_)` - Command execution failed
    fn is_authenticated(&self) -> Result<bool> {
        match self.execute_op_command(&["vault", "list", "--format", "json"], None) {
            Ok(_) => Ok(true),
            Err(SecretSpecError::ProviderOperationFailed(msg))
                if msg.contains("authentication required") || msg.contains("no account found") =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Determines the vault name to use.
    ///
    /// # Arguments
    ///
    /// * `profile` - The profile name (currently unused, but kept for potential future use)
    ///
    /// # Returns
    ///
    /// The vault name to use - always returns the configured default_vault or "Private"
    fn get_vault_name(&self, _profile: &str) -> String {
        self.config
            .default_vault
            .clone()
            .unwrap_or_else(|| "Private".to_string())
    }

    /// Finds an item by title in the vault and returns its ID.
    ///
    /// Uses `op item list` to search for items, which is more reliable than
    /// `op item get` for existence checking because it doesn't fail when
    /// an item exists but has no extractable value.
    ///
    /// # Arguments
    ///
    /// * `item_name` - The item title to search for
    /// * `vault` - The vault to search in
    ///
    /// # Returns
    ///
    /// * `Ok(Some(id))` - Item found, returns its ID
    /// * `Ok(None)` - Item not found
    /// * `Err(_)` - Search failed
    fn find_item_id(&self, item_name: &str, vault: &str) -> Result<Option<String>> {
        let args = vec!["item", "list", "--vault", vault, "--format", "json"];

        let output = self.execute_op_command(&args, None)?;

        #[derive(Deserialize)]
        struct ListItem {
            id: String,
            title: String,
        }

        let items: Vec<ListItem> = serde_json::from_str(&output).unwrap_or_default();

        Ok(items
            .into_iter()
            .find(|item| item.title == item_name)
            .map(|item| item.id))
    }

    /// Formats the item name for storage in OnePassword.
    ///
    /// Creates a hierarchical name using the folder_prefix format string.
    /// Supports placeholders: {project}, {profile}, and {key}.
    /// Defaults to "secretspec/{project}/{profile}/{key}" if not configured.
    ///
    /// # Arguments
    ///
    /// * `project` - The project name
    /// * `key` - The secret key
    /// * `profile` - The profile name
    ///
    /// # Returns
    ///
    /// A formatted string based on the configured pattern
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

    /// Creates a template for a new OnePassword item.
    ///
    /// This template is serialized to JSON and used with `op item create`.
    /// The item is created as a Secure Note with structured fields.
    ///
    /// # Arguments
    ///
    /// * `project` - The project name
    /// * `key` - The secret key
    /// * `value` - The secret value
    /// * `profile` - The profile name
    ///
    /// # Returns
    ///
    /// A OnePasswordItemTemplate ready for serialization
    fn create_item_template(
        &self,
        project: &str,
        key: &str,
        value: &SecretString,
        profile: &str,
    ) -> OnePasswordItemTemplate {
        OnePasswordItemTemplate {
            title: self.format_item_name(project, key, profile),
            category: "SECURE_NOTE".to_string(),
            fields: vec![
                OnePasswordFieldTemplate {
                    label: "project".to_string(),
                    field_type: "STRING".to_string(),
                    value: project.to_string(),
                },
                OnePasswordFieldTemplate {
                    label: "key".to_string(),
                    field_type: "STRING".to_string(),
                    value: key.to_string(),
                },
                OnePasswordFieldTemplate {
                    label: "value".to_string(),
                    field_type: "STRING".to_string(),
                    value: value.expose_secret().to_string(),
                },
            ],
            tags: vec!["automated".to_string(), project.to_string()],
        }
    }

    /// Extracts the secret value from a OnePassword item JSON.
    ///
    /// Looks for a field labeled "value" first, then falls back to
    /// password or concealed fields.
    fn extract_value_from_item(&self, output: &str) -> Result<Option<SecretString>> {
        let item: OnePasswordItem = serde_json::from_str(output)?;

        // Look for the "value" field
        for field in &item.fields {
            if field.label.as_deref() == Some("value") {
                return Ok(field
                    .value
                    .as_ref()
                    .map(|v| SecretString::new(v.clone().into())));
            }
        }

        // Fallback: look for password field or first concealed field
        for field in &item.fields {
            if field.field_type == "CONCEALED" || field.id == "password" {
                return Ok(field
                    .value
                    .as_ref()
                    .map(|v| SecretString::new(v.clone().into())));
            }
        }

        Ok(None)
    }
}

impl OnePasswordProvider {
    /// Checks that the user is authenticated with OnePassword.
    /// Called by the preflight guard before any provider operations.
    pub(crate) fn check_auth(&self) -> Result<()> {
        if self.is_authenticated()? {
            Ok(())
        } else {
            Err(SecretSpecError::ProviderOperationFailed(
                AUTH_REQUIRED_HELP.to_string(),
            ))
        }
    }

    fn native_reference_parts(&self, key: &str, request: Option<&SecretRequest>) -> Vec<String> {
        let mut parts = self.config.reference_base_path.clone();
        if let Some(request) = request {
            if let Some(path) = &request.path {
                parts.extend(path.iter().cloned());
            }
            parts.push(request.key.as_deref().unwrap_or(key).to_string());
        } else {
            parts.push(key.to_string());
        }
        parts
    }

    fn native_reference(&self, profile: &str, parts: &[String]) -> String {
        let mut reference = format!(
            "op://{}",
            ProviderUrl::encode(&self.get_vault_name(profile))
        );
        for part in parts {
            reference.push('/');
            reference.push_str(&ProviderUrl::encode(part));
        }
        reference
    }

    fn native_item_and_assignment(
        &self,
        key: &str,
        value: &SecretString,
        request: Option<&SecretRequest>,
    ) -> Result<(String, String)> {
        let parts = self.native_reference_parts(key, request);
        if parts.len() < 2 {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Native 1Password provider requires an item path before the field name".into(),
            ));
        }

        let item = parts[0].clone();
        let field = parts.last().expect("parts length checked");
        let assignment_name = if parts.len() > 2 {
            format!("{}.{}", parts[1..parts.len() - 1].join("."), field)
        } else {
            field.clone()
        };
        Ok((
            item,
            format!("{}[concealed]={}", assignment_name, value.expose_secret()),
        ))
    }

    fn native_missing_message(message: &str) -> bool {
        message.contains("isn't an item")
            || message.contains("isn't a field")
            || message.contains("couldn't find")
            || message.contains("not found")
    }

    fn read_native_reference(
        &self,
        key: &str,
        profile: &str,
        request: Option<&SecretRequest>,
    ) -> Result<Option<SecretString>> {
        let parts = self.native_reference_parts(key, request);
        if parts.len() < 2 {
            return Ok(None);
        }
        let reference = self.native_reference(profile, &parts);
        let args = vec!["read", reference.as_str()];
        match self.execute_op_command(&args, None) {
            Ok(output) => Ok(Some(SecretString::new(
                output.trim_end_matches(['\r', '\n']).to_string().into(),
            ))),
            Err(SecretSpecError::ProviderOperationFailed(msg))
                if Self::native_missing_message(&msg) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    fn set_native_reference(
        &self,
        key: &str,
        value: &SecretString,
        profile: &str,
        request: Option<&SecretRequest>,
    ) -> Result<()> {
        let vault = self.get_vault_name(profile);
        if self.read_native_reference(key, profile, request)?.is_none() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Cannot set native 1Password reference because it does not exist".into(),
            ));
        }
        let (item, assignment) = self.native_item_and_assignment(key, value, request)?;
        let edit_args = vec![
            "item",
            "edit",
            item.as_str(),
            "--vault",
            vault.as_str(),
            assignment.as_str(),
        ];
        self.execute_op_command(&edit_args, None).map(|_| ())
    }
}

impl Provider for OnePasswordProvider {
    fn configure_dependency_secrets(
        &mut self,
        dependencies: &[(String, SecretString)],
    ) -> Result<()> {
        for (name, value) in dependencies {
            if name == "OP_SERVICE_ACCOUNT_TOKEN" {
                self.dependency_env.insert(name.clone(), value.clone());
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        // Reconstruct the URI from the config
        // Format: onepassword://[account@]vault, onepassword+token://[token@]vault,
        // op://vault[/item], or op+token://[token@]vault[/item]

        let scheme = match (
            self.config.native_references,
            self.config.service_account_token.is_some(),
        ) {
            (true, true) => "op+token",
            (true, false) => "op",
            (false, true) => "onepassword+token",
            (false, false) => "onepassword",
        };

        let mut uri = format!("{}://", scheme);

        // For service account token, the token itself might be in the URI
        // but we don't want to expose the actual token value, just indicate it's configured
        if self.config.service_account_token.is_some() {
            // Just indicate token auth is being used without exposing the token
            if let Some(ref vault) = self.config.default_vault {
                uri.push_str(&ProviderUrl::encode(vault));
            }
        } else {
            // Regular auth: account@vault format
            if let Some(ref account) = self.config.account {
                uri.push_str(&ProviderUrl::encode(account));
                uri.push('@');
            }

            if let Some(ref vault) = self.config.default_vault {
                uri.push_str(&ProviderUrl::encode(vault));
            }
        }

        if self.config.native_references {
            for segment in &self.config.reference_base_path {
                uri.push('/');
                uri.push_str(&ProviderUrl::encode(segment));
            }
        }

        uri
    }

    /// Retrieves a secret from OnePassword.
    ///
    /// Searches for an item with the title formatted according to the folder_prefix
    /// configuration in the appropriate vault. The method looks for a field labeled "value"
    /// first, then falls back to password or concealed fields.
    ///
    /// If multiple items exist with the same title, falls back to ID-based lookup
    /// to retrieve the first matching item.
    ///
    /// # Arguments
    ///
    /// * `project` - The project name
    /// * `key` - The secret key to retrieve
    /// * `profile` - The profile to use for vault selection
    ///
    /// # Returns
    ///
    /// * `Ok(Some(value))` - The secret value if found
    /// * `Ok(None)` - No secret found with the given key
    /// * `Err(_)` - Authentication or retrieval error
    fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<SecretString>> {
        if self.config.native_references {
            return self.read_native_reference(key, profile, None);
        }

        let vault = self.get_vault_name(profile);
        let item_name = self.format_item_name(project, key, profile);

        // Try to get the item by title
        let args = vec![
            "item", "get", &item_name, "--vault", &vault, "--format", "json",
        ];

        match self.execute_op_command(&args, None) {
            Ok(output) => self.extract_value_from_item(&output),
            Err(SecretSpecError::ProviderOperationFailed(msg)) if msg.contains("isn't an item") => {
                Ok(None)
            }
            Err(SecretSpecError::ProviderOperationFailed(msg))
                if msg.contains("More than one item") =>
            {
                // Multiple items with same title - fall back to ID-based lookup
                if let Some(item_id) = self.find_item_id(&item_name, &vault)? {
                    let args = vec![
                        "item", "get", &item_id, "--vault", &vault, "--format", "json",
                    ];
                    match self.execute_op_command(&args, None) {
                        Ok(output) => self.extract_value_from_item(&output),
                        Err(e) => Err(e),
                    }
                } else {
                    Ok(None)
                }
            }
            Err(e) => Err(e),
        }
    }

    fn get_with_request(
        &self,
        project: &str,
        key: &str,
        profile: &str,
        request: &SecretRequest,
    ) -> Result<Option<SecretString>> {
        if self.config.native_references {
            return self.read_native_reference(key, profile, Some(request));
        }

        // If no path, delegate to base `get` (one item per secret), honoring
        // an alternate storage key when the provider ref supplied one.
        let storage_key = request.key.as_deref().unwrap_or(key);
        let Some(path_segments) = &request.path else {
            return self.get(project, storage_key, profile);
        };
        if path_segments.is_empty() {
            return self.get(project, storage_key, profile);
        }

        // Provider-relative lookup for a shared OnePassword item. The first
        // path segment is the item title, and the optional second segment is
        // the section label inside that item:
        // `{ provider = "op", path = ["dotfiles", "forges"] }`.
        let vault = self.get_vault_name(profile);
        let item_name = path_segments[0].as_str();

        // The key to look for: request.key if set, otherwise the secret name.
        let field_key = request.key.as_deref().unwrap_or(key);
        let section_name = path_segments.get(1).map(String::as_str);

        tracing::debug!(
            item = %item_name,
            vault = %vault,
            section = ?section_name,
            field = %field_key,
            "reading 1Password field via provider-relative request"
        );

        let args = vec![
            "item", "get", item_name, "--vault", &vault, "--format", "json",
        ];

        let output = match self.execute_op_command(&args, None) {
            Ok(output) => output,
            Err(SecretSpecError::ProviderOperationFailed(msg)) if msg.contains("isn't an item") => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        // Parse the item.
        let item: OnePasswordItem = match serde_json::from_str(&output) {
            Ok(item) => item,
            Err(e) => {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to parse OnePassword item JSON: {e}"
                )));
            }
        };

        // Find field matching section name and field key.
        for field in &item.fields {
            let section_match = section_name.is_none_or(|section_name| {
                field.section.as_ref().and_then(|s| s.label.as_deref()) == Some(section_name)
            });
            let label_match = field.label.as_deref() == Some(field_key);
            if section_match
                && label_match
                && let Some(ref value) = field.value
            {
                return Ok(Some(SecretString::new(value.clone().into())));
            }
        }

        tracing::warn!(
            item = %item_name,
            vault = %vault,
            section = ?section_name,
            field = %field_key,
            "1Password item did not contain requested section/field"
        );
        Ok(None)
    }

    /// Stores or updates a secret in OnePassword.
    ///
    /// If an item with the same title exists, it updates the "value" field.
    /// Otherwise, it creates a new Secure Note item with the secret data.
    ///
    /// # Arguments
    ///
    /// * `project` - The project name
    /// * `key` - The secret key
    /// * `value` - The secret value to store
    /// * `profile` - The profile to use for vault selection
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Secret stored successfully
    /// * `Err(_)` - Storage or authentication error
    ///
    /// # Errors
    ///
    /// - Authentication required if not signed in
    /// - Item creation/update failures
    /// - Temporary file creation errors
    fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()> {
        if self.config.native_references {
            return self.set_native_reference(key, value, profile, None);
        }

        let vault = self.get_vault_name(profile);
        let item_name = self.format_item_name(project, key, profile);

        // Check if item exists by listing items (more reliable than get which requires
        // a readable value). This prevents creating duplicates when an item exists
        // but has no extractable value field.
        if let Some(item_id) = self.find_item_id(&item_name, &vault)? {
            // Item exists, update it by ID to avoid "more than one item" ambiguity
            let field_assignment = format!("value={}", value.expose_secret());
            let args = vec![
                "item",
                "edit",
                &item_id,
                "--vault",
                &vault,
                &field_assignment,
            ];

            self.execute_op_command(&args, None)?;
        } else {
            // Item doesn't exist, create it
            let template = self.create_item_template(project, key, value, profile);
            let template_json = serde_json::to_string(&template)?;

            let args = vec!["item", "create", "--vault", &vault, "-"];

            self.execute_op_command(&args, Some(&template_json))?;
        }

        Ok(())
    }

    fn set_with_request(
        &self,
        _project: &str,
        key: &str,
        value: &SecretString,
        profile: &str,
        request: &SecretRequest,
    ) -> Result<()> {
        if self.config.native_references {
            return self.set_native_reference(key, value, profile, Some(request));
        }

        let storage_key = request.key.as_deref().unwrap_or(key);
        self.set(_project, storage_key, value, profile)
    }

    /// Retrieves multiple secrets from OnePassword in a single batch operation.
    ///
    /// This optimized implementation:
    /// 1. Authenticates once (cached)
    /// 2. Lists all items in the vault once to identify which secrets exist
    /// 3. Fetches only the items that exist, using parallel threads
    ///
    /// This significantly improves performance compared to fetching secrets one-by-one,
    /// especially when checking many secrets.
    fn get_batch(
        &self,
        project: &str,
        keys: &[&str],
        profile: &str,
    ) -> Result<HashMap<String, SecretString>> {
        use std::thread;

        if keys.is_empty() {
            return Ok(HashMap::new());
        }
        if self.config.native_references {
            let mut results = HashMap::new();
            for key in keys {
                if let Some(value) = self.read_native_reference(key, profile, None)? {
                    results.insert((*key).to_string(), value);
                }
            }
            return Ok(results);
        }

        let vault = self.get_vault_name(profile);

        // List all items in the vault once
        let args = vec!["item", "list", "--vault", &vault, "--format", "json"];
        let output = self.execute_op_command(&args, None)?;

        #[derive(Deserialize)]
        struct ListItem {
            id: String,
            title: String,
        }

        let items: Vec<ListItem> = serde_json::from_str(&output).unwrap_or_default();

        // Build a map of item titles to IDs for quick lookup
        let item_map: HashMap<String, String> = items
            .into_iter()
            .map(|item| (item.title, item.id))
            .collect();

        // Find which keys exist and need to be fetched
        let keys_to_fetch: Vec<(&str, String)> = keys
            .iter()
            .filter_map(|key| {
                let item_name = self.format_item_name(project, key, profile);
                item_map.get(&item_name).map(|id| (*key, id.clone()))
            })
            .collect();

        // Fetch items in parallel using threads
        let vault_clone = vault.clone();
        let op_command = self.op_command.clone();
        let service_token = self.config.service_account_token.clone();
        let account = self.config.account.clone();

        let handles: Vec<_> = keys_to_fetch
            .into_iter()
            .map(|(key, item_id)| {
                let vault = vault_clone.clone();
                let op_cmd = op_command.clone();
                let token = service_token.clone();
                let acct = account.clone();
                let key_owned = key.to_string();

                thread::spawn(move || {
                    let mut cmd = Command::new(&op_cmd);
                    strip_op_session_env(&mut cmd);

                    if let Some(ref t) = token {
                        cmd.env("OP_SERVICE_ACCOUNT_TOKEN", t);
                    }
                    if let Some(ref a) = acct {
                        cmd.arg("--account").arg(a);
                    }

                    cmd.args([
                        "item", "get", &item_id, "--vault", &vault, "--format", "json",
                    ]);

                    match cmd.output() {
                        Ok(output) if output.status.success() => {
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            // Parse the item and extract value
                            if let Ok(item) = serde_json::from_str::<OnePasswordItem>(&stdout) {
                                // Look for "value" field first
                                for field in &item.fields {
                                    if field.label.as_deref() == Some("value")
                                        && let Some(ref v) = field.value
                                    {
                                        return Some((
                                            key_owned,
                                            SecretString::new(v.clone().into()),
                                        ));
                                    }
                                }
                                // Fallback: look for password/concealed field
                                for field in &item.fields {
                                    if (field.field_type == "CONCEALED" || field.id == "password")
                                        && let Some(ref v) = field.value
                                    {
                                        return Some((
                                            key_owned,
                                            SecretString::new(v.clone().into()),
                                        ));
                                    }
                                }
                            }
                            None
                        }
                        _ => None,
                    }
                })
            })
            .collect();

        // Collect results from all threads
        let mut results = HashMap::new();
        for handle in handles {
            if let Ok(Some((key, value))) = handle.join() {
                results.insert(key, value);
            }
        }

        Ok(results)
    }
}

impl Default for OnePasswordProvider {
    /// Creates a OnePasswordProvider with default configuration.
    ///
    /// Uses interactive authentication and the "Private" vault by default.
    fn default() -> Self {
        Self::new(OnePasswordConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn config(s: &str) -> OnePasswordConfig {
        OnePasswordConfig::try_from(&ProviderUrl::new(Url::parse(s).unwrap())).unwrap()
    }

    #[test]
    fn try_from_parses_account_and_vault() {
        let c = config("onepassword://work@Production");
        assert_eq!(c.account.as_deref(), Some("work"));
        assert_eq!(c.default_vault.as_deref(), Some("Production"));
        assert_eq!(c.service_account_token, None);
    }

    #[test]
    fn try_from_parses_vault_only() {
        let c = config("onepassword://Production");
        assert_eq!(c.account, None);
        assert_eq!(c.default_vault.as_deref(), Some("Production"));
    }

    #[test]
    fn try_from_token_scheme_captures_token_from_username() {
        let c = config("onepassword+token://ops_tok@Private");
        assert_eq!(c.service_account_token.as_deref(), Some("ops_tok"));
        assert_eq!(c.default_vault.as_deref(), Some("Private"));
        assert_eq!(c.account, None);
    }

    #[test]
    fn try_from_token_scheme_captures_token_from_password() {
        let c = config("onepassword+token://acct:ops_tok@Private");
        assert_eq!(c.service_account_token.as_deref(), Some("ops_tok"));
    }

    #[test]
    fn try_from_ignores_localhost_host() {
        let c = config("onepassword://localhost");
        assert_eq!(c.default_vault, None);
        assert_eq!(c.account, None);
    }

    // Note: the `"1password"` guard arm in `try_from` is effectively unreachable
    // via ProviderUrl, because `Url::parse` rejects schemes that start with a
    // digit (RFC 3986). It therefore cannot be exercised through a real URL.

    #[test]
    fn try_from_rejects_unknown_scheme() {
        let err =
            OnePasswordConfig::try_from(&ProviderUrl::new(Url::parse("keyring://vault").unwrap()))
                .unwrap_err();
        assert!(err.to_string().contains("Invalid scheme"));
    }

    #[test]
    fn get_vault_name_defaults_to_private() {
        let default = OnePasswordProvider::new(OnePasswordConfig::default());
        assert_eq!(default.get_vault_name("any"), "Private");

        let configured = OnePasswordProvider::new(config("onepassword://Production"));
        assert_eq!(configured.get_vault_name("any"), "Production");
    }

    #[test]
    fn format_item_name_default_and_custom() {
        let default = OnePasswordProvider::new(OnePasswordConfig::default());
        assert_eq!(
            default.format_item_name("proj", "KEY", "prod"),
            "secretspec/proj/prod/KEY"
        );

        let custom = OnePasswordProvider::new(OnePasswordConfig {
            folder_prefix: Some("{project}-{key}".to_string()),
            ..Default::default()
        });
        assert_eq!(custom.format_item_name("proj", "KEY", "prod"), "proj-KEY");
    }

    #[test]
    fn uri_for_account_round_trips() {
        let provider = OnePasswordProvider::new(config("onepassword://work@Production"));
        assert_eq!(provider.uri(), "onepassword://work@Production");
    }

    #[test]
    fn uri_for_token_does_not_leak_secret() {
        let provider =
            OnePasswordProvider::new(config("onepassword+token://ops_secret_tok@Private"));
        let uri = provider.uri();
        assert_eq!(uri, "onepassword+token://Private");
        assert!(!uri.contains("ops_secret_tok"));

#[cfg(all(test, unix))]
mod dependency_env_tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn write_op_stub(script: &std::path::Path, log: &std::path::Path) {
        let script_body = format!(
            r#"#!/bin/sh
printf '%s\n' "$OP_SERVICE_ACCOUNT_TOKEN" >> '{}'
printf '{{"fields":[{{"id":"value","type":"CONCEALED","label":"value","value":"%s"}}]}}\n' "$OP_SERVICE_ACCOUNT_TOKEN"
"#,
            log.display()
        );
        fs::write(script, script_body).unwrap();
        let mut permissions = fs::metadata(script).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(script, permissions).unwrap();
    }

    #[test]
    fn dependency_token_is_command_scoped_for_every_op_invocation() {
        let temp = tempfile::TempDir::new().unwrap();
        let script = temp.path().join("op-stub");
        let log = temp.path().join("calls.log");
        write_op_stub(&script, &log);

        let mut provider = OnePasswordProvider::new(OnePasswordConfig {
            service_account_token: None,
            default_vault: Some("Development".into()),
            ..OnePasswordConfig::default()
        });
        provider.op_command = script.display().to_string();
        provider
            .configure_dependency_secrets(&[
                ("IGNORED".into(), SecretString::new("ignored".into())),
                (
                    "OP_SERVICE_ACCOUNT_TOKEN".into(),
                    SecretString::new("dependency-token".into()),
                ),
            ])
            .unwrap();

        let first = provider
            .get("project", "API_KEY", "default")
            .unwrap()
            .unwrap();
        let second = provider
            .get("project", "API_KEY", "default")
            .unwrap()
            .unwrap();

        assert_eq!(first.expose_secret(), "dependency-token");
        assert_eq!(second.expose_secret(), "dependency-token");
        assert_eq!(
            fs::read_to_string(log).unwrap(),
            "dependency-token\ndependency-token\n"
        );
    }

    #[test]
    fn explicit_uri_token_takes_precedence_over_dependency_token() {
        let temp = tempfile::TempDir::new().unwrap();
        let script = temp.path().join("op-stub");
        let log = temp.path().join("calls.log");
        write_op_stub(&script, &log);

        let mut provider = OnePasswordProvider::new(OnePasswordConfig {
            service_account_token: Some("uri-token".into()),
            default_vault: Some("Development".into()),
            ..OnePasswordConfig::default()
        });
        provider.op_command = script.display().to_string();
        provider
            .configure_dependency_secrets(&[(
                "OP_SERVICE_ACCOUNT_TOKEN".into(),
                SecretString::new("dependency-token".into()),
            )])
            .unwrap();

        let value = provider
            .get("project", "API_KEY", "default")
            .unwrap()
            .unwrap();

        assert_eq!(value.expose_secret(), "uri-token");
        assert_eq!(fs::read_to_string(log).unwrap(), "uri-token\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::fs;

    #[cfg(unix)]
    fn write_fake_op(temp_dir: &tempfile::TempDir, log: &std::path::Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let script = temp_dir.path().join("op");
        fs::write(
            &script,
            format!(
                r#"#!/usr/bin/env sh
printf '%s\n' "$*" >> '{0}'
case "$1 $2" in
  read*)
    case "$2" in
      op://Development/dotfiles/forges/GITHUB_TOKEN)
        printf '%s\n' 'native-github-token'
        ;;
      op://Development/dotfiles/GITHUB_TOKEN)
        printf '%s\n' 'native-root-github-token'
        ;;
      op://Development/dotfiles/error/GITHUB_TOKEN)
        printf '%s\n' 'permission denied' >&2
        exit 1
        ;;
      *)
        printf '%s\n' 'not found' >&2
        exit 1
        ;;
    esac
    ;;
  "item edit")
    printf '%s\n' 'edited'
    ;;
  "item create")
    cat >> '{0}'
    printf '%s\n' 'created'
    ;;
  "item get")
    case "$3" in
      *STORED_ITEM*)
        printf '%s\n' '{{"fields":[{{"id":"value","type":"STRING","label":"value","value":"from-stored-item"}}]}}'
        ;;
      dotfiles)
        printf '%s\n' '{{"fields":[{{"id":"github","type":"CONCEALED","label":"GITHUB_TOKEN","section":{{"label":"forges"}},"value":"from-dotfiles-item"}}]}}'
        ;;
      *)
        printf '%s\n' "isn't an item" >&2
        exit 1
        ;;
    esac
    ;;
  *)
    printf '%s\n' '[]'
    ;;
esac
"#,
                log.display()
            ),
        )
        .expect("write fake op script");
        let mut permissions = fs::metadata(&script)
            .expect("stat fake op script")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).expect("make fake op executable");
        script
    }

    fn init_test_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(std::io::sink)
            .try_init();
    }

    #[test]
    #[cfg(unix)]
    fn onepassword_get_with_request_uses_key_hint_when_path_is_absent_or_empty() {
        init_test_tracing();
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let log = temp_dir.path().join("calls.log");
        let op = write_fake_op(&temp_dir, &log);
        let mut provider = OnePasswordProvider::new(OnePasswordConfig::default());
        provider.op_command = op.display().to_string();

        let no_path_request = SecretRequest {
            path: None,
            key: Some("STORED_ITEM".to_string()),
        };
        let empty_path_request = SecretRequest {
            path: Some(Vec::new()),
            key: Some("STORED_ITEM".to_string()),
        };

        let no_path_value = provider
            .get_with_request("proj", "SECRET_NAME", "default", &no_path_request)
            .expect("read with key hint and no path")
            .expect("value from fake op");
        let empty_path_value = provider
            .get_with_request("proj", "SECRET_NAME", "default", &empty_path_request)
            .expect("read with key hint and empty path")
            .expect("value from fake op");

        assert_eq!(no_path_value.expose_secret(), "from-stored-item");
        assert_eq!(empty_path_value.expose_secret(), "from-stored-item");

        let calls = fs::read_to_string(log).expect("read fake op call log");
        assert!(
            calls.lines().all(|line| line.contains("STORED_ITEM")),
            "expected OnePassword item lookups to use request.key, not the SecretSpec name\n{calls}"
        );
        assert!(
            !calls.contains("SECRET_NAME"),
            "request.key should replace the SecretSpec variable name for item lookup\n{calls}"
        );

        let missing_value = provider
            .get("proj", "MISSING_ITEM", "default")
            .expect("missing item should not be a hard error");
        assert!(missing_value.is_none());
    }

    #[test]
    fn onepassword_uri_path_becomes_provider_relative_item_root() {
        let provider_url =
            ProviderUrl::new(url::Url::parse("onepassword+token://Development/dotfiles").unwrap());
        let config = OnePasswordConfig::try_from(&provider_url).unwrap();

        assert_eq!(config.default_vault.as_deref(), Some("Development"));
        assert_eq!(config.folder_prefix.as_deref(), Some("dotfiles/{key}"));
        assert_eq!(config.service_account_token, None);

        let provider_url = ProviderUrl::new(
            url::Url::parse("onepassword://Development/secretspec/{project}/{profile}/{key}")
                .unwrap(),
        );
        let config = OnePasswordConfig::try_from(&provider_url).unwrap();
        assert_eq!(
            config.folder_prefix.as_deref(),
            Some("secretspec/{project}/{profile}/{key}")
        );
    }

    #[test]
    fn op_uri_path_becomes_native_reference_base_path() {
        let provider_url =
            ProviderUrl::new(url::Url::parse("op+token://Development/dotfiles").unwrap());
        let config = OnePasswordConfig::try_from(&provider_url).unwrap();
        let provider = OnePasswordProvider::new(config.clone());

        assert!(config.native_references);
        assert_eq!(config.default_vault.as_deref(), Some("Development"));
        assert_eq!(config.reference_base_path, vec!["dotfiles"]);
        assert_eq!(config.folder_prefix, None);
        assert_eq!(provider.uri(), "op://Development/dotfiles");

        let op_token_provider = OnePasswordProvider::new(OnePasswordConfig {
            default_vault: Some("Development".to_string()),
            service_account_token: Some("token".to_string()),
            native_references: true,
            reference_base_path: vec!["dotfiles".to_string()],
            ..OnePasswordConfig::default()
        });
        assert_eq!(op_token_provider.uri(), "op+token://Development/dotfiles");

        let legacy_token_provider = OnePasswordProvider::new(OnePasswordConfig {
            default_vault: Some("Development".to_string()),
            service_account_token: Some("token".to_string()),
            ..OnePasswordConfig::default()
        });
        assert_eq!(legacy_token_provider.uri(), "onepassword+token://Development");

        let legacy_url =
            ProviderUrl::new(url::Url::parse("onepassword://Development/dotfiles").unwrap());
        let legacy_config = OnePasswordConfig::try_from(&legacy_url).unwrap();
        assert!(!legacy_config.native_references);
        assert_eq!(
            legacy_config.folder_prefix.as_deref(),
            Some("dotfiles/{key}")
        );
        assert!(legacy_config.reference_base_path.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn op_command_auth_failure_returns_helpful_error() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let op = temp_dir.path().join("op-auth-fails");
        fs::write(
            &op,
            "#!/usr/bin/env sh\nprintf '%s\\n' 'not currently signed in' >&2\nexit 1\n",
        )
        .expect("write fake op");
        let mut permissions = fs::metadata(&op).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&op, permissions).expect("chmod fake op");

        let mut provider = OnePasswordProvider::new(OnePasswordConfig::default());
        provider.op_command = op.display().to_string();

        let err = provider
            .execute_op_command(&["item", "list"], None)
            .expect_err("auth failures should be rewritten");
        assert!(err.to_string().contains("OnePassword authentication required"), "{err}");
    }

    #[test]
    #[cfg(unix)]
    fn op_get_without_request_reads_native_reference_from_uri_base() {
        init_test_tracing();
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let log = temp_dir.path().join("calls.log");
        let op = write_fake_op(&temp_dir, &log);
        let mut provider = OnePasswordProvider::new(OnePasswordConfig {
            default_vault: Some("Development".to_string()),
            native_references: true,
            reference_base_path: vec!["dotfiles".to_string()],
            ..OnePasswordConfig::default()
        });
        provider.op_command = op.display().to_string();

        let value = provider
            .get("dotfiles", "GITHUB_TOKEN", "default")
            .expect("read native reference")
            .expect("value from fake op");
        assert_eq!(value.expose_secret(), "native-root-github-token");

        provider
            .set(
                "dotfiles",
                "GITHUB_TOKEN",
                &SecretString::new("new-token".into()),
                "default",
            )
            .expect("edit native reference without request");

        let batch = provider
            .get_batch("dotfiles", &["GITHUB_TOKEN", "MISSING"], "default")
            .expect("batch native reads");
        assert_eq!(batch["GITHUB_TOKEN"].expose_secret(), "native-root-github-token");
        assert!(!batch.contains_key("MISSING"));

        let calls = fs::read_to_string(log).expect("read fake op call log");
        assert!(calls.contains("read op://Development/dotfiles/GITHUB_TOKEN"));
        assert!(calls.contains("item edit dotfiles --vault Development GITHUB_TOKEN[concealed]=new-token"));
    }

    #[test]
    #[cfg(unix)]
    fn op_get_without_item_path_returns_none_and_set_errors() {
        let mut provider = OnePasswordProvider::new(OnePasswordConfig {
            default_vault: Some("Development".to_string()),
            native_references: true,
            ..OnePasswordConfig::default()
        });
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let log = temp_dir.path().join("calls.log");
        let op = write_fake_op(&temp_dir, &log);
        provider.op_command = op.display().to_string();

        let value = provider
            .get("dotfiles", "GITHUB_TOKEN", "default")
            .expect("short native reference should not hard fail");
        assert!(value.is_none());

        let err = provider
            .native_item_and_assignment(
                "GITHUB_TOKEN",
                &SecretString::new("new-token".into()),
                None,
            )
            .expect_err("native set needs an item path");
        assert!(err.to_string().contains("requires an item path"));
    }

    #[test]
    #[cfg(unix)]
    fn op_get_with_request_propagates_non_missing_errors() {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let log = temp_dir.path().join("calls.log");
        let op = write_fake_op(&temp_dir, &log);
        let mut provider = OnePasswordProvider::new(OnePasswordConfig {
            default_vault: Some("Development".to_string()),
            native_references: true,
            reference_base_path: vec!["dotfiles".to_string()],
            ..OnePasswordConfig::default()
        });
        provider.op_command = op.display().to_string();

        let request = SecretRequest {
            path: Some(vec!["error".to_string()]),
            key: None,
        };
        let err = provider
            .get_with_request("dotfiles", "GITHUB_TOKEN", "default", &request)
            .expect_err("permission errors should propagate");
        assert!(err.to_string().contains("permission denied"));
    }

    #[test]
    #[cfg(unix)]
    fn onepassword_set_with_request_uses_key_hint_for_legacy_storage() {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let log = temp_dir.path().join("calls.log");
        let op = write_fake_op(&temp_dir, &log);
        let mut provider = OnePasswordProvider::new(OnePasswordConfig {
            default_vault: Some("Development".to_string()),
            ..OnePasswordConfig::default()
        });
        provider.op_command = op.display().to_string();

        let request = SecretRequest {
            path: None,
            key: Some("STORED_ITEM".to_string()),
        };
        provider
            .set_with_request(
                "dotfiles",
                "SECRET_NAME",
                &SecretString::new("new-token".into()),
                "default",
                &request,
            )
            .expect("legacy set with key hint");

        let calls = fs::read_to_string(log).expect("read fake op call log");
        assert!(calls.contains("STORED_ITEM"));
        assert!(!calls.contains("SECRET_NAME"));

        let batch = provider
            .get_batch("dotfiles", &["STORED_ITEM"], "default")
            .expect("legacy get_batch should still run through item listing");
        assert!(batch.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn op_set_with_request_uses_field_without_section_when_path_is_item_only() {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let log = temp_dir.path().join("calls.log");
        let op = write_fake_op(&temp_dir, &log);
        let mut provider = OnePasswordProvider::new(OnePasswordConfig {
            default_vault: Some("Development".to_string()),
            native_references: true,
            ..OnePasswordConfig::default()
        });
        provider.op_command = op.display().to_string();

        let request = SecretRequest {
            path: Some(vec!["dotfiles".to_string()]),
            key: None,
        };
        provider
            .set_with_request(
                "dotfiles",
                "GITHUB_TOKEN",
                &SecretString::new("new-token".into()),
                "default",
                &request,
            )
            .expect("edit native field without section");

        let calls = fs::read_to_string(log).expect("read fake op call log");
        assert!(calls.contains("item edit dotfiles --vault Development GITHUB_TOKEN[concealed]=new-token"));
    }

    #[test]
    #[cfg(unix)]
    fn op_get_with_request_reads_native_reference() {
        init_test_tracing();
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let log = temp_dir.path().join("calls.log");
        let op = write_fake_op(&temp_dir, &log);
        let mut provider = OnePasswordProvider::new(OnePasswordConfig {
            default_vault: Some("Development".to_string()),
            native_references: true,
            reference_base_path: vec!["dotfiles".to_string()],
            ..OnePasswordConfig::default()
        });
        provider.op_command = op.display().to_string();

        let request = SecretRequest {
            path: Some(vec!["forges".to_string()]),
            key: None,
        };
        let value = provider
            .get_with_request("dotfiles", "GITHUB_TOKEN", "default", &request)
            .expect("read native reference")
            .expect("value from fake op");

        assert_eq!(value.expose_secret(), "native-github-token");
        let calls = fs::read_to_string(log).expect("read fake op call log");
        assert!(
            calls.contains("read op://Development/dotfiles/forges/GITHUB_TOKEN"),
            "expected native op read reference\n{calls}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn op_set_with_request_edits_existing_native_reference() {
        init_test_tracing();
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let log = temp_dir.path().join("calls.log");
        let op = write_fake_op(&temp_dir, &log);
        let mut provider = OnePasswordProvider::new(OnePasswordConfig {
            default_vault: Some("Development".to_string()),
            native_references: true,
            reference_base_path: vec!["dotfiles".to_string()],
            ..OnePasswordConfig::default()
        });
        provider.op_command = op.display().to_string();

        let request = SecretRequest {
            path: Some(vec!["forges".to_string()]),
            key: None,
        };
        provider
            .set_with_request(
                "dotfiles",
                "GITHUB_TOKEN",
                &SecretString::new("new-token".into()),
                "default",
                &request,
            )
            .expect("edit existing native reference");

        let calls = fs::read_to_string(log).expect("read fake op call log");
        assert!(
            calls.contains("read op://Development/dotfiles/forges/GITHUB_TOKEN"),
            "expected existence check before editing\n{calls}"
        );
        assert!(
            calls.contains(
                "item edit dotfiles --vault Development forges.GITHUB_TOKEN[concealed]=new-token"
            ),
            "expected native item edit for existing field\n{calls}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn op_set_with_request_rejects_missing_native_reference() {
        init_test_tracing();
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let log = temp_dir.path().join("calls.log");
        let op = write_fake_op(&temp_dir, &log);
        let mut provider = OnePasswordProvider::new(OnePasswordConfig {
            default_vault: Some("Development".to_string()),
            native_references: true,
            reference_base_path: vec!["dotfiles".to_string()],
            ..OnePasswordConfig::default()
        });
        provider.op_command = op.display().to_string();

        let request = SecretRequest {
            path: Some(vec!["missing".to_string()]),
            key: None,
        };
        let err = provider
            .set_with_request(
                "dotfiles",
                "GITHUB_TOKEN",
                &SecretString::new("new-token".into()),
                "default",
                &request,
            )
            .expect_err("missing native reference should not be created");

        assert!(err.to_string().contains("does not exist"));
        let calls = fs::read_to_string(log).expect("read fake op call log");
        assert!(
            !calls.contains("item edit"),
            "missing native references should not be created or edited\n{calls}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn onepassword_get_with_request_uses_path_item_and_section() {
        init_test_tracing();
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let log = temp_dir.path().join("calls.log");
        let op = write_fake_op(&temp_dir, &log);
        let mut provider = OnePasswordProvider::new(OnePasswordConfig {
            default_vault: Some("Development".to_string()),
            ..OnePasswordConfig::default()
        });
        provider.op_command = op.display().to_string();

        let request = SecretRequest {
            path: Some(vec!["dotfiles".to_string(), "forges".to_string()]),
            key: None,
        };
        let value = provider
            .get_with_request("dotfiles", "GITHUB_TOKEN", "default", &request)
            .expect("read provider-relative field")
            .expect("value from fake op");

        assert_eq!(value.expose_secret(), "from-dotfiles-item");
        let calls = fs::read_to_string(log).expect("read fake op call log");
        assert!(
            calls.contains("item get dotfiles --vault Development"),
            "expected path[0] to select the shared 1Password item\n{calls}"
        );

        let missing_request = SecretRequest {
            path: Some(vec!["dotfiles".to_string(), "packages".to_string()]),
            key: Some("CARGO_REGISTRY_TOKEN".to_string()),
        };
        let missing_value = provider
            .get_with_request(
                "dotfiles",
                "CARGO_REGISTRY_TOKEN",
                "default",
                &missing_request,
            )
            .expect("missing section/field should not be a hard error");
        assert!(missing_value.is_none());

        let missing_item_request = SecretRequest {
            path: Some(vec!["missing-item".to_string(), "forges".to_string()]),
            key: Some("GITHUB_TOKEN".to_string()),
        };
        let missing_item_value = provider
            .get_with_request("dotfiles", "GITHUB_TOKEN", "default", &missing_item_request)
            .expect("missing item should not be a hard error");
        assert!(missing_item_value.is_none());
    }
}
