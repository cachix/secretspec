use crate::provider::Provider;
use crate::{Result, SecretSpecError};
use once_cell::sync::OnceCell;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use url::Url;

/// Represents a OnePassword item retrieved from the CLI.
///
/// This struct deserializes the JSON output from the `op item get` command
/// and contains an array of fields that hold the actual secret data.
#[derive(Debug, Deserialize)]
struct OnePasswordItem {
    /// Collection of fields within the OnePassword item.
    /// Each field represents a piece of data stored in the item.
    fields: Vec<OnePasswordField>,
}

/// Represents a single field within a OnePassword item.
///
/// Fields can contain various types of data such as passwords, strings,
/// or concealed values. The field's label is used to identify specific
/// data within an item.
#[derive(Debug, Deserialize)]
struct OnePasswordField {
    /// Unique identifier for the field within the item.
    id: String,
    /// The type of field (e.g., "STRING", "CONCEALED", "PASSWORD").
    #[serde(rename = "type")]
    field_type: String,
    /// Optional human-readable label for the field.
    /// Used to identify fields like "value", "password", etc.
    label: Option<String>,
    /// The actual value stored in the field.
    /// May be None for certain field types.
    value: Option<String>,
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
    /// Optional folder prefix format string for organizing secrets in OnePassword.
    ///
    /// Supports placeholders: {project}, {profile}, and {key}.
    /// Defaults to "secretspec/{project}/{profile}/{key}" if not specified.
    pub folder_prefix: Option<String>,
}

impl TryFrom<&Url> for OnePasswordConfig {
    type Error = SecretSpecError;

    fn try_from(url: &Url) -> std::result::Result<Self, Self::Error> {
        let scheme = url.scheme();

        match scheme {
            "1password" => {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "Invalid scheme '1password'. Use 'onepassword' instead (e.g., onepassword://vault/path)".to_string()
                ));
            }
            "onepassword" | "onepassword+token" => {}
            _ => {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Invalid scheme '{}' for OnePassword provider",
                    scheme
                )));
            }
        }

        let mut config = Self::default();

        // Parse URL components for account@vault format, ignoring dummy localhost
        if let Some(host) = url.host_str() {
            if host != "localhost" {
                // Check if we have username (account) information
                if !url.username().is_empty() {
                    // Handle user:token format for service account tokens
                    if scheme == "onepassword+token" {
                        if let Some(password) = url.password() {
                            config.service_account_token = Some(password.to_string());
                        } else {
                            config.service_account_token = Some(url.username().to_string());
                        }
                    } else {
                        config.account = Some(url.username().to_string());
                    }
                    config.default_vault = Some(host.to_string());
                } else {
                    // No username, so the host is the vault
                    config.default_vault = Some(host.to_string());
                }
            }
        }

        Ok(config)
    }
}

impl TryFrom<Url> for OnePasswordConfig {
    type Error = SecretSpecError;

    fn try_from(url: Url) -> std::result::Result<Self, Self::Error> {
        (&url).try_into()
    }
}

impl OnePasswordConfig {}

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

/// Provider implementation for OnePassword password manager.
///
/// This provider integrates with OnePassword CLI (`op`) to store and retrieve
/// secrets. It organizes secrets in a hierarchical structure within OnePassword
/// items using a configurable format string that defaults to: `secretspec/{project}/{profile}/{key}`.
///
/// # Authentication
///
/// The provider supports two authentication methods:
///
/// 1. **Interactive Authentication**: Users run `eval $(op signin)` before using secretspec
/// 2. **Service Account Tokens**: For CI/CD, configure a token in the config
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
/// # Interactive auth
/// eval $(op signin)
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
    /// Cached authentication status to avoid repeated `op whoami` calls.
    auth_verified: OnceCell<bool>,
}

crate::register_provider! {
    struct: OnePasswordProvider,
    config: OnePasswordConfig,
    name: "onepassword",
    description: "OnePassword password manager",
    schemes: ["onepassword", "onepassword+token"],
    examples: ["onepassword://vault", "onepassword://work@Production", "onepassword+token://vault"],
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
            auth_verified: OnceCell::new(),
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

        let mut cmd = Command::new(&self.op_command);

        // Set service account token if provided
        if let Some(token) = &self.config.service_account_token {
            cmd.env("OP_SERVICE_ACCOUNT_TOKEN", token);
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
                        "OnePassword CLI (op) is not installed.\n\nTo install it:\n  - macOS: brew install 1password-cli\n  - Linux: Download from https://1password.com/downloads/command-line/\n  - Windows: Download from https://1password.com/downloads/command-line/\n  - NixOS: nix-env -iA nixpkgs.onepassword\n\nAfter installation, run 'eval $(op signin)' to authenticate.".to_string(),
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
                        "OnePassword CLI (op) is not installed.\n\nTo install it:\n  - macOS: brew install 1password-cli\n  - Linux: Download from https://1password.com/downloads/command-line/\n  - Windows: Download from https://1password.com/downloads/command-line/\n  - NixOS: nix-env -iA nixpkgs.onepassword\n\nAfter installation, run 'eval $(op signin)' to authenticate.".to_string(),
                    ));
                }
                Err(e) => return Err(e.into()),
            }
        };

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            if error_msg.contains("not currently signed in")
                || error_msg.contains("no active session")
                || error_msg.contains("could not find session token")
            {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "OnePassword authentication required. Please run 'eval $(op signin)' first."
                        .to_string(),
                ));
            }
            return Err(SecretSpecError::ProviderOperationFailed(
                error_msg.to_string(),
            ));
        }

        String::from_utf8(output.stdout)
            .map_err(|e| SecretSpecError::ProviderOperationFailed(e.to_string()))
    }

    /// Checks if the user is authenticated with OnePassword (uncached).
    ///
    /// Uses the `op whoami` command to verify authentication status.
    /// This is non-intrusive and doesn't require any permissions.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - User is authenticated
    /// * `Ok(false)` - User is not authenticated
    /// * `Err(_)` - Command execution failed
    fn whoami(&self) -> Result<bool> {
        match self.execute_op_command(&["whoami"], None) {
            Ok(_) => Ok(true),
            Err(SecretSpecError::ProviderOperationFailed(msg))
                if msg.contains("authentication required") || msg.contains("no account found") =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Ensures the user is authenticated, caching the result for subsequent calls.
    ///
    /// This method only calls `op whoami` once per provider instance, significantly
    /// improving performance when checking multiple secrets.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - User is authenticated
    /// * `Err(_)` - User is not authenticated or command failed
    fn ensure_authenticated(&self) -> Result<()> {
        let is_authenticated = self.auth_verified.get_or_try_init(|| self.whoami())?;

        if *is_authenticated {
            Ok(())
        } else {
            Err(SecretSpecError::ProviderOperationFailed(
                "OnePassword authentication required. Please run 'eval $(op signin)' first."
                    .to_string(),
            ))
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

impl Provider for OnePasswordProvider {
    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        // Reconstruct the URI from the config
        // Format: onepassword://[account@]vault or onepassword+token://[token@]vault

        let scheme = if self.config.service_account_token.is_some() {
            "onepassword+token"
        } else {
            "onepassword"
        };

        let mut uri = format!("{}://", scheme);

        // For service account token, the token itself might be in the URI
        // but we don't want to expose the actual token value, just indicate it's configured
        if self.config.service_account_token.is_some() {
            // Just indicate token auth is being used without exposing the token
            if let Some(ref vault) = self.config.default_vault {
                uri.push_str(vault);
            }
        } else {
            // Regular auth: account@vault format
            if let Some(ref account) = self.config.account {
                uri.push_str(account);
                uri.push('@');
            }

            if let Some(ref vault) = self.config.default_vault {
                uri.push_str(vault);
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
        // Check authentication status first (cached)
        self.ensure_authenticated()?;

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
        // Check authentication status first (cached)
        self.ensure_authenticated()?;

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

        // Check authentication status first (cached)
        self.ensure_authenticated()?;

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
                                    if field.label.as_deref() == Some("value") {
                                        if let Some(ref v) = field.value {
                                            return Some((
                                                key_owned,
                                                SecretString::new(v.clone().into()),
                                            ));
                                        }
                                    }
                                }
                                // Fallback: look for password/concealed field
                                for field in &item.fields {
                                    if field.field_type == "CONCEALED" || field.id == "password" {
                                        if let Some(ref v) = field.value {
                                            return Some((
                                                key_owned,
                                                SecretString::new(v.clone().into()),
                                            ));
                                        }
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
