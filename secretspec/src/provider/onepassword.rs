use crate::provider::{Address, Provider, ProviderUrl};
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

/// The item/field coordinates a native address resolves against 1Password,
/// consumed by the `op read` / `op item edit` command paths. Built from a
/// secret's `ref` table (see [`crate::config::NativeAddress`]); the vault is
/// resolved separately (the address's `vault` key or the store's default).
#[derive(Debug)]
pub struct SecretReference {
    /// The item name or UUID.
    pub item: String,
    /// Optional section the field lives under.
    pub section: Option<String>,
    /// The field label or ID to read and write.
    pub field: String,
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

impl TryFrom<&ProviderUrl> for OnePasswordConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        let scheme = url.scheme();

        match scheme {
            "1password" => {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "Invalid scheme '1password'. Use 'onepassword' instead (e.g., onepassword://vault)".to_string()
                ));
            }
            "onepassword" | "onepassword+token" | "op" => {}
            _ => {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Invalid scheme '{}' for OnePassword provider",
                    scheme
                )));
            }
        }

        let mut config = Self::default();

        // Parse URL components for account@vault format, ignoring dummy localhost
        if let Some(host) = url.host()
            && host != "localhost"
        {
            let username = url.username();

            // Check if we have username (account) information
            if !username.is_empty() {
                // Handle user:token format for service account tokens
                if scheme == "onepassword+token" {
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

        // Item paths (the `op://vault/item/field` form earlier iterations
        // accepted, including via `onepassword://`) are rejected with the
        // exact `ref` table translation, instead of being silently ignored
        // and reading the conventional layout.
        let path = url.path();
        let path = path.trim_matches('/');
        if !path.is_empty() || scheme == "op" {
            let vault = config.default_vault.as_deref().unwrap_or("<vault>");
            let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            let hint = match segments.as_slice() {
                [item, field] => {
                    crate::config::ref_table_hint(Some(vault), item, None, Some(field))
                }
                [item, section, field] => {
                    crate::config::ref_table_hint(Some(vault), item, Some(section), Some(field))
                }
                _ => crate::config::ref_table_hint(Some(vault), "<item>", None, Some("<field>")),
            };
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "1Password items are addressed with a secret's `ref`, not in the provider URI: \
                 use providers = [\"onepassword://{vault}\"] with {hint}"
            )));
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
    - Service account (CI): set OP_SERVICE_ACCOUNT_TOKEN or use the onepassword+token:// scheme\n  \
    - Manual signin: run 'eval $(op signin)' (session expires after 30 minutes of inactivity)";

fn strip_op_session_env(cmd: &mut Command) {
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
/// A secret with native `ref` coordinates instead reads the referenced item
/// field via `op read` and writes it via `op item edit`, ignoring the layout
/// above. See [`SecretReference`].
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
}

crate::register_provider! {
    struct: OnePasswordProvider,
    config: OnePasswordConfig,
    name: "onepassword",
    description: "OnePassword password manager",
    schemes: ["onepassword", "onepassword+token", "op"],
    examples: ["onepassword://vault", "onepassword://work@Production", "onepassword+token://vault"],
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
        Self { config, op_command }
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
        strip_op_session_env(&mut cmd);

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
            if error_msg.contains("not currently signed in")
                || error_msg.contains("no active session")
                || error_msg.contains("could not find session token")
                || error_msg.contains("account is not signed in")
            {
                return Err(SecretSpecError::ProviderOperationFailed(
                    AUTH_REQUIRED_HELP.to_string(),
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
    /// # Returns
    ///
    /// The vault name to use - always returns the configured default_vault or "Private"
    fn get_vault_name(&self) -> String {
        self.config
            .default_vault
            .clone()
            .unwrap_or_else(|| "Private".to_string())
    }

    /// Renders the full `op://` reference string for `op read`.
    ///
    /// Names are rendered decoded (spaces and all): the reference is passed to
    /// `op` as a single process argument, so no URL encoding is involved.
    fn reference_uri(vault: &str, reference: &SecretReference) -> String {
        match &reference.section {
            Some(section) => format!(
                "op://{}/{}/{}/{}",
                vault, reference.item, section, reference.field
            ),
            None => format!("op://{}/{}/{}", vault, reference.item, reference.field),
        }
    }

    /// Reads the pinned reference via `op read` from the given vault.
    ///
    /// Returns `Ok(None)` when the referenced item or field does not exist,
    /// mirroring how the conventional layout reports unprovisioned secrets.
    fn read_reference(
        &self,
        vault: &str,
        reference: &SecretReference,
    ) -> Result<Option<SecretString>> {
        let reference_uri = Self::reference_uri(vault, reference);
        match self.execute_op_command(&["read", "--no-newline", &reference_uri], None) {
            Ok(output) => Ok(Some(SecretString::new(output.into()))),
            Err(SecretSpecError::ProviderOperationFailed(msg))
                if msg.contains("isn't an item") || msg.contains("doesn't have a field") =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Writes a value to the pinned reference via `op item edit` in the given
    /// vault.
    ///
    /// The referenced item must already exist: references point at externally
    /// managed items, so the provider never creates one. `op item edit` adds
    /// the field to the item if it is missing.
    fn set_reference(
        &self,
        vault: &str,
        reference: &SecretReference,
        value: &SecretString,
    ) -> Result<()> {
        let assignment = format!(
            "{}={}",
            Self::assignment_target(reference),
            value.expose_secret()
        );
        let args = vec![
            "item",
            "edit",
            &reference.item,
            "--vault",
            vault,
            &assignment,
        ];
        self.execute_op_command(&args, None)?;
        Ok(())
    }

    /// Builds the internal reference a native address's coordinates describe,
    /// resolving the vault (the address's `vault` overrides the store's
    /// default) and rejecting coordinate combinations 1Password cannot honor.
    /// Without a `field`, the address names a whole item, read like a
    /// convention secret and written through its `value` field.
    ///
    /// Takes coordinates already resolved (and therefore validated) by
    /// [`Provider::resolve_coords`].
    fn native_reference(
        &self,
        native: &crate::config::NativeAddress,
    ) -> Result<(String, Option<SecretReference>)> {
        let vault = native
            .vault
            .clone()
            .unwrap_or_else(|| self.get_vault_name());
        let reference = match &native.field {
            Some(field) => Some(SecretReference {
                item: native.item.clone(),
                section: native.section.clone(),
                field: field.clone(),
            }),
            None => {
                if native.section.is_some() {
                    return Err(SecretSpecError::ProviderOperationFailed(
                        "onepassword references with a `section` also need a `field`".to_string(),
                    ));
                }
                None
            }
        };
        Ok((vault, reference))
    }

    /// Reads a whole item by title (or ID) from a vault and extracts its value:
    /// the field labeled "value" first, then password/concealed fields. Shared
    /// by convention reads and whole-item native addresses.
    ///
    /// If multiple items share the title, falls back to ID-based lookup for
    /// the first match.
    fn read_item(&self, vault: &str, item_name: &str) -> Result<Option<SecretString>> {
        let args = vec![
            "item", "get", item_name, "--vault", vault, "--format", "json",
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
                if let Some(item_id) = self.find_item_id(item_name, vault)? {
                    let args = vec![
                        "item", "get", &item_id, "--vault", vault, "--format", "json",
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

    /// Builds the `[section.]field` left-hand side of an `op item edit`
    /// assignment. Periods are structural in `op`'s assignment syntax and get
    /// backslash-escaped so they stay part of the name.
    fn assignment_target(reference: &SecretReference) -> String {
        let escape = |s: &str| s.replace('.', "\\.");
        match &reference.section {
            Some(section) => format!("{}.{}", escape(section), escape(&reference.field)),
            None => escape(&reference.field),
        }
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
    /// Called by the preflight guard before any provider operations, which
    /// dedupes the probe across instances via [`Provider::auth_scope_key`].
    pub(crate) fn check_auth(&self) -> Result<()> {
        match self.is_authenticated() {
            Ok(true) => Ok(()),
            Ok(false) => Err(SecretSpecError::ProviderOperationFailed(
                AUTH_REQUIRED_HELP.to_string(),
            )),
            Err(e) => Err(e),
        }
    }
}

impl Provider for OnePasswordProvider {
    /// Convention items are titled by the folder-prefix format string,
    /// `secretspec/{project}/{profile}/{key}` by default, in the store's
    /// default vault, and read like whole-item references: the `value` field
    /// first, then password/concealed fields.
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: self.format_item_name(project, key, profile),
            vault: Some(self.get_vault_name()),
            ..Default::default()
        })
    }

    /// `vault` overrides the store's default vault, `section`/`field` address a
    /// component within the item. 1Password items are not versioned.
    fn supported_coords(&self) -> &'static [&'static str] {
        &["field", "vault", "section"]
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    /// Auth state is per account/token (and `op` binary), not per provider
    /// instance, so the preflight probe is shared across instances with the
    /// same identity. Pinned secret references produce one instance per
    /// referenced secret; without this, N references would run N identical
    /// `op vault list` round-trips.
    fn auth_scope_key(&self) -> Option<String> {
        Some(format!(
            "{:?}",
            (
                &self.config.account,
                &self.config.service_account_token,
                &self.op_command
            )
        ))
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

        uri
    }

    /// Retrieves a secret from OnePassword.
    ///
    /// If multiple items exist with the same title, falls back to ID-based
    /// lookup to retrieve the first matching item.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(value))` - The secret value if found
    /// * `Ok(None)` - No secret found at the address
    /// * `Err(_)` - Authentication or retrieval error
    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let coords = self.resolve_coords(addr)?;
        let (vault, reference) = self.native_reference(&coords)?;
        match reference {
            // A field-addressed reference goes through `op read`.
            Some(reference) => self.read_reference(&vault, &reference),
            // A whole-item address (every convention secret, and field-less
            // refs) reads via the value/password field extraction of
            // `op item get`.
            None => self.read_item(&vault, &coords.item),
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
    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        let (project, profile, key) = match addr {
            Address::Native(native) => {
                let coords = self.resolve_coords(addr)?;
                let (vault, reference) = self.native_reference(&coords)?;
                // Writes through a native address go to the existing item in
                // place (`op item edit` adds a missing field but never creates
                // an item): a whole-item address writes its `value` field, the
                // same field convention reads extract first.
                let reference = reference.unwrap_or_else(|| SecretReference {
                    item: native.item.clone(),
                    section: None,
                    field: "value".to_string(),
                });
                return self.set_reference(&vault, &reference, value);
            }
            Address::Convention {
                project,
                profile,
                key,
            } => (project, profile, key),
        };
        let vault = self.get_vault_name();
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
    /// Whole-item addresses (every convention secret, and field-less refs)
    /// are served from one item listing per vault plus parallel `op item get`
    /// calls for the titles that exist. Field-addressed refs go through
    /// `op read` each, concurrently.
    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        if requests.is_empty() {
            return Ok(HashMap::new());
        }

        // Whole-item requests as (request name, item title), grouped by vault.
        let mut whole_items: HashMap<String, Vec<(String, String)>> = HashMap::new();
        let mut field_refs: Vec<(&str, Address<'_>)> = Vec::new();
        for (name, addr) in requests {
            let coords = self.resolve_coords(*addr)?;
            let (vault, reference) = self.native_reference(&coords)?;
            match reference {
                Some(_) => field_refs.push((name, *addr)),
                None => whole_items
                    .entry(vault)
                    .or_default()
                    .push((name.to_string(), coords.item.clone())),
            }
        }

        let mut results = HashMap::new();
        for (vault, items) in whole_items {
            results.extend(self.get_items_batch(&vault, items)?);
        }
        results.extend(super::get_each(self, &field_refs)?);
        Ok(results)
    }
}

impl OnePasswordProvider {
    /// Fetches the given `(request name, item title)` pairs from one vault:
    /// lists the vault once to resolve titles to ids, then fetches the items
    /// that exist in parallel threads and extracts their value/password field.
    fn get_items_batch(
        &self,
        vault: &str,
        items: Vec<(String, String)>,
    ) -> Result<HashMap<String, SecretString>> {
        // List all items in the vault once
        let args = vec!["item", "list", "--vault", vault, "--format", "json"];
        let output = self.execute_op_command(&args, None)?;

        #[derive(Deserialize)]
        struct ListItem {
            id: String,
            title: String,
        }

        let listed: Vec<ListItem> = serde_json::from_str(&output).unwrap_or_default();

        // Build a map of item titles to IDs for quick lookup
        let item_map: HashMap<String, String> = listed
            .into_iter()
            .map(|item| (item.title, item.id))
            .collect();

        // Find which titles exist and need to be fetched
        let to_fetch: Vec<(String, String)> = items
            .into_iter()
            .filter_map(|(name, title)| item_map.get(&title).map(|id| (name, id.clone())))
            .collect();

        // Fetch the items concurrently. Each id came from the listing above, so
        // it is unambiguous: `read_item`'s duplicate-title fallback never fires.
        let fetched: Vec<(String, Result<Option<SecretString>>)> = std::thread::scope(|scope| {
            let handles: Vec<_> = to_fetch
                .into_iter()
                .map(|(name, item_id)| (name, scope.spawn(move || self.read_item(vault, &item_id))))
                .collect();
            handles
                .into_iter()
                .map(|(name, handle)| (name, handle.join().expect("op item get thread panicked")))
                .collect()
        });

        let mut results = HashMap::new();
        for (name, result) in fetched {
            if let Some(value) = result? {
                results.insert(name, value);
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
        assert_eq!(default.get_vault_name(), "Private");

        let configured = OnePasswordProvider::new(config("onepassword://Production"));
        assert_eq!(configured.get_vault_name(), "Production");
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
    }

    fn config_err(s: &str) -> SecretSpecError {
        OnePasswordConfig::try_from(&ProviderUrl::new(Url::parse(s).unwrap())).unwrap_err()
    }

    /// Every URI shape that used to be an instance-level reference now errors
    /// with a pointer at the `ref` table.
    #[test]
    fn item_paths_are_rejected_with_ref_hint() {
        // A full reference gets the exact translation.
        let err = config_err("op://Infra/db/password");
        assert!(
            err.to_string()
                .contains("ref = { vault = \"Infra\", item = \"db\", field = \"password\" }"),
            "{err}"
        );

        // A bare op:// with no path still points at `ref`.
        let err = config_err("op://Infra");
        assert!(
            err.to_string().contains("addressed with a secret's `ref`"),
            "{err}"
        );

        // Odd shapes (single segment, too deep) get the generic pointer.
        let err = config_err("onepassword://vault/Production");
        assert!(
            err.to_string().contains("addressed with a secret's `ref`"),
            "{err}"
        );
        let err = config_err("op://Infra/a/b/c/d");
        assert!(
            err.to_string().contains("addressed with a secret's `ref`"),
            "{err}"
        );
    }

    #[test]
    fn assignment_target_escapes_dots() {
        let reference = SecretReference {
            item: "db".to_string(),
            section: Some("api.keys".to_string()),
            field: "connection.url".to_string(),
        };
        assert_eq!(
            OnePasswordProvider::assignment_target(&reference),
            "api\\.keys.connection\\.url"
        );

        let reference = SecretReference {
            section: None,
            ..reference
        };
        assert_eq!(
            OnePasswordProvider::assignment_target(&reference),
            "connection\\.url"
        );
    }

    #[test]
    fn pasted_reference_hint_preserves_spaces() {
        // Spaces in vault and item names must survive into the translation
        // hint, since users paste references straight from the 1Password app.
        let Err(err) = Box::<dyn Provider>::try_from("op://Prod Vault/My Item/field") else {
            panic!("op:// provider spec must be rejected");
        };
        assert!(
            err.to_string().contains(
                "ref = { vault = \"Prod Vault\", item = \"My Item\", field = \"field\" }"
            ),
            "{err}"
        );
    }

    /// A native address maps its coordinates onto the internal reference: the
    /// `vault` key overrides the store's default vault, `section` and `field`
    /// carry through.
    #[test]
    fn native_address_maps_coordinates_with_vault_override() {
        let provider = OnePasswordProvider::new(config("onepassword://Personal"));
        let addr = crate::config::NativeAddress {
            item: "db".into(),
            field: Some("password".into()),
            section: Some("api".into()),
            vault: Some("Production".into()),
            ..Default::default()
        };
        let (vault, reference) = provider.native_reference(&addr).unwrap();
        assert_eq!(vault, "Production");
        let reference = reference.expect("field-addressed reference");
        assert_eq!(
            OnePasswordProvider::reference_uri(&vault, &reference),
            "op://Production/db/api/password"
        );
    }

    /// Without a `vault` key, the store URI's vault applies.
    #[test]
    fn native_address_vault_defaults_to_store_vault() {
        let provider = OnePasswordProvider::new(config("onepassword://Personal"));
        let addr = crate::config::NativeAddress {
            item: "db".into(),
            field: Some("password".into()),
            ..Default::default()
        };
        let (vault, _) = provider.native_reference(&addr).unwrap();
        assert_eq!(vault, "Personal");
    }

    /// A whole-item address (no `field`) resolves to no internal reference:
    /// reads go through the convention item extraction.
    #[test]
    fn native_address_without_field_names_the_whole_item() {
        let provider = OnePasswordProvider::new(config("onepassword://Personal"));
        let addr = crate::config::NativeAddress {
            item: "My API Item".into(),
            ..Default::default()
        };
        let (_, reference) = provider.native_reference(&addr).unwrap();
        assert!(reference.is_none());
    }

    /// 1Password items are not versioned; the coordinate is rejected.
    #[test]
    fn native_address_rejects_version() {
        let provider = OnePasswordProvider::new(config("onepassword://Personal"));
        let addr = crate::config::NativeAddress {
            item: "db".into(),
            version: Some("3".into()),
            ..Default::default()
        };
        let err = provider.resolve_coords(Address::Native(&addr)).unwrap_err();
        assert!(err.to_string().contains("`version`"), "{err}");
    }

    /// A `section` only makes sense when addressing a `field` within it.
    #[test]
    fn native_address_section_requires_field() {
        let provider = OnePasswordProvider::new(config("onepassword://Personal"));
        let addr = crate::config::NativeAddress {
            item: "db".into(),
            section: Some("api".into()),
            ..Default::default()
        };
        let err = provider.native_reference(&addr).unwrap_err();
        assert!(err.to_string().contains("need a `field`"), "{err}");
    }
}
