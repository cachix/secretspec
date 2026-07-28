use crate::provider::{Address, Provider, ProviderCredentials, ProviderUrl};
use crate::{Result, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::OnceLock;

/// Bitwarden item type enum for different vault item types
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum BitwardenItemType {
    /// Login item (type 1) - stores usernames, passwords, TOTP, URIs
    Login = 1,
    /// Secure Note item (type 2) - stores notes and custom fields
    SecureNote = 2,
    /// Card item (type 3) - stores credit card information
    Card = 3,
    /// Identity item (type 4) - stores personal identity information
    Identity = 4,
    /// SSH Key item (type 5) - stores SSH private/public keys
    SshKey = 5,
}

impl BitwardenItemType {
    /// Convert from integer to enum
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(BitwardenItemType::Login),
            2 => Some(BitwardenItemType::SecureNote),
            3 => Some(BitwardenItemType::Card),
            4 => Some(BitwardenItemType::Identity),
            5 => Some(BitwardenItemType::SshKey),
            _ => None,
        }
    }

    /// Convert to integer for JSON serialization
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// The field this item type uses when the caller does not name one.
    ///
    /// This is the single default shared by creation, update, and unqualified
    /// reads, and each entry is the field the corresponding `extract_from_*`
    /// method looks at first. Keeping one table is what makes a plain `set`
    /// followed by a plain `get` round-trip: when the write and read defaults
    /// disagree, `set` reports success while `get` keeps returning the old
    /// value, because it is reading a different field than the one written.
    ///
    /// Deliberately not derived from the item or secret name. Reads resolve a
    /// field from the address, `BITWARDEN_DEFAULT_FIELD`, or the provider URI
    /// and never consult the name, so a name-derived write target cannot be
    /// mirrored by a read. Name a field explicitly with `?field=` or
    /// `ref = { item, field }` to address anything other than these.
    pub fn default_field(&self) -> &'static str {
        match self {
            BitwardenItemType::Login => "password",
            // A custom field rather than the note body: this is where creation
            // has always written, and where reads look before the body.
            BitwardenItemType::SecureNote => "value",
            BitwardenItemType::Card => "number",
            BitwardenItemType::Identity => "email",
            BitwardenItemType::SshKey => "private_key",
        }
    }

    /// Parse from string (for environment variables)
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "login" => Some(BitwardenItemType::Login),
            "securenote" | "note" | "secure_note" => Some(BitwardenItemType::SecureNote),
            "card" => Some(BitwardenItemType::Card),
            "identity" => Some(BitwardenItemType::Identity),
            "sshkey" | "ssh_key" | "ssh" => Some(BitwardenItemType::SshKey),
            _ => None,
        }
    }

    /// Get string representation
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            BitwardenItemType::Login => "login",
            BitwardenItemType::SecureNote => "securenote",
            BitwardenItemType::Card => "card",
            BitwardenItemType::Identity => "identity",
            BitwardenItemType::SshKey => "sshkey",
        }
    }
}

/// Bitwarden field type enum for custom fields
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum BitwardenFieldType {
    /// Text field (type 0) - visible text
    Text = 0,
    /// Hidden field (type 1) - masked/password field
    Hidden = 1,
    /// Boolean field (type 2) - checkbox
    Boolean = 2,
    /// Linked field (type 3) - references another item; skipped during read/write
    Linked = 3,
}

impl BitwardenFieldType {
    /// Convert from integer to enum
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(BitwardenFieldType::Text),
            1 => Some(BitwardenFieldType::Hidden),
            2 => Some(BitwardenFieldType::Boolean),
            3 => Some(BitwardenFieldType::Linked),
            _ => None,
        }
    }

    /// Convert to integer for JSON serialization
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Get the appropriate field type for a field name
    pub fn for_field_name(field_name: &str) -> Self {
        let name_lower = field_name.to_lowercase();

        if name_lower.contains("password")
            || name_lower.contains("secret")
            || name_lower.contains("token")
            || name_lower.contains("key")
            || name_lower.contains("value")
            || name_lower.contains("code")
            || name_lower.contains("cvv")
            || name_lower.contains("cvc")
        {
            BitwardenFieldType::Hidden
        } else {
            BitwardenFieldType::Text
        }
    }

    /// Get string representation
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            BitwardenFieldType::Text => "text",
            BitwardenFieldType::Hidden => "hidden",
            BitwardenFieldType::Boolean => "boolean",
            BitwardenFieldType::Linked => "linked",
        }
    }
}

/// Represents a Bitwarden item retrieved from the CLI.
///
/// This struct deserializes the JSON output from the `bw get item` and `bw list items` commands.
/// It supports all Bitwarden item types: Login, Secure Note, Card, Identity, etc.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct BitwardenItem {
    /// Unique identifier for the item.
    id: String,
    /// The name/title of the item.
    name: String,
    /// Type of item (Login, Secure Note, Card, Identity).
    #[serde(rename = "type", deserialize_with = "deserialize_item_type")]
    item_type: BitwardenItemType,
    /// Collection of custom fields within the Bitwarden item.
    fields: Option<Vec<BitwardenField>>,
    /// Notes associated with the item.
    notes: Option<String>,
    /// Login-specific data (present when item_type = Login).
    login: Option<BitwardenLogin>,
    /// Card-specific data (present when item_type = Card).
    card: Option<BitwardenCard>,
    /// Identity-specific data (present when item_type = Identity).
    identity: Option<BitwardenIdentity>,
    /// SSH key-specific data (present when item_type = SshKey).
    #[serde(rename = "sshKey")]
    ssh_key: Option<BitwardenSshKey>,
    /// Object type (always "item").
    object: Option<String>,
    /// Organization ID if this item belongs to an organization.
    #[serde(rename = "organizationId")]
    organization_id: Option<String>,
    /// Array of collection IDs this item belongs to.
    #[serde(rename = "collectionIds")]
    collection_ids: Option<Vec<String>>,
    /// Folder ID this item belongs to.
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
    /// Whether this item is marked as favorite.
    favorite: Option<bool>,
    /// Reprompt setting for this item.
    reprompt: Option<u8>,
    /// Password history for this item.
    #[serde(rename = "passwordHistory")]
    password_history: Option<Vec<serde_json::Value>>,
    /// Creation date timestamp.
    #[serde(rename = "creationDate")]
    creation_date: Option<String>,
    /// Last revision date timestamp.
    #[serde(rename = "revisionDate")]
    revision_date: Option<String>,
    /// Deletion date timestamp (null if not deleted).
    #[serde(rename = "deletedDate")]
    deleted_date: Option<String>,
}

/// Custom deserializer for item type
fn deserialize_item_type<'de, D>(
    deserializer: D,
) -> std::result::Result<BitwardenItemType, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = u8::deserialize(deserializer)?;
    BitwardenItemType::from_u8(value)
        .ok_or_else(|| serde::de::Error::custom(format!("Unknown item type: {}", value)))
}

/// Represents login data within a Bitwarden Login item.
#[derive(Debug, Serialize, Deserialize)]
struct BitwardenLogin {
    /// Username for the login.
    username: Option<String>,
    /// Password for the login.
    password: Option<String>,
    /// TOTP seed/secret for two-factor authentication.
    totp: Option<String>,
    /// Array of URIs associated with this login.
    uris: Option<Vec<BitwardenUri>>,
    /// Password revision date timestamp.
    #[serde(rename = "passwordRevisionDate")]
    password_revision_date: Option<String>,
}

/// Represents a URI within a Bitwarden Login item.
#[derive(Debug, Serialize, Deserialize)]
struct BitwardenUri {
    /// The URI/URL.
    uri: Option<String>,
    /// Match type for the URI.
    #[serde(rename = "match")]
    match_type: Option<u8>,
}

/// Represents card data within a Bitwarden Card item.
#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct BitwardenCard {
    /// Cardholder name.
    #[serde(rename = "cardholderName")]
    cardholder_name: Option<String>,
    /// Card number.
    number: Option<String>,
    /// Brand of the card (Visa, Mastercard, etc.).
    brand: Option<String>,
    /// Expiration month.
    #[serde(rename = "expMonth")]
    exp_month: Option<String>,
    /// Expiration year.
    #[serde(rename = "expYear")]
    exp_year: Option<String>,
    /// Security code (CVV).
    code: Option<String>,
}

/// Represents identity data within a Bitwarden Identity item.
#[derive(Debug, Serialize, Deserialize)]
struct BitwardenIdentity {
    /// Title (Mr., Ms., etc.).
    title: Option<String>,
    /// First name.
    #[serde(rename = "firstName")]
    first_name: Option<String>,
    /// Middle name.
    #[serde(rename = "middleName")]
    middle_name: Option<String>,
    /// Last name.
    #[serde(rename = "lastName")]
    last_name: Option<String>,
    /// Username.
    username: Option<String>,
    /// Company.
    company: Option<String>,
    /// Email address.
    email: Option<String>,
    /// Phone number.
    phone: Option<String>,
}

/// Represents SSH key data within a Bitwarden SSH Key item.
#[derive(Debug, Serialize, Deserialize)]
struct BitwardenSshKey {
    /// Private SSH key.
    #[serde(rename = "privateKey")]
    private_key: Option<String>,
    /// Public SSH key.
    #[serde(rename = "publicKey")]
    public_key: Option<String>,
    /// Key fingerprint.
    #[serde(rename = "keyFingerprint")]
    key_fingerprint: Option<String>,
}

/// Represents a single field within a Bitwarden item.
///
/// Fields can contain various types of data such as text, hidden values,
/// or boolean values. The field's name is used to identify specific
/// data within an item.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct BitwardenField {
    /// The name/label of the field.
    name: Option<String>,
    /// The value stored in the field.
    value: Option<String>,
    /// The type of field (Text, Hidden, Boolean).
    #[serde(rename = "type", deserialize_with = "deserialize_field_type")]
    field_type: BitwardenFieldType,
    /// Linked field ID (null if not linked).  Accepts both string and integer
    /// forms since the bw CLI may return either.
    #[serde(rename = "linkedId", default)]
    linked_id: Option<serde_json::Value>,
}

/// Custom deserializer for field type
fn deserialize_field_type<'de, D>(
    deserializer: D,
) -> std::result::Result<BitwardenFieldType, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = u8::deserialize(deserializer)?;
    BitwardenFieldType::from_u8(value)
        .ok_or_else(|| serde::de::Error::custom(format!("Unknown field type: {}", value)))
}

/// Configuration for the Bitwarden Password Manager provider.
///
/// This struct contains all the necessary configuration options for
/// interacting with Bitwarden Password Manager.
/// It supports various authentication methods and organizational contexts.
///
/// # Examples
///
/// ```ignore
/// # use secretspec::provider::bw::BitwardenConfig;
/// // Personal vault
/// let config = BitwardenConfig::default();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitwardenConfig {
    /// Optional organization ID for organization vaults.
    ///
    /// When set, secrets are stored in the specified organization
    /// rather than the personal vault. Used with the `--organizationid`
    /// flag in CLI commands. Can be overridden by BITWARDEN_ORGANIZATION environment variable.
    pub organization_id: Option<String>,
    /// Optional collection ID for organizing secrets within an organization.
    ///
    /// When set along with organization_id, secrets are stored in
    /// the specified collection. Used for team-based secret organization.
    /// Can be overridden by BITWARDEN_COLLECTION environment variable.
    pub collection_id: Option<String>,
    /// Server URL for self-hosted Bitwarden instances.
    ///
    /// When set, the CLI will be configured to use the specified server
    /// instead of the default bitwarden.com. Should include the full URL.
    pub server: Option<String>,
    /// Optional folder name prefix for organizing secrets in Bitwarden.
    ///
    /// Supports placeholders: {project} and {profile}.
    /// Defaults to "secretspec/{project}/{profile}" if not specified.
    pub folder_prefix: Option<String>,

    // Flexible item creation fields
    /// Default item type for creating new items.
    /// Can be overridden by BITWARDEN_DEFAULT_TYPE environment variable.
    pub default_item_type: Option<BitwardenItemType>,
    /// Default field name for storing values.
    /// Can be overridden by BITWARDEN_DEFAULT_FIELD environment variable.
    pub default_field: Option<String>,
}

impl Default for BitwardenConfig {
    fn default() -> Self {
        Self {
            organization_id: None,
            collection_id: None,
            server: None,
            folder_prefix: None,
            default_item_type: Some(BitwardenItemType::Login), // Login by default
            default_field: None,
        }
    }
}

impl TryFrom<&ProviderUrl> for BitwardenConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        let scheme = url.scheme();

        if scheme != "bw" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for Bitwarden provider. Use 'bw://' for Password Manager",
                scheme
            )));
        }

        let mut config = BitwardenConfig::default();

        // Parse Password Manager configuration
        if let Some(host) = url.host()
            && host != "localhost"
        {
            // Check if we have username (organization) information
            if !url.username().is_empty() {
                // Handle org@collection format
                config.organization_id = Some(url.username());
                config.collection_id = Some(host);
            } else {
                // Just collection ID
                config.collection_id = Some(host);
            }
        }

        // Parse query parameters
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "org" | "organization" => config.organization_id = Some(value.into_owned()),
                "collection" => config.collection_id = Some(value.into_owned()),
                "server" => config.server = Some(value.into_owned()),
                "folder" => config.folder_prefix = Some(value.into_owned()),
                "type" => {
                    if let Some(item_type) = BitwardenItemType::from_str(&value) {
                        config.default_item_type = Some(item_type);
                    }
                }
                "field" => config.default_field = Some(value.into_owned()),
                _ => {} // Ignore unknown parameters
            }
        }

        Ok(config)
    }
}

/// Provider implementation for Bitwarden password manager.
///
/// This provider integrates with Bitwarden CLI (`bw`) to store and retrieve
/// secrets. It organizes secrets in a hierarchical structure within Bitwarden
/// items using a configurable format string that defaults to: `secretspec/{project}/{profile}`.
///
/// # Authentication
///
/// The provider requires users to be logged in and unlocked via the Bitwarden CLI:
/// 1. Self-hosted only: `bw config server <url>` (must run while logged out)
/// 2. Login: `bw login` (interactive or with API key)
/// 3. Unlock: `bw unlock` (generates session key)
/// 4. Export session: `export BW_SESSION="session-key"`
///
/// # Storage Structure
///
/// Secrets are stored as Secure Note items in Bitwarden with:
/// - Name: formatted according to folder_prefix configuration
/// - Type: Secure Note (type 2)
/// - Fields: project, profile, key, value
/// - Notes: metadata about the secret
///
/// # Example Usage
///
/// ```ignore
/// # Personal vault
/// secretspec set MY_SECRET --provider bw://
///
/// # Organization collection
/// secretspec get MY_SECRET --provider bw://myorg@collection-id
///
/// # Self-hosted: `?server=` asserts which server the CLI must already be
/// # configured for (via `bw config server`); it does not configure the CLI.
/// secretspec set API_KEY --provider bw://?server=https://vault.company.com
/// ```
pub struct BitwardenProvider {
    /// Configuration for the provider including org/collection settings.
    config: BitwardenConfig,
    /// Credentials supplied by the provider alias.
    credentials: ProviderCredentials,
    /// Memoized outcome of the self-hosted server check, so `bw status` is
    /// spawned at most once per process instead of once per CLI invocation.
    /// The error is carried as a `String` because [`SecretSpecError`] is not
    /// `Clone`; it is re-wrapped on each read.
    server_check: OnceLock<std::result::Result<(), String>>,
}

/// Server the `bw` CLI targets when no self-hosted server is configured. `bw
/// status` reports `"serverUrl": null` in that state rather than naming it.
const BITWARDEN_CLOUD_SERVER: &str = "https://vault.bitwarden.com";

/// Extracts `serverUrl` from `bw status` JSON.
///
/// Returns `Ok(None)` when the CLI targets the public cloud, which it reports as
/// `null` (older builds may omit the key entirely).
fn parse_status_server(stdout: &str) -> std::result::Result<Option<String>, String> {
    let status: serde_json::Value = serde_json::from_str(stdout.trim())
        .map_err(|e| format!("could not parse `bw status` output as JSON: {e}"))?;

    match status.get("serverUrl") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s.trim().to_string())),
        Some(other) => Err(format!(
            "unexpected `serverUrl` type in `bw status` output: {other}"
        )),
    }
}

/// Canonicalizes a server address for comparison.
///
/// Only differences that cannot change which server is addressed are erased:
/// surrounding whitespace, a trailing slash, a port that is the scheme default,
/// and the case of the scheme and host. Path case is preserved, since a guard
/// that compares too loosely would wave through a genuinely different server.
fn normalize_server(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');

    match url::Url::parse(trimmed) {
        // `Url::parse` already lowercases the scheme and host for us.
        Ok(url) => {
            let mut out = format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default());
            // `port()` is `None` for the scheme's default port, so `:443` on an
            // https URL collapses into the same form as omitting it.
            if let Some(port) = url.port() {
                out.push_str(&format!(":{port}"));
            }
            out.push_str(url.path().trim_end_matches('/'));
            out
        }
        Err(_) => trimmed.to_ascii_lowercase(),
    }
}

/// Whether two server addresses name the same server.
fn servers_match(expected: &str, current: &str) -> bool {
    normalize_server(expected) == normalize_server(current)
}

crate::register_provider! {
    struct: BitwardenProvider,
    config: BitwardenConfig,
    name: "bw",
    description: "Bitwarden Password Manager",
    schemes: ["bw"],
    examples: [
        "bw://",
        "bw://collection-id",
        "bw://org@collection"
    ],
}

impl BitwardenProvider {
    /// Creates a new BitwardenProvider with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the provider
    pub fn new(config: BitwardenConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
            server_check: OnceLock::new(),
        }
    }

    /// Verifies that the `bw` CLI targets the server this provider expects.
    ///
    /// The CLI takes its server address only from its own configuration file,
    /// written by `bw config server` while logged out. It honours neither an
    /// environment variable nor a per-command flag, so SecretSpec cannot select
    /// a server per invocation and instead fails closed when the CLI points
    /// somewhere else. A no-op unless `?server=` was given.
    ///
    /// The result is memoized: the check runs `bw status` once per process.
    fn ensure_server_configured(&self) -> Result<()> {
        let Some(expected) = self.config.server.as_deref() else {
            return Ok(());
        };

        match self
            .server_check
            .get_or_init(|| self.check_server(expected))
        {
            Ok(()) => Ok(()),
            Err(message) => Err(SecretSpecError::ProviderOperationFailed(message.clone())),
        }
    }

    /// Runs `bw status` and compares its `serverUrl` against `expected`.
    ///
    /// Separate from [`Self::ensure_server_configured`] so the memoization stays
    /// readable; the parsing and comparison it relies on are pure functions that
    /// are unit-tested directly.
    fn check_server(&self, expected: &str) -> std::result::Result<(), String> {
        // `execute_bw_command` calls this method, so invoke the CLI directly to
        // avoid recursing.
        let output = match Command::new("bw")
            .args(["--nointeraction", "status"])
            .output()
        {
            Ok(output) => output,
            // Say nothing about a missing CLI here: `execute_bw_command` reports
            // that with installation instructions, and it runs immediately after.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(format!(
                    "could not run `bw status` to verify the configured server: {e}"
                ));
            }
        };

        if !output.status.success() {
            return Err(format!(
                "`bw status` failed while verifying the configured server ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        let reported = parse_status_server(&String::from_utf8_lossy(&output.stdout))?;
        let current = reported.as_deref().unwrap_or(BITWARDEN_CLOUD_SERVER);

        if servers_match(expected, current) {
            return Ok(());
        }

        // Name the public cloud explicitly; `bw status` only reports it as null,
        // which would otherwise surface as a bare URL the user never configured.
        let current_description = match reported.as_deref() {
            Some(server) => server.to_string(),
            None => format!("the public Bitwarden cloud ({BITWARDEN_CLOUD_SERVER})"),
        };

        Err(format!(
            "The bw CLI is configured for {current_description}, but this provider \
             expects {expected}.\n\n\
             The bw CLI reads its server only from its own configuration, so point \
             it at the expected server before retrying:\n\
             \n  bw logout\
             \n  bw config server {expected}\
             \n  bw login\
             \n  bw unlock\
             \n\nThen export BW_SESSION from the unlock output."
        ))
    }

    /// Executes a Bitwarden Password Manager CLI command with proper error handling.
    ///
    /// This method handles:
    /// - Setting up server configuration for self-hosted instances
    /// - Executing the command
    /// - Parsing error messages for common issues
    /// - Providing helpful error messages for missing CLI
    ///
    /// # Arguments
    ///
    /// * `args` - The command arguments to pass to `bw`
    ///
    /// # Returns
    ///
    /// * `Result<String>` - The command output or an error
    ///
    /// # Errors
    ///
    /// Returns specific errors for:
    /// - Missing Bitwarden CLI installation
    /// - Authentication required (not logged in or unlocked)
    /// - Command execution failures
    fn execute_bw_command(&self, args: &[&str]) -> Result<String> {
        self.ensure_server_configured()?;

        let mut cmd = Command::new("bw");

        // Never allow bw to prompt on stdin; fail fast with a clear error
        // instead (e.g. when the session is missing or expired in CI).
        cmd.arg("--nointeraction");
        cmd.args(args);

        let output = match cmd.output() {
            Ok(output) => output,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "Bitwarden CLI (bw) is not installed.\n\nTo install it:\n  - npm: npm install -g @bitwarden/cli\n  - Homebrew: brew install bitwarden-cli\n  - Chocolatey: choco install bitwarden-cli\n  - Download: https://bitwarden.com/help/cli/\n\nAfter installation, run 'bw login' and 'bw unlock' to authenticate.".to_string(),
                ));
            }
            Err(e) => return Err(e.into()),
        };

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);

            if error_msg.contains("You are not logged in") {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "Bitwarden authentication required. Please run 'bw login' first.".to_string(),
                ));
            }

            if error_msg.contains("Vault is locked") {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "Bitwarden vault is locked. Please run 'bw unlock' and set the BW_SESSION environment variable.".to_string(),
                ));
            }

            return Err(SecretSpecError::ProviderOperationFailed(
                error_msg.to_string(),
            ));
        }

        String::from_utf8(output.stdout)
            .map_err(|e| SecretSpecError::ProviderOperationFailed(e.to_string()))
    }

    /// Checks if the user is authenticated with Bitwarden.
    ///
    /// Uses the `bw status` command to verify authentication status.
    /// This is non-intrusive and provides detailed status information.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - User is authenticated and unlocked
    /// * `Ok(false)` - User is not authenticated or vault is locked
    /// * `Err(_)` - Command execution failed
    fn is_authenticated(&self) -> Result<bool> {
        match self.execute_bw_command(&["status"]) {
            Ok(output) => {
                // Parse the JSON status response
                let status: serde_json::Value = serde_json::from_str(&output)?;
                let status_str = status["status"].as_str().unwrap_or("");
                Ok(status_str == "unlocked")
            }
            Err(SecretSpecError::ProviderOperationFailed(msg))
                if msg.contains("You are not logged in") || msg.contains("Vault is locked") =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Retrieves a secret from Bitwarden Password Manager.
    ///
    /// This method searches the entire vault for items matching the key name,
    /// supporting all item types (Login, Secure Note, Card, Identity) and
    /// extracting values using smart field detection.
    fn get_from_password_manager(
        &self,
        item_name: &str,
        field_hint: Option<&str>,
    ) -> Result<Option<SecretString>> {
        // Check authentication status first
        if !self.is_authenticated()? {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Bitwarden authentication required. Please run 'bw login' and 'bw unlock', then set the BW_SESSION environment variable.".to_string(),
            ));
        }

        // Use Bitwarden's built-in search to find items matching the key
        let mut list_args = vec!["list", "items", "--search", item_name];

        // Add organization filter if configured (from config or environment variable)
        let org_id = std::env::var("BITWARDEN_ORGANIZATION")
            .ok()
            .or_else(|| self.config.organization_id.clone());
        if let Some(org_id) = &org_id {
            list_args.extend_from_slice(&["--organizationid", org_id]);
        }

        // Add collection filter if configured (from config or environment variable)
        let coll_id = std::env::var("BITWARDEN_COLLECTION")
            .ok()
            .or_else(|| self.config.collection_id.clone());
        if let Some(coll_id) = &coll_id {
            list_args.extend_from_slice(&["--collectionid", coll_id]);
        }

        let output = self.execute_bw_command(&list_args)?;
        let items: Vec<BitwardenItem> = serde_json::from_str(&output)?;

        // If we found items, use the first one
        if let Some(item) = items.first() {
            return self.extract_value_from_item(item, field_hint);
        }

        // No matching item found
        Ok(None)
    }

    /// Extracts a value from a Bitwarden item using smart field detection based on item type.
    ///
    /// This method understands different Bitwarden item types and knows where to look
    /// for secret values in each type.
    fn extract_value_from_item(
        &self,
        item: &BitwardenItem,
        field_hint: Option<&str>,
    ) -> Result<Option<SecretString>> {
        // Resolve field: explicit field_hint > env > config > smart default
        let resolved_field = field_hint
            .map(|s| s.to_string())
            .or_else(|| std::env::var("BITWARDEN_DEFAULT_FIELD").ok())
            .or_else(|| self.config.default_field.clone());

        match item.item_type {
            BitwardenItemType::Login => {
                self.extract_from_login_item(item, resolved_field.as_deref())
            }
            BitwardenItemType::SecureNote => {
                self.extract_from_secure_note_item(item, resolved_field.as_deref())
            }
            BitwardenItemType::Card => self.extract_from_card_item(item, resolved_field.as_deref()),
            BitwardenItemType::Identity => {
                self.extract_from_identity_item(item, resolved_field.as_deref())
            }
            BitwardenItemType::SshKey => {
                self.extract_from_ssh_key_item(item, resolved_field.as_deref())
            }
        }
    }

    /// Extracts value from Login item (type 1).
    fn extract_from_login_item(
        &self,
        item: &BitwardenItem,
        resolved_field: Option<&str>,
    ) -> Result<Option<SecretString>> {
        if let Some(login) = &item.login {
            // If specific field requested, try to find it
            if let Some(field_name) = resolved_field {
                match field_name.to_lowercase().as_str() {
                    "password" => {
                        return Ok(login
                            .password
                            .as_ref()
                            .map(|p| SecretString::new(p.clone().into())));
                    }
                    "username" => {
                        return Ok(login
                            .username
                            .as_ref()
                            .map(|u| SecretString::new(u.clone().into())));
                    }
                    "totp" => {
                        return Ok(login
                            .totp
                            .as_ref()
                            .map(|t| SecretString::new(t.clone().into())));
                    }
                    _ => {
                        // Check custom fields for requested field name
                        if let Some(value) = self.extract_from_custom_fields(item, field_name)? {
                            return Ok(Some(SecretString::new(value.into())));
                        } else {
                            return Ok(None);
                        }
                    }
                }
            }

            // Default: prefer password, then username
            if let Some(password) = &login.password {
                return Ok(Some(SecretString::new(password.clone().into())));
            }
            if let Some(username) = &login.username {
                return Ok(Some(SecretString::new(username.clone().into())));
            }
        }

        // Fallback to custom fields
        if let Some(value) = self.extract_from_custom_fields(item, "value")? {
            Ok(Some(SecretString::new(value.into())))
        } else {
            Ok(None)
        }
    }

    /// Extracts value from Secure Note item (type 2).
    fn extract_from_secure_note_item(
        &self,
        item: &BitwardenItem,
        resolved_field: Option<&str>,
    ) -> Result<Option<SecretString>> {
        // If specific field requested, check custom fields first
        if let Some(field_name) = resolved_field
            && let Some(value) = self.extract_from_custom_fields(item, field_name)?
        {
            return Ok(Some(SecretString::new(value.into())));
        }

        // Look for legacy "value" field (backward compatibility)
        if let Some(value) = self.extract_from_custom_fields(item, "value")? {
            return Ok(Some(SecretString::new(value.into())));
        }

        // Fallback: return notes content
        Ok(item
            .notes
            .as_ref()
            .map(|notes| SecretString::new(notes.clone().into())))
    }

    /// Extracts value from Card item (type 3).
    fn extract_from_card_item(
        &self,
        item: &BitwardenItem,
        resolved_field: Option<&str>,
    ) -> Result<Option<SecretString>> {
        if let Some(card) = &item.card {
            // If specific field requested
            if let Some(field_name) = resolved_field {
                match field_name.to_lowercase().as_str() {
                    "number" => {
                        return Ok(card
                            .number
                            .as_ref()
                            .map(|n| SecretString::new(n.clone().into())));
                    }
                    "code" | "cvv" | "cvc" => {
                        return Ok(card
                            .code
                            .as_ref()
                            .map(|c| SecretString::new(c.clone().into())));
                    }
                    "cardholder" | "name" => {
                        return Ok(card
                            .cardholder_name
                            .as_ref()
                            .map(|n| SecretString::new(n.clone().into())));
                    }
                    "brand" => {
                        return Ok(card
                            .brand
                            .as_ref()
                            .map(|b| SecretString::new(b.clone().into())));
                    }
                    "expmonth" | "exp_month" => {
                        return Ok(card
                            .exp_month
                            .as_ref()
                            .map(|m| SecretString::new(m.clone().into())));
                    }
                    "expyear" | "exp_year" => {
                        return Ok(card
                            .exp_year
                            .as_ref()
                            .map(|y| SecretString::new(y.clone().into())));
                    }
                    _ => {
                        if let Some(value) = self.extract_from_custom_fields(item, field_name)? {
                            return Ok(Some(SecretString::new(value.into())));
                        } else {
                            return Ok(None);
                        }
                    }
                }
            }

            // Default: return card number
            if let Some(number) = &card.number {
                return Ok(Some(SecretString::new(number.clone().into())));
            }
        }

        // Fallback to custom fields
        if let Some(value) = self.extract_from_custom_fields(item, "value")? {
            Ok(Some(SecretString::new(value.into())))
        } else {
            Ok(None)
        }
    }

    /// Extracts value from Identity item (type 4).
    fn extract_from_identity_item(
        &self,
        item: &BitwardenItem,
        resolved_field: Option<&str>,
    ) -> Result<Option<SecretString>> {
        if let Some(identity) = &item.identity {
            // If specific field requested
            if let Some(field_name) = resolved_field {
                match field_name.to_lowercase().as_str() {
                    "email" => {
                        return Ok(identity
                            .email
                            .as_ref()
                            .map(|e| SecretString::new(e.clone().into())));
                    }
                    "username" => {
                        return Ok(identity
                            .username
                            .as_ref()
                            .map(|u| SecretString::new(u.clone().into())));
                    }
                    "phone" => {
                        return Ok(identity
                            .phone
                            .as_ref()
                            .map(|p| SecretString::new(p.clone().into())));
                    }
                    "firstname" | "first_name" => {
                        return Ok(identity
                            .first_name
                            .as_ref()
                            .map(|f| SecretString::new(f.clone().into())));
                    }
                    "lastname" | "last_name" => {
                        return Ok(identity
                            .last_name
                            .as_ref()
                            .map(|l| SecretString::new(l.clone().into())));
                    }
                    "company" => {
                        return Ok(identity
                            .company
                            .as_ref()
                            .map(|c| SecretString::new(c.clone().into())));
                    }
                    _ => {
                        if let Some(value) = self.extract_from_custom_fields(item, field_name)? {
                            return Ok(Some(SecretString::new(value.into())));
                        } else {
                            return Ok(None);
                        }
                    }
                }
            }

            // Default: prefer email, then username
            if let Some(email) = &identity.email {
                return Ok(Some(SecretString::new(email.clone().into())));
            }
            if let Some(username) = &identity.username {
                return Ok(Some(SecretString::new(username.clone().into())));
            }
        }

        // Fallback to custom fields
        if let Some(value) = self.extract_from_custom_fields(item, "value")? {
            Ok(Some(SecretString::new(value.into())))
        } else {
            Ok(None)
        }
    }

    /// Extracts value from SSH Key item (type 5).
    fn extract_from_ssh_key_item(
        &self,
        item: &BitwardenItem,
        resolved_field: Option<&str>,
    ) -> Result<Option<SecretString>> {
        if let Some(ssh_key) = &item.ssh_key {
            // If specific field requested
            if let Some(field_name) = resolved_field {
                match field_name.to_lowercase().as_str() {
                    "private_key" | "privatekey" | "private" => {
                        return Ok(ssh_key
                            .private_key
                            .as_ref()
                            .map(|k| SecretString::new(k.clone().into())));
                    }
                    "public_key" | "publickey" | "public" => {
                        return Ok(ssh_key
                            .public_key
                            .as_ref()
                            .map(|k| SecretString::new(k.clone().into())));
                    }
                    "fingerprint" | "key_fingerprint" => {
                        return Ok(ssh_key
                            .key_fingerprint
                            .as_ref()
                            .map(|f| SecretString::new(f.clone().into())));
                    }
                    _ => {
                        if let Some(value) = self.extract_from_custom_fields(item, field_name)? {
                            return Ok(Some(SecretString::new(value.into())));
                        } else {
                            return Ok(None);
                        }
                    }
                }
            }

            // Default: return private key (most common use case for SSH keys)
            if let Some(private_key) = &ssh_key.private_key {
                return Ok(Some(SecretString::new(private_key.clone().into())));
            }
        }

        // Fallback to custom fields
        if let Some(value) = self.extract_from_custom_fields(item, "value")? {
            Ok(Some(SecretString::new(value.into())))
        } else {
            Ok(None)
        }
    }

    /// Extracts value from custom fields in any item type.
    fn extract_from_custom_fields(
        &self,
        item: &BitwardenItem,
        field_name: &str,
    ) -> Result<Option<String>> {
        if let Some(fields) = &item.fields {
            // Exact match first
            for field in fields {
                if let Some(name) = &field.name
                    && name.eq_ignore_ascii_case(field_name)
                {
                    return Ok(field.value.clone());
                }
            }

            // Partial match (contains)
            for field in fields {
                if let Some(name) = &field.name
                    && name.to_lowercase().contains(&field_name.to_lowercase())
                {
                    return Ok(field.value.clone());
                }
            }
        }

        Ok(None)
    }

    /// Sets a secret in Bitwarden Password Manager.
    ///
    /// This method searches the entire vault for existing items and updates them,
    /// or creates new items with flexible type support based on configuration.
    fn set_to_password_manager(
        &self,
        item_name: &str,
        target_field: Option<&str>,
        value: &SecretString,
    ) -> Result<()> {
        // Check authentication status first
        if !self.is_authenticated()? {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Bitwarden authentication required. Please run 'bw login' and 'bw unlock', then set the BW_SESSION environment variable.".to_string(),
            ));
        }

        // First, search for existing items using the same strategy as get()
        let mut list_args = vec!["list", "items"];

        // Add organization filter if configured (from config or environment variable)
        let org_id = std::env::var("BITWARDEN_ORGANIZATION")
            .ok()
            .or_else(|| self.config.organization_id.clone());
        if let Some(org_id) = &org_id {
            list_args.extend_from_slice(&["--organizationid", org_id]);
        }

        // Add collection filter if configured (from config or environment variable)
        let coll_id = std::env::var("BITWARDEN_COLLECTION")
            .ok()
            .or_else(|| self.config.collection_id.clone());
        if let Some(coll_id) = &coll_id {
            list_args.extend_from_slice(&["--collectionid", coll_id]);
        }

        let output = self.execute_bw_command(&list_args)?;
        let items: Vec<BitwardenItem> = serde_json::from_str(&output)?;

        // Search strategies:
        // 1. Exact name match with item_name
        // 2. Items containing the item name in their name

        // Strategy 1: Exact key match
        if let Some(item) = items.iter().find(|item| item.name == item_name) {
            return self.update_existing_item(item, target_field, value.expose_secret());
        }

        // Strategy 2: Contains item_name in name (case-insensitive)
        if let Some(item) = items
            .iter()
            .find(|item| item.name.to_lowercase().contains(&item_name.to_lowercase()))
        {
            return self.update_existing_item(item, target_field, value.expose_secret());
        }

        // No existing item found, create a new one
        self.create_new_item(item_name, target_field, value.expose_secret())
    }

    /// Updates an existing Bitwarden item with a new value.
    ///
    /// This method preserves the item type and structure while updating
    /// the appropriate field based on the item type and configuration.
    fn update_existing_item(
        &self,
        item: &BitwardenItem,
        target_field: Option<&str>,
        value: &str,
    ) -> Result<()> {
        // Which field to update: explicit > env > config > the item type's
        // default. Shared with creation and unqualified reads via
        // `default_field` so that a plain `set` is round-trippable.
        let field = target_field
            .map(|s| s.to_string())
            .or_else(|| std::env::var("BITWARDEN_DEFAULT_FIELD").ok())
            .or_else(|| self.config.default_field.clone())
            .unwrap_or_else(|| item.item_type.default_field().to_string());

        // Get the current item as JSON template
        let mut item_json = self.get_item_as_template(&item.id)?;

        match item.item_type {
            BitwardenItemType::Login => self.update_login_item_json(&mut item_json, &field, value),
            BitwardenItemType::SecureNote => {
                self.update_secure_note_item_json(&mut item_json, &field, value)
            }
            BitwardenItemType::Card => self.update_card_item_json(&mut item_json, &field, value),
            BitwardenItemType::Identity => {
                self.update_identity_item_json(&mut item_json, &field, value)
            }
            BitwardenItemType::SshKey => {
                self.update_ssh_key_item_json(&mut item_json, &field, value)
            }
        }?;

        self.update_item_with_json(&item.id, &item_json)
    }

    /// Updates Login item fields in JSON.
    fn update_login_item_json(
        &self,
        item_json: &mut serde_json::Value,
        field: &str,
        value: &str,
    ) -> Result<()> {
        match field.to_lowercase().as_str() {
            "password" => {
                item_json["login"]["password"] = serde_json::Value::String(value.to_string());
            }
            "username" => {
                item_json["login"]["username"] = serde_json::Value::String(value.to_string());
            }
            "totp" => {
                item_json["login"]["totp"] = serde_json::Value::String(value.to_string());
            }
            _ => {
                // Update custom field
                return self.update_custom_field_in_json(item_json, field, value);
            }
        }
        Ok(())
    }

    /// Updates Secure Note item fields in JSON.
    fn update_secure_note_item_json(
        &self,
        item_json: &mut serde_json::Value,
        field: &str,
        value: &str,
    ) -> Result<()> {
        if field == "notes" {
            item_json["notes"] = serde_json::Value::String(value.to_string());
            Ok(())
        } else {
            // Update custom field
            self.update_custom_field_in_json(item_json, field, value)
        }
    }

    /// Updates Card item fields in JSON.
    fn update_card_item_json(
        &self,
        item_json: &mut serde_json::Value,
        field: &str,
        value: &str,
    ) -> Result<()> {
        match field.to_lowercase().as_str() {
            "number" => {
                item_json["card"]["number"] = serde_json::Value::String(value.to_string());
            }
            "code" | "cvv" | "cvc" => {
                item_json["card"]["code"] = serde_json::Value::String(value.to_string());
            }
            "cardholder" | "name" => {
                item_json["card"]["cardholderName"] = serde_json::Value::String(value.to_string());
            }
            "brand" => {
                item_json["card"]["brand"] = serde_json::Value::String(value.to_string());
            }
            "expmonth" | "exp_month" => {
                item_json["card"]["expMonth"] = serde_json::Value::String(value.to_string());
            }
            "expyear" | "exp_year" => {
                item_json["card"]["expYear"] = serde_json::Value::String(value.to_string());
            }
            _ => {
                // Update custom field
                return self.update_custom_field_in_json(item_json, field, value);
            }
        }
        Ok(())
    }

    /// Updates Identity item fields in JSON.
    fn update_identity_item_json(
        &self,
        item_json: &mut serde_json::Value,
        field: &str,
        value: &str,
    ) -> Result<()> {
        match field.to_lowercase().as_str() {
            "email" => {
                item_json["identity"]["email"] = serde_json::Value::String(value.to_string());
            }
            "username" => {
                item_json["identity"]["username"] = serde_json::Value::String(value.to_string());
            }
            "phone" => {
                item_json["identity"]["phone"] = serde_json::Value::String(value.to_string());
            }
            "firstname" | "first_name" => {
                item_json["identity"]["firstName"] = serde_json::Value::String(value.to_string());
            }
            "lastname" | "last_name" => {
                item_json["identity"]["lastName"] = serde_json::Value::String(value.to_string());
            }
            "company" => {
                item_json["identity"]["company"] = serde_json::Value::String(value.to_string());
            }
            _ => {
                // Update custom field
                return self.update_custom_field_in_json(item_json, field, value);
            }
        }
        Ok(())
    }

    /// Updates an SSH Key item JSON with a new field value.
    fn update_ssh_key_item_json(
        &self,
        item_json: &mut serde_json::Value,
        field: &str,
        value: &str,
    ) -> Result<()> {
        match field.to_lowercase().as_str() {
            "private_key" | "privatekey" | "private" => {
                item_json["sshKey"]["privateKey"] = serde_json::Value::String(value.to_string());
            }
            "public_key" | "publickey" | "public" => {
                item_json["sshKey"]["publicKey"] = serde_json::Value::String(value.to_string());
            }
            "fingerprint" | "key_fingerprint" => {
                item_json["sshKey"]["keyFingerprint"] =
                    serde_json::Value::String(value.to_string());
            }
            _ => {
                // Update custom field
                return self.update_custom_field_in_json(item_json, field, value);
            }
        }
        Ok(())
    }

    /// Gets an item as a JSON template for editing.
    fn get_item_as_template(&self, item_id: &str) -> Result<serde_json::Value> {
        let mut args = vec!["get", "item", item_id];

        let org_id = std::env::var("BITWARDEN_ORGANIZATION")
            .ok()
            .or_else(|| self.config.organization_id.clone());
        if let Some(org_id) = &org_id {
            args.extend_from_slice(&["--organizationid", org_id]);
        }

        let output = self.execute_bw_command(&args)?;
        let item_json: serde_json::Value = serde_json::from_str(&output)?;
        Ok(item_json)
    }

    /// Updates a custom field in the JSON template.
    fn update_custom_field_in_json(
        &self,
        item_json: &mut serde_json::Value,
        field: &str,
        value: &str,
    ) -> Result<()> {
        // Get or create the fields array
        if item_json["fields"].is_null() {
            item_json["fields"] = serde_json::Value::Array(vec![]);
        }

        let fields = item_json["fields"].as_array_mut().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed("Invalid fields array".to_string())
        })?;

        // Look for existing field (case-insensitive, matching the read path)
        for field_obj in fields.iter_mut() {
            if let Some(name) = field_obj["name"].as_str()
                && name.eq_ignore_ascii_case(field)
            {
                field_obj["value"] = serde_json::Value::String(value.to_string());
                return Ok(());
            }
        }

        // Add new field
        let field_type = BitwardenFieldType::for_field_name(field);
        let new_field = serde_json::json!({
            "name": field,
            "value": value,
            "type": field_type.to_u8()
        });
        fields.push(new_field);

        Ok(())
    }

    /// Updates an item using the JSON template.
    fn update_item_with_json(&self, item_id: &str, item_json: &serde_json::Value) -> Result<()> {
        // This path drives the CLI directly rather than through
        // `execute_bw_command`, so the server guard has to be applied here too;
        // it is memoized, so this costs nothing after the first call.
        self.ensure_server_configured()?;

        let item_json_str = serde_json::to_string(item_json)?;

        // Bitwarden CLI expects base64-encoded JSON via stdin
        // TODO: Research if all item types actually need this encoding or if
        // some could use simpler command formats for better performance
        use base64::{Engine as _, engine::general_purpose};
        use std::process::Stdio;
        let encoded_json = general_purpose::STANDARD.encode(&item_json_str);

        let mut cmd = std::process::Command::new("bw");

        let mut args = vec!["--nointeraction", "edit", "item", item_id];
        let org_id = std::env::var("BITWARDEN_ORGANIZATION")
            .ok()
            .or_else(|| self.config.organization_id.clone());
        if let Some(org_id) = &org_id {
            args.extend_from_slice(&["--organizationid", org_id]);
        }

        cmd.args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SecretSpecError::ProviderOperationFailed(
                    "Bitwarden CLI (bw) is not installed.\n\nTo install it:\n  - npm: npm install -g @bitwarden/cli\n  - Homebrew: brew install bitwarden-cli\n  - Chocolatey: choco install bitwarden-cli\n  - Download: https://bitwarden.com/help/cli/".to_string(),
                )
            } else {
                SecretSpecError::ProviderOperationFailed(e.to_string())
            }
        })?;

        // Write base64-encoded JSON to stdin
        use std::io::Write;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(encoded_json.as_bytes()).map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!("Failed to write to stdin: {}", e))
            })?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| SecretSpecError::ProviderOperationFailed(e.to_string()))?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(SecretSpecError::ProviderOperationFailed(
                error_msg.to_string(),
            ));
        }

        Ok(())
    }

    /// Creates a new Bitwarden item with flexible type support.
    fn create_new_item(
        &self,
        item_name: &str,
        target_field: Option<&str>,
        value: &str,
    ) -> Result<()> {
        // Determine item type from config, environment variable, or use default (Login)
        let item_type = std::env::var("BITWARDEN_DEFAULT_TYPE")
            .ok()
            .and_then(|s| BitwardenItemType::from_str(&s))
            .or(self.config.default_item_type)
            .unwrap_or(BitwardenItemType::Login);

        // Which field to write: explicit > env > config > the item type's
        // default. Shared with update and unqualified reads via `default_field`.
        let field = target_field
            .map(|s| s.to_string())
            .or_else(|| std::env::var("BITWARDEN_DEFAULT_FIELD").ok())
            .or_else(|| self.config.default_field.clone())
            .unwrap_or_else(|| item_type.default_field().to_string());

        let template = match item_type {
            BitwardenItemType::Login => self.login_template(item_name, value, &field),
            BitwardenItemType::Card => self.card_template(item_name, value, &field),
            BitwardenItemType::Identity => self.identity_template(item_name, value, &field),
            BitwardenItemType::SecureNote => self.secure_note_template(item_name, value, &field),
            BitwardenItemType::SshKey => self.ssh_key_template(item_name, value, &field),
        };

        self.create_item_from_template(&template)
    }

    /// Builds the creation template for a Login item.
    fn login_template(&self, item_name: &str, value: &str, field: &str) -> serde_json::Value {
        let mut login_data = serde_json::json!({
            "username": null,
            "password": null,
            "totp": null,
            "uris": []
        });

        let mut fields = vec![];

        match field.to_lowercase().as_str() {
            "username" => login_data["username"] = serde_json::Value::String(value.to_string()),
            "totp" => login_data["totp"] = serde_json::Value::String(value.to_string()),
            "password" => login_data["password"] = serde_json::Value::String(value.to_string()),
            _ => {
                // Store unknown fields as custom fields so they can be read back
                let field_type = BitwardenFieldType::for_field_name(field);
                fields.push(serde_json::json!({
                    "name": field,
                    "value": value,
                    "type": field_type.to_u8()
                }));
            }
        }

        serde_json::json!({
            "type": BitwardenItemType::Login.to_u8(),
            "name": item_name,
            "notes": format!("SecretSpec managed secret: {}", item_name),
            "login": login_data,
            "fields": fields,
            "organizationId": std::env::var("BITWARDEN_ORGANIZATION").ok()
                .or_else(|| self.config.organization_id.clone()),
            "collectionIds": std::env::var("BITWARDEN_COLLECTION").ok()
                .or_else(|| self.config.collection_id.clone())
                .map(|id| vec![id])
        })
    }

    /// Builds the creation template for a Card item.
    fn card_template(&self, item_name: &str, value: &str, field: &str) -> serde_json::Value {
        let mut card_data = serde_json::json!({
            "number": null,
            "code": null,
            "cardholderName": null,
            "brand": null,
            "expMonth": null,
            "expYear": null
        });

        let mut fields = vec![];

        match field.to_lowercase().as_str() {
            "code" | "cvv" | "cvc" => {
                card_data["code"] = serde_json::Value::String(value.to_string())
            }
            "cardholder" | "name" => {
                card_data["cardholderName"] = serde_json::Value::String(value.to_string())
            }
            "brand" => card_data["brand"] = serde_json::Value::String(value.to_string()),
            "number" => card_data["number"] = serde_json::Value::String(value.to_string()),
            _ => {
                // Store unknown fields as custom fields so they can be read back
                let field_type = BitwardenFieldType::for_field_name(field);
                fields.push(serde_json::json!({
                    "name": field,
                    "value": value,
                    "type": field_type.to_u8()
                }));
            }
        }

        serde_json::json!({
            "type": BitwardenItemType::Card.to_u8(),
            "name": item_name,
            "notes": format!("SecretSpec managed secret: {}", item_name),
            "card": card_data,
            "fields": fields,
            "organizationId": std::env::var("BITWARDEN_ORGANIZATION").ok()
                .or_else(|| self.config.organization_id.clone()),
            "collectionIds": std::env::var("BITWARDEN_COLLECTION").ok()
                .or_else(|| self.config.collection_id.clone())
                .map(|id| vec![id])
        })
    }

    /// Builds the creation template for an Identity item.
    fn identity_template(&self, item_name: &str, value: &str, field: &str) -> serde_json::Value {
        let mut identity_data = serde_json::json!({
            "title": null,
            "firstName": null,
            "middleName": null,
            "lastName": null,
            "username": null,
            "company": null,
            "email": null,
            "phone": null
        });

        let mut fields = vec![];

        match field.to_lowercase().as_str() {
            "username" => identity_data["username"] = serde_json::Value::String(value.to_string()),
            "phone" => identity_data["phone"] = serde_json::Value::String(value.to_string()),
            "company" => identity_data["company"] = serde_json::Value::String(value.to_string()),
            "email" => identity_data["email"] = serde_json::Value::String(value.to_string()),
            _ => {
                // Store unknown fields as custom fields so they can be read back
                let field_type = BitwardenFieldType::for_field_name(field);
                fields.push(serde_json::json!({
                    "name": field,
                    "value": value,
                    "type": field_type.to_u8()
                }));
            }
        }

        serde_json::json!({
            "type": BitwardenItemType::Identity.to_u8(),
            "name": item_name,
            "notes": format!("SecretSpec managed secret: {}", item_name),
            "identity": identity_data,
            "fields": fields,
            "organizationId": std::env::var("BITWARDEN_ORGANIZATION").ok()
                .or_else(|| self.config.organization_id.clone()),
            "collectionIds": std::env::var("BITWARDEN_COLLECTION").ok()
                .or_else(|| self.config.collection_id.clone())
                .map(|id| vec![id])
        })
    }

    /// Builds the creation template for a Secure Note item.
    fn secure_note_template(&self, item_name: &str, value: &str, field: &str) -> serde_json::Value {
        let mut fields = vec![];

        if field != "notes" {
            // Store in custom field
            let field_type = BitwardenFieldType::for_field_name(field);
            fields.push(serde_json::json!({
                "name": field,
                "value": value,
                "type": field_type.to_u8()
            }));
        }

        serde_json::json!({
            "type": BitwardenItemType::SecureNote.to_u8(),
            "name": item_name,
            "notes": if field == "notes" { value.to_string() } else { format!("SecretSpec managed secret: {}", item_name) },
            "secureNote": {
                "type": 0
            },
            "fields": fields,
            "organizationId": std::env::var("BITWARDEN_ORGANIZATION").ok()
                .or_else(|| self.config.organization_id.clone()),
            "collectionIds": std::env::var("BITWARDEN_COLLECTION").ok()
                .or_else(|| self.config.collection_id.clone())
                .map(|id| vec![id])
        })
    }

    /// Builds the creation template for an SSH Key item.
    fn ssh_key_template(&self, item_name: &str, value: &str, field: &str) -> serde_json::Value {
        let mut ssh_key_data = serde_json::json!({
            "privateKey": null,
            "publicKey": null,
            "keyFingerprint": null
        });

        let mut fields = vec![];

        match field.to_lowercase().as_str() {
            "private_key" | "privatekey" | "private" => {
                ssh_key_data["privateKey"] = serde_json::Value::String(value.to_string())
            }
            "public_key" | "publickey" | "public" => {
                ssh_key_data["publicKey"] = serde_json::Value::String(value.to_string())
            }
            "fingerprint" | "key_fingerprint" => {
                ssh_key_data["keyFingerprint"] = serde_json::Value::String(value.to_string())
            }
            _ => {
                // Store unknown fields as custom fields so they can be read back
                let field_type = BitwardenFieldType::for_field_name(field);
                fields.push(serde_json::json!({
                    "name": field,
                    "value": value,
                    "type": field_type.to_u8()
                }));
            }
        }

        serde_json::json!({
            "type": BitwardenItemType::SshKey.to_u8(),
            "name": item_name,
            "notes": format!("SecretSpec managed secret: {}", item_name),
            "sshKey": ssh_key_data,
            "fields": fields,
            "organizationId": std::env::var("BITWARDEN_ORGANIZATION").ok()
                .or_else(|| self.config.organization_id.clone()),
            "collectionIds": std::env::var("BITWARDEN_COLLECTION").ok()
                .or_else(|| self.config.collection_id.clone())
                .map(|id| vec![id])
        })
    }

    /// Creates an item from a JSON template.
    ///
    /// NOTE: This method currently uses base64-encoded JSON for all item types,
    /// following the documented Bitwarden CLI workflow (template → encode → create).
    /// Future optimization: investigate if simpler creation methods exist for
    /// basic Login/Card/Identity items that don't require complex JSON encoding.
    fn create_item_from_template(&self, template: &serde_json::Value) -> Result<()> {
        // As in `update_item_with_json`: this bypasses `execute_bw_command`, so
        // the memoized server guard is applied here as well.
        self.ensure_server_configured()?;

        let template_json = serde_json::to_string(template)?;

        // Bitwarden CLI expects base64-encoded JSON via stdin
        // TODO: Research if all item types actually need this encoding or if
        // some could use simpler command formats for better performance
        use base64::{Engine as _, engine::general_purpose};
        use std::process::Stdio;
        let encoded_json = general_purpose::STANDARD.encode(&template_json);

        let mut cmd = std::process::Command::new("bw");

        let mut args = vec!["--nointeraction", "create", "item"];
        let org_id = std::env::var("BITWARDEN_ORGANIZATION")
            .ok()
            .or_else(|| self.config.organization_id.clone());
        if let Some(org_id) = &org_id {
            args.extend_from_slice(&["--organizationid", org_id]);
        }

        cmd.args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SecretSpecError::ProviderOperationFailed(
                    "Bitwarden CLI (bw) is not installed.\n\nTo install it:\n  - npm: npm install -g @bitwarden/cli\n  - Homebrew: brew install bitwarden-cli\n  - Chocolatey: choco install bitwarden-cli\n  - Download: https://bitwarden.com/help/cli/".to_string(),
                )
            } else {
                SecretSpecError::ProviderOperationFailed(e.to_string())
            }
        })?;

        // Write base64-encoded JSON to stdin
        use std::io::Write;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(encoded_json.as_bytes()).map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!("Failed to write to stdin: {}", e))
            })?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| SecretSpecError::ProviderOperationFailed(e.to_string()))?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(SecretSpecError::ProviderOperationFailed(
                error_msg.to_string(),
            ));
        }

        Ok(())
    }
}

impl Provider for BitwardenProvider {
    /// Convention items are addressed by the secret key name directly,
    /// leveraging Bitwarden's vault-wide search.
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

    /// Bitwarden items support `field` coordinates for specifying which field
    /// to extract from the item. Items are not versioned.
    fn supported_coords(&self) -> &'static [&'static str] {
        &["field"]
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let mut uri = String::from("bw://");
        if let Some(ref org_id) = self.config.organization_id {
            uri.push_str(&ProviderUrl::encode(org_id));
            uri.push('@');
        }
        if let Some(ref coll_id) = self.config.collection_id {
            uri.push_str(&ProviderUrl::encode(coll_id));
        }
        if let Some(ref server) = self.config.server {
            uri.push('?');
            uri.push_str(&format!("server={}", server));
        }
        uri
    }

    /// Retrieves a secret from Bitwarden.
    ///
    /// Searches the entire vault for items matching the resolved item name,
    /// extracting the value from the resolved field (or config default).
    ///
    /// # Arguments
    ///
    /// * `addr` - The address to retrieve, resolved via `resolve_coords`
    ///
    /// # Returns
    ///
    /// * `Ok(Some(value))` - The secret value if found
    /// * `Ok(None)` - No secret found at the address
    /// * `Err(_)` - Authentication or retrieval error
    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let coords = self.resolve_coords(addr)?;
        let item_name = &coords.item;
        let target_field = coords.field.as_deref();
        self.get_from_password_manager(item_name, target_field)
    }

    /// Stores or updates a secret in Bitwarden.
    ///
    /// Searches for an existing item matching the resolved item name.
    /// If found, updates the resolved field. Otherwise creates a new
    /// item with the appropriate type and field.
    ///
    /// # Arguments
    ///
    /// * `addr` - The address to write, resolved via `resolve_coords`
    /// * `value` - The secret value to store
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Secret stored successfully
    /// * `Err(_)` - Storage or authentication error
    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        let coords = self.resolve_coords(addr)?;
        let item_name = &coords.item;
        let target_field = coords.field.as_deref();
        self.set_to_password_manager(item_name, target_field, value)
    }
}

impl Default for BitwardenProvider {
    /// Creates a BitwardenProvider with default configuration.
    ///
    /// Uses personal vault by default.
    fn default() -> Self {
        Self::new(BitwardenConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_linked_field_type() {
        // R1: Linked fields (type 3) should not cause deserialization to fail.
        // An item with a linked field should parse successfully.
        let json = r#"{
            "object": "item",
            "id": "test-id",
            "name": "Test Item",
            "type": 1,
            "fields": [
                {
                    "name": "API Key",
                    "value": "secret-123",
                    "type": 0
                },
                {
                    "name": "Related Item",
                    "value": null,
                    "type": 3,
                    "linkedId": "other-item-id"
                }
            ]
        }"#;

        let item: BitwardenItem = serde_json::from_str(json).unwrap();
        assert_eq!(item.name, "Test Item");
        let fields = item.fields.unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name.as_deref(), Some("API Key"));
        assert_eq!(fields[1].name.as_deref(), Some("Related Item"));
        // Linked field should have type Linked and carry the linkedId
        assert!(matches!(fields[1].field_type, BitwardenFieldType::Linked));
        assert_eq!(
            fields[1].linked_id.as_ref().and_then(|v| v.as_str()),
            Some("other-item-id")
        );
    }

    #[test]
    fn test_deserialize_mixed_fields_including_linked() {
        // An item with text, hidden, boolean, and linked fields should parse.
        let json = r#"{
            "object": "item",
            "id": "mixed-id",
            "name": "Mixed Fields",
            "type": 1,
            "fields": [
                { "name": "username", "value": "alice", "type": 0 },
                { "name": "password", "value": "s3cret", "type": 1 },
                { "name": "active", "value": "true", "type": 2 },
                { "name": "link", "value": null, "type": 3, "linkedId": "abc-123" }
            ]
        }"#;

        let item: BitwardenItem = serde_json::from_str(json).unwrap();
        let fields = item.fields.unwrap();
        assert_eq!(fields.len(), 4);
        assert!(matches!(fields[0].field_type, BitwardenFieldType::Text));
        assert!(matches!(fields[1].field_type, BitwardenFieldType::Hidden));
        assert!(matches!(fields[2].field_type, BitwardenFieldType::Boolean));
        assert!(matches!(fields[3].field_type, BitwardenFieldType::Linked));
    }

    #[test]
    fn test_deserialize_linked_field_integer_id() {
        // The bw CLI may return linkedId as an integer (e.g. 100), not a string.
        // The linked_id field must accept both.
        let json = r#"{
            "object": "item",
            "id": "test-id",
            "name": "Test Item",
            "type": 1,
            "fields": [
                {
                    "name": "linked_field",
                    "value": null,
                    "type": 3,
                    "linkedId": 100
                }
            ]
        }"#;

        let item: BitwardenItem = serde_json::from_str(json).unwrap();
        let fields = item.fields.unwrap();
        assert_eq!(fields.len(), 1);
        assert!(matches!(fields[0].field_type, BitwardenFieldType::Linked));
        assert_eq!(
            fields[0].linked_id.as_ref().and_then(|v| v.as_u64()),
            Some(100)
        );
    }

    /// Verbatim `bw status` output from bitwarden-cli 2025.11.0, which is JSON
    /// rather than the line-oriented text an earlier revision of the server
    /// guard tried to parse. Kept literal so a change in the CLI's shape shows
    /// up here as a test failure.
    const REAL_STATUS_CLOUD: &str = r#"{"serverUrl":null,"lastSync":"2026-07-17T21:52:42.940Z","userEmail":"user@example.com","userId":"183fb6e7-a07f-400c-ad76-b27000074032","status":"locked"}"#;

    #[test]
    fn status_reports_the_public_cloud_as_null() {
        // The guard must read `serverUrl` out of JSON. Parsing this as text and
        // looking for a "Server URL:" line yields nothing, which previously made
        // every `?server=` operation fail.
        assert_eq!(parse_status_server(REAL_STATUS_CLOUD).unwrap(), None);
    }

    #[test]
    fn null_server_url_matches_the_cloud_address() {
        // A null `serverUrl` means the public cloud, so naming that cloud
        // explicitly in the URI must not be reported as a mismatch.
        let reported = parse_status_server(REAL_STATUS_CLOUD).unwrap();
        let current = reported.as_deref().unwrap_or(BITWARDEN_CLOUD_SERVER);
        assert!(servers_match("https://vault.bitwarden.com", current));
        assert!(!servers_match("https://vault.company.com", current));
    }

    #[test]
    fn status_reports_a_self_hosted_server() {
        let json = r#"{"serverUrl":"https://vault.company.com","status":"unlocked"}"#;
        assert_eq!(
            parse_status_server(json).unwrap().as_deref(),
            Some("https://vault.company.com")
        );
    }

    #[test]
    fn status_treats_missing_and_empty_server_url_as_the_cloud() {
        let missing = r#"{"status":"unlocked"}"#;
        let empty = r#"{"serverUrl":"   ","status":"unlocked"}"#;
        assert_eq!(parse_status_server(missing).unwrap(), None);
        assert_eq!(parse_status_server(empty).unwrap(), None);
    }

    #[test]
    fn status_rejects_unparseable_output() {
        // A hard error beats silently treating an unreadable response as a match.
        assert!(parse_status_server("Server URL: https://vault.company.com").is_err());
        assert!(parse_status_server("").is_err());
        assert!(parse_status_server(r#"{"serverUrl":42}"#).is_err());
    }

    #[test]
    fn server_comparison_ignores_only_insignificant_differences() {
        // Same server, written differently.
        assert!(servers_match(
            "https://vault.company.com",
            "https://vault.company.com/"
        ));
        assert!(servers_match(
            "https://vault.company.com",
            "  https://vault.company.com  "
        ));
        assert!(servers_match(
            "HTTPS://Vault.Company.COM",
            "https://vault.company.com"
        ));
        // :443 is the https default, so it addresses the same server.
        assert!(servers_match(
            "https://vault.company.com:443",
            "https://vault.company.com"
        ));
        assert!(servers_match(
            "https://vault.company.com/bitwarden",
            "https://vault.company.com/bitwarden/"
        ));
    }

    #[test]
    fn server_comparison_distinguishes_different_servers() {
        assert!(!servers_match(
            "https://vault.company.com",
            "https://vault.other.com"
        ));
        // A non-default port is significant.
        assert!(!servers_match(
            "https://vault.company.com:8443",
            "https://vault.company.com"
        ));
        // So is the scheme.
        assert!(!servers_match(
            "http://vault.company.com",
            "https://vault.company.com"
        ));
        // And so is a base path.
        assert!(!servers_match(
            "https://vault.company.com/bitwarden",
            "https://vault.company.com"
        ));
    }

    #[test]
    fn server_guard_is_skipped_without_a_configured_server() {
        // `bw://` must not consult the CLI at all: with no expected server there
        // is nothing to compare, and spawning `bw status` here would make the
        // guard cost apply to every user.
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        assert!(provider.config.server.is_none());
        assert!(provider.ensure_server_configured().is_ok());
    }

    /// Every item type, so the round-trip test below cannot silently skip one.
    const ALL_ITEM_TYPES: [BitwardenItemType; 5] = [
        BitwardenItemType::Login,
        BitwardenItemType::SecureNote,
        BitwardenItemType::Card,
        BitwardenItemType::Identity,
        BitwardenItemType::SshKey,
    ];

    /// Turns a creation template into the item `bw` would hand back for it.
    ///
    /// The only addition is an `id`, which the server assigns on creation and
    /// which `BitwardenItem` requires. This is what lets a write be checked
    /// against a read without a vault.
    fn item_from_template(mut template: serde_json::Value) -> BitwardenItem {
        template["id"] = serde_json::Value::String("test-id".to_string());
        serde_json::from_value(template)
            .expect("a creation template must deserialize as a vault item")
    }

    fn template_for(
        provider: &BitwardenProvider,
        item_type: BitwardenItemType,
        name: &str,
        value: &str,
        field: &str,
    ) -> serde_json::Value {
        match item_type {
            BitwardenItemType::Login => provider.login_template(name, value, field),
            BitwardenItemType::SecureNote => provider.secure_note_template(name, value, field),
            BitwardenItemType::Card => provider.card_template(name, value, field),
            BitwardenItemType::Identity => provider.identity_template(name, value, field),
            BitwardenItemType::SshKey => provider.ssh_key_template(name, value, field),
        }
    }

    /// Reads an item the way `get` does when no field is named.
    ///
    /// Mirrors `extract_value_from_item`'s dispatch but passes no resolved
    /// field, which both models the unqualified case and keeps the test
    /// independent of a `BITWARDEN_DEFAULT_FIELD` in the developer's shell.
    fn read_without_naming_a_field(
        provider: &BitwardenProvider,
        item: &BitwardenItem,
    ) -> Option<String> {
        let extracted = match item.item_type {
            BitwardenItemType::Login => provider.extract_from_login_item(item, None),
            BitwardenItemType::SecureNote => provider.extract_from_secure_note_item(item, None),
            BitwardenItemType::Card => provider.extract_from_card_item(item, None),
            BitwardenItemType::Identity => provider.extract_from_identity_item(item, None),
            BitwardenItemType::SshKey => provider.extract_from_ssh_key_item(item, None),
        };
        extracted
            .expect("extraction must not fail")
            .map(|secret| secret.expose_secret().to_string())
    }

    #[test]
    fn default_field_table_is_pinned() {
        // Each entry is also the field the matching extract_from_* method looks
        // at first; changing one side without the other reintroduces the
        // write-here/read-there class of bug.
        assert_eq!(BitwardenItemType::Login.default_field(), "password");
        assert_eq!(BitwardenItemType::SecureNote.default_field(), "value");
        assert_eq!(BitwardenItemType::Card.default_field(), "number");
        assert_eq!(BitwardenItemType::Identity.default_field(), "email");
        assert_eq!(BitwardenItemType::SshKey.default_field(), "private_key");
    }

    #[test]
    fn plain_set_round_trips_for_every_item_type() {
        // A `set` with no field named, followed by a `get` with no field named,
        // must return what was written. This failed for Card and Identity, whose
        // creation default resolved to the item name and so wrote a custom field
        // that an unqualified read never looks at, and for Secure Notes, whose
        // update default wrote the note body while reads prefer the `value`
        // custom field.
        let provider = BitwardenProvider::new(BitwardenConfig::default());

        for item_type in ALL_ITEM_TYPES {
            let template = template_for(
                &provider,
                item_type,
                "Round Trip",
                "secret-value",
                item_type.default_field(),
            );
            let item = item_from_template(template);

            assert_eq!(
                read_without_naming_a_field(&provider, &item).as_deref(),
                Some("secret-value"),
                "{item_type:?}: value written to the default field was not readable without naming a field"
            );
        }
    }

    #[test]
    fn named_custom_field_round_trips_for_every_item_type() {
        // The original R2 case: an explicitly named field that matches none of a
        // type's built-ins has to be stored as that named custom field, not
        // folded into the type's primary field.
        let provider = BitwardenProvider::new(BitwardenConfig::default());

        for item_type in ALL_ITEM_TYPES {
            let template = template_for(
                &provider,
                item_type,
                "Named Field",
                "sk_test_123",
                "api_key",
            );
            let item = item_from_template(template);

            let by_name = provider
                .extract_from_custom_fields(&item, "api_key")
                .expect("extraction must not fail");

            assert_eq!(
                by_name.as_deref(),
                Some("sk_test_123"),
                "{item_type:?}: value written to field=api_key was not stored as that custom field"
            );
        }
    }

    /// Applies the update path's JSON mutation for `item_type`.
    ///
    /// `update_existing_item` fetches the item and writes it back through the
    /// CLI; the mutation in between is pure, and is the part that decides which
    /// field a fieldless `set` lands in.
    fn apply_update(
        provider: &BitwardenProvider,
        item_type: BitwardenItemType,
        item_json: &mut serde_json::Value,
        field: &str,
        value: &str,
    ) {
        let result = match item_type {
            BitwardenItemType::Login => provider.update_login_item_json(item_json, field, value),
            BitwardenItemType::SecureNote => {
                provider.update_secure_note_item_json(item_json, field, value)
            }
            BitwardenItemType::Card => provider.update_card_item_json(item_json, field, value),
            BitwardenItemType::Identity => {
                provider.update_identity_item_json(item_json, field, value)
            }
            BitwardenItemType::SshKey => provider.update_ssh_key_item_json(item_json, field, value),
        };
        result.expect("update must not fail");
    }

    #[test]
    fn update_after_create_round_trips_for_every_item_type() {
        // R3's shape: create with no field named, `set` again with no field
        // named, then read with no field named. Creation and update have to
        // choose the same field, or `set` reports success while `get` keeps
        // returning the value from before it.
        let provider = BitwardenProvider::new(BitwardenConfig::default());

        for item_type in ALL_ITEM_TYPES {
            let mut item_json = template_for(
                &provider,
                item_type,
                "Update Round Trip",
                "first-value",
                item_type.default_field(),
            );

            apply_update(
                &provider,
                item_type,
                &mut item_json,
                item_type.default_field(),
                "second-value",
            );

            let item = item_from_template(item_json);
            assert_eq!(
                read_without_naming_a_field(&provider, &item).as_deref(),
                Some("second-value"),
                "{item_type:?}: update wrote somewhere an unqualified read does not look"
            );
        }
    }

    #[test]
    fn update_reaches_the_field_reads_prefer_on_a_legacy_secure_note() {
        // A Secure Note carrying both a `value` custom field and a note body,
        // which is the shape earlier versions produced. Reads prefer the custom
        // field, so an update that writes the body instead leaves `get`
        // returning the stale value. This is what pins the Secure Note default
        // to `value` rather than `notes`: with no legacy data present both
        // choices round-trip, so only this case distinguishes them.
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let mut item_json = serde_json::json!({
            "type": BitwardenItemType::SecureNote.to_u8(),
            "name": "Legacy Note",
            "notes": "stale-body",
            "secureNote": { "type": 0 },
            "fields": [
                { "name": "value", "value": "stale-custom-field", "type": 1 }
            ]
        });

        apply_update(
            &provider,
            BitwardenItemType::SecureNote,
            &mut item_json,
            BitwardenItemType::SecureNote.default_field(),
            "fresh-value",
        );

        let item = item_from_template(item_json);
        assert_eq!(
            read_without_naming_a_field(&provider, &item).as_deref(),
            Some("fresh-value"),
            "update must write the field an unqualified read consults first"
        );
    }

    #[test]
    fn default_field_does_not_depend_on_the_item_name() {
        // The default is per type, never derived from the name. Reads resolve a
        // field from the address, env, or URI and never look at the name, so a
        // name-derived write target could not be mirrored by a read.
        let provider = BitwardenProvider::new(BitwardenConfig::default());

        for name in [
            "MY_TOTP_SECRET",
            "cardholder name",
            "user login",
            "public key",
        ] {
            for item_type in ALL_ITEM_TYPES {
                let template =
                    template_for(&provider, item_type, name, "v", item_type.default_field());
                let item = item_from_template(template);
                assert_eq!(
                    read_without_naming_a_field(&provider, &item).as_deref(),
                    Some("v"),
                    "{item_type:?} named {name:?}: the name must not change where the value lands"
                );
            }
        }
    }

    #[test]
    fn test_collection_id_from_uri() {
        // C3: collection_id must be parsed from the URI so that list commands
        // can filter by --collectionid.
        let url = url::Url::parse("bw://my-collection").unwrap();
        let purl = ProviderUrl::new(url);
        let config = BitwardenConfig::try_from(&purl).unwrap();
        assert_eq!(config.collection_id.as_deref(), Some("my-collection"));
        assert!(config.organization_id.is_none());
    }

    #[test]
    fn test_org_collection_from_uri() {
        let url = url::Url::parse("bw://myorg@dev-secrets").unwrap();
        let purl = ProviderUrl::new(url);
        let config = BitwardenConfig::try_from(&purl).unwrap();
        assert_eq!(config.organization_id.as_deref(), Some("myorg"));
        assert_eq!(config.collection_id.as_deref(), Some("dev-secrets"));
    }

    #[test]
    fn test_collection_from_query_param() {
        let url = url::Url::parse("bw://?collection=prod-secrets").unwrap();
        let purl = ProviderUrl::new(url);
        let config = BitwardenConfig::try_from(&purl).unwrap();
        assert_eq!(config.collection_id.as_deref(), Some("prod-secrets"));
    }

    #[test]
    fn test_update_custom_field_case_insensitive() {
        // R4: Update should match existing fields case-insensitively.
        // If an item has field "API_KEY" and we update "api_key", it should
        // update the existing field, not create a duplicate.
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let mut item_json = serde_json::json!({
            "fields": [
                { "name": "API_KEY", "value": "old-value", "type": 0 }
            ]
        });

        provider
            .update_custom_field_in_json(&mut item_json, "api_key", "new-value")
            .unwrap();

        let fields = item_json["fields"].as_array().unwrap();
        assert_eq!(
            fields.len(),
            1,
            "should update existing field, not add duplicate"
        );
        assert_eq!(fields[0]["name"].as_str(), Some("API_KEY"));
        assert_eq!(fields[0]["value"].as_str(), Some("new-value"));
    }
}
