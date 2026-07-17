use crate::provider::{Address, Provider, ProviderCredentials, ProviderUrl};
use crate::{Result, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::process::Command;

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
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }

    /// Get the default field name for this item type
    pub fn default_field_for_hint(&self, hint: &str) -> String {
        let hint_lower = hint.to_lowercase();

        match self {
            BitwardenItemType::Login => {
                if hint_lower.contains("user") || hint_lower.contains("login") {
                    "username".to_string()
                } else if hint_lower.contains("totp")
                    || hint_lower.contains("2fa")
                    || hint_lower.contains("mfa")
                {
                    "totp".to_string()
                } else {
                    "password".to_string() // Default for Login items
                }
            }
            BitwardenItemType::SecureNote => "value".to_string(), // Use custom field "value"
            BitwardenItemType::Card => {
                if hint_lower.contains("code")
                    || hint_lower.contains("cvv")
                    || hint_lower.contains("cvc")
                {
                    "code".to_string()
                } else if hint_lower.contains("name") || hint_lower.contains("cardholder") {
                    "cardholder".to_string()
                } else if hint_lower.contains("number") || hint_lower.contains("card") {
                    "number".to_string()
                } else {
                    hint.to_string() // Use the hint as custom field name for Card items
                }
            }
            BitwardenItemType::Identity => {
                if hint_lower.contains("phone") || hint_lower.contains("tel") {
                    "phone".to_string()
                } else if hint_lower.contains("user") || hint_lower.contains("login") {
                    "username".to_string()
                } else if hint_lower.contains("email") || hint_lower.contains("mail") {
                    "email".to_string()
                } else {
                    hint.to_string() // Use the hint as custom field name for Identity items
                }
            }
            BitwardenItemType::SshKey => {
                if hint_lower.contains("public") || hint_lower.contains("pub") {
                    "public_key".to_string()
                } else if hint_lower.contains("passphrase") || hint_lower.contains("password") {
                    "passphrase".to_string()
                } else if hint_lower.contains("private") || hint_lower.contains("key") {
                    "private_key".to_string()
                } else {
                    "private_key".to_string() // Default for SSH Key items
                }
            }
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
}

impl BitwardenFieldType {
    /// Convert from integer to enum
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(BitwardenFieldType::Text),
            1 => Some(BitwardenFieldType::Hidden),
            2 => Some(BitwardenFieldType::Boolean),
            _ => None,
        }
    }

    /// Convert to integer for JSON serialization
    pub fn to_u8(&self) -> u8 {
        *self as u8
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
    pub fn as_str(&self) -> &'static str {
        match self {
            BitwardenFieldType::Text => "text",
            BitwardenFieldType::Hidden => "hidden",
            BitwardenFieldType::Boolean => "boolean",
        }
    }
}

/// Represents a Bitwarden item retrieved from the CLI.
///
/// This struct deserializes the JSON output from the `bw get item` and `bw list items` commands.
/// It supports all Bitwarden item types: Login, Secure Note, Card, Identity, etc.
#[derive(Debug, Deserialize)]
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
struct BitwardenField {
    /// The name/label of the field.
    name: Option<String>,
    /// The value stored in the field.
    value: Option<String>,
    /// The type of field (Text, Hidden, Boolean).
    #[serde(rename = "type", deserialize_with = "deserialize_field_type")]
    field_type: BitwardenFieldType,
    /// Linked field ID (null if not linked).
    #[serde(rename = "linkedId")]
    linked_id: Option<String>,
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

/// Template for creating new Bitwarden items via the CLI.
///
/// This struct is serialized to JSON and passed to the `bw create item` command
/// using encoded JSON. It defines the structure and metadata for items that store secrets.
/// Default item type is Login for better script compatibility.
#[derive(Debug, Serialize)]
struct BitwardenItemTemplate {
    /// The type of item (Login by default).
    #[serde(rename = "type", serialize_with = "serialize_item_type")]
    item_type: BitwardenItemType,
    /// The name/title of the item.
    name: String,
    /// Notes field containing additional metadata.
    notes: String,
    /// Login-specific data (for Login items).
    #[serde(skip_serializing_if = "Option::is_none")]
    login: Option<BitwardenLogin>,
    /// Secure note specific configuration (for Secure Note items).
    #[serde(rename = "secureNote", skip_serializing_if = "Option::is_none")]
    secure_note: Option<BitwardenSecureNote>,
    /// Card-specific data (for Card items).
    #[serde(skip_serializing_if = "Option::is_none")]
    card: Option<BitwardenCard>,
    /// Identity-specific data (for Identity items).
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<BitwardenIdentity>,
    /// Collection of fields to include in the item.
    /// Contains project, profile, key, and value fields.
    fields: Vec<BitwardenFieldTemplate>,
    /// Optional organization ID if storing in an organization.
    #[serde(rename = "organizationId", skip_serializing_if = "Option::is_none")]
    organization_id: Option<String>,
    /// Optional collection IDs for organization items.
    #[serde(rename = "collectionIds", skip_serializing_if = "Option::is_none")]
    collection_ids: Option<Vec<String>>,
}

/// Custom serializer for item type
fn serialize_item_type<S>(
    item_type: &BitwardenItemType,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_u8(item_type.to_u8())
}

/// Secure note configuration required for Bitwarden secure note items.
#[derive(Debug, Serialize)]
struct BitwardenSecureNote {
    /// Type of secure note. Always 0 for generic secure notes.
    #[serde(rename = "type")]
    note_type: u8,
}

/// Template for individual fields when creating Bitwarden items.
///
/// Each field represents a piece of data to store in the item.
/// Used within BitwardenItemTemplate to define the item's content.
#[derive(Debug, Serialize)]
struct BitwardenFieldTemplate {
    /// The name/label of the field (e.g., "project", "key", "value").
    name: String,
    /// The value to store in the field.
    value: String,
    /// The type of field (Text, Hidden, Boolean).
    #[serde(rename = "type", serialize_with = "serialize_field_type")]
    field_type: BitwardenFieldType,
}

/// Custom serializer for field type
fn serialize_field_type<S>(
    field_type: &BitwardenFieldType,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_u8(field_type.to_u8())
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
/// # use secretspec::provider::bitwarden::BitwardenConfig;
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

        if scheme != "bitwarden" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for Bitwarden provider. Use 'bitwarden://' for Password Manager",
                scheme
            )));
        }

        let mut config = BitwardenConfig::default();

        // Parse Password Manager configuration
        if let Some(host) = url.host() {
            if host != "localhost" {
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
/// 1. Login: `bw login` (interactive or with API key)
/// 2. Unlock: `bw unlock` (generates session key)
/// 3. Export session: `export BW_SESSION="session-key"`
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
/// secretspec set MY_SECRET --provider bitwarden://
///
/// # Organization collection
/// secretspec get MY_SECRET --provider bitwarden://myorg@collection-id
///
/// # Self-hosted with custom server
/// secretspec set API_KEY --provider bitwarden://?server=https://vault.company.com
/// ```
pub struct BitwardenProvider {
    /// Configuration for the provider including org/collection settings.
    config: BitwardenConfig,
    /// Credentials supplied by the provider alias.
    credentials: ProviderCredentials,
}

crate::register_provider! {
    struct: BitwardenProvider,
    config: BitwardenConfig,
    name: "bitwarden",
    description: "Bitwarden Password Manager",
    schemes: ["bitwarden"],
    examples: [
        "bitwarden://",
        "bitwarden://collection-id",
        "bitwarden://org@collection"
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
        }
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
        let mut cmd = Command::new("bw");

        // Configure server if specified
        if let Some(server) = &self.config.server {
            cmd.env("BW_SERVER", server);
        }

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

    /// Formats the item name for storage in Bitwarden.
    ///
    /// Creates a hierarchical name using the folder_prefix format string.
    /// Supports placeholders: {project} and {profile}.
    /// Defaults to "secretspec/{project}/{profile}" if not configured.
    ///
    /// # Arguments
    ///
    /// * `project` - The project name
    /// * `profile` - The profile name
    ///
    /// # Returns
    ///
    /// A formatted string based on the configured pattern
    fn format_folder_name(&self, project: &str, profile: &str) -> String {
        let format_string = self
            .config
            .folder_prefix
            .as_deref()
            .unwrap_or("secretspec/{project}/{profile}");

        format_string
            .replace("{project}", project)
            .replace("{profile}", profile)
    }

    /// Formats the complete item name for storage in Bitwarden.
    ///
    /// Combines the folder name with the secret key to create a unique item name.
    ///
    /// # Arguments
    ///
    /// * `project` - The project name
    /// * `key` - The secret key
    /// * `profile` - The profile name
    ///
    /// # Returns
    ///
    /// A formatted string like "secretspec/{project}/{profile}/{key}"
    fn format_item_name(&self, project: &str, key: &str, profile: &str) -> String {
        let folder = self.format_folder_name(project, profile);
        format!("{}/{}", folder, key)
    }

    /// Creates a template for a new Bitwarden item.
    ///
    /// This template is serialized to JSON and used with `bw create item`.
    /// The item is created as a Login item by default (better for scripts).
    ///
    /// # Arguments
    ///
    /// * `project` - The project name (unused, kept for compatibility)
    /// * `key` - The secret key (becomes item name)
    /// * `value` - The secret value (stored in password field)
    /// * `profile` - The profile name (unused, kept for compatibility)
    ///
    /// # Returns
    ///
    /// A BitwardenItemTemplate ready for serialization
    fn create_item_template(
        &self,
        _project: &str,
        key: &str,
        value: &str,
        _profile: &str,
    ) -> BitwardenItemTemplate {
        // Create a Login item by default - better for script compatibility
        let template = BitwardenItemTemplate {
            item_type: BitwardenItemType::Login,
            name: key.to_string(),
            notes: format!("SecretSpec managed secret: {}", key),
            login: Some(BitwardenLogin {
                username: None,
                password: Some(value.to_string()),
                totp: None,
                uris: None,
                password_revision_date: None,
            }),
            secure_note: None,
            card: None,
            identity: None,
            fields: vec![],
            organization_id: std::env::var("BITWARDEN_ORGANIZATION")
                .ok()
                .or_else(|| self.config.organization_id.clone()),
            collection_ids: std::env::var("BITWARDEN_COLLECTION")
                .ok()
                .or_else(|| self.config.collection_id.clone())
                .map(|id| vec![id]),
        };

        template
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

        eprintln!("DEBUG: get_from_password_manager called for item='{}'", item_name);

        // Use Bitwarden's built-in search to find items matching the key
        let mut list_args = vec!["list", "items", "--search", item_name];

        // Add organization filter if configured (from config or environment variable)
        let org_id = std::env::var("BITWARDEN_ORGANIZATION")
            .ok()
            .or_else(|| self.config.organization_id.clone());
        if let Some(org_id) = &org_id {
            list_args.extend_from_slice(&["--organizationid", org_id]);
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
            BitwardenItemType::Card => {
                self.extract_from_card_item(item, resolved_field.as_deref())
            }
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
                    "password" => return Ok(login.password.as_ref().map(|p| SecretString::new(p.clone().into()))),
                    "username" => return Ok(login.username.as_ref().map(|u| SecretString::new(u.clone().into()))),
                    "totp" => return Ok(login.totp.as_ref().map(|t| SecretString::new(t.clone().into()))),
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
        if let Some(field_name) = resolved_field {
            if let Some(value) = self.extract_from_custom_fields(item, field_name)? {
                return Ok(Some(SecretString::new(value.into())));
            }
        }

        // Look for legacy "value" field (backward compatibility)
        if let Some(value) = self.extract_from_custom_fields(item, "value")? {
            return Ok(Some(SecretString::new(value.into())));
        }

        // Fallback: return notes content
        Ok(item.notes.as_ref().map(|notes| SecretString::new(notes.clone().into())))
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
                    "number" => return Ok(card.number.as_ref().map(|n| SecretString::new(n.clone().into()))),
                    "code" | "cvv" | "cvc" => return Ok(card.code.as_ref().map(|c| SecretString::new(c.clone().into()))),
                    "cardholder" | "name" => return Ok(card.cardholder_name.as_ref().map(|n| SecretString::new(n.clone().into()))),
                    "brand" => return Ok(card.brand.as_ref().map(|b| SecretString::new(b.clone().into()))),
                    "expmonth" | "exp_month" => return Ok(card.exp_month.as_ref().map(|m| SecretString::new(m.clone().into()))),
                    "expyear" | "exp_year" => return Ok(card.exp_year.as_ref().map(|y| SecretString::new(y.clone().into()))),
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
                    "email" => return Ok(identity.email.as_ref().map(|e| SecretString::new(e.clone().into()))),
                    "username" => return Ok(identity.username.as_ref().map(|u| SecretString::new(u.clone().into()))),
                    "phone" => return Ok(identity.phone.as_ref().map(|p| SecretString::new(p.clone().into()))),
                    "firstname" | "first_name" => return Ok(identity.first_name.as_ref().map(|f| SecretString::new(f.clone().into()))),
                    "lastname" | "last_name" => return Ok(identity.last_name.as_ref().map(|l| SecretString::new(l.clone().into()))),
                    "company" => return Ok(identity.company.as_ref().map(|c| SecretString::new(c.clone().into()))),
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
                        return Ok(ssh_key.private_key.as_ref().map(|k| SecretString::new(k.clone().into())));
                    }
                    "public_key" | "publickey" | "public" => return Ok(ssh_key.public_key.as_ref().map(|k| SecretString::new(k.clone().into()))),
                    "fingerprint" | "key_fingerprint" => {
                        return Ok(ssh_key.key_fingerprint.as_ref().map(|f| SecretString::new(f.clone().into())));
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
                if let Some(name) = &field.name {
                    if name.eq_ignore_ascii_case(field_name) {
                        return Ok(field.value.clone());
                    }
                }
            }

            // Partial match (contains)
            for field in fields {
                if let Some(name) = &field.name {
                    if name.to_lowercase().contains(&field_name.to_lowercase()) {
                        return Ok(field.value.clone());
                    }
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
    fn update_existing_item(&self, item: &BitwardenItem, target_field: Option<&str>, value: &str) -> Result<()> {
        // Determine which field to update: explicit > env > config > smart default
        let field = target_field
            .map(|s| s.to_string())
            .or_else(|| std::env::var("BITWARDEN_DEFAULT_FIELD").ok())
            .or_else(|| self.config.default_field.clone())
            .unwrap_or_else(|| "password".to_string());

        // Get the current item as JSON template
        let mut item_json = self.get_item_as_template(&item.id)?;

        match item.item_type {
            BitwardenItemType::Login => {
                self.update_login_item_json(&mut item_json, &field, value)
            }
            BitwardenItemType::SecureNote => {
                self.update_secure_note_item_json(&mut item_json, &field, value)
            }
            BitwardenItemType::Card => {
                self.update_card_item_json(&mut item_json, &field, value)
            }
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

        // Look for existing field
        for field_obj in fields.iter_mut() {
            if field_obj["name"].as_str() == Some(field) {
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
        let item_json_str = serde_json::to_string(item_json)?;

        // Bitwarden CLI expects base64-encoded JSON via stdin
        // TODO: Research if all item types actually need this encoding or if
        // some could use simpler command formats for better performance
        use base64::{Engine as _, engine::general_purpose};
        use std::process::Stdio;
        let encoded_json = general_purpose::STANDARD.encode(&item_json_str);

        let mut cmd = std::process::Command::new("bw");

        // Set server if specified
        if let Some(server) = &self.config.server {
            cmd.env("BW_SERVER", server);
        }

        let mut args = vec!["edit", "item", item_id];
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
    fn create_new_item(&self, item_name: &str, target_field: Option<&str>, value: &str) -> Result<()> {
        // Determine item type from config, environment variable, or use default (Login)
        let item_type = std::env::var("BITWARDEN_DEFAULT_TYPE")
            .ok()
            .and_then(|s| BitwardenItemType::from_str(&s))
            .or(self.config.default_item_type)
            .unwrap_or(BitwardenItemType::Login);

        // Determine target field: explicit > env > config > smart default
        let field = target_field
            .map(|s| s.to_string())
            .or_else(|| std::env::var("BITWARDEN_DEFAULT_FIELD").ok())
            .or_else(|| self.config.default_field.clone())
            .unwrap_or_else(|| item_type.default_field_for_hint(item_name));

        match item_type {
            BitwardenItemType::Login => self.create_login_item(item_name, value, &field),
            BitwardenItemType::Card => self.create_card_item(item_name, value, &field),
            BitwardenItemType::Identity => self.create_identity_item(item_name, value, &field),
            BitwardenItemType::SecureNote => {
                self.create_secure_note_item(item_name, value, &field)
            }
            BitwardenItemType::SshKey => self.create_ssh_key_item(item_name, value, &field),
        }
    }

    /// Creates a new Login item.
    fn create_login_item(&self, item_name: &str, value: &str, field: &str) -> Result<()> {
        let mut login_data = serde_json::json!({
            "username": null,
            "password": null,
            "totp": null,
            "uris": []
        });

        match target_field.to_lowercase().as_str() {
            "username" => login_data["username"] = serde_json::Value::String(value.to_string()),
            "totp" => login_data["totp"] = serde_json::Value::String(value.to_string()),
            _ => login_data["password"] = serde_json::Value::String(value.to_string()),
        }

        let template = serde_json::json!({
            "type": BitwardenItemType::Login.to_u8(),
            "name": item_name,
            "notes": format!("SecretSpec managed secret: {}", item_name),
            "login": login_data,
            "organizationId": std::env::var("BITWARDEN_ORGANIZATION").ok()
                .or_else(|| self.config.organization_id.clone()),
            "collectionIds": std::env::var("BITWARDEN_COLLECTION").ok()
                .or_else(|| self.config.collection_id.clone())
                .map(|id| vec![id])
        });

        self.create_item_from_template(&template)
    }

    /// Creates a new Card item.
    fn create_card_item(&self, item_name: &str, value: &str, field: &str) -> Result<()> {
        let mut card_data = serde_json::json!({
            "number": null,
            "code": null,
            "cardholderName": null,
            "brand": null,
            "expMonth": null,
            "expYear": null
        });

        match target_field.to_lowercase().as_str() {
            "code" | "cvv" | "cvc" => {
                card_data["code"] = serde_json::Value::String(value.to_string())
            }
            "cardholder" | "name" => {
                card_data["cardholderName"] = serde_json::Value::String(value.to_string())
            }
            "brand" => card_data["brand"] = serde_json::Value::String(value.to_string()),
            _ => card_data["number"] = serde_json::Value::String(value.to_string()),
        }

        let template = serde_json::json!({
            "type": BitwardenItemType::Card.to_u8(),
            "name": item_name,
            "notes": format!("SecretSpec managed secret: {}", item_name),
            "card": card_data,
            "organizationId": std::env::var("BITWARDEN_ORGANIZATION").ok()
                .or_else(|| self.config.organization_id.clone()),
            "collectionIds": std::env::var("BITWARDEN_COLLECTION").ok()
                .or_else(|| self.config.collection_id.clone())
                .map(|id| vec![id])
        });

        self.create_item_from_template(&template)
    }

    /// Creates a new Identity item.
    fn create_identity_item(&self, item_name: &str, value: &str, field: &str) -> Result<()> {
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

        match target_field.to_lowercase().as_str() {
            "username" => identity_data["username"] = serde_json::Value::String(value.to_string()),
            "phone" => identity_data["phone"] = serde_json::Value::String(value.to_string()),
            "company" => identity_data["company"] = serde_json::Value::String(value.to_string()),
            _ => identity_data["email"] = serde_json::Value::String(value.to_string()),
        }

        let template = serde_json::json!({
            "type": BitwardenItemType::Identity.to_u8(),
            "name": item_name,
            "notes": format!("SecretSpec managed secret: {}", item_name),
            "identity": identity_data,
            "organizationId": std::env::var("BITWARDEN_ORGANIZATION").ok()
                .or_else(|| self.config.organization_id.clone()),
            "collectionIds": std::env::var("BITWARDEN_COLLECTION").ok()
                .or_else(|| self.config.collection_id.clone())
                .map(|id| vec![id])
        });

        self.create_item_from_template(&template)
    }

    /// Creates a new Secure Note item.
    fn create_secure_note_item(&self, item_name: &str, value: &str, field: &str) -> Result<()> {
        let mut fields = vec![];

        if target_field != "notes" {
            // Store in custom field
            let field_type = BitwardenFieldType::for_field_name(target_field);
            fields.push(serde_json::json!({
                "name": target_field,
                "value": value,
                "type": field_type.to_u8()
            }));
        }

        let template = serde_json::json!({
            "type": BitwardenItemType::SecureNote.to_u8(),
            "name": item_name,
            "notes": if target_field == "notes" { value.to_string() } else { format!("SecretSpec managed secret: {}", key) },
            "secureNote": {
                "type": 0
            },
            "fields": fields,
            "organizationId": std::env::var("BITWARDEN_ORGANIZATION").ok()
                .or_else(|| self.config.organization_id.clone()),
            "collectionIds": std::env::var("BITWARDEN_COLLECTION").ok()
                .or_else(|| self.config.collection_id.clone())
                .map(|id| vec![id])
        });

        self.create_item_from_template(&template)
    }

    /// Creates a new SSH Key item.
    fn create_ssh_key_item(&self, item_name: &str, value: &str, field: &str) -> Result<()> {
        let mut ssh_key_data = serde_json::json!({
            "privateKey": null,
            "publicKey": null,
            "keyFingerprint": null
        });

        match target_field.to_lowercase().as_str() {
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
                // For other field names, store as custom field
                let mut fields = vec![];
                let field_type = BitwardenFieldType::for_field_name(target_field);
                fields.push(serde_json::json!({
                    "name": target_field,
                    "value": value,
                    "type": field_type.to_u8()
                }));

                let template = serde_json::json!({
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
                });

                return self.create_item_from_template(&template);
            }
        }

        let template = serde_json::json!({
            "type": BitwardenItemType::SshKey.to_u8(),
            "name": item_name,
            "notes": format!("SecretSpec managed secret: {}", item_name),
            "sshKey": ssh_key_data,
            "organizationId": std::env::var("BITWARDEN_ORGANIZATION").ok()
                .or_else(|| self.config.organization_id.clone()),
            "collectionIds": std::env::var("BITWARDEN_COLLECTION").ok()
                .or_else(|| self.config.collection_id.clone())
                .map(|id| vec![id])
        });

        self.create_item_from_template(&template)
    }

    /// Creates an item from a JSON template.
    ///
    /// NOTE: This method currently uses base64-encoded JSON for all item types,
    /// following the documented Bitwarden CLI workflow (template → encode → create).
    /// Future optimization: investigate if simpler creation methods exist for
    /// basic Login/Card/Identity items that don't require complex JSON encoding.
    fn create_item_from_template(&self, template: &serde_json::Value) -> Result<()> {
        let template_json = serde_json::to_string(template)?;

        // Bitwarden CLI expects base64-encoded JSON via stdin
        // TODO: Research if all item types actually need this encoding or if
        // some could use simpler command formats for better performance
        use base64::{Engine as _, engine::general_purpose};
        use std::process::Stdio;
        let encoded_json = general_purpose::STANDARD.encode(&template_json);

        let mut cmd = std::process::Command::new("bw");

        // Set server if specified
        if let Some(server) = &self.config.server {
            cmd.env("BW_SERVER", server);
        }

        let mut args = vec!["create", "item"];
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
        let mut uri = String::from("bitwarden://");
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
