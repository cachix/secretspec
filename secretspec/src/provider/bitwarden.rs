use crate::provider::Provider;
use crate::{Result, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::time::{Duration, Instant};
use url::Url;

/// Bitwarden service type enum for distinguishing between Password Manager and Secrets Manager
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BitwardenService {
    /// Password Manager service (uses `bw` CLI)
    PasswordManager,
    /// Secrets Manager service (uses `bws` CLI)
    SecretsManager,
}

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
    #[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
fn serialize_field_type<S>(
    field_type: &BitwardenFieldType,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_u8(field_type.to_u8())
}

/// Represents a Bitwarden Secrets Manager secret retrieved from the `bws` CLI.
///
/// This struct deserializes the JSON output from `bws secret get` and `bws secret list` commands.
/// Unlike Password Manager items, Secrets Manager secrets are native key-value pairs.
#[derive(Debug, Deserialize, Serialize)]
struct BitwardenSecret {
    /// Type of object (may not always be present in responses).
    #[serde(default)]
    pub object: Option<String>,
    /// Unique identifier for the secret.
    pub id: String,
    /// Organization ID that owns this secret.
    #[serde(rename = "organizationId")]
    pub organization_id: String,
    /// Project ID that contains this secret.
    #[serde(rename = "projectId")]
    pub project_id: String,
    /// The secret key name.
    pub key: String,
    /// The secret value.
    pub value: String,
    /// Optional note/description for the secret.
    pub note: String,
    /// When the secret was created.
    #[serde(rename = "creationDate")]
    pub creation_date: String,
    /// When the secret was last modified.
    #[serde(rename = "revisionDate")]
    pub revision_date: String,
}

/// Represents a Bitwarden Secrets Manager project.
///
/// Projects are used to organize secrets in Secrets Manager.
#[derive(Debug, Deserialize, Serialize)]
struct BitwardenProject {
    /// Type of object (always "project").
    pub object: String,
    /// Unique identifier for the project.
    pub id: String,
    /// Organization ID that owns this project.
    #[serde(rename = "organizationId")]
    pub organization_id: String,
    /// The project name.
    pub name: String,
    /// When the project was created.
    #[serde(rename = "creationDate")]
    pub creation_date: String,
    /// When the project was last modified.
    #[serde(rename = "revisionDate")]
    pub revision_date: String,
}

/// Configuration for the Bitwarden provider.
///
/// This struct contains all the necessary configuration options for
/// interacting with both Bitwarden Password Manager and Secrets Manager.
/// It supports various authentication methods and organizational contexts.
///
/// # Examples
///
/// ```ignore
/// # use secretspec::provider::bitwarden::{BitwardenConfig, BitwardenService};
/// // Password Manager configuration (personal vault)
/// let config = BitwardenConfig {
///     service: BitwardenService::PasswordManager,
///     ..Default::default()
/// };
///
/// // Secrets Manager configuration with specific project
/// let config = BitwardenConfig {
///     service: BitwardenService::SecretsManager,
///     project_id: Some("be8e0ad8-d545-4017-a55a-b02f014d4158".to_string()),
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitwardenConfig {
    /// Which Bitwarden service to use
    pub service: BitwardenService,

    // Password Manager specific fields
    /// Optional organization ID for organization vaults (Password Manager only).
    ///
    /// When set, secrets are stored in the specified organization
    /// rather than the personal vault. Used with the `--organizationid`
    /// flag in CLI commands. Can be overridden by BITWARDEN_ORGANIZATION environment variable.
    pub organization_id: Option<String>,
    /// Optional collection ID for organizing secrets within an organization (Password Manager only).
    ///
    /// When set along with organization_id, secrets are stored in
    /// the specified collection. Used for team-based secret organization.
    /// Can be overridden by BITWARDEN_COLLECTION environment variable.
    pub collection_id: Option<String>,
    /// Server URL for self-hosted Bitwarden instances (Password Manager only).
    ///
    /// When set, the CLI will be configured to use the specified server
    /// instead of the default bitwarden.com. Should include the full URL.
    pub server: Option<String>,
    /// Optional folder name prefix for organizing secrets in Bitwarden (Password Manager only).
    ///
    /// Supports placeholders: {project} and {profile}.
    /// Defaults to "secretspec/{project}/{profile}" if not specified.
    pub folder_prefix: Option<String>,

    // Secrets Manager specific fields
    /// Optional project ID for Secrets Manager projects.
    ///
    /// When set, secrets are stored in/retrieved from the specified project.
    /// If not set, operations may work across all accessible projects.
    pub project_id: Option<String>,
    /// Optional access token for Secrets Manager authentication.
    ///
    /// If not provided, will use BWS_ACCESS_TOKEN environment variable.
    pub access_token: Option<String>,

    // Flexible item creation fields
    /// Default item type for creating new items.
    /// Can be overridden by BITWARDEN_DEFAULT_TYPE environment variable.
    pub default_item_type: Option<BitwardenItemType>,
    /// Default field name for storing values.
    /// Can be overridden by BITWARDEN_DEFAULT_FIELD environment variable.
    pub default_field: Option<String>,

    /// Timeout in seconds for CLI commands (default: 30 seconds).
    /// Prevents hanging CLI processes and provides better error handling.
    /// Can be overridden by BITWARDEN_CLI_TIMEOUT environment variable.
    pub cli_timeout: Option<u64>,
}

impl Default for BitwardenConfig {
    fn default() -> Self {
        Self {
            service: BitwardenService::PasswordManager,
            organization_id: None,
            collection_id: None,
            server: None,
            folder_prefix: None,
            project_id: None,
            access_token: None,
            default_item_type: Some(BitwardenItemType::Login), // Login by default
            default_field: None,
            cli_timeout: Some(30), // 30 seconds default timeout
        }
    }
}

impl TryFrom<&Url> for BitwardenConfig {
    type Error = SecretSpecError;

    fn try_from(url: &Url) -> std::result::Result<Self, Self::Error> {
        let scheme = url.scheme();

        // Determine service based on scheme
        let service = match scheme {
            "bitwarden" => BitwardenService::PasswordManager,
            "bws" => BitwardenService::SecretsManager,
            _ => {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Invalid scheme '{}' for Bitwarden provider. Use 'bitwarden://' for Password Manager or 'bws://' for Secrets Manager",
                    scheme
                )));
            }
        };

        let mut config = BitwardenConfig {
            service: service.clone(),
            ..Default::default()
        };

        match service {
            BitwardenService::PasswordManager => {
                // Parse Password Manager specific configuration
                if let Some(host) = url.host_str() {
                    if host != "localhost" {
                        // Check if we have username (organization) information
                        if !url.username().is_empty() {
                            // Handle org@collection format
                            config.organization_id = Some(url.username().to_string());
                            config.collection_id = Some(host.to_string());
                        } else {
                            // Just collection ID
                            config.collection_id = Some(host.to_string());
                        }
                    }
                }

                // Parse query parameters for Password Manager
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
                        "timeout" => {
                            if let Ok(timeout) = value.parse::<u64>() {
                                config.cli_timeout = Some(timeout);
                            }
                        }
                        _ => {} // Ignore unknown parameters
                    }
                }
            }
            BitwardenService::SecretsManager => {
                // Parse Secrets Manager specific configuration
                if let Some(host) = url.host_str() {
                    if host != "localhost" {
                        // Host is the project ID for Secrets Manager
                        config.project_id = Some(host.to_string());
                    }
                }

                // Parse query parameters for Secrets Manager
                for (key, value) in url.query_pairs() {
                    match key.as_ref() {
                        "project" => config.project_id = Some(value.into_owned()),
                        "token" => config.access_token = Some(value.into_owned()),
                        "type" => {
                            if let Some(item_type) = BitwardenItemType::from_str(&value) {
                                config.default_item_type = Some(item_type);
                            }
                        }
                        "field" => config.default_field = Some(value.into_owned()),
                        "timeout" => {
                            if let Ok(timeout) = value.parse::<u64>() {
                                config.cli_timeout = Some(timeout);
                            }
                        }
                        _ => {} // Ignore unknown parameters
                    }
                }
            }
        }

        Ok(config)
    }
}

impl TryFrom<Url> for BitwardenConfig {
    type Error = SecretSpecError;

    fn try_from(url: Url) -> std::result::Result<Self, Self::Error> {
        (&url).try_into()
    }
}

impl BitwardenConfig {}

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
}

crate::register_provider! {
    struct: BitwardenProvider,
    config: BitwardenConfig,
    name: "bitwarden",
    description: "Bitwarden Password Manager and Secrets Manager",
    schemes: ["bitwarden", "bws"],
    examples: [
        "bitwarden://",
        "bitwarden://collection-id",
        "bitwarden://org@collection",
        "bws://",
        "bws://project-id"
    ],
}

impl BitwardenProvider {
    /// Creates a new BitwardenProvider with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the provider
    pub fn new(config: BitwardenConfig) -> Self {
        Self { config }
    }

    /// Helper to convert any string-like type to SecretString.
    ///
    /// This centralizes the conversion logic and uses AsRef<str> to accept
    /// various string types (&str, String, &String, etc.) efficiently.
    pub(crate) fn to_secret_string<S: AsRef<str>>(value: S) -> SecretString {
        SecretString::new(value.as_ref().into())
    }

    /// Helper to convert Option<String-like> to Option<SecretString>.
    ///
    /// This reduces the repetitive pattern of `.map(|s| SecretString::new(s.as_str().into()))`
    /// to a more concise and efficient `.and_then(Self::option_to_secret_string)`.
    pub(crate) fn option_to_secret_string<S: AsRef<str>>(opt: Option<S>) -> Option<SecretString> {
        opt.map(Self::to_secret_string)
    }

    /// Gets the CLI timeout value from configuration or environment variable.
    ///
    /// Priority: environment variable > config value > default (30s)
    pub(crate) fn get_cli_timeout(&self) -> Duration {
        // Check environment variable first
        if let Ok(timeout_str) = std::env::var("BITWARDEN_CLI_TIMEOUT") {
            if let Ok(timeout_secs) = timeout_str.parse::<u64>() {
                return Duration::from_secs(timeout_secs);
            }
        }

        // Use config value or default
        let timeout_secs = self.config.cli_timeout.unwrap_or(30);
        Duration::from_secs(timeout_secs)
    }

    /// Sanitizes CLI error messages to prevent secret leakage.
    ///
    /// This method removes or redacts potential secrets from error messages while
    /// preserving useful diagnostic information for users.
    ///
    /// # Security Considerations
    ///
    /// CLI error messages can sometimes contain:
    /// - Access tokens or session keys in curl/HTTP error messages
    /// - Secret values in JSON parsing errors
    /// - File paths that might reveal sensitive information
    /// - Command arguments that contain secrets
    ///
    /// # Arguments
    ///
    /// * `error_msg` - The raw error message from CLI stderr
    ///
    /// # Returns
    ///
    /// A sanitized error message safe for logging and user display
    pub(crate) fn sanitize_error_message(&self, error_msg: &str) -> String {
        let mut sanitized = error_msg.to_string();

        // Redact file paths first to avoid false positives with secret patterns
        sanitized = self.redact_file_paths(sanitized);
        sanitized = self.redact_secret_patterns(sanitized);
        sanitized = self.redact_bearer_tokens(sanitized);
        sanitized = self.redact_base64_tokens(sanitized);
        sanitized = self.truncate_long_message(sanitized);

        sanitized
    }

    /// Redacts potential secret patterns in JSON/key-value formats.
    pub(crate) fn redact_secret_patterns(&self, mut sanitized: String) -> String {
        let secret_patterns = [
            // JSON patterns: "token": "value", "key": "value"
            ("\"token\":", "\"[REDACTED]\""),
            ("\"key\":", "\"[REDACTED]\""),
            ("\"secret\":", "\"[REDACTED]\""),
            ("\"password\":", "\"[REDACTED]\""),
            ("\"session\":", "\"[REDACTED]\""),
            ("\"access_token\":", "\"[REDACTED]\""),
            ("\"api_key\":", "\"[REDACTED]\""),
            ("\"authorization\":", "\"[REDACTED]\""),
            ("\"bearer\":", "\"[REDACTED]\""),
            ("\"jwt\":", "\"[REDACTED]\""),
            ("\"refresh_token\":", "\"[REDACTED]\""),
            ("\"client_secret\":", "\"[REDACTED]\""),
            ("\"private_key\":", "\"[REDACTED]\""),
            ("\"client_id\":", "\"[REDACTED]\""),
            // URL/form patterns: token=value, key=value
            ("token=", "token=[REDACTED]"),
            ("key=", "key=[REDACTED]"),
            ("secret=", "secret=[REDACTED]"),
            ("password=", "password=[REDACTED]"),
            ("session=", "session=[REDACTED]"),
            ("access_token=", "access_token=[REDACTED]"),
            ("api_key=", "api_key=[REDACTED]"),
            ("authorization=", "authorization=[REDACTED]"),
            ("bearer=", "bearer=[REDACTED]"),
            ("jwt=", "jwt=[REDACTED]"),
            ("refresh_token=", "refresh_token=[REDACTED]"),
            ("client_secret=", "client_secret=[REDACTED]"),
            ("private_key=", "private_key=[REDACTED]"),
            ("client_id=", "client_id=[REDACTED]"),
            // Error message patterns: "token: value", "key: value"
            ("token: ", "token: [REDACTED]"),
            ("key: ", "key: [REDACTED]"),
            ("secret: ", "secret: [REDACTED]"),
            ("password: ", "password: [REDACTED]"),
            ("session: ", "session: [REDACTED]"),
            ("access_token: ", "access_token: [REDACTED]"),
            ("api_key: ", "api_key: [REDACTED]"),
            ("authorization: ", "authorization: [REDACTED]"),
            ("bearer: ", "bearer: [REDACTED]"),
            ("jwt: ", "jwt: [REDACTED]"),
            ("refresh_token: ", "refresh_token: [REDACTED]"),
            ("client_secret: ", "client_secret: [REDACTED]"),
            ("private_key: ", "private_key: [REDACTED]"),
            ("client_id: ", "client_id: [REDACTED]"),
        ];

        for (pattern, replacement) in &secret_patterns {
            if let Some(start) = sanitized.to_lowercase().find(&pattern.to_lowercase()) {
                let value_start = start + pattern.len();
                if let Some(value_part) = sanitized.get(value_start..) {
                    // Skip whitespace and quotes to get to the actual value
                    let mut actual_value_start = 0;
                    for (i, ch) in value_part.char_indices() {
                        if ch != ' ' && ch != '"' {
                            actual_value_start = i;
                            break;
                        }
                    }

                    if let Some(actual_value) = value_part.get(actual_value_start..) {
                        // Find end of value (quote, comma, newline, brace, bracket)
                        // Don't break on spaces for values like "Bearer token123"
                        let end_chars = ['"', ',', '\n', '\r', '}', ']'];
                        let mut end_pos = actual_value.len();

                        for &end_char in &end_chars {
                            if let Some(pos) = actual_value.find(end_char) {
                                if pos < end_pos {
                                    end_pos = pos;
                                }
                            }
                        }

                        // Only redact if value looks like a secret (>= 8 chars)
                        if end_pos >= 8 {
                            let before = &sanitized[..value_start + actual_value_start];
                            let after = &sanitized[value_start + actual_value_start + end_pos..];
                            sanitized = format!("{}{}{}", before, replacement, after);
                        }
                    }
                }
            }
        }

        sanitized
    }

    /// Redacts Bearer tokens from error messages.
    pub(crate) fn redact_bearer_tokens(&self, mut sanitized: String) -> String {
        if let Some(bearer_start) = sanitized.to_lowercase().find("bearer ") {
            let token_start = bearer_start + 7;
            if let Some(token_part) = sanitized.get(token_start..) {
                let token_end = token_part.find(' ').unwrap_or(token_part.len().min(60));
                if token_end >= 20 {
                    // Typical token length
                    let before = &sanitized[..token_start];
                    let after = &sanitized[token_start + token_end..];
                    sanitized = format!("{}[REDACTED]{}", before, after);
                }
            }
        }
        sanitized
    }

    /// Redacts long base64-like strings (potential tokens/keys).
    pub(crate) fn redact_base64_tokens(&self, sanitized: String) -> String {
        let words: Vec<String> = sanitized
            .split_whitespace()
            .map(|word| {
                // Check for JWT pattern (base64.base64.base64 or base64.base64)
                if word.contains('.') && word.len() >= 20 {
                    let parts: Vec<&str> = word.split('.').collect();
                    if parts.len() >= 2 && parts.iter().all(|part| {
                        part.len() >= 4 && part.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_')
                    }) {
                        return "[REDACTED]".to_string();
                    }
                }

                // Check for regular base64-like strings
                if word.len() >= 20
                   && word.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_')
                   && !word.chars().all(|c| c.is_ascii_digit()) // Don't redact pure numbers
                   && !word.chars().all(|c| c == word.chars().next().unwrap()) // Don't redact repeated chars
                {
                    "[REDACTED]".to_string()
                } else {
                    word.to_string()
                }
            })
            .collect();
        words.join(" ")
    }

    /// Redacts sensitive file paths while preserving filenames for debugging.
    pub(crate) fn redact_file_paths(&self, sanitized: String) -> String {
        let words: Vec<String> = sanitized
            .split_whitespace()
            .map(|word| {
                // Unix paths: /path/to/file
                if word.starts_with('/') && word.matches('/').count() >= 2 {
                    if let Some(filename) = word.split('/').last() {
                        if !filename.is_empty() {
                            format!(".../{}", filename)
                        } else {
                            "[PATH_REDACTED]".to_string()
                        }
                    } else {
                        "[PATH_REDACTED]".to_string()
                    }
                }
                // Windows paths: C:\path\to\file or \\server\share\file
                else if (word.len() >= 3
                    && word.chars().nth(1) == Some(':')
                    && word.chars().nth(2) == Some('\\'))
                    || word.starts_with("\\\\")
                {
                    if let Some(filename) = word.split('\\').last() {
                        if !filename.is_empty() && filename != word {
                            format!("...\\{}", filename)
                        } else {
                            "[PATH_REDACTED]".to_string()
                        }
                    } else {
                        "[PATH_REDACTED]".to_string()
                    }
                } else {
                    word.to_string()
                }
            })
            .collect();
        words.join(" ")
    }

    /// Truncates overly long error messages for security and readability.
    pub(crate) fn truncate_long_message(&self, mut sanitized: String) -> String {
        if sanitized.len() > 500 {
            sanitized.truncate(450);
            sanitized.push_str("... [truncated for security]");
        }
        sanitized
    }

    /// Executes a command with timeout using cross-platform approach.
    ///
    /// This method implements proper timeout handling using threads and channels
    /// to prevent CLI commands from hanging indefinitely. It attempts to minimize
    /// resource leaks by using detached threads for command execution.
    ///
    /// # Arguments
    ///
    /// * `cmd` - The command to execute with configured arguments
    ///
    /// # Returns
    ///
    /// * `Result<std::process::Output>` - The command output or timeout error
    ///
    /// # Errors
    ///
    /// Returns errors for:
    /// - Command timeout (based on configuration)
    /// - CLI not installed
    /// - Command execution failures
    ///
    /// # Resource Management
    ///
    /// When a timeout occurs, the spawned thread may continue running until the
    /// CLI command completes. This is a known limitation of cross-platform timeout
    /// implementation without external process management dependencies.
    fn execute_command_with_timeout(&self, mut cmd: Command) -> Result<std::process::Output> {
        use std::sync::{Arc, Mutex, mpsc};
        use std::thread;
        use std::time::Instant;

        let timeout = self.get_cli_timeout();
        let (tx, rx) = mpsc::channel();

        // Use Arc<Mutex<Option<Child>>> to potentially store process handle for future cleanup
        let process_handle: Arc<Mutex<Option<std::process::Child>>> = Arc::new(Mutex::new(None));
        let process_handle_clone = Arc::clone(&process_handle);

        // Spawn command execution in separate thread
        let handle = thread::spawn(move || {
            // Configure command for potential process management
            let child = match cmd.spawn() {
                Ok(mut child) => {
                    // Store the child process handle for potential cleanup
                    if let Ok(mut handle_guard) = process_handle_clone.lock() {
                        *handle_guard = Some(child);
                    } else {
                        // If we can't store the handle, kill the child and return error
                        let _ = child.kill();
                        let _ = tx.send(Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Failed to manage process handle",
                        )));
                        return;
                    }

                    // Get the child from the mutex to wait for it
                    let child = process_handle_clone.lock().unwrap().take().unwrap();
                    child
                }
                Err(e) => {
                    let _ = tx.send(Err(e));
                    return;
                }
            };

            // Wait for the process to complete and collect output
            let result = child.wait_with_output();

            // Send result through channel (ignore send errors if receiver dropped)
            let _ = tx.send(result);
        });

        let _start_time = Instant::now();

        // Wait for either completion or timeout
        match rx.recv_timeout(timeout) {
            Ok(Ok(output)) => {
                // Command completed successfully, thread will naturally terminate
                let _ = handle.join(); // Clean up the thread
                Ok(output)
            }
            Ok(Err(e)) => {
                // Command execution failed, thread will naturally terminate
                let _ = handle.join(); // Clean up the thread

                if e.kind() == std::io::ErrorKind::NotFound {
                    Err(SecretSpecError::ProviderOperationFailed(
                        "Bitwarden CLI is not installed. Please install it and ensure it's in your PATH.".to_string(),
                    ))
                } else {
                    Err(SecretSpecError::ProviderOperationFailed(format!(
                        "Command execution failed: {}",
                        e
                    )))
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Attempt to kill the process if we still have the handle
                if let Ok(mut handle_guard) = process_handle.lock() {
                    if let Some(ref mut child) = handle_guard.as_mut() {
                        let _ = child.kill(); // Best effort to stop the process
                        let _ = child.wait(); // Clean up zombie process
                    }
                }

                // Note: The thread may still be running briefly, but the process should be killed
                // We don't join the thread here to avoid blocking on the cleanup
                Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Bitwarden CLI command timed out after {} seconds. You can increase the timeout with BITWARDEN_CLI_TIMEOUT environment variable.",
                    timeout.as_secs()
                )))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Thread panicked or channel closed unexpectedly
                // Try to clean up if possible
                let _ = handle.join();

                Err(SecretSpecError::ProviderOperationFailed(
                    "Command execution failed: internal error".to_string(),
                ))
            }
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
        // Performance timing if enabled
        let start_time = if std::env::var("SECRETSPEC_PERF_LOG").is_ok() {
            Some(Instant::now())
        } else {
            None
        };

        let mut cmd = Command::new("bw");

        // Configure server if specified
        if let Some(server) = &self.config.server {
            cmd.env("BW_SERVER", server);
        }

        cmd.args(args);

        let output = self.execute_command_with_timeout(cmd).or_else(|e| {
            // Provide more specific error message for CLI not found
            if e.to_string().contains("not installed") {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "Bitwarden CLI (bw) is not installed.\n\nTo install it:\n  - npm: npm install -g @bitwarden/cli\n  - Homebrew: brew install bitwarden-cli\n  - Chocolatey: choco install bitwarden-cli\n  - Download: https://bitwarden.com/help/cli/\n\nAfter installation, run 'bw login' and 'bw unlock' to authenticate.".to_string(),
                ));
            }
            Err(e)
        })?;

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
                self.sanitize_error_message(&error_msg),
            ));
        }

        let result = String::from_utf8(output.stdout).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(self.sanitize_error_message(&e.to_string()))
        });

        // Log performance timing if enabled
        if let Some(start) = start_time {
            let duration = start.elapsed();
            eprintln!(
                "[PERF] bw {} took {:?} ({}ms)",
                args.join(" "),
                duration,
                duration.as_millis()
            );
        }

        result
    }

    /// Executes a Bitwarden Secrets Manager CLI command with proper error handling.
    ///
    /// This method handles:
    /// - Setting up access token authentication
    /// - Executing the command
    /// - Parsing error messages for common issues
    /// - Providing helpful error messages for missing CLI
    /// - Rate limiting detection and guidance
    ///
    /// # Arguments
    ///
    /// * `args` - The command arguments to pass to `bws`
    ///
    /// # Returns
    ///
    /// * `Result<String>` - The command output or an error
    ///
    /// # Errors
    ///
    /// Returns specific errors for:
    /// - Missing Bitwarden Secrets Manager CLI installation
    /// - Authentication required (missing access token)
    /// - Rate limiting issues
    /// - Command execution failures
    fn execute_bws_command(&self, args: &[&str]) -> Result<String> {
        // Performance timing if enabled
        let start_time = if std::env::var("SECRETSPEC_PERF_LOG").is_ok() {
            Some(Instant::now())
        } else {
            None
        };

        let mut cmd = Command::new("bws");

        // Configure access token - check config first, then environment variable
        if let Some(token) = &self.config.access_token {
            cmd.env("BWS_ACCESS_TOKEN", token);
        } else if let Ok(token) = std::env::var("BWS_ACCESS_TOKEN") {
            cmd.env("BWS_ACCESS_TOKEN", token);
        }

        cmd.args(args);

        let output = self.execute_command_with_timeout(cmd).or_else(|e| {
            // Provide more specific error message for CLI not found
            if e.to_string().contains("not installed") {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "Bitwarden Secrets Manager CLI (bws) is not installed.\n\nTo install it:\n  - Cargo: cargo install bws\n  - Script: curl -sSL https://bitwarden.com/secrets/install | sh\n  - Download: https://github.com/bitwarden/sdk-sm/releases\n\nAfter installation, set BWS_ACCESS_TOKEN environment variable with your access token.".to_string(),
                ));
            }
            Err(e)
        })?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);

            // Handle common Secrets Manager errors
            if error_msg.contains("Access token is required") || error_msg.contains("Unauthorized")
            {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "Bitwarden Secrets Manager authentication required. Please set the BWS_ACCESS_TOKEN environment variable with your machine account access token.".to_string(),
                ));
            }

            if error_msg.contains("Internal error: Failed to parse IdentityTokenResponse") {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "Bitwarden Secrets Manager rate limit exceeded. Please wait ~20 seconds and try again. Consider using state files to reduce API calls.".to_string(),
                ));
            }

            if error_msg.contains("Resource not found") || error_msg.contains("Not found") {
                // This often indicates permission issues rather than missing resources
                return Err(SecretSpecError::ProviderOperationFailed(
                    "Bitwarden Secrets Manager access denied. Please verify:\n1. Machine account has read/write access to the specified project\n2. Project ID is correct\n3. Organization permissions are properly configured\n\nResource not found errors often indicate permission issues rather than missing resources.".to_string()
                ));
            }

            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Bitwarden Secrets Manager CLI error: {}",
                self.sanitize_error_message(&error_msg)
            )));
        }

        let result = String::from_utf8(output.stdout).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(self.sanitize_error_message(&e.to_string()))
        });

        // Log performance timing if enabled
        if let Some(start) = start_time {
            let duration = start.elapsed();
            eprintln!(
                "[PERF] bws {} took {:?} ({}ms)",
                args.join(" "),
                duration,
                duration.as_millis()
            );
        }

        result
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
    #[allow(dead_code)]
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

    /// Gets a secret from Bitwarden Password Manager.
    ///
    /// This method searches the entire vault for items matching the key name,
    /// supporting all item types (Login, Secure Note, Card, Identity) and
    /// extracting values using smart field detection.
    fn get_from_password_manager(
        &self,
        _project: &str,
        key: &str,
        _profile: &str,
    ) -> Result<Option<SecretString>> {
        // Check authentication status first
        if !self.is_authenticated()? {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Bitwarden authentication required. Please run 'bw login' and 'bw unlock', then set the BW_SESSION environment variable.".to_string(),
            ));
        }

        // Use Bitwarden's built-in search to find items matching the key
        let mut list_args = vec!["list", "items", "--search", key];

        // Add organization filter if configured (from config or environment variable)
        let org_id = std::env::var("BITWARDEN_ORGANIZATION")
            .ok()
            .or_else(|| self.config.organization_id.clone());
        if let Some(org_id) = &org_id {
            list_args.extend_from_slice(&["--organizationid", org_id]);
        }

        let output = self.execute_bw_command(&list_args)?;

        // Handle empty output (no search results)
        let items: Vec<BitwardenItem> = if output.trim().is_empty() {
            Vec::new()
        } else {
            // Performance timing for JSON parsing (equivalent to jq processing)
            let parse_start = if std::env::var("SECRETSPEC_PERF_LOG").is_ok() {
                Some(std::time::Instant::now())
            } else {
                None
            };

            let items: Vec<BitwardenItem> = serde_json::from_str(&output).map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to parse Bitwarden search results: {}. Output was: '{}'",
                    e,
                    output.chars().take(100).collect::<String>()
                ))
            })?;

            // Log JSON parsing performance (equivalent to jq timing)
            if let Some(start) = parse_start {
                let duration = start.elapsed();
                eprintln!(
                    "[PERF] JSON parse took {}μs for {} items ({}B)",
                    duration.as_micros(),
                    items.len(),
                    output.len()
                );
            }

            items
        };

        // If we found items, use the first one (Bitwarden's search is already good)
        if let Some(item) = items.first() {
            return self.extract_value_from_item(item, key);
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
        field_hint: &str,
    ) -> Result<Option<SecretString>> {
        // Check if a specific field is requested via environment variable, config, or default
        let requested_field = std::env::var("BITWARDEN_DEFAULT_FIELD")
            .ok()
            .or_else(|| self.config.default_field.clone());

        match item.item_type {
            BitwardenItemType::Login => {
                self.extract_from_login_item(item, field_hint, requested_field.as_deref())
            }
            BitwardenItemType::SecureNote => {
                self.extract_from_secure_note_item(item, field_hint, requested_field.as_deref())
            }
            BitwardenItemType::Card => {
                self.extract_from_card_item(item, field_hint, requested_field.as_deref())
            }
            BitwardenItemType::Identity => {
                self.extract_from_identity_item(item, field_hint, requested_field.as_deref())
            }
            BitwardenItemType::SshKey => {
                self.extract_from_ssh_key_item(item, field_hint, requested_field.as_deref())
            }
        }
    }

    /// Extracts value from Login item (type 1).
    fn extract_from_login_item(
        &self,
        item: &BitwardenItem,
        field_hint: &str,
        requested_field: Option<&str>,
    ) -> Result<Option<SecretString>> {
        if let Some(login) = &item.login {
            // If specific field requested, try to find it
            if let Some(field_name) = requested_field {
                match field_name.to_lowercase().as_str() {
                    "password" => {
                        return Ok(Self::option_to_secret_string(login.password.as_deref()));
                    }
                    "username" => {
                        return Ok(Self::option_to_secret_string(login.username.as_deref()));
                    }
                    "totp" => {
                        return Ok(Self::option_to_secret_string(login.totp.as_deref()));
                    }
                    _ => {
                        // Check custom fields for requested field name
                        if let Some(value) = self.extract_from_custom_fields(item, field_name)? {
                            return Ok(Some(Self::to_secret_string(value)));
                        } else {
                            return Ok(None);
                        }
                    }
                }
            }

            // Smart defaults based on field hint
            let hint_lower = field_hint.to_lowercase();
            if hint_lower.contains("password")
                || hint_lower.contains("pass")
                || hint_lower.contains("secret")
                || hint_lower.contains("token")
            {
                if let Some(password) = &login.password {
                    return Ok(Some(Self::to_secret_string(password)));
                }
            }

            if hint_lower.contains("user") || hint_lower.contains("login") {
                if let Some(username) = &login.username {
                    return Ok(Some(Self::to_secret_string(username)));
                }
            }

            if hint_lower.contains("totp")
                || hint_lower.contains("2fa")
                || hint_lower.contains("mfa")
            {
                if let Some(totp) = &login.totp {
                    return Ok(Some(Self::to_secret_string(totp)));
                }
            }

            // Default: prefer password, then username
            if let Some(password) = &login.password {
                return Ok(Some(Self::to_secret_string(password)));
            }
            if let Some(username) = &login.username {
                return Ok(Some(Self::to_secret_string(username)));
            }
        }

        // Fallback to custom fields
        if let Some(value) = self.extract_from_custom_fields(item, field_hint)? {
            Ok(Some(SecretString::new(value.into())))
        } else {
            Ok(None)
        }
    }

    /// Extracts value from Secure Note item (type 2).
    fn extract_from_secure_note_item(
        &self,
        item: &BitwardenItem,
        field_hint: &str,
        requested_field: Option<&str>,
    ) -> Result<Option<SecretString>> {
        // If specific field requested, check custom fields first
        if let Some(field_name) = requested_field {
            if let Some(value) = self.extract_from_custom_fields(item, field_name)? {
                return Ok(Some(Self::to_secret_string(value)));
            }
        }

        // Look for legacy "value" field (backward compatibility)
        if let Some(value) = self.extract_from_custom_fields(item, "value")? {
            return Ok(Some(Self::to_secret_string(value)));
        }

        // Look for field matching the hint
        if let Some(value) = self.extract_from_custom_fields(item, field_hint)? {
            return Ok(Some(Self::to_secret_string(value)));
        }

        // Fallback: return notes content
        Ok(Self::option_to_secret_string(item.notes.as_deref()))
    }

    /// Extracts value from Card item (type 3).
    fn extract_from_card_item(
        &self,
        item: &BitwardenItem,
        field_hint: &str,
        requested_field: Option<&str>,
    ) -> Result<Option<SecretString>> {
        if let Some(card) = &item.card {
            // If specific field requested
            if let Some(field_name) = requested_field {
                match field_name.to_lowercase().as_str() {
                    "number" => {
                        return Ok(Self::option_to_secret_string(card.number.as_deref()));
                    }
                    "code" | "cvv" | "cvc" => {
                        return Ok(Self::option_to_secret_string(card.code.as_deref()));
                    }
                    "cardholder" | "name" => {
                        return Ok(Self::option_to_secret_string(
                            card.cardholder_name.as_deref(),
                        ));
                    }
                    "brand" => {
                        return Ok(Self::option_to_secret_string(card.brand.as_deref()));
                    }
                    "expmonth" | "exp_month" => {
                        return Ok(Self::option_to_secret_string(card.exp_month.as_deref()));
                    }
                    "expyear" | "exp_year" => {
                        return Ok(Self::option_to_secret_string(card.exp_year.as_deref()));
                    }
                    _ => {
                        if let Some(value) = self.extract_from_custom_fields(item, field_name)? {
                            return Ok(Some(Self::to_secret_string(value)));
                        } else {
                            return Ok(None);
                        }
                    }
                }
            }

            // Smart defaults based on field hint
            let hint_lower = field_hint.to_lowercase();
            if hint_lower.contains("number") || hint_lower.contains("card") {
                if let Some(number) = &card.number {
                    return Ok(Some(Self::to_secret_string(number)));
                }
            }

            if hint_lower.contains("code")
                || hint_lower.contains("cvv")
                || hint_lower.contains("cvc")
            {
                if let Some(code) = &card.code {
                    return Ok(Some(Self::to_secret_string(code)));
                }
            }

            // Default: return card number
            if let Some(number) = &card.number {
                return Ok(Some(Self::to_secret_string(number)));
            }
        }

        // Fallback to custom fields
        if let Some(value) = self.extract_from_custom_fields(item, field_hint)? {
            Ok(Some(SecretString::new(value.into())))
        } else {
            Ok(None)
        }
    }

    /// Extracts value from Identity item (type 4).
    fn extract_from_identity_item(
        &self,
        item: &BitwardenItem,
        field_hint: &str,
        requested_field: Option<&str>,
    ) -> Result<Option<SecretString>> {
        if let Some(identity) = &item.identity {
            // If specific field requested
            if let Some(field_name) = requested_field {
                match field_name.to_lowercase().as_str() {
                    "email" => {
                        return Ok(identity.email.as_ref().map(Self::to_secret_string));
                    }
                    "username" => {
                        return Ok(identity.username.as_ref().map(Self::to_secret_string));
                    }
                    "phone" => {
                        return Ok(identity
                            .phone
                            .as_ref()
                            .map(|p| SecretString::new(p.clone().into())));
                    }
                    "firstname" | "first_name" => {
                        return Ok(Self::option_to_secret_string(
                            identity.first_name.as_deref(),
                        ));
                    }
                    "lastname" | "last_name" => {
                        return Ok(Self::option_to_secret_string(identity.last_name.as_deref()));
                    }
                    "company" => {
                        return Ok(Self::option_to_secret_string(identity.company.as_deref()));
                    }
                    _ => {
                        if let Some(value) = self.extract_from_custom_fields(item, field_name)? {
                            return Ok(Some(Self::to_secret_string(value)));
                        } else {
                            return Ok(None);
                        }
                    }
                }
            }

            // Smart defaults based on field hint
            let hint_lower = field_hint.to_lowercase();
            if hint_lower.contains("email") || hint_lower.contains("mail") {
                if let Some(email) = &identity.email {
                    return Ok(Some(Self::to_secret_string(email)));
                }
            }

            if hint_lower.contains("phone") || hint_lower.contains("tel") {
                if let Some(phone) = &identity.phone {
                    return Ok(Some(Self::to_secret_string(phone)));
                }
            }

            if hint_lower.contains("user") || hint_lower.contains("login") {
                if let Some(username) = &identity.username {
                    return Ok(Some(Self::to_secret_string(username)));
                }
            }

            // Default: prefer email, then username
            if let Some(email) = &identity.email {
                return Ok(Some(Self::to_secret_string(email)));
            }
            if let Some(username) = &identity.username {
                return Ok(Some(Self::to_secret_string(username)));
            }
        }

        // Fallback to custom fields
        if let Some(value) = self.extract_from_custom_fields(item, field_hint)? {
            Ok(Some(SecretString::new(value.into())))
        } else {
            Ok(None)
        }
    }

    /// Extracts value from SSH Key item (type 5).
    fn extract_from_ssh_key_item(
        &self,
        item: &BitwardenItem,
        field_hint: &str,
        requested_field: Option<&str>,
    ) -> Result<Option<SecretString>> {
        if let Some(ssh_key) = &item.ssh_key {
            // If specific field requested
            if let Some(field_name) = requested_field {
                match field_name.to_lowercase().as_str() {
                    "private_key" | "privatekey" | "private" => {
                        return Ok(Self::option_to_secret_string(
                            ssh_key.private_key.as_deref(),
                        ));
                    }
                    "public_key" | "publickey" | "public" => {
                        return Ok(Self::option_to_secret_string(ssh_key.public_key.as_deref()));
                    }
                    "fingerprint" | "key_fingerprint" => {
                        return Ok(Self::option_to_secret_string(
                            ssh_key.key_fingerprint.as_deref(),
                        ));
                    }
                    _ => {
                        if let Some(value) = self.extract_from_custom_fields(item, field_name)? {
                            return Ok(Some(Self::to_secret_string(value)));
                        } else {
                            return Ok(None);
                        }
                    }
                }
            }

            // Smart defaults based on field hint
            let hint_lower = field_hint.to_lowercase();
            if hint_lower.contains("public") || hint_lower.contains("pub") {
                if let Some(public_key) = &ssh_key.public_key {
                    return Ok(Some(Self::to_secret_string(public_key)));
                }
            }

            if hint_lower.contains("fingerprint") || hint_lower.contains("finger") {
                if let Some(fingerprint) = &ssh_key.key_fingerprint {
                    return Ok(Some(Self::to_secret_string(fingerprint)));
                }
            }

            // Default: return private key (most common use case for SSH keys)
            if let Some(private_key) = &ssh_key.private_key {
                return Ok(Some(Self::to_secret_string(private_key)));
            }
        }

        // Fallback to custom fields
        if let Some(value) = self.extract_from_custom_fields(item, field_hint)? {
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

    /// Gets a secret from Bitwarden Secrets Manager.
    fn get_from_secrets_manager(
        &self,
        project: &str,
        key: &str,
        _profile: &str,
    ) -> Result<Option<SecretString>> {
        let perf_enabled = std::env::var("SECRETSPEC_PERF_LOG").is_ok();

        // For Secrets Manager, we create a secret name based on project and key
        // Profile is encoded in the secret name since SM doesn't have built-in profile support
        let secret_name = format!("{}_{}", project, key);

        // First, try to list all secrets to find the one we want
        let mut args = vec!["secret", "list"];

        // If project_id is specified, add it to narrow the search
        if let Some(project_id) = &self.config.project_id {
            args.push(project_id);
        }

        let list_start = if perf_enabled {
            Some(Instant::now())
        } else {
            None
        };
        match self.execute_bws_command(&args) {
            Ok(output) => {
                if let Some(start) = list_start {
                    eprintln!(
                        "[PERF] BWS secret list took {}ms",
                        start.elapsed().as_millis()
                    );
                }

                let parse_start = if perf_enabled {
                    Some(Instant::now())
                } else {
                    None
                };
                let secrets: Vec<BitwardenSecret> = serde_json::from_str(&output)?;
                if let Some(start) = parse_start {
                    eprintln!(
                        "[PERF] BWS JSON parse took {}μs, {} secrets",
                        start.elapsed().as_micros(),
                        secrets.len()
                    );
                }

                // Look for a secret with matching key name
                for secret in secrets {
                    if secret.key == secret_name || secret.key == key {
                        return Ok(Some(SecretString::new(secret.value.into())));
                    }
                }

                // No matching secret found
                Ok(None)
            }
            Err(SecretSpecError::ProviderOperationFailed(msg)) if msg.contains("Not found") => {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Sets a secret in Bitwarden Password Manager.
    ///
    /// This method searches the entire vault for existing items and updates them,
    /// or creates new items with flexible type support based on configuration.
    fn set_to_password_manager(
        &self,
        project: &str,
        key: &str,
        value: &SecretString,
        profile: &str,
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

        // Handle empty output (no search results)
        let items: Vec<BitwardenItem> = if output.trim().is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(&output).map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to parse Bitwarden item list: {}. Output was: '{}'",
                    e,
                    output.chars().take(100).collect::<String>()
                ))
            })?
        };

        // Search strategies (same as get method):
        // 1. Exact name match with secretspec format (for compatibility)
        // 2. Exact name match with key
        // 3. Items containing the key in their name

        let legacy_item_name = self.format_item_name(project, key, profile);

        // Strategy 1: Legacy secretspec format
        if let Some(item) = items.iter().find(|item| item.name == legacy_item_name) {
            return self.update_existing_item(item, key, value.expose_secret());
        }

        // Strategy 2: Exact key match
        if let Some(item) = items.iter().find(|item| item.name == key) {
            return self.update_existing_item(item, key, value.expose_secret());
        }

        // Strategy 3: Contains key in name (case-insensitive)
        if let Some(item) = items
            .iter()
            .find(|item| item.name.to_lowercase().contains(&key.to_lowercase()))
        {
            return self.update_existing_item(item, key, value.expose_secret());
        }

        // No existing item found, create a new one
        self.create_new_item(key, value.expose_secret())
    }

    /// Updates an existing Bitwarden item with a new value.
    ///
    /// This method preserves the item type and structure while updating
    /// the appropriate field based on the item type and configuration.
    fn update_existing_item(&self, item: &BitwardenItem, key: &str, value: &str) -> Result<()> {
        // Determine which field to update based on config and environment variables
        let target_field = std::env::var("BITWARDEN_DEFAULT_FIELD")
            .ok()
            .or_else(|| self.config.default_field.clone())
            .unwrap_or_else(|| item.item_type.default_field_for_hint(key));

        // Get the current item as JSON template
        let mut item_json = self.get_item_as_template(&item.id)?;

        match item.item_type {
            BitwardenItemType::Login => {
                self.update_login_item_json(&mut item_json, &target_field, value)
            }
            BitwardenItemType::SecureNote => {
                self.update_secure_note_item_json(&mut item_json, &target_field, value)
            }
            BitwardenItemType::Card => {
                self.update_card_item_json(&mut item_json, &target_field, value)
            }
            BitwardenItemType::Identity => {
                self.update_identity_item_json(&mut item_json, &target_field, value)
            }
            BitwardenItemType::SshKey => {
                self.update_ssh_key_item_json(&mut item_json, &target_field, value)
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
                SecretSpecError::ProviderOperationFailed(self.sanitize_error_message(&e.to_string()))
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
                self.sanitize_error_message(&error_msg),
            ));
        }

        Ok(())
    }

    /// Creates a new Bitwarden item with flexible type support.
    fn create_new_item(&self, key: &str, value: &str) -> Result<()> {
        // Determine item type from config, environment variable, or use default (Login)
        let item_type = std::env::var("BITWARDEN_DEFAULT_TYPE")
            .ok()
            .and_then(|s| BitwardenItemType::from_str(&s))
            .or(self.config.default_item_type)
            .unwrap_or(BitwardenItemType::Login);

        // Determine target field
        let target_field = std::env::var("BITWARDEN_DEFAULT_FIELD")
            .ok()
            .or_else(|| self.config.default_field.clone())
            .unwrap_or_else(|| item_type.default_field_for_hint(key));

        match item_type {
            BitwardenItemType::Login => self.create_login_item(key, value, &target_field),
            BitwardenItemType::Card => self.create_card_item(key, value, &target_field),
            BitwardenItemType::Identity => self.create_identity_item(key, value, &target_field),
            BitwardenItemType::SecureNote => {
                self.create_secure_note_item(key, value, &target_field)
            }
            BitwardenItemType::SshKey => self.create_ssh_key_item(key, value, &target_field),
        }
    }

    /// Creates a new Login item.
    fn create_login_item(&self, key: &str, value: &str, target_field: &str) -> Result<()> {
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
            "name": key,
            "notes": format!("SecretSpec managed secret: {}", key),
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
    fn create_card_item(&self, key: &str, value: &str, target_field: &str) -> Result<()> {
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
            "name": key,
            "notes": format!("SecretSpec managed secret: {}", key),
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
    fn create_identity_item(&self, key: &str, value: &str, target_field: &str) -> Result<()> {
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
            "name": key,
            "notes": format!("SecretSpec managed secret: {}", key),
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
    fn create_secure_note_item(&self, key: &str, value: &str, target_field: &str) -> Result<()> {
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
            "name": key,
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
    fn create_ssh_key_item(&self, key: &str, value: &str, target_field: &str) -> Result<()> {
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
                    "name": key,
                    "notes": format!("SecretSpec managed secret: {}", key),
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
            "name": key,
            "notes": format!("SecretSpec managed secret: {}", key),
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
                SecretSpecError::ProviderOperationFailed(self.sanitize_error_message(&e.to_string()))
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
                self.sanitize_error_message(&error_msg),
            ));
        }

        Ok(())
    }

    /// Sets a secret in Bitwarden Secrets Manager.
    fn set_to_secrets_manager(
        &self,
        project: &str,
        key: &str,
        value: &SecretString,
        _profile: &str,
    ) -> Result<()> {
        // For Secrets Manager, we create a secret name based on project and key
        let secret_name = format!("{}_{}", project, key);

        // Check if we have a required project_id
        let project_id = self.config.project_id.as_ref().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "Project ID is required for Bitwarden Secrets Manager. Use bws://project-id or bws://?project=project-id".to_string()
            )
        })?;

        // Try to create the secret first (it will fail if it exists)
        let note = format!("SecretSpec managed secret: {}/{}", project, key);
        let create_args = vec![
            "secret",
            "create",
            &secret_name,
            value.expose_secret(),
            project_id,
            "--note",
            &note,
        ];

        match self.execute_bws_command(&create_args) {
            Ok(_) => {
                // Secret created successfully
                Ok(())
            }
            Err(SecretSpecError::ProviderOperationFailed(msg))
                if msg.contains("already exists") =>
            {
                // Secret exists, now we need to update it
                // First list secrets to find the ID
                let list_args = vec!["secret", "list", project_id];
                match self.execute_bws_command(&list_args) {
                    Ok(output) => {
                        let secrets: Vec<BitwardenSecret> = serde_json::from_str(&output)?;

                        // Look for existing secret
                        for secret in secrets {
                            if secret.key == secret_name || secret.key == key {
                                // Secret exists, update it
                                let update_args = vec![
                                    "secret",
                                    "edit",
                                    &secret.id,
                                    "--key",
                                    &secret_name,
                                    "--value",
                                    value.expose_secret(),
                                ];

                                self.execute_bws_command(&update_args)?;
                                return Ok(());
                            }
                        }

                        // If we get here, the secret wasn't found in the list
                        Err(SecretSpecError::ProviderOperationFailed(
                            "Secret creation failed with 'already exists' but could not find it in the list".to_string()
                        ))
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }
}

impl Provider for BitwardenProvider {
    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    /// Retrieves a secret from Bitwarden.
    ///
    /// Searches for an item with the name formatted according to the folder_prefix
    /// configuration. The method looks for a field named "value" first,
    /// then falls back to examining other fields or notes.
    ///
    /// # Arguments
    ///
    /// * `project` - The project name
    /// * `key` - The secret key to retrieve
    /// * `profile` - The profile name
    ///
    /// # Returns
    ///
    /// * `Ok(Some(value))` - The secret value if found
    /// * `Ok(None)` - No secret found with the given key
    /// * `Err(_)` - Authentication or retrieval error
    ///
    /// # Errors
    ///
    /// - Authentication required if not logged in or unlocked
    /// - Item retrieval failures
    /// - JSON parsing errors
    fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<SecretString>> {
        let start_time = if std::env::var("SECRETSPEC_PERF_LOG").is_ok() {
            Some(Instant::now())
        } else {
            None
        };

        let result = match self.config.service {
            BitwardenService::PasswordManager => {
                self.get_from_password_manager(project, key, profile)
            }
            BitwardenService::SecretsManager => {
                self.get_from_secrets_manager(project, key, profile)
            }
        };

        // Log performance timing if enabled
        if let Some(start) = start_time {
            let duration = start.elapsed();
            eprintln!(
                "[PERF] get('{}') took {:?} ({}ms)",
                key,
                duration,
                duration.as_millis()
            );
        }

        result
    }

    /// Stores or updates a secret in Bitwarden.
    ///
    /// If an item with the same name exists, it updates the "value" field.
    /// Otherwise, it creates a new Secure Note item with the secret data.
    ///
    /// # Arguments
    ///
    /// * `project` - The project name
    /// * `key` - The secret key
    /// * `value` - The secret value to store
    /// * `profile` - The profile name
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Secret stored successfully
    /// * `Err(_)` - Storage or authentication error
    ///
    /// # Errors
    ///
    /// - Authentication required if not logged in or unlocked
    /// - Item creation/update failures
    /// - Temporary file creation errors
    fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()> {
        let start_time = if std::env::var("SECRETSPEC_PERF_LOG").is_ok() {
            Some(Instant::now())
        } else {
            None
        };

        let result = match self.config.service {
            BitwardenService::PasswordManager => {
                self.set_to_password_manager(project, key, value, profile)
            }
            BitwardenService::SecretsManager => {
                self.set_to_secrets_manager(project, key, value, profile)
            }
        };

        // Log performance timing if enabled
        if let Some(start) = start_time {
            let duration = start.elapsed();
            eprintln!(
                "[PERF] set('{}') took {:?} ({}ms)",
                key,
                duration,
                duration.as_millis()
            );
        }

        result
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
