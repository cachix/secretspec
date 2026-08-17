use crate::provider::{Address, DiscoveryContext, Provider, ProviderCredentials, ProviderUrl};
use crate::{Result, Secret, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

    /// Get string representation.
    ///
    /// Each spelling is one `from_str` accepts, so `uri()` can emit `type=`
    /// and have it read back as the same type.
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    /// Item type selected by `?type=`, if the address named one.
    ///
    /// `None` means the address did not ask for a type, which is distinct from
    /// asking for a Login: a named type also *filters* reads and update targets
    /// (see [`BitwardenProvider::find_addressed_item`]), while an unnamed one
    /// matches any type and only picks a default at creation time. Collapsing
    /// the two would make `bw://` behave as though every read had been
    /// restricted to Logins.
    ///
    /// Can be overridden by BITWARDEN_DEFAULT_TYPE environment variable.
    ///
    /// Defaults to `None` rather than `Some(Login)`, which is what makes the
    /// distinction above expressible; creation falls back to Login in
    /// `create_new_item`, the only place that has to pick a type when the
    /// address named none.
    pub default_item_type: Option<BitwardenItemType>,
    /// Default field name for storing values.
    /// Can be overridden by BITWARDEN_DEFAULT_FIELD environment variable.
    pub default_field: Option<String>,
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
                "type" => config.default_item_type = Some(parse_item_type(&value, "?type=")?),
                "field" => config.default_field = Some(value.into_owned()),
                unknown => {
                    // Ignoring these made `?feild=api_key` a silent no-op: the
                    // address looked accepted and the secret came back from
                    // whatever the default field was.
                    return Err(SecretSpecError::ProviderOperationFailed(format!(
                        "Unknown Bitwarden URI parameter '{unknown}'. Valid parameters are \
                         org (or organization), collection, server, folder, type, and field."
                    )));
                }
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
    /// Memoized organization/collection resolution, so the two `bw list` calls
    /// that turn names into UUIDs run once per process rather than once per
    /// CLI invocation. Empty addresses resolve without spawning anything.
    /// Carries its error as a `String` for the same reason as `server_check`.
    vault_scope: OnceLock<std::result::Result<VaultScope, String>>,
    /// Executable used by tests to exercise subprocess failures without
    /// mutating the process-global PATH observed by concurrently running tests.
    #[cfg(test)]
    cli_binary_path: std::path::PathBuf,
}

/// Server the `bw` CLI targets when no self-hosted server is configured. `bw
/// status` reports `"serverUrl": null` in that state rather than naming it.
const BITWARDEN_CLOUD_SERVER: &str = "https://vault.bitwarden.com";

/// Placeholder for the `sshKey` members a write does not address.
///
/// SSH key items must carry a non-empty string in all three of `privateKey`,
/// `publicKey` and `keyFingerprint`; a null loses the whole object. Chosen to
/// read as obviously synthetic in the Bitwarden UI, so it is not mistaken for
/// key material a user should try to use.
const SSH_KEY_FIELD_UNSET: &str = "(not set by SecretSpec)";

/// Extracts `serverUrl` from `bw status` JSON.
///
/// Returns `Ok(None)` when the CLI targets the public cloud, which it reports as
/// `null` (older builds may omit the key entirely).
fn parse_status_server(stdout: &str) -> std::result::Result<Option<String>, String> {
    let status: serde_json::Value = serde_json::from_str(stdout.trim()).map_err(|e| {
        format!(
            "could not parse `bw status` output as JSON: {}",
            crate::error::display_error_chain(&e)
        )
    })?;

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

/// An organization or collection as listed by the `bw` CLI.
///
/// `bw list organizations` and `bw list collections` share the `id`/`name`
/// shape; collections additionally name the organization they belong to.
#[derive(Debug, Deserialize)]
struct BitwardenNamedObject {
    id: String,
    name: String,
    #[serde(rename = "organizationId", default)]
    organization_id: Option<String>,
}

/// The organization and collection this provider addresses, as the UUIDs the
/// `bw` CLI requires.
///
/// The CLI's `--organizationid` and `--collectionid` accept ids only — every
/// example in its help output is a UUID — while `bw://myorg@dev-secrets` reads
/// as a pair of names. [`resolve_scope`] closes that gap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct VaultScope {
    organization_id: Option<String>,
    collection_id: Option<String>,
}

/// Where a newly created item is filed.
///
/// Unlike a search filter this is not a query but the item's home, so creation
/// needs the organization *and* the collection together: an item filed into a
/// collection without naming its organization is rejected, and one created with
/// neither lands in the personal vault where no collection-scoped read reaches
/// it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ItemPlacement {
    organization_id: Option<String>,
    collection_ids: Option<Vec<String>>,
}

impl From<&VaultScope> for ItemPlacement {
    fn from(scope: &VaultScope) -> Self {
        Self {
            organization_id: scope.organization_id.clone(),
            collection_ids: scope.collection_id.clone().map(|id| vec![id]),
        }
    }
}

/// Parses one of the `bw list` outputs.
///
/// Empty output counts as an empty list rather than a parse failure. The CLI
/// prints nothing at all when it holds no decryptable copy of the data — a
/// stale session, or a vault that has never been synced, both surface that way
/// — and "no collection matching 'dev-secrets'; run `bw sync`" points at the
/// problem far better than a JSON error would.
fn parse_named_objects(
    json: &str,
    kind: &str,
) -> std::result::Result<Vec<BitwardenNamedObject>, String> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    serde_json::from_str(trimmed).map_err(|e| {
        format!(
            "could not parse `bw list {kind}` output as JSON: {}",
            crate::error::display_error_chain(&e)
        )
    })
}

/// Names an organization for an error message, preferring its human-readable
/// name and falling back to the bare id when the CLI never listed it.
fn describe_org(id: Option<&str>, organizations: &[BitwardenNamedObject]) -> String {
    match id {
        None => "your personal vault".to_string(),
        Some(id) => match organizations.iter().find(|o| o.id == id) {
            Some(org) => format!("'{}' ({id})", org.name),
            None => format!("'{id}'"),
        },
    }
}

/// Renders the addressable organizations for an error message.
fn list_organizations(organizations: &[BitwardenNamedObject]) -> String {
    if organizations.is_empty() {
        return "The bw CLI listed no organizations. If you do belong to one, the \
                CLI cannot currently read it: check that BW_SESSION is exported \
                and current, then run `bw sync --force`."
            .to_string();
    }

    let mut out = String::from("Available organizations:");
    for org in organizations {
        out.push_str(&format!("\n  - {} ({})", org.name, org.id));
    }
    out
}

/// Renders the addressable collections for an error message, each with the
/// organization it lives in.
fn list_collections(
    collections: &[&BitwardenNamedObject],
    organizations: &[BitwardenNamedObject],
) -> String {
    if collections.is_empty() {
        return "The bw CLI listed no collections. If you expected some, the CLI \
                cannot currently read them: check that BW_SESSION is exported and \
                current, then run `bw sync --force`."
            .to_string();
    }

    let mut out = String::from("Available collections:");
    for collection in collections {
        out.push_str(&format!(
            "\n  - {} ({}) — organization {}",
            collection.name,
            collection.id,
            describe_org(collection.organization_id.as_deref(), organizations)
        ));
    }
    out
}

/// Resolves the organization named in the address, by id or by name.
fn resolve_organization<'a>(
    organizations: &'a [BitwardenNamedObject],
    requested: &str,
) -> std::result::Result<&'a BitwardenNamedObject, String> {
    if let Some(hit) = organizations.iter().find(|o| o.id == requested) {
        return Ok(hit);
    }

    // `to_lowercase`, not `eq_ignore_ascii_case`: the CLI compares names with
    // JavaScript's `toLowerCase`, so an ASCII-only fold would leave a name like
    // `ÜBERBLICK` addressable in `bw` but not here. Same fold as
    // `find_addressed_item` uses for item names.
    let matches: Vec<&BitwardenNamedObject> = organizations
        .iter()
        .filter(|o| o.name.to_lowercase() == requested.to_lowercase())
        .collect();

    match matches.as_slice() {
        [only] => Ok(only),
        [] => Err(format!(
            "No organization matching '{requested}' is visible to the bw CLI.\n\n{}\n\n\
             An organization is addressed by name or by UUID. Run `bw sync` if it was \
             created or shared with you recently.",
            list_organizations(organizations)
        )),
        multiple => Err(format!(
            "Organization name '{requested}' is ambiguous: {} organizations share it. \
             Use the organization's UUID instead.\n\n{}",
            multiple.len(),
            list_organizations(organizations)
        )),
    }
}

/// Verifies that a collection found by id lives in the organization the address
/// named.
fn check_collection_org<'a>(
    collection: &'a BitwardenNamedObject,
    organizations: &[BitwardenNamedObject],
    org: Option<&BitwardenNamedObject>,
) -> std::result::Result<&'a BitwardenNamedObject, String> {
    let Some(org) = org else {
        return Ok(collection);
    };

    if collection.organization_id.as_deref() == Some(org.id.as_str()) {
        return Ok(collection);
    }

    Err(format!(
        "Collection '{}' ({}) belongs to organization {}, but the address names {}.\n\n\
         A collection id already identifies its organization, so drop the organization \
         from the address or correct it.",
        collection.name,
        collection.id,
        describe_org(collection.organization_id.as_deref(), organizations),
        describe_org(Some(org.id.as_str()), organizations),
    ))
}

/// Resolves the collection named in the address, by id or by name.
///
/// An id is matched against the whole vault rather than the addressed
/// organization, so a collection that exists but sits elsewhere is reported as
/// a mismatch instead of the much vaguer "not found".
fn resolve_collection<'a>(
    collections: &'a [BitwardenNamedObject],
    organizations: &[BitwardenNamedObject],
    requested: &str,
    org: Option<&BitwardenNamedObject>,
) -> std::result::Result<&'a BitwardenNamedObject, String> {
    if let Some(hit) = collections.iter().find(|c| c.id == requested) {
        return check_collection_org(hit, organizations, org);
    }

    // Folded like organization names above.
    let by_name: Vec<&BitwardenNamedObject> = collections
        .iter()
        .filter(|c| c.name.to_lowercase() == requested.to_lowercase())
        .collect();

    // Narrow by organization only when the address gave one: an unqualified
    // name that occurs exactly once in the vault is unambiguous by itself.
    let scoped: Vec<&BitwardenNamedObject> = match org {
        Some(org) => by_name
            .iter()
            .copied()
            .filter(|c| c.organization_id.as_deref() == Some(org.id.as_str()))
            .collect(),
        None => by_name.clone(),
    };

    match scoped.as_slice() {
        [only] => Ok(only),
        // The name exists, just not where the address said to look. Report the
        // disagreement rather than claiming the collection does not exist.
        [] if !by_name.is_empty() => {
            let org = org.expect("names are only narrowed when the address gave an organization");
            Err(format!(
                "Collection '{requested}' is not in organization {}. It exists in {}.\n\n\
                 Correct the organization in the address, or drop it and address the \
                 collection on its own.",
                describe_org(Some(org.id.as_str()), organizations),
                by_name
                    .iter()
                    .map(|c| describe_org(c.organization_id.as_deref(), organizations))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }
        [] => {
            let visible: Vec<&BitwardenNamedObject> = match org {
                Some(org) => collections
                    .iter()
                    .filter(|c| c.organization_id.as_deref() == Some(org.id.as_str()))
                    .collect(),
                None => collections.iter().collect(),
            };
            let scope_note = match org {
                Some(org) => format!(" in organization '{}'", org.name),
                None => String::new(),
            };
            Err(format!(
                "No collection matching '{requested}' is visible to the bw CLI{scope_note}.\n\n{}\n\n\
                 A collection is addressed by name or by UUID. Run `bw sync` if it was \
                 created or shared with you recently.",
                list_collections(&visible, organizations)
            ))
        }
        multiple => Err(format!(
            "Collection name '{requested}' is ambiguous: {} collections share it.\n\n{}\n\n\
             Qualify it with an organization, for example bw://{}@{requested}, or use \
             the collection's UUID.",
            multiple.len(),
            list_collections(multiple, organizations),
            multiple
                .first()
                .and_then(|c| c.organization_id.as_deref())
                .and_then(|id| organizations.iter().find(|o| o.id == id))
                .map(|o| o.name.as_str())
                .unwrap_or("myorg")
        )),
    }
}

/// Resolves the addressed organization and collection to the UUIDs the CLI needs.
///
/// Names and ids are both accepted, and an id is validated rather than trusted:
/// a value that looks like a UUID but names nothing in the vault is a typo, and
/// failing here beats a silent empty result later. Resolution is skipped
/// entirely when the address configures neither, so a plain `bw://` spawns no
/// extra CLI calls.
///
/// When both are given the organization acts as scope and assertion — it
/// disambiguates the collection name and must agree with the collection's real
/// organization — but it is deliberately not returned as a second search
/// filter. See [`BitwardenProvider::search_filter_args`].
fn resolve_scope(
    organizations_json: &str,
    collections_json: &str,
    requested_org: Option<&str>,
    requested_collection: Option<&str>,
) -> std::result::Result<VaultScope, String> {
    if requested_org.is_none() && requested_collection.is_none() {
        return Ok(VaultScope::default());
    }

    let organizations = parse_named_objects(organizations_json, "organizations")?;
    let collections = parse_named_objects(collections_json, "collections")?;

    let org = requested_org
        .map(|requested| resolve_organization(&organizations, requested))
        .transpose()?;

    let Some(requested_collection) = requested_collection else {
        return Ok(VaultScope {
            organization_id: org.map(|o| o.id.clone()),
            collection_id: None,
        });
    };

    let collection = resolve_collection(&collections, &organizations, requested_collection, org)?;

    Ok(VaultScope {
        // A collection uniquely determines its organization, so record the one
        // it actually belongs to. This is what lets `bw://dev-secrets` work
        // without naming the organization at all.
        organization_id: collection
            .organization_id
            .clone()
            .or_else(|| org.map(|o| o.id.clone())),
        collection_id: Some(collection.id.clone()),
    })
}

/// Parses an addressed item type, naming the offending value and its source.
///
/// Shared by `?type=` and `BITWARDEN_DEFAULT_TYPE` so a spelling the address
/// rejects cannot still be swallowed by the environment. Both used to discard
/// what they could not parse, leaving the default in place — a typo then
/// surfaced much later, as a Login created where an SSH key was asked for.
fn parse_item_type(value: &str, source: &str) -> Result<BitwardenItemType> {
    BitwardenItemType::from_str(value).ok_or_else(|| {
        SecretSpecError::ProviderOperationFailed(format!(
            "Unknown Bitwarden item type '{value}' in {source}. Valid types are \
             login, note (or securenote, secure_note), card, identity, and ssh \
             (or sshkey, ssh_key)."
        ))
    })
}

/// The member of `item_type`'s JSON object that `field` names, if any.
///
/// One table for both writers — the creation template and the update mutation —
/// so a name cannot be a built-in on one path and a custom field on the other.
/// That split is exactly what made `set --field exp_month` store a custom field
/// while `get` read the untouched `card.expMonth`.
///
/// Reading resolves the same aliases through its typed accessors rather than
/// through JSON, so it cannot share this table directly;
/// `a_built_in_field_named_on_create_is_readable_under_that_name` walks every
/// alias here and is what keeps the two descriptions in step.
fn builtin_member(item_type: BitwardenItemType, field: &str) -> Option<&'static str> {
    let field = field.to_lowercase();
    let member = match item_type {
        BitwardenItemType::Login => match field.as_str() {
            "password" => "password",
            "username" => "username",
            "totp" => "totp",
            _ => return None,
        },
        BitwardenItemType::Card => match field.as_str() {
            "number" => "number",
            "code" | "cvv" | "cvc" => "code",
            "cardholder" | "name" => "cardholderName",
            "brand" => "brand",
            "expmonth" | "exp_month" => "expMonth",
            "expyear" | "exp_year" => "expYear",
            _ => return None,
        },
        BitwardenItemType::Identity => match field.as_str() {
            "email" => "email",
            "username" => "username",
            "phone" => "phone",
            "firstname" | "first_name" => "firstName",
            "lastname" | "last_name" => "lastName",
            "company" => "company",
            _ => return None,
        },
        BitwardenItemType::SshKey => match field.as_str() {
            "private_key" | "privatekey" | "private" => "privateKey",
            "public_key" | "publickey" | "public" => "publicKey",
            "fingerprint" | "key_fingerprint" => "keyFingerprint",
            _ => return None,
        },
        // A note's body is not a member of a sub-object; `is_note_body_field`
        // is its equivalent.
        BitwardenItemType::SecureNote => return None,
    };
    Some(member)
}

/// Describes a `bw` invocation that exited non-zero.
///
/// The CLI's stderr used to be the whole error, which left the reader to guess
/// which of several `bw` calls behind one `get` or `set` had failed, and lost
/// the exit status entirely. `operation` names the call the way it would be
/// typed.
///
/// Not a job for [`crate::error::display_error_chain`]: this is a subprocess's
/// output, not a `std::error::Error`, so there is no `source()` to walk. What
/// was missing here is attribution.
///
/// Falls back to stdout when stderr is empty because `bw` is not consistent
/// about which stream carries a diagnostic, and an error saying only that a
/// command failed is barely better than the status code.
///
/// Safe to name the command: secret *values* never reach argv. `set` writes
/// them as base64 JSON on stdin (see `create_item_from_template` and
/// `update_item_with_json`); arguments carry only subcommands, ids and item
/// names.
fn bw_command_failed(operation: &str, output: &std::process::Output) -> SecretSpecError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = match stderr.trim() {
        "" => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.trim().to_string()
        }
        message => message.to_string(),
    };

    let status = match output.status.code() {
        Some(code) => format!("exit status {code}"),
        None => "terminated by a signal".to_string(),
    };

    if detail.is_empty() {
        SecretSpecError::ProviderOperationFailed(format!("`{operation}` failed ({status})"))
    } else {
        SecretSpecError::ProviderOperationFailed(format!(
            "`{operation}` failed ({status}): {detail}"
        ))
    }
}

/// Whether `field` addresses a secure note's body rather than a custom field.
///
/// The one built-in a Secure Note has. Shared by the reader, the updater and
/// the creation template so a value written under this name is read back from
/// the same place; the fold matches how field names are compared everywhere
/// else in this provider.
fn is_note_body_field(field: &str) -> bool {
    field.eq_ignore_ascii_case("notes")
}

/// Finds the one item `item_name` addresses, for both reads and writes.
///
/// Narrows the way `bw get item` itself does — by name, then by type, then
/// refusing what is still ambiguous — with one deliberate difference: the name
/// has to match in full.
///
/// `bw`'s own lookup accepts a substring (`searchCiphersBasic` splits the query
/// and matches parts across name, username and URIs) because it is an
/// interactive affordance: when it matches several items it prints their ids
/// and a human picks one. A provider resolving a coordinate from
/// `secretspec.toml` has no such backstop, and a substring that quietly
/// resolves to a neighbouring item is a wrong secret on a read and an
/// overwritten one on a write. So the fuzziness goes and the guardrails —
/// the type filter and the hard stop on ambiguity — stay.
///
/// Case still folds, because `bw` folds it: an item the user can address in the
/// CLI has to be addressable here. `to_lowercase` rather than
/// `eq_ignore_ascii_case` for the same reason as `dashlane`'s titles — the CLI
/// compares with JavaScript's `toLowerCase`, so an ASCII-only fold would leave
/// `Überblick` unreachable as `überblick`.
///
/// `require_type` is `Some` only when the address named a type; see
/// [`BitwardenConfig::default_item_type`].
fn find_addressed_item<'a>(
    items: &'a [BitwardenItem],
    item_name: &str,
    require_type: Option<BitwardenItemType>,
) -> Result<Option<&'a BitwardenItem>> {
    let wanted = item_name.to_lowercase();
    let by_name: Vec<&BitwardenItem> = items
        .iter()
        .filter(|item| item.name.to_lowercase() == wanted)
        .collect();

    // An addressed type filters unconditionally, which is the one place this
    // is stricter than `bw get` — the CLI only consults its type filter to
    // break a tie. `?type=` is a standing part of the address rather than a
    // one-off flag, so it has to mean the same thing on every operation: a
    // `set` through `bw://?type=card` creates a Card next to a same-named
    // Login, and a read through it then has to find that Card rather than the
    // Login that also matches the name.
    let candidates: Vec<&BitwardenItem> = match require_type {
        Some(wanted_type) => by_name
            .into_iter()
            .filter(|item| item.item_type == wanted_type)
            .collect(),
        None => by_name,
    };

    match candidates.as_slice() {
        [] => Ok(None),
        [only] => Ok(Some(only)),
        several => Err(SecretSpecError::ProviderOperationFailed(format!(
            "{} Bitwarden items are named '{item_name}'. Rename them, or point the \
             secret at one of these ids with ref = {{ item = \"<id>\" }}:\n{}",
            several.len(),
            several
                .iter()
                .map(|item| format!("  {} ({:?})", item.id, item.item_type))
                .collect::<Vec<_>>()
                .join("\n"),
        ))),
    }
}

/// Builds declarations for the Bitwarden items the provider can address.
///
/// Reflection uses the same optional type filter as reads and writes. Item
/// names are otherwise direct convention addresses, so every reflected name
/// must already be a valid SecretSpec identifier. Bitwarden compares names
/// case-insensitively and permits duplicates; reject either kind of collision
/// instead of generating declarations that would be ambiguous at read time.
fn declarations_from_items(
    items: &[BitwardenItem],
    required_type: Option<BitwardenItemType>,
) -> Result<HashMap<String, Secret>> {
    let mut declarations = HashMap::new();
    let mut seen_names = HashMap::<String, &BitwardenItem>::new();

    for item in items
        .iter()
        .filter(|item| required_type.is_none_or(|item_type| item.item_type == item_type))
    {
        if !crate::config::is_valid_identifier(&item.name) {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Bitwarden item '{}' cannot become a SecretSpec declaration: names must be \
                 alphanumeric and underscores and cannot start with a number. Rename the item \
                 or narrow discovery with a collection and/or `?type=`.",
                item.name
            )));
        }
        if item.name == "defaults" {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Bitwarden item 'defaults' cannot become a SecretSpec declaration because \
                 that name is reserved for profile defaults. Rename the item or narrow \
                 discovery with a collection and/or `?type=`."
                    .to_string(),
            ));
        }

        let folded_name = item.name.to_lowercase();
        if let Some(previous) = seen_names.insert(folded_name, item) {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Bitwarden items '{}' ({}) and '{}' ({}) have names that collide \
                 case-insensitively. Rename one or narrow discovery with `?type=` so every \
                 reflected declaration has one address.",
                previous.name, previous.id, item.name, item.id
            )));
        }

        declarations.insert(
            item.name.clone(),
            Secret {
                description: Some(format!("{} Bitwarden secret", item.name)),
                required: Some(true),
                ..Default::default()
            },
        );
    }

    Ok(declarations)
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
            vault_scope: OnceLock::new(),
            #[cfg(test)]
            cli_binary_path: "bw".into(),
        }
    }

    /// Builds a command for the Bitwarden CLI.
    fn command(&self) -> Command {
        #[cfg(test)]
        return Command::new(&self.cli_binary_path);

        #[cfg(not(test))]
        Command::new("bw")
    }

    /// The organization the address asks for, before resolution.
    ///
    /// `BITWARDEN_ORGANIZATION` wins over the provider URI, matching the
    /// precedence every call site used before resolution was centralized here.
    fn requested_org(&self) -> Option<String> {
        std::env::var("BITWARDEN_ORGANIZATION")
            .ok()
            .or_else(|| self.config.organization_id.clone())
    }

    /// The collection the address asks for, before resolution.
    fn requested_collection(&self) -> Option<String> {
        std::env::var("BITWARDEN_COLLECTION")
            .ok()
            .or_else(|| self.config.collection_id.clone())
    }

    /// Resolves the addressed organization and collection to UUIDs, once.
    fn resolved_scope(&self) -> Result<&VaultScope> {
        match self.vault_scope.get_or_init(|| self.look_up_scope()) {
            Ok(scope) => Ok(scope),
            Err(message) => Err(SecretSpecError::ProviderOperationFailed(message.clone())),
        }
    }

    /// The resolved organization UUID, if the address names one (or if the
    /// addressed collection implies one).
    fn resolved_org_id(&self) -> Result<Option<&str>> {
        Ok(self.resolved_scope()?.organization_id.as_deref())
    }

    /// Runs the `bw list` calls behind [`Self::resolved_scope`].
    ///
    /// Split out so the memoization stays readable and so [`resolve_scope`],
    /// which holds all the matching rules, can be unit-tested against pinned
    /// CLI output without spawning anything.
    fn look_up_scope(&self) -> std::result::Result<VaultScope, String> {
        let requested_org = self.requested_org();
        let requested_collection = self.requested_collection();

        // Skip both CLI calls when the address scopes nothing, which is the
        // common `bw://` case.
        if requested_org.is_none() && requested_collection.is_none() {
            return Ok(VaultScope::default());
        }

        let organizations = self
            .execute_bw_command(&["list", "organizations"])
            .map_err(|e| {
                format!(
                    "could not list Bitwarden organizations: {}",
                    crate::error::display_error_chain(&e)
                )
            })?;
        let collections = self
            .execute_bw_command(&["list", "collections"])
            .map_err(|e| {
                format!(
                    "could not list Bitwarden collections: {}",
                    crate::error::display_error_chain(&e)
                )
            })?;

        resolve_scope(
            &organizations,
            &collections,
            requested_org.as_deref(),
            requested_collection.as_deref(),
        )
    }

    /// The filter flags for an item **search**, of which there is at most one.
    ///
    /// `bw list` combines multiple filters with a logical **OR**, so passing
    /// `--organizationid` alongside `--collectionid` widens the search to the
    /// whole organization instead of narrowing it to the collection. That makes
    /// every collection in an organization address the same set of items, which
    /// is the very bug this resolution exists to fix, and on the write path it
    /// lets `set` overwrite a same-named item in a sibling collection.
    ///
    /// Measured against bitwarden-cli 2025.11.0, in an organization holding a
    /// single item that belongs to one collection and not the other:
    ///
    /// ```text
    /// bw list items --organizationid $ORG                        -> 1
    /// bw list items --collectionid $EMPTY_COLLECTION             -> 0
    /// bw list items --organizationid $ORG --collectionid $EMPTY_COLLECTION -> 1
    /// ```
    ///
    /// The last line returns an item the named collection does not contain.
    /// Under AND it would return none. The CLI's own help says the same
    /// ("Combining multiple filters performs a logical OR operation"), but this
    /// is the observation the rule rests on — do not restore the second flag on
    /// the assumption that two filters narrow.
    ///
    /// A collection id already identifies its organization, so sending the
    /// collection alone loses nothing. The organization is still resolved and
    /// checked against the collection; it just is not re-sent as a filter.
    ///
    /// This is only for searches. `bw get`/`create`/`edit item` take
    /// `--organizationid` as the organization to act in rather than as a
    /// filter, and the creation templates need both ids because that is what
    /// places the new item.
    fn search_filter_args(&self) -> Result<Vec<String>> {
        let scope = self.resolved_scope()?;

        if let Some(collection_id) = scope.collection_id.as_deref() {
            return Ok(vec![
                "--collectionid".to_string(),
                collection_id.to_string(),
            ]);
        }

        if let Some(org_id) = scope.organization_id.as_deref() {
            return Ok(vec!["--organizationid".to_string(), org_id.to_string()]);
        }

        Ok(Vec::new())
    }

    /// The item type this address selected, if it selected one at all.
    ///
    /// Environment beats config, matching every other resolution in this
    /// provider. `None` means no type was named, which reads and writes treat
    /// as "any type" rather than as Login — only `create_new_item` has to
    /// invent one. See [`BitwardenConfig::default_item_type`].
    fn resolved_item_type(&self) -> Result<Option<BitwardenItemType>> {
        match std::env::var("BITWARDEN_DEFAULT_TYPE") {
            Ok(raw) => parse_item_type(&raw, "BITWARDEN_DEFAULT_TYPE").map(Some),
            Err(_) => Ok(self.config.default_item_type),
        }
    }

    /// Lists the items in scope, optionally narrowed by bw's own search.
    ///
    /// `search` is an optimization only. Callers must treat an empty result as
    /// "the prefilter matched nothing" rather than as "no such item"; see
    /// `get_from_password_manager` for the CLI bug that makes the distinction
    /// load-bearing.
    fn list_items(&self, search: Option<&str>) -> Result<Vec<BitwardenItem>> {
        let mut list_args = vec!["list", "items"];
        if let Some(term) = search {
            list_args.push("--search");
            list_args.push(term);
        }

        // At most one scope filter; see `search_filter_args` for why a second
        // would widen the candidate set rather than narrow it. That matters
        // most on the write path, where a wider set means `set` could update a
        // same-named item sitting in a sibling collection.
        let filter = self.search_filter_args()?;
        list_args.extend(filter.iter().map(String::as_str));

        let output = self.execute_bw_command(&list_args)?;
        Ok(serde_json::from_str(&output)?)
    }

    /// Where newly created items are filed, with names already resolved.
    fn item_placement(&self) -> Result<ItemPlacement> {
        Ok(ItemPlacement::from(self.resolved_scope()?))
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
        let output = match self.command().args(["--nointeraction", "status"]).output() {
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

        let mut cmd = self.command();

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

            // Both cases above are more useful than anything generic, so they
            // stay ahead of it; this is for everything else.
            return Err(bw_command_failed(
                &format!("bw {}", args.join(" ")),
                &output,
            ));
        }

        String::from_utf8(output.stdout).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "`bw {}` returned output that is not valid UTF-8: {}",
                args.join(" "),
                crate::error::display_error_chain(&e)
            ))
        })
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
                // `execute_bw_command` rewrites the not-logged-in and locked
                // stderr into its own messages before this is reached, so
                // both the raw phrases and the rewrites are matched. The
                // comparisons are case-insensitive: the rewrites spell the
                // locked vault in lowercase ("Bitwarden vault is locked…").
                // Only the phrases that uniquely describe those two states
                // match: a missing CLI's install instructions also contain
                // "bw login" and "bw unlock" ("…run 'bw login' and 'bw
                // unlock' to authenticate"), and folding that error into
                // "not authenticated" would make a machine without bw
                // report a bogus login prompt instead of the install error.
                if {
                    let lower = msg.to_lowercase();
                    lower.contains("you are not logged in")
                        || lower.contains("vault is locked")
                        || lower.contains("please run 'bw login'")
                        || lower.contains("please run 'bw unlock'")
                } =>
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

        // `--search` narrows server-side, which is worth having on a large
        // vault, but it is bw's own fuzzy matcher and not the lookup: it
        // decides on its own terms which items are even considered.
        //
        // Those terms have been wrong. Before bitwarden/clients e1aa943b
        // (2026-07-13, first released in CLI 2026.7.0), `searchCiphersBasic`
        // stripped diacritics from the query but not from the item names, so
        // `--search überblick` returned nothing for an item named `Überblick`.
        // On any older CLI a diacritic name is unreachable — the candidate is
        // filtered out before this provider ever compares it.
        //
        // So an empty result means "the prefilter found nothing", not "the
        // secret is absent", and the fall back re-lists unfiltered. `set` has
        // always listed unfiltered, so this also makes reads and writes
        // consider the same set of items.
        let mut items = self.list_items(Some(item_name))?;
        if items.is_empty() {
            items = self.list_items(None)?;
        }

        if let Some(item) = find_addressed_item(&items, item_name, self.resolved_item_type()?)? {
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
        // An explicit selector resolves to that field or to nothing, the same
        // as every other item type (see the Login, Card, Identity and SSH key
        // extractors). Falling through to another field would answer a request
        // for one secret with a different one.
        if let Some(field_name) = resolved_field {
            // `notes` is the body, not a custom field: that is where both the
            // creation template and the updater put it, so a read has to look
            // there or `set --field notes` stops round-tripping.
            if is_note_body_field(field_name) {
                return Ok(item
                    .notes
                    .as_ref()
                    .map(|notes| SecretString::new(notes.clone().into())));
            }

            return Ok(self
                .extract_from_custom_fields(item, field_name)?
                .map(|value| SecretString::new(value.into())));
        }

        // Nothing named: the legacy "value" field (backward compatibility),
        // then the note body.
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

        // Unfiltered: a write must see every item that could already hold this
        // address, and `--search` decides candidacy on its own fuzzy terms.
        let items = self.list_items(None)?;

        if let Some(item) = find_addressed_item(&items, item_name, self.resolved_item_type()?)? {
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
        // Same table as the creation template, so an update lands in the member
        // a later read looks at.
        match builtin_member(BitwardenItemType::Login, field) {
            Some(member) => {
                item_json["login"][member] = serde_json::Value::String(value.to_string());
                Ok(())
            }
            None => self.update_custom_field_in_json(item_json, field, value),
        }
    }

    /// Updates Secure Note item fields in JSON.
    fn update_secure_note_item_json(
        &self,
        item_json: &mut serde_json::Value,
        field: &str,
        value: &str,
    ) -> Result<()> {
        if is_note_body_field(field) {
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
        // Same table as the creation template, so an update lands in the member
        // a later read looks at.
        match builtin_member(BitwardenItemType::Card, field) {
            Some(member) => {
                item_json["card"][member] = serde_json::Value::String(value.to_string());
                Ok(())
            }
            None => self.update_custom_field_in_json(item_json, field, value),
        }
    }

    /// Updates Identity item fields in JSON.
    fn update_identity_item_json(
        &self,
        item_json: &mut serde_json::Value,
        field: &str,
        value: &str,
    ) -> Result<()> {
        // Same table as the creation template, so an update lands in the member
        // a later read looks at.
        match builtin_member(BitwardenItemType::Identity, field) {
            Some(member) => {
                item_json["identity"][member] = serde_json::Value::String(value.to_string());
                Ok(())
            }
            None => self.update_custom_field_in_json(item_json, field, value),
        }
    }

    /// Updates an SSH Key item JSON with a new field value.
    fn update_ssh_key_item_json(
        &self,
        item_json: &mut serde_json::Value,
        field: &str,
        value: &str,
    ) -> Result<()> {
        // Same table as the creation template, so an update lands in the member
        // a later read looks at.
        match builtin_member(BitwardenItemType::SshKey, field) {
            Some(member) => {
                item_json["sshKey"][member] = serde_json::Value::String(value.to_string());
                Ok(())
            }
            None => self.update_custom_field_in_json(item_json, field, value),
        }
    }

    /// Gets an item as a JSON template for editing.
    fn get_item_as_template(&self, item_id: &str) -> Result<serde_json::Value> {
        let mut args = vec!["get", "item", item_id];

        // Not a search filter: this names the organization to act in, so the
        // resolved id is passed even when a collection was also addressed.
        let org_id = self.resolved_org_id()?.map(str::to_string);
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

        let mut cmd = self.command();

        let mut args = vec!["--nointeraction", "edit", "item", item_id];
        // The organization to act in, not a filter — see `search_filter_args`.
        let org_id = self.resolved_org_id()?.map(str::to_string);
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
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to run `bw {}`: {}",
                    args.join(" "),
                    crate::error::display_error_chain(&e)
                ))
            }
        })?;

        // Write base64-encoded JSON to stdin
        use std::io::Write;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(encoded_json.as_bytes()).map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to send the item to `bw {}` on stdin: {}",
                    args.join(" "),
                    crate::error::display_error_chain(&e)
                ))
            })?;
        }

        let output = child.wait_with_output().map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to wait for `bw {}`: {}",
                args.join(" "),
                crate::error::display_error_chain(&e)
            ))
        })?;

        if !output.status.success() {
            return Err(bw_command_failed(
                &format!("bw {}", args.join(" ")),
                &output,
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
        // Creation is the one path that must name a type even when the address
        // did not, so this is where the Login default lives.
        let item_type = self
            .resolved_item_type()?
            .unwrap_or(BitwardenItemType::Login);

        // Which field to write: explicit > env > config > the item type's
        // default. Shared with update and unqualified reads via `default_field`.
        let field = target_field
            .map(|s| s.to_string())
            .or_else(|| std::env::var("BITWARDEN_DEFAULT_FIELD").ok())
            .or_else(|| self.config.default_field.clone())
            .unwrap_or_else(|| item_type.default_field().to_string());

        // Resolved once here rather than inside each template, so a name that
        // cannot be resolved fails before anything is written.
        let placement = self.item_placement()?;

        let template = match item_type {
            BitwardenItemType::Login => self.login_template(item_name, value, &field, &placement),
            BitwardenItemType::Card => self.card_template(item_name, value, &field, &placement),
            BitwardenItemType::Identity => {
                self.identity_template(item_name, value, &field, &placement)
            }
            BitwardenItemType::SecureNote => {
                self.secure_note_template(item_name, value, &field, &placement)
            }
            BitwardenItemType::SshKey => {
                self.ssh_key_template(item_name, value, &field, &placement)
            }
        };

        self.create_item_from_template(&template)
    }

    /// Builds the creation template for a Login item.
    fn login_template(
        &self,
        item_name: &str,
        value: &str,
        field: &str,
        placement: &ItemPlacement,
    ) -> serde_json::Value {
        let mut login_data = serde_json::json!({
            "username": null,
            "password": null,
            "totp": null,
            "uris": []
        });

        let mut fields = vec![];

        // The shared table, so a built-in named here lands where the getter
        // looks for it rather than in a custom field it will never read.
        match builtin_member(BitwardenItemType::Login, field) {
            Some(member) => login_data[member] = serde_json::Value::String(value.to_string()),
            None => {
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
            "organizationId": placement.organization_id.clone(),
            "collectionIds": placement.collection_ids.clone()
        })
    }

    /// Builds the creation template for a Card item.
    fn card_template(
        &self,
        item_name: &str,
        value: &str,
        field: &str,
        placement: &ItemPlacement,
    ) -> serde_json::Value {
        let mut card_data = serde_json::json!({
            "number": null,
            "code": null,
            "cardholderName": null,
            "brand": null,
            "expMonth": null,
            "expYear": null
        });

        let mut fields = vec![];

        // The shared table, so a built-in named here lands where the getter
        // looks for it rather than in a custom field it will never read.
        match builtin_member(BitwardenItemType::Card, field) {
            Some(member) => card_data[member] = serde_json::Value::String(value.to_string()),
            None => {
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
            "organizationId": placement.organization_id.clone(),
            "collectionIds": placement.collection_ids.clone()
        })
    }

    /// Builds the creation template for an Identity item.
    fn identity_template(
        &self,
        item_name: &str,
        value: &str,
        field: &str,
        placement: &ItemPlacement,
    ) -> serde_json::Value {
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

        // The shared table, so a built-in named here lands where the getter
        // looks for it rather than in a custom field it will never read.
        match builtin_member(BitwardenItemType::Identity, field) {
            Some(member) => identity_data[member] = serde_json::Value::String(value.to_string()),
            None => {
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
            "organizationId": placement.organization_id.clone(),
            "collectionIds": placement.collection_ids.clone()
        })
    }

    /// Builds the creation template for a Secure Note item.
    fn secure_note_template(
        &self,
        item_name: &str,
        value: &str,
        field: &str,
        placement: &ItemPlacement,
    ) -> serde_json::Value {
        let mut fields = vec![];
        let into_body = is_note_body_field(field);

        if !into_body {
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
            "notes": if into_body { value.to_string() } else { format!("SecretSpec managed secret: {}", item_name) },
            "secureNote": {
                "type": 0
            },
            "fields": fields,
            "organizationId": placement.organization_id.clone(),
            "collectionIds": placement.collection_ids.clone()
        })
    }

    /// Builds the creation template for an SSH Key item.
    fn ssh_key_template(
        &self,
        item_name: &str,
        value: &str,
        field: &str,
        placement: &ItemPlacement,
    ) -> serde_json::Value {
        // Every member has to be a non-empty string. A null (serde reports it
        // as "invalid type: unit value, expected a valid string") is refused
        // outright by Bitwarden cloud, and Vaultwarden 1.37.0 is worse about
        // it: the upload succeeds, the server stores `sshKey: null`, and the
        // secret is silently discarded -- `set` reports success and `get` then
        // returns "[error: cannot decrypt]". Measured against both servers;
        // arbitrary non-empty strings are accepted, so this is about presence
        // and not about parseable key material.
        //
        // Only the addressed field carries the secret; the other two exist to
        // keep the item well-formed. See ashebanow/secretspec#3.
        let mut ssh_key_data = serde_json::json!({
            "privateKey": SSH_KEY_FIELD_UNSET,
            "publicKey": SSH_KEY_FIELD_UNSET,
            "keyFingerprint": SSH_KEY_FIELD_UNSET
        });

        let mut fields = vec![];

        // The shared table, so a built-in named here lands where the getter
        // looks for it rather than in a custom field it will never read.
        match builtin_member(BitwardenItemType::SshKey, field) {
            Some(member) => ssh_key_data[member] = serde_json::Value::String(value.to_string()),
            None => {
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
            "organizationId": placement.organization_id.clone(),
            "collectionIds": placement.collection_ids.clone()
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

        let mut cmd = self.command();

        let mut args = vec!["--nointeraction", "create", "item"];
        // The organization to create in, not a filter — see `search_filter_args`.
        let org_id = self.resolved_org_id()?.map(str::to_string);
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
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to run `bw {}`: {}",
                    args.join(" "),
                    crate::error::display_error_chain(&e)
                ))
            }
        })?;

        // Write base64-encoded JSON to stdin
        use std::io::Write;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(encoded_json.as_bytes()).map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to send the item to `bw {}` on stdin: {}",
                    args.join(" "),
                    crate::error::display_error_chain(&e)
                ))
            })?;
        }

        let output = child.wait_with_output().map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to wait for `bw {}`: {}",
                args.join(" "),
                crate::error::display_error_chain(&e)
            ))
        })?;

        if !output.status.success() {
            return Err(bw_command_failed(
                &format!("bw {}", args.join(" ")),
                &output,
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

    fn entry_coordinates<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<std::borrow::Cow<'a, crate::config::NativeAddress>> {
        let mut coords = self.resolve_coords(addr)?.into_owned();
        if coords.field.is_none() {
            coords.field = Some(
                match std::env::var("BITWARDEN_DEFAULT_FIELD")
                    .ok()
                    .or_else(|| self.config.default_field.clone())
                {
                    Some(field) => field,
                    None => self
                        .resolved_item_type()?
                        .unwrap_or(BitwardenItemType::Login)
                        .default_field()
                        .to_string(),
                },
            );
        }
        Ok(std::borrow::Cow::Owned(coords))
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    fn name(&self) -> &str {
        Self::PROVIDER_NAME
    }

    /// Reconstructs every option that changes which secret this provider
    /// answers with.
    ///
    /// SecretSpec fingerprints cached routes with this string and names the
    /// answering store with it in audit records and reports, so two addresses
    /// that read different secrets have to render differently. Omitting
    /// `type`, `field` or `folder` made `bw://team?field=password` and
    /// `bw://team?field=api_key` the same store: repointing the source left the
    /// cached password fresh and served it for the API key.
    fn uri(&self) -> String {
        let mut uri = String::from("bw://");
        let mut params: Vec<String> = Vec::new();

        // `org@collection` is only a valid authority when there is a
        // collection to anchor it -- `bw://myorg@` has an empty host and
        // re-parses with no organization at all. Alone, the organization goes
        // in the query, which is also how it can be addressed on the way in.
        match (&self.config.organization_id, &self.config.collection_id) {
            (org, Some(collection)) => {
                if let Some(org) = org {
                    uri.push_str(&ProviderUrl::encode(org));
                    uri.push('@');
                }
                uri.push_str(&ProviderUrl::encode(collection));
            }
            (Some(org), None) => {
                params.push(format!("org={}", ProviderUrl::encode_query(org)));
            }
            (None, None) => {}
        }

        if let Some(folder) = &self.config.folder_prefix {
            params.push(format!("folder={}", ProviderUrl::encode_query(folder)));
        }
        if let Some(item_type) = self.config.default_item_type {
            // `as_str` spells each type the way `from_str` accepts it.
            params.push(format!("type={}", item_type.as_str()));
        }
        if let Some(field) = &self.config.default_field {
            params.push(format!("field={}", ProviderUrl::encode_query(field)));
        }
        if let Some(server) = &self.config.server {
            params.push(format!("server={}", ProviderUrl::encode_query(server)));
        }

        if !params.is_empty() {
            uri.push('?');
            uri.push_str(&params.join("&"));
        }
        uri
    }

    /// Defaults that compile into native coordinates do not identify the
    /// Bitwarden vault itself. In particular, a scoped ref can override the
    /// URI's default field, and the resolved field is compared separately by
    /// `same_entries`.
    fn entry_container_identity(&self) -> String {
        format!(
            "bw:{:?}",
            (
                self.requested_org(),
                self.requested_collection(),
                self.resolved_item_type().ok().flatten(),
                self.config.server.as_deref().map(normalize_server),
            )
        )
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

    fn reflect(&self, _context: DiscoveryContext<'_>) -> Result<HashMap<String, Secret>> {
        if !self.is_authenticated()? {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Bitwarden authentication required. Please run 'bw login' and 'bw unlock', then set the BW_SESSION environment variable.".to_string(),
            ));
        }

        let items = self.list_items(None)?;
        declarations_from_items(&items, self.resolved_item_type()?)
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
    use serde_json::json;

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
        // An unscoped address, i.e. the personal vault: the same `null`
        // organization and collection these templates emitted before placement
        // was resolved up front.
        let placement = ItemPlacement::default();

        match item_type {
            BitwardenItemType::Login => provider.login_template(name, value, field, &placement),
            BitwardenItemType::SecureNote => {
                provider.secure_note_template(name, value, field, &placement)
            }
            BitwardenItemType::Card => provider.card_template(name, value, field, &placement),
            BitwardenItemType::Identity => {
                provider.identity_template(name, value, field, &placement)
            }
            BitwardenItemType::SshKey => provider.ssh_key_template(name, value, field, &placement),
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

    /// Reads an item the way `get` does when a field *is* named.
    ///
    /// The companion to [`read_without_naming_a_field`]. Named fields are the
    /// half of the round trip that had no coverage: the existing sweep uses
    /// `api_key`, chosen precisely because it matches no built-in, so a name
    /// that collides with one was never read back.
    fn read_naming_a_field(
        provider: &BitwardenProvider,
        item: &BitwardenItem,
        field: &str,
    ) -> Option<String> {
        provider
            .extract_value_from_item(item, Some(field))
            .expect("extraction must not fail")
            .map(|secret| secret.expose_secret().to_string())
    }

    /// Field names that name a built-in of their item type, in both spellings.
    ///
    /// Reading and updating already route these to the type's own slot; the
    /// creation templates did not, so `set` stored a custom field that `get`
    /// would never look at.
    const BUILTIN_FIELD_ALIASES: &[(BitwardenItemType, &str)] = &[
        (BitwardenItemType::Card, "exp_month"),
        (BitwardenItemType::Card, "expmonth"),
        (BitwardenItemType::Card, "exp_year"),
        (BitwardenItemType::Card, "expyear"),
        (BitwardenItemType::Card, "number"),
        (BitwardenItemType::Card, "brand"),
        (BitwardenItemType::Card, "code"),
        (BitwardenItemType::Identity, "first_name"),
        (BitwardenItemType::Identity, "firstname"),
        (BitwardenItemType::Identity, "last_name"),
        (BitwardenItemType::Identity, "lastname"),
        (BitwardenItemType::Identity, "email"),
        (BitwardenItemType::Identity, "company"),
        (BitwardenItemType::Login, "username"),
        (BitwardenItemType::Login, "totp"),
        (BitwardenItemType::SshKey, "public_key"),
        (BitwardenItemType::SshKey, "fingerprint"),
        (BitwardenItemType::SecureNote, "notes"),
    ];

    #[test]
    fn a_built_in_field_named_on_create_is_readable_under_that_name() {
        // `set --field exp_month` reported success while writing a custom
        // field, and the getter -- which knows `exp_month` as a built-in --
        // read the still-null `card.expMonth`. An immediate `get` returned
        // nothing. Creation has to recognise the same aliases as reading.
        let provider = BitwardenProvider::new(BitwardenConfig::default());

        for (item_type, field) in BUILTIN_FIELD_ALIASES {
            let template = template_for(&provider, *item_type, "Built In", "written-value", field);
            let item = item_from_template(template);

            assert_eq!(
                read_naming_a_field(&provider, &item, field).as_deref(),
                Some("written-value"),
                "{item_type:?}: value written to field={field} was not readable under that name",
            );
        }
    }

    #[test]
    fn a_built_in_field_survives_an_update_to_the_item_it_created() {
        // The other half of the round trip. Creation and update read the same
        // table now, so this holds by construction -- which is the point: it
        // fails the moment either writer grows an alias the other lacks.
        let provider = BitwardenProvider::new(BitwardenConfig::default());

        for (item_type, field) in BUILTIN_FIELD_ALIASES {
            let mut item_json =
                template_for(&provider, *item_type, "Built In", "created-value", field);
            apply_update(
                &provider,
                *item_type,
                &mut item_json,
                field,
                "updated-value",
            );
            let item = item_from_template(item_json);

            assert_eq!(
                read_naming_a_field(&provider, &item, field).as_deref(),
                Some("updated-value"),
                "{item_type:?}: update to field={field} was not readable under that name",
            );
        }
    }

    #[test]
    fn ssh_key_template_never_emits_a_null_member() {
        // A null in any sshKey member costs the entire object: Bitwarden cloud
        // rejects the create ("invalid type: unit value, expected a valid
        // string") and Vaultwarden 1.37.0 accepts it, stores `sshKey: null`,
        // and silently drops the secret. Every field a caller can address has
        // to leave the other two populated. See ashebanow/secretspec#3.
        let provider = BitwardenProvider::default();

        for field in [
            "private_key",
            "privatekey",
            "private",
            "public_key",
            "publickey",
            "public",
            "fingerprint",
            "key_fingerprint",
            // An unrecognised field goes to `fields[]`, but the sshKey object
            // still has to be well-formed or the item is lost the same way.
            "something_custom",
        ] {
            let template = template_for(
                &provider,
                BitwardenItemType::SshKey,
                "item",
                "the-secret",
                field,
            );
            let ssh_key = &template["sshKey"];

            for member in ["privateKey", "publicKey", "keyFingerprint"] {
                let value = &ssh_key[member];
                assert!(
                    value.is_string(),
                    "sshKey.{member} must be a string when writing field '{field}', got {value}"
                );
                assert!(
                    !value.as_str().unwrap().is_empty(),
                    "sshKey.{member} must be non-empty when writing field '{field}'"
                );
            }
        }
    }

    #[test]
    fn ssh_key_template_puts_the_secret_in_the_addressed_member() {
        // The placeholders must not displace the value itself.
        let provider = BitwardenProvider::default();

        for (field, member) in [
            ("private_key", "privateKey"),
            ("public_key", "publicKey"),
            ("key_fingerprint", "keyFingerprint"),
        ] {
            let template = template_for(
                &provider,
                BitwardenItemType::SshKey,
                "item",
                "the-secret",
                field,
            );
            assert_eq!(
                template["sshKey"][member], "the-secret",
                "field '{field}' must land in sshKey.{member}"
            );
        }
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

    // ---------------------------------------------------------------------
    // C3: organization and collection name resolution.
    //
    // `--collectionid` and `--organizationid` take UUIDs, but `bw://myorg@dev`
    // reads as names, so the provider resolves one to the other. These fixtures
    // mirror `bw list organizations` / `bw list collections` output: two
    // organizations, and a collection name deliberately duplicated across them
    // so ambiguity and cross-organization mismatches are exercised.
    // ---------------------------------------------------------------------

    const ACME_ID: &str = "11111111-1111-4111-8111-111111111111";
    const GLOBEX_ID: &str = "22222222-2222-4222-8222-222222222222";
    const ACME_DEV_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const ACME_PROD_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const GLOBEX_DEV_ID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    const UMLAUT_ID: &str = "33333333-3333-4333-8333-333333333333";

    const ORGANIZATIONS_JSON: &str = r#"[
        {"object":"organization","id":"11111111-1111-4111-8111-111111111111","name":"Acme Inc","status":2,"type":0,"enabled":true},
        {"object":"organization","id":"22222222-2222-4222-8222-222222222222","name":"Globex","status":2,"type":0,"enabled":true},
        {"object":"organization","id":"33333333-3333-4333-8333-333333333333","name":"ÜBERBLICK","status":2,"type":0,"enabled":true}
    ]"#;

    const COLLECTIONS_JSON: &str = r#"[
        {"object":"collection","id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","organizationId":"11111111-1111-4111-8111-111111111111","name":"dev-secrets","externalId":null},
        {"object":"collection","id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","organizationId":"11111111-1111-4111-8111-111111111111","name":"prod-secrets","externalId":null},
        {"object":"collection","id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","organizationId":"22222222-2222-4222-8222-222222222222","name":"dev-secrets","externalId":null},
        {"object":"collection","id":"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee","organizationId":"33333333-3333-4333-8333-333333333333","name":"Geheimnisse","externalId":null}
    ]"#;

    fn resolve(
        org: Option<&str>,
        collection: Option<&str>,
    ) -> std::result::Result<VaultScope, String> {
        resolve_scope(ORGANIZATIONS_JSON, COLLECTIONS_JSON, org, collection)
    }

    #[test]
    fn an_unscoped_address_resolves_to_nothing() {
        // The `bw://` case. Must not require the CLI listings at all, since
        // `look_up_scope` skips both `bw list` calls when nothing is addressed.
        assert_eq!(resolve(None, None).unwrap(), VaultScope::default());
        assert_eq!(
            resolve_scope("not json", "not json", None, None).unwrap(),
            VaultScope::default(),
            "an unscoped address must not even parse the listings"
        );
    }

    #[test]
    fn empty_cli_output_is_an_empty_list_not_a_parse_error() {
        // The CLI prints nothing at all when it cannot decrypt what it holds —
        // a stale BW_SESSION does this, and so does a vault that was never
        // synced. Surfacing that as a JSON parse error would point at the
        // wrong thing entirely.
        let err = resolve_scope("", "", None, Some("dev-secrets")).unwrap_err();
        assert!(
            !err.contains("could not parse"),
            "empty output must not read as malformed output: {err}"
        );
        assert!(
            err.contains("No collection matching 'dev-secrets'"),
            "{err}"
        );
        assert!(err.contains("BW_SESSION"), "{err}");
        assert!(err.contains("bw sync"), "{err}");

        // Whitespace-only output is the same case.
        assert!(
            resolve_scope("\n", "  \n", None, Some("x"))
                .unwrap_err()
                .contains("No collection matching"),
        );
    }

    #[test]
    fn genuinely_malformed_output_is_still_reported_as_such() {
        let err = resolve_scope("not json", COLLECTIONS_JSON, Some("Acme Inc"), None).unwrap_err();
        assert!(
            err.contains("could not parse `bw list organizations`"),
            "{err}"
        );
    }

    #[test]
    fn names_resolve_to_ids() {
        // The headline fix: `bw://Acme Inc@dev-secrets` addressed nothing before,
        // because the names went straight to flags that accept only UUIDs.
        let scope = resolve(Some("Acme Inc"), Some("dev-secrets")).unwrap();
        assert_eq!(scope.organization_id.as_deref(), Some(ACME_ID));
        assert_eq!(scope.collection_id.as_deref(), Some(ACME_DEV_ID));
    }

    #[test]
    fn names_match_case_insensitively() {
        // Matches how the read path already compares custom field names.
        let scope = resolve(Some("acme inc"), Some("DEV-SECRETS")).unwrap();
        assert_eq!(scope.organization_id.as_deref(), Some(ACME_ID));
        assert_eq!(scope.collection_id.as_deref(), Some(ACME_DEV_ID));
    }

    #[test]
    fn names_fold_case_beyond_ascii() {
        // `bw` compares names with JavaScript's `toLowerCase`, so a vault the
        // user can address in the CLI has to be addressable here. An
        // ASCII-only fold leaves every non-ASCII name unreachable in lower
        // case -- and the fixtures above are all ASCII, which is why the
        // divergence went unnoticed.
        let scope = resolve(Some("überblick"), None).unwrap();
        assert_eq!(scope.organization_id.as_deref(), Some(UMLAUT_ID));
    }

    #[test]
    fn ids_still_resolve_and_are_validated() {
        let scope = resolve(Some(ACME_ID), Some(ACME_PROD_ID)).unwrap();
        assert_eq!(scope.organization_id.as_deref(), Some(ACME_ID));
        assert_eq!(scope.collection_id.as_deref(), Some(ACME_PROD_ID));

        // A UUID that names nothing is a typo, and saying so beats letting the
        // search return zero items and reporting the secret as missing.
        let err = resolve(None, Some("dddddddd-dddd-4ddd-8ddd-dddddddddddd")).unwrap_err();
        assert!(err.contains("No collection matching"), "{err}");
        assert!(err.contains("bw sync"), "{err}");
    }

    #[test]
    fn a_collection_addressed_alone_supplies_its_organization() {
        // `bw://prod-secrets` has to reach an organization item, and the
        // collection is the only thing that can say which organization.
        let scope = resolve(None, Some("prod-secrets")).unwrap();
        assert_eq!(scope.collection_id.as_deref(), Some(ACME_PROD_ID));
        assert_eq!(
            scope.organization_id.as_deref(),
            Some(ACME_ID),
            "the organization must be derived from the collection"
        );
    }

    #[test]
    fn an_organization_addressed_alone_resolves_without_a_collection() {
        let scope = resolve(Some("Globex"), None).unwrap();
        assert_eq!(scope.organization_id.as_deref(), Some(GLOBEX_ID));
        assert_eq!(scope.collection_id, None);
    }

    #[test]
    fn an_organization_disambiguates_a_duplicated_collection_name() {
        // `dev-secrets` exists in both organizations. Naming the organization is
        // what makes each address point at exactly one of them.
        let acme = resolve(Some("Acme Inc"), Some("dev-secrets")).unwrap();
        let globex = resolve(Some("Globex"), Some("dev-secrets")).unwrap();

        assert_eq!(acme.collection_id.as_deref(), Some(ACME_DEV_ID));
        assert_eq!(globex.collection_id.as_deref(), Some(GLOBEX_DEV_ID));
        assert_ne!(
            acme.collection_id, globex.collection_id,
            "the same collection name in two organizations must resolve apart"
        );
    }

    #[test]
    fn an_ambiguous_collection_name_is_rejected() {
        // Without an organization, `dev-secrets` could be either. Guessing would
        // mean reading or overwriting a secret in the wrong organization.
        let err = resolve(None, Some("dev-secrets")).unwrap_err();
        assert!(err.contains("ambiguous"), "{err}");
        assert!(err.contains("Acme Inc"), "{err}");
        assert!(err.contains("Globex"), "{err}");
    }

    #[test]
    fn a_collection_in_another_organization_is_rejected_by_name() {
        // `prod-secrets` exists, but only in Acme.
        let err = resolve(Some("Globex"), Some("prod-secrets")).unwrap_err();
        assert!(err.contains("not in organization"), "{err}");
        assert!(err.contains("Globex"), "{err}");
        assert!(err.contains("Acme Inc"), "{err}");
    }

    #[test]
    fn a_collection_id_from_another_organization_is_rejected() {
        // The mismatch has to be caught for ids too. Resolving by id and then
        // trusting it would silently search Acme while the address said Globex.
        let err = resolve(Some("Globex"), Some(ACME_DEV_ID)).unwrap_err();
        assert!(err.contains("belongs to organization"), "{err}");
        assert!(err.contains("Acme Inc"), "{err}");
        assert!(err.contains("Globex"), "{err}");
    }

    #[test]
    fn an_unknown_organization_lists_the_ones_that_exist() {
        let err = resolve(Some("Initech"), None).unwrap_err();
        assert!(err.contains("No organization matching 'Initech'"), "{err}");
        assert!(err.contains("Acme Inc"), "{err}");
        assert!(err.contains("Globex"), "{err}");
    }

    #[test]
    fn an_unknown_collection_lists_only_the_addressed_organization() {
        // Listing Globex's collections here would be noise: the address already
        // said Acme, so those are the only ones the user can pick from.
        let err = resolve(Some("Acme Inc"), Some("staging")).unwrap_err();
        assert!(err.contains("No collection matching 'staging'"), "{err}");
        assert!(err.contains("prod-secrets"), "{err}");
        assert!(
            !err.contains(GLOBEX_DEV_ID),
            "collections outside the addressed organization must not be offered: {err}"
        );
    }

    #[test]
    fn search_sends_at_most_one_filter() {
        // The invariant that keeps this fix working. `bw list` was measured to
        // combine multiple filters with OR (see `search_filter_args`), so
        // emitting both would widen the search back to the whole organization
        // and make every collection address equivalent — exactly the bug the
        // resolution above exists to fix.
        let collection_scope = VaultScope {
            organization_id: Some(ACME_ID.to_string()),
            collection_id: Some(ACME_DEV_ID.to_string()),
        };
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        provider
            .vault_scope
            .set(Ok(collection_scope))
            .expect("scope is set once");

        let args = provider.search_filter_args().unwrap();
        assert_eq!(
            args,
            vec!["--collectionid".to_string(), ACME_DEV_ID.to_string()]
        );
        assert!(
            !args.iter().any(|a| a == "--organizationid"),
            "a resolved collection already implies its organization: {args:?}"
        );
    }

    #[test]
    fn search_falls_back_to_the_organization_filter() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        provider
            .vault_scope
            .set(Ok(VaultScope {
                organization_id: Some(GLOBEX_ID.to_string()),
                collection_id: None,
            }))
            .expect("scope is set once");

        assert_eq!(
            provider.search_filter_args().unwrap(),
            vec!["--organizationid".to_string(), GLOBEX_ID.to_string()]
        );
    }

    #[test]
    fn an_unscoped_search_sends_no_filter() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        provider
            .vault_scope
            .set(Ok(VaultScope::default()))
            .expect("scope is set once");

        assert!(provider.search_filter_args().unwrap().is_empty());
    }

    #[test]
    fn creation_places_the_item_in_the_resolved_collection() {
        // Placement is not a filter: an item created without its organization
        // and collection lands in the personal vault, where no collection-scoped
        // read can reach it. Both ids have to survive into the template.
        let placement = ItemPlacement::from(&VaultScope {
            organization_id: Some(ACME_ID.to_string()),
            collection_id: Some(ACME_DEV_ID.to_string()),
        });
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let template = provider.login_template("Shared Secret", "v", "password", &placement);

        assert_eq!(template["organizationId"].as_str(), Some(ACME_ID));
        assert_eq!(
            template["collectionIds"].as_array().map(Vec::as_slice),
            Some([serde_json::Value::String(ACME_DEV_ID.to_string())].as_slice())
        );
    }

    #[test]
    fn an_unscoped_creation_names_no_organization() {
        // The personal-vault case must keep emitting nulls rather than, say, an
        // empty array, which the CLI rejects.
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let template = provider.login_template("x", "v", "password", &ItemPlacement::default());

        assert!(template["organizationId"].is_null());
        assert!(template["collectionIds"].is_null());
    }

    // ---- Error reporting ----

    /// A finished `bw` invocation, without running one.
    ///
    /// Unix-only because `ExitStatus` cannot be built portably; the assertions
    /// are about `bw_command_failed`'s formatting, which is platform-independent.
    /// Same gating as `bws`'s process tests.
    #[cfg(unix)]
    fn finished(code: i32, stdout: &str, stderr: &str) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    #[cfg(unix)]
    fn a_failed_command_names_itself_and_its_status() {
        // Returning bare stderr left the reader guessing which of the several
        // `bw` calls behind one `get` had failed, and dropped the status.
        let err = bw_command_failed("bw list items", &finished(1, "", "Vault is locked."));
        let msg = err.to_string();

        assert!(msg.contains("bw list items"), "{msg}");
        assert!(msg.contains("exit status 1"), "{msg}");
        assert!(msg.contains("Vault is locked."), "{msg}");
    }

    #[test]
    #[cfg(unix)]
    fn a_failed_command_falls_back_to_stdout() {
        // `bw` is not consistent about which stream carries a diagnostic, and
        // an error reporting only a status code is barely better than none.
        let err = bw_command_failed("bw create item", &finished(1, "Cipher already exists", ""));

        assert!(err.to_string().contains("Cipher already exists"), "{err}");
    }

    #[test]
    #[cfg(unix)]
    fn a_failed_command_still_reports_when_both_streams_are_empty() {
        let err = bw_command_failed("bw sync", &finished(2, "", ""));
        let msg = err.to_string();

        assert!(msg.contains("bw sync"), "{msg}");
        assert!(msg.contains("exit status 2"), "{msg}");
        // No trailing separator with nothing after it.
        assert!(!msg.trim_end().ends_with(':'), "{msg}");
    }

    #[test]
    fn a_reported_cause_keeps_the_chain_underneath_it() {
        // The half `display_error_chain` supplies: an io::Error reaching a
        // provider message has to bring its cause, not just its own summary.
        // Mirrors error.rs's own round-trip for the helper.
        let source = std::io::Error::other("broken pipe while writing");
        let rendered = crate::error::display_error_chain(&source);

        assert!(rendered.contains("broken pipe while writing"), "{rendered}");
    }

    // ---- Strict address parsing (PR #166 review round 2, finding #6) ----

    fn config_error(spec: &str) -> String {
        let url = url::Url::parse(spec).expect("the spec must parse");
        BitwardenConfig::try_from(&ProviderUrl::new(url))
            .expect_err("the spec must be rejected")
            .to_string()
    }

    #[test]
    fn a_misspelled_item_type_is_rejected_rather_than_ignored() {
        // Silently falling back to Login means the typo surfaces much later,
        // as a Login item created where a key was wanted.
        let msg = config_error("bw://?type=sshkee");
        assert!(msg.contains("sshkee"), "{msg}");
        assert!(msg.contains("ssh"), "{msg}");
    }

    #[test]
    fn a_misspelled_query_key_is_rejected_rather_than_ignored() {
        // `?feild=api_key` used to parse cleanly and do nothing at all.
        let msg = config_error("bw://?feild=api_key");
        assert!(msg.contains("feild"), "{msg}");
        assert!(msg.contains("field"), "{msg}");
    }

    #[test]
    fn every_documented_query_key_is_still_accepted() {
        // The guard on the rejection above: strictness must not cost a
        // parameter the docs promise.
        for spec in [
            "bw://?org=acme",
            "bw://?organization=acme",
            "bw://?collection=dev",
            "bw://?server=https://vault.example.com",
            "bw://?folder=team",
            "bw://?type=note",
            "bw://?field=api_key",
        ] {
            let url = url::Url::parse(spec).expect("the spec must parse");
            assert!(
                BitwardenConfig::try_from(&ProviderUrl::new(url)).is_ok(),
                "{spec} was rejected",
            );
        }
    }

    #[test]
    fn an_item_type_is_parsed_the_same_way_wherever_it_is_named() {
        // The URI and BITWARDEN_DEFAULT_TYPE share one parser, so the
        // environment variable cannot keep swallowing what the URI rejects.
        // Exercised directly rather than through the environment, which tests
        // running in parallel cannot safely set.
        assert_eq!(
            parse_item_type("note", "?type=").expect("a valid spelling"),
            BitwardenItemType::SecureNote,
        );
        let msg = parse_item_type("garbage", "BITWARDEN_DEFAULT_TYPE")
            .expect_err("an invalid spelling")
            .to_string();
        assert!(msg.contains("BITWARDEN_DEFAULT_TYPE"), "{msg}");
    }

    // ---- Canonical URI (PR #166 review round 2, finding #5) ----

    fn config_from_spec(spec: &str) -> BitwardenConfig {
        let url = url::Url::parse(spec).expect("the spec must parse");
        BitwardenConfig::try_from(&ProviderUrl::new(url)).expect("the spec must be valid")
    }

    fn uri_of(spec: &str) -> String {
        BitwardenProvider::new(config_from_spec(spec)).uri()
    }

    /// Every field of the parsed config, for comparing two spellings of one
    /// store. `BitwardenConfig` has no `PartialEq`, and `Debug` already names
    /// the field that differs when this fails.
    fn store_identity(spec: &str) -> String {
        format!("{:?}", config_from_spec(spec))
    }

    #[test]
    fn uri_round_trips_every_behaviour_changing_option() {
        // `uri()` is the provider's identity: SecretSpec fingerprints cached
        // routes with it and names the answering store with it in audit records
        // and reports. Dropping an option that changes which secret is read
        // makes two different stores indistinguishable -- a cache filled
        // through `?field=password` stays "fresh" after the source is repointed
        // at `?field=api_key`, and serves the password for the API key.
        for spec in [
            "bw://",
            "bw://my-collection",
            "bw://myorg@dev-secrets",
            "bw://?type=card",
            "bw://?field=api_key",
            "bw://?folder=team/{project}",
            "bw://?server=https://vault.company.com",
            "bw://myorg@dev-secrets?type=card&field=api_key",
        ] {
            let rendered = uri_of(spec);
            assert_eq!(
                store_identity(&rendered),
                store_identity(spec),
                "{spec} rendered as {rendered}, which does not read back as the same store",
            );
        }
    }

    #[test]
    fn uri_keeps_an_organization_addressed_without_a_collection() {
        // `bw://?org=myorg` used to render as `bw://myorg@`, whose empty host
        // makes the org unparseable on the way back in -- the scope silently
        // widened to the whole vault.
        let rendered = uri_of("bw://?org=myorg");
        assert_eq!(
            config_from_spec(&rendered).organization_id.as_deref(),
            Some("myorg"),
            "rendered as {rendered}, which loses the organization",
        );
    }

    #[test]
    fn uri_escapes_values_that_would_break_the_query() {
        // Every other query-emitting provider encodes; `server` was
        // interpolated raw.
        let rendered = uri_of("bw://?folder=a%26b%3Dc");
        assert_eq!(
            config_from_spec(&rendered).folder_prefix.as_deref(),
            Some("a&b=c"),
            "rendered as {rendered}, which does not survive re-parsing",
        );
    }

    // ---- Explicit field selectors (PR #166 review round 2, finding #3) ----

    /// A secure note carrying both a legacy `value` field and a body.
    fn note_with_value_field_and_body() -> BitwardenItem {
        serde_json::from_value(serde_json::json!({
            "id": "note",
            "name": "Config",
            "type": BitwardenItemType::SecureNote.to_u8(),
            "notes": "the-note-body",
            "fields": [{"name": "value", "value": "the-value-field", "type": 1}],
        }))
        .expect("a minimal note must deserialize")
    }

    #[test]
    fn an_absent_secure_note_field_returns_nothing_rather_than_another_secret() {
        // Naming a field is a statement about *which* secret is wanted. When
        // that field is missing, falling back to `value` or to the note body
        // hands back a different secret under the requested name -- the four
        // other item types already return `None` here.
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = note_with_value_field_and_body();

        let got = provider
            .extract_from_secure_note_item(&item, Some("config_value"))
            .expect("extraction must not fail");

        assert!(
            got.is_none(),
            "field=config_value returned '{}'",
            got.map(|s| s.expose_secret().to_string())
                .unwrap_or_default(),
        );
    }

    #[test]
    fn field_notes_reads_the_note_body_not_the_value_field() {
        // Both the creation template and the updater treat `field=notes` as the
        // note body, so the reader has to agree or `set --field notes` stops
        // round-tripping.
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = note_with_value_field_and_body();

        let got = provider
            .extract_from_secure_note_item(&item, Some("notes"))
            .expect("extraction must not fail")
            .expect("the note has a body");

        assert_eq!(got.expose_secret(), "the-note-body");
    }

    #[test]
    fn an_unqualified_secure_note_read_still_prefers_the_legacy_value_field() {
        // The compatibility path stays exactly where it was: it applies when no
        // field was named, which is the case it was written for.
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = note_with_value_field_and_body();

        let got = provider
            .extract_from_secure_note_item(&item, None)
            .expect("extraction must not fail")
            .expect("the legacy field is present");

        assert_eq!(got.expose_secret(), "the-value-field");
    }

    // ---- Item addressing (PR #166 review round 2, findings #1 and #2) ----

    /// A vault item with just the fields addressing looks at.
    fn named_item(id: &str, name: &str, item_type: BitwardenItemType) -> BitwardenItem {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "name": name,
            "type": item_type.to_u8(),
        }))
        .expect("a minimal item must deserialize")
    }

    #[test]
    fn a_read_does_not_answer_with_a_similarly_named_item() {
        // `bw list items --search API_KEY` matches substrings, so `API_KEY_OLD`
        // comes back too — and `bw` does not specify the order. Answering with
        // whatever landed first hands back a different secret than the one the
        // address names.
        let items = [
            named_item("old", "API_KEY_OLD", BitwardenItemType::Login),
            named_item("wanted", "API_KEY", BitwardenItemType::Login),
        ];

        let hit = find_addressed_item(&items, "API_KEY", None)
            .expect("one API_KEY item is not ambiguous")
            .expect("the item exists");

        assert_eq!(
            hit.id, "wanted",
            "a read of API_KEY answered with {} instead",
            hit.name
        );
    }

    #[test]
    fn a_read_honours_an_explicitly_addressed_type() {
        // `bw://?type=card` has to be able to tell a Card from a Login of the
        // same name; `bw get` narrows the same way before reporting ambiguity.
        let items = [
            named_item("login", "API_KEY", BitwardenItemType::Login),
            named_item("card", "API_KEY", BitwardenItemType::Card),
        ];

        let hit = find_addressed_item(&items, "API_KEY", Some(BitwardenItemType::Card))
            .expect("the type filter leaves exactly one")
            .expect("the card exists");

        assert_eq!(hit.id, "card", "?type=card selected a {:?}", hit.item_type);
    }

    #[test]
    fn a_write_never_adopts_a_substring_match() {
        // The data-loss case: setting API_KEY with no such item present must
        // create one, not overwrite the unrelated OLD_API_KEY that happens to
        // contain the name.
        let items = [named_item("old", "OLD_API_KEY", BitwardenItemType::Login)];

        assert!(
            find_addressed_item(&items, "API_KEY", None)
                .expect("no match is not an error")
                .is_none(),
            "a write to API_KEY selected OLD_API_KEY as its update target"
        );
    }

    #[test]
    fn an_ambiguous_name_is_refused_rather_than_guessed() {
        // Bitwarden does not enforce unique names, and `bw get item` reports
        // the collision instead of picking one. Silently choosing here would
        // reintroduce the bug the exact match just fixed.
        let items = [
            named_item("first", "API_KEY", BitwardenItemType::Login),
            named_item("second", "API_KEY", BitwardenItemType::Login),
        ];

        let err =
            find_addressed_item(&items, "API_KEY", None).expect_err("two items share the name");
        let msg = err.to_string();

        assert!(msg.contains("2 Bitwarden items"), "{msg}");
        assert!(msg.contains("first") && msg.contains("second"), "{msg}");
        assert!(msg.contains("ref = { item ="), "{msg}");
    }

    #[test]
    fn an_addressed_type_selects_between_same_named_items_on_write() {
        // The `set` half of the type filter: with only a Login present, an
        // address that named Card must not adopt it as an update target --
        // that is what lets `bw://?type=card` create the Card it asked for.
        let items = [named_item("login", "API_KEY", BitwardenItemType::Login)];

        assert!(
            find_addressed_item(&items, "API_KEY", Some(BitwardenItemType::Card))
                .expect("a type mismatch is not an error")
                .is_none(),
            "?type=card adopted a Login as its update target",
        );
    }

    #[test]
    fn addressing_folds_case_like_the_bw_cli() {
        // `bw` compares names with JavaScript's `toLowerCase`, so an item the
        // user can address in the CLI has to be addressable here too — and the
        // fold has to be Unicode-aware, not ASCII-only.
        let items = [
            named_item("db", "Test Database", BitwardenItemType::Login),
            named_item("u", "Überblick", BitwardenItemType::SecureNote),
        ];

        assert_eq!(
            find_addressed_item(&items, "test database", None)
                .unwrap()
                .map(|i| i.id.as_str()),
            Some("db"),
        );
        assert_eq!(
            find_addressed_item(&items, "überblick", None)
                .unwrap()
                .map(|i| i.id.as_str()),
            Some("u"),
            "an ASCII-only fold leaves non-ASCII names unaddressable",
        );
    }

    #[test]
    fn reflection_builds_declarations_for_the_addressed_item_type() {
        let items = [
            named_item("login", "API_KEY", BitwardenItemType::Login),
            named_item("card", "API_KEY", BitwardenItemType::Card),
            named_item("token", "CARD_TOKEN", BitwardenItemType::Card),
        ];

        let declarations = declarations_from_items(&items, Some(BitwardenItemType::Card))
            .expect("the type filter makes every item addressable");

        assert_eq!(declarations.len(), 2);
        assert_eq!(
            declarations["API_KEY"].description.as_deref(),
            Some("API_KEY Bitwarden secret")
        );
        assert_eq!(declarations["API_KEY"].required, Some(true));
        assert!(declarations.contains_key("CARD_TOKEN"));
    }

    #[test]
    fn reflection_rejects_names_that_cannot_be_declared() {
        let items = [named_item(
            "invalid",
            "Database Login",
            BitwardenItemType::Login,
        )];

        let err = declarations_from_items(&items, None)
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("cannot become a SecretSpec declaration"),
            "{err}"
        );
        assert!(err.contains("Database Login"), "{err}");
        assert!(err.contains("collection and/or `?type=`"), "{err}");
    }

    #[test]
    fn reflection_rejects_the_reserved_defaults_name() {
        let items = [named_item(
            "reserved",
            "defaults",
            BitwardenItemType::SecureNote,
        )];

        let err = declarations_from_items(&items, None)
            .unwrap_err()
            .to_string();

        assert!(err.contains("reserved for profile defaults"), "{err}");
    }

    #[test]
    fn reflection_rejects_case_insensitive_name_collisions() {
        let items = [
            named_item("first", "API_KEY", BitwardenItemType::Login),
            named_item("second", "api_key", BitwardenItemType::Login),
        ];

        let err = declarations_from_items(&items, None)
            .unwrap_err()
            .to_string();

        assert!(err.contains("collide case-insensitively"), "{err}");
        assert!(err.contains("first") && err.contains("second"), "{err}");
    }

    // ---------------------------------------------------------------------
    // Behavioral coverage for the pure extraction / mutation / resolution
    // helpers (see ashebanow/secretspec#5). These read and write the same
    // JSON shapes `bw` hands back, without spawning the CLI.
    // ---------------------------------------------------------------------

    /// Builds an item from JSON, the way `bw` would hand it back.
    fn item_from(json: serde_json::Value) -> BitwardenItem {
        serde_json::from_value(json).expect("fixture must deserialize as a vault item")
    }

    /// The env-sensitive resolution helpers read process-global variables, so
    /// tests that flip them run one at a time.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Runs `body` with the BITWARDEN_* resolution variables unset, restoring
    /// whatever was there. The variables are only read by `requested_org`,
    /// `requested_collection` and `resolved_item_type`, so no other test can
    /// observe a transient change.
    fn with_clean_env<T>(body: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap();
        let saved = [
            "BITWARDEN_ORGANIZATION",
            "BITWARDEN_COLLECTION",
            "BITWARDEN_DEFAULT_TYPE",
            "BITWARDEN_DEFAULT_FIELD",
        ]
        .map(|key| (key, std::env::var(key).ok()));
        for (key, _) in &saved {
            unsafe { std::env::remove_var(key) };
        }
        let result = body();
        for (key, previous) in saved {
            match previous {
                Some(previous) => unsafe { std::env::set_var(key, previous) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
        result
    }

    /// Runs `body` with `key` set to `value`, restoring whatever was there.
    fn with_env<T>(key: &str, value: &str, body: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap();
        let previous = std::env::var(key).ok();
        unsafe { std::env::set_var(key, value) };
        let result = body();
        match previous {
            Some(previous) => unsafe { std::env::set_var(key, previous) },
            None => unsafe { std::env::remove_var(key) },
        }
        result
    }

    // ---------------------------------------------------------------------
    // Fake-`bw` CLI harness: the pure helpers above cover the code that runs
    // without a CLI; these cover the code that spawns `bw` at all. The fake
    // is a shell script installed into a per-test directory that is put first
    // on PATH (see tests/fixtures/bw-shim.sh). Unit tests must never run the
    // developer's real `bw`, which would answer with — and write to — a real
    // vault; the fake answers fixture files instead and records every
    // invocation so tests can assert what was asked for.
    //
    // Everything below this line is `#[cfg(unix)]`-only: the fake is an
    // extensionless POSIX shell script, and on Windows `Command::new("bw")`
    // goes through CreateProcess, which cannot execute such a file (bare-name
    // resolution only finds `.exe`-style programs). A compiled fake would
    // need a helper binary, which unit tests cannot build — `CARGO_BIN_EXE_*`
    // is only available to integration tests. So the subprocess flows are
    // exercised on Linux/macOS only, while the pure helpers above still run
    // on every platform, including the Windows CI job.
    // ---------------------------------------------------------------------

    /// Tests that put the fake `bw` on PATH run one at a time: PATH is
    /// process-global state, exactly like the BITWARDEN_* variables guarded by
    /// [`ENV_LOCK`].
    #[cfg(unix)]
    static BW_SHIM_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A disposable fake `bw` CLI for one test.
    ///
    /// The directory holds the shim script (installed from
    /// `tests/fixtures/bw-shim.sh`), fixture JSON files the script answers
    /// with, and `invocations.log` recording every call. [`FakeBw::run`] puts
    /// the directory first on PATH for the duration of `body` and isolates
    /// `BITWARDENCLI_APPDATA_DIR`, mirroring the vaultwarden harness, so
    /// nothing the fake does can reach the developer's own bw config.
    #[cfg(unix)]
    struct FakeBw {
        dir: std::path::PathBuf,
    }

    /// Restores the process-global state [`FakeBw::run`] changed, even when
    /// `body` panics — a leaked PATH pointing at a soon-deleted fixture
    /// directory would turn a later accidental `bw` spawn into a silent
    /// NotFound.
    #[cfg(unix)]
    struct PathRestore {
        old_path: String,
        old_appdata: Option<String>,
    }

    #[cfg(unix)]
    impl Drop for PathRestore {
        fn drop(&mut self) {
            unsafe { std::env::set_var("PATH", &self.old_path) };
            match &self.old_appdata {
                Some(appdata) => unsafe { std::env::set_var("BITWARDENCLI_APPDATA_DIR", appdata) },
                None => unsafe { std::env::remove_var("BITWARDENCLI_APPDATA_DIR") },
            }
        }
    }

    #[cfg(unix)]
    impl FakeBw {
        /// Creates a fresh fake in a temp directory with the shim script
        /// installed and ready to answer `[]` to every listing.
        fn new() -> FakeBw {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "bw-shim-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).expect("create fake bw directory");
            let script = include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../tests/fixtures/bw-shim.sh"
            ));
            std::fs::write(dir.join("bw"), script).expect("install fake bw script");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(dir.join("bw"))
                    .expect("stat fake bw")
                    .permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(dir.join("bw"), perms).expect("chmod fake bw");
            }
            FakeBw { dir }
        }

        /// Writes the fixture `bw status` answers with.
        fn with_status(self, status: serde_json::Value) -> Self {
            std::fs::write(self.dir.join("status.json"), status.to_string())
                .expect("write status fixture");
            self
        }

        /// Writes the fixture `bw list organizations` answers with.
        fn with_organizations(self, organizations: serde_json::Value) -> Self {
            std::fs::write(
                self.dir.join("organizations.json"),
                organizations.to_string(),
            )
            .expect("write organizations fixture");
            self
        }

        /// Writes the fixture `bw list collections` answers with.
        fn with_collections(self, collections: serde_json::Value) -> Self {
            std::fs::write(self.dir.join("collections.json"), collections.to_string())
                .expect("write collections fixture");
            self
        }

        /// Writes the fixture `bw list items` and `bw get item` answer with.
        fn with_items(self, items: serde_json::Value) -> Self {
            std::fs::write(self.dir.join("items.json"), items.to_string())
                .expect("write items fixture");
            self
        }

        /// Forces every `bw` call to exit `code` with these streams, driving
        /// the provider's subprocess error paths (missing login, locked
        /// vault, generic failure, malformed output).
        fn with_failure(self, code: i32, stdout: &str, stderr: &str) -> Self {
            std::fs::write(
                self.dir.join("fail.env"),
                format!("{code}\n{stdout}\n{stderr}"),
            )
            .expect("write failure fixture");
            self
        }

        /// Like [`Self::with_failure`], but only for invocations whose argv
        /// contains `arg` — so one listing can fail while a sibling listing
        /// in the same flow succeeds.
        fn with_failure_on(self, code: i32, stdout: &str, stderr: &str, arg: &str) -> Self {
            std::fs::write(
                self.dir.join("fail.env"),
                format!("{code}\n{stdout}\n{stderr}\n{arg}"),
            )
            .expect("write failure fixture");
            self
        }

        /// Makes every `bw` call print these raw bytes and exit 0, for output
        /// that is not valid UTF-8.
        fn with_garbage(self, bytes: &[u8]) -> Self {
            std::fs::write(self.dir.join("garbage.bin"), bytes).expect("write garbage fixture");
            self
        }

        /// The invocation log: one `argv: <...>` line per call, plus
        /// `stdin=<base64>` when the provider piped JSON at it.
        fn invocations(&self) -> String {
            std::fs::read_to_string(self.dir.join("invocations.log")).unwrap_or_default()
        }

        /// Runs `body` with this fake first on PATH.
        ///
        /// Takes [`BW_SHIM_LOCK`] so no other fake-`bw` test observes the
        /// process-global PATH while it is installed.
        fn run<T>(&self, body: impl FnOnce() -> T) -> T {
            let _guard = BW_SHIM_LOCK.lock().unwrap();
            let old_path = std::env::var("PATH").unwrap_or_default();
            let old_appdata = std::env::var("BITWARDENCLI_APPDATA_DIR").ok();
            let new_path = if old_path.is_empty() {
                self.dir.display().to_string()
            } else {
                format!("{}:{}", self.dir.display(), old_path)
            };
            let _restore = PathRestore {
                old_path,
                old_appdata,
            };
            unsafe {
                std::env::set_var("PATH", new_path);
                std::env::set_var("BITWARDENCLI_APPDATA_DIR", self.dir.join("appdata"));
            }
            body()
        }
    }

    #[cfg(unix)]
    impl Drop for FakeBw {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Returns a provider whose CLI path cannot exist, so the provider's "CLI
    /// not installed" branches (a distinct `NotFound` handling per call site)
    /// are exercised without mutating the process-global PATH.
    #[cfg(unix)]
    fn provider_without_bw() -> BitwardenProvider {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let missing = std::env::temp_dir().join(format!(
            "missing-bw-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut provider = BitwardenProvider::new(BitwardenConfig::default());
        provider.cli_binary_path = missing;
        provider
    }

    // -- fake-bw CLI subprocess tests -------------------------------------

    // -- check_server ------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn check_server_accepts_a_matching_server_url() {
        // A self-hosted address verifies that the CLI already targets that
        // server; a matching `bw status` must pass.
        let fake = FakeBw::new().with_status(json!({
            "serverUrl": "https://vault.company.com",
            "status": "unlocked"
        }));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            assert_eq!(provider.check_server("https://vault.company.com"), Ok(()));
        });
    }

    #[cfg(unix)]
    #[test]
    fn check_server_accepts_the_public_cloud_when_expected() {
        // `bw status` reports the cloud as a null serverUrl; that must
        // satisfy an expectation of the cloud URL rather than read as a
        // mismatch.
        let fake = FakeBw::new(); // default status: cloud, unlocked
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            assert_eq!(provider.check_server(BITWARDEN_CLOUD_SERVER), Ok(()));
        });
    }

    #[cfg(unix)]
    #[test]
    fn check_server_rejects_a_mismatched_server_with_remediation() {
        // The provider must fail closed when the CLI points elsewhere and
        // name the expected server, so the operator knows which command to
        // run to fix it.
        let fake = FakeBw::new().with_status(json!({
            "serverUrl": "https://vault.other.com",
            "status": "unlocked"
        }));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let err = provider
                .check_server("https://vault.company.com")
                .unwrap_err();
            assert!(err.contains("expects https://vault.company.com"), "{err}");
            assert!(
                err.contains("bw config server https://vault.company.com"),
                "{err}"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn check_server_names_the_public_cloud_as_the_current_server() {
        // A null serverUrl means the cloud; the mismatch message must say so
        // explicitly instead of printing a bare null the user never
        // configured.
        let fake = FakeBw::new(); // default status: cloud
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let err = provider
                .check_server("https://vault.company.com")
                .unwrap_err();
            assert!(
                err.contains(&format!(
                    "the public Bitwarden cloud ({BITWARDEN_CLOUD_SERVER})"
                )),
                "{err}"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn check_server_ignores_a_missing_cli() {
        // `execute_bw_command` reports a missing CLI with install
        // instructions immediately after, so `check_server` must stay quiet
        // on NotFound rather than error twice.
        let provider = provider_without_bw();
        assert_eq!(provider.check_server("https://vault.company.com"), Ok(()));
    }

    #[cfg(unix)]
    #[test]
    fn check_server_reports_a_failed_status_call() {
        let fake = FakeBw::new().with_failure(1, "", "boom");
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let err = provider
                .check_server("https://vault.company.com")
                .unwrap_err();
            assert!(err.contains("`bw status` failed while verifying"), "{err}");
            assert!(err.contains("boom"), "{err}");
        });
    }

    #[cfg(unix)]
    #[test]
    fn check_server_reports_unparseable_status_output() {
        // A successful-but-garbage `bw status` is a configuration problem
        // the operator needs to see, not a server mismatch.
        let fake = FakeBw::new().with_failure(0, "not json", "");
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let err = provider
                .check_server("https://vault.company.com")
                .unwrap_err();
            assert!(
                err.contains("could not parse `bw status` output as JSON"),
                "{err}"
            );
        });
    }

    // -- execute_bw_command ------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn execute_bw_command_returns_the_stdout_of_a_successful_call() {
        let fake = FakeBw::new().with_items(json!([{
            "id": "it1", "name": "Vault", "type": 1
        }]));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let out = provider.execute_bw_command(&["list", "items"]).unwrap();
            let items: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(items[0]["name"], "Vault");
        });
    }

    #[cfg(unix)]
    #[test]
    fn execute_bw_command_reports_a_missing_cli_with_install_instructions() {
        // A machine without the CLI gets instructions, not a bare "command
        // not found".
        let provider = provider_without_bw();
        let err = provider.execute_bw_command(&["status"]).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("Bitwarden CLI (bw) is not installed"), "{msg}");
        assert!(msg.contains("brew install bitwarden-cli"), "{msg}");
    }

    #[cfg(unix)]
    #[test]
    fn execute_bw_command_maps_a_not_logged_in_error() {
        // `bw` says this on stderr when no session exists; the provider must
        // translate it into an actionable message instead of the raw failure.
        let fake = FakeBw::new().with_failure(1, "", "You are not logged in.");
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let err = provider.execute_bw_command(&["status"]).unwrap_err();
            let msg = format!("{err}");
            assert!(msg.contains("Please run 'bw login' first"), "{msg}");
        });
    }

    #[cfg(unix)]
    #[test]
    fn execute_bw_command_maps_a_locked_vault_error() {
        let fake = FakeBw::new().with_failure(1, "", "Vault is locked.");
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let err = provider.execute_bw_command(&["status"]).unwrap_err();
            let msg = format!("{err}");
            assert!(msg.contains("Please run 'bw unlock'"), "{msg}");
        });
    }

    #[cfg(unix)]
    #[test]
    fn execute_bw_command_reports_generic_failures_with_stderr() {
        // Anything outside the two known states surfaces as a plain failure
        // that names the command and the exit status.
        let fake = FakeBw::new().with_failure(3, "", "some generic failure");
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let err = provider.execute_bw_command(&["list", "items"]).unwrap_err();
            let msg = format!("{err}");
            assert!(
                msg.contains("`bw list items` failed (exit status 3)"),
                "{msg}"
            );
            assert!(msg.contains("some generic failure"), "{msg}");
        });
    }

    #[cfg(unix)]
    #[test]
    fn execute_bw_command_falls_back_to_stdout_for_failure_detail() {
        // An error with empty stderr must not read as an empty message: the
        // detail falls back to stdout.
        let fake = FakeBw::new().with_failure(1, "detail on stdout", "");
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let err = provider.execute_bw_command(&["status"]).unwrap_err();
            let msg = format!("{err}");
            assert!(msg.contains("detail on stdout"), "{msg}");
        });
    }

    #[cfg(unix)]
    #[test]
    fn execute_bw_command_rejects_non_utf8_stdout() {
        // `bw` output is treated as text; bytes that are not UTF-8 must fail
        // loudly rather than be lossily mangled into a secret.
        let fake = FakeBw::new().with_garbage(&[0xff, 0xfe]);
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let err = provider.execute_bw_command(&["status"]).unwrap_err();
            let msg = format!("{err}");
            assert!(
                msg.contains("returned output that is not valid UTF-8"),
                "{msg}"
            );
        });
    }

    // -- is_authenticated --------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn is_authenticated_is_true_when_the_vault_is_unlocked() {
        let fake = FakeBw::new(); // default status: unlocked
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            assert!(provider.is_authenticated().unwrap());
        });
    }

    #[cfg(unix)]
    #[test]
    fn is_authenticated_is_false_when_the_vault_is_locked() {
        // A locked vault is a known, non-fatal state: the caller sees
        // "not authenticated" rather than an error.
        let fake = FakeBw::new().with_status(json!({
            "serverUrl": null, "status": "locked", "authenticated": true
        }));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            assert!(!provider.is_authenticated().unwrap());
        });
    }

    #[cfg(unix)]
    #[test]
    fn is_authenticated_is_false_when_not_logged_in() {
        let fake = FakeBw::new().with_failure(1, "", "You are not logged in.");
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            assert!(!provider.is_authenticated().unwrap());
        });
    }

    #[cfg(unix)]
    #[test]
    fn is_authenticated_is_false_when_the_vault_is_locked_on_stderr() {
        let fake = FakeBw::new().with_failure(1, "", "Vault is locked.");
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            assert!(!provider.is_authenticated().unwrap());
        });
    }

    #[cfg(unix)]
    #[test]
    fn is_authenticated_surfaces_unexpected_failures() {
        // Any other failure is not a known state: it must propagate as an
        // error rather than masquerade as "not authenticated".
        let fake = FakeBw::new().with_failure(1, "", "mystery failure");
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            assert!(provider.is_authenticated().is_err());
        });
    }

    #[cfg(unix)]
    #[test]
    fn is_authenticated_reports_a_missing_cli() {
        // A missing `bw` is not a known auth state: it must propagate as the
        // install error, not masquerade as "not authenticated" (the install
        // instructions contain "bw login"/"bw unlock", which used to match
        // the auth-state guard).
        let provider = provider_without_bw();
        let err = provider.is_authenticated().unwrap_err();
        assert!(format!("{err}").contains("is not installed"), "{err}");
    }

    // -- get / create over the fake CLI -----------------------------------

    #[cfg(unix)]
    #[test]
    fn get_item_as_template_answers_with_the_named_item() {
        let fake = FakeBw::new().with_items(json!([
            {"id": "it1", "name": "Vault", "type": 1, "login": {"password": "pw"}},
            {"id": "it2", "name": "Other", "type": 1}
        ]));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let item = provider.get_item_as_template("it2").unwrap();
            assert_eq!(item["name"], "Other");
            let log = fake.invocations();
            assert!(
                log.contains("argv: <--nointeraction> <get> <item> <it2>"),
                "{log}"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn get_item_as_template_fails_when_the_item_is_missing() {
        let fake = FakeBw::new(); // empty vault
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let err = provider.get_item_as_template("nope").unwrap_err();
            assert!(format!("{err}").contains("Not found"), "{err}");
        });
    }

    #[cfg(unix)]
    #[test]
    fn create_item_from_template_pipes_the_template_to_create_item() {
        // The provider builds the item JSON itself and hands it to
        // `bw create item` as base64 on stdin; the shim's log must show
        // exactly that payload so a created secret is the one that was asked
        // for.
        use base64::{Engine as _, engine::general_purpose};
        let template = json!({
            "type": 1, "name": "New",
            "notes": "SecretSpec managed secret: New",
            "login": {"username": null, "password": "s3cret", "totp": null, "uris": []},
            "fields": [], "organizationId": null, "collectionIds": []
        });
        let fake = FakeBw::new();
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            provider.create_item_from_template(&template).unwrap();
        });
        let log = fake.invocations();
        assert!(
            log.contains("argv: <--nointeraction> <create> <item>"),
            "{log}"
        );
        let stdin_line = log
            .lines()
            .find(|line| line.starts_with(" stdin="))
            .expect("create must pipe the item on stdin");
        let sent = general_purpose::STANDARD
            .decode(stdin_line.trim_start_matches(" stdin="))
            .expect("stdin must be base64");
        let sent: serde_json::Value = serde_json::from_slice(&sent).unwrap();
        assert_eq!(sent["name"], "New");
        assert_eq!(sent["login"]["password"], "s3cret");
    }

    // -- scope resolution over the fake CLI --------------------------------

    #[cfg(unix)]
    #[test]
    fn look_up_scope_resolves_an_organization_name_through_the_fake_cli() {
        let fake = FakeBw::new().with_organizations(json!([
            {"id": "org-1", "name": "DevOps"},
            {"id": "org-2", "name": "Security"}
        ]));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig {
                organization_id: Some("DevOps".to_string()),
                ..Default::default()
            });
            let scope = provider.look_up_scope().unwrap();
            assert_eq!(scope.organization_id.as_deref(), Some("org-1"));
            let log = fake.invocations();
            assert!(
                log.contains("argv: <--nointeraction> <list> <organizations>"),
                "{log}"
            );
            assert!(
                log.contains("argv: <--nointeraction> <list> <collections>"),
                "{log}"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn look_up_scope_fails_when_the_organization_is_not_visible() {
        let fake = FakeBw::new().with_organizations(json!([]));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig {
                organization_id: Some("Missing".to_string()),
                ..Default::default()
            });
            let err = provider.look_up_scope().unwrap_err();
            assert!(err.contains("No organization matching 'Missing'"), "{err}");
        });
    }

    #[cfg(unix)]
    #[test]
    fn server_check_is_memoized_to_one_status_call_per_provider() {
        // `ensure_server_configured` may run before every command, but the
        // `bw status` behind it must happen once per process, not once per
        // command.
        let fake = FakeBw::new().with_status(json!({
            "serverUrl": "https://vault.company.com", "status": "unlocked"
        }));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig {
                server: Some("https://vault.company.com".to_string()),
                ..Default::default()
            });
            provider.ensure_server_configured().unwrap();
            provider.ensure_server_configured().unwrap();
            provider.ensure_server_configured().unwrap();
            let status_calls = fake
                .invocations()
                .lines()
                .filter(|line| line.contains("<status>"))
                .count();
            assert_eq!(status_calls, 1);
        });
    }

    // -- get / set flows over the fake CLI --------------------------------

    #[cfg(unix)]
    #[test]
    fn get_answers_with_the_password_of_a_matching_login() {
        // The read path: authenticate, narrow with bw's own search, match
        // the name ourselves, and answer with the type's default field.
        let fake = FakeBw::new().with_items(json!([{
            "id": "it1", "name": "Vault", "type": 1,
            "login": {"username": "alice", "password": "pw"}
        }]));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let value = provider.get_from_password_manager("Vault", None).unwrap();
            assert_eq!(
                value.map(|s| s.expose_secret().to_string()),
                Some("pw".to_string())
            );
            let log = fake.invocations();
            assert!(
                log.contains("argv: <--nointeraction> <list> <items> <--search> <Vault>"),
                "{log}"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn get_falls_back_from_an_empty_search_to_an_unfiltered_listing() {
        // bw's own search is a fuzzy matcher that has been wrong; an empty
        // search result must mean "the prefilter matched nothing", not "no
        // such secret", so the read re-lists unfiltered. Here the shim's
        // case-sensitive filter rejects "api_key" against "API_KEY" and the
        // fall-back must still find the item by the provider's own
        // case-insensitive name match.
        let fake = FakeBw::new().with_items(json!([{
            "id": "it1", "name": "API_KEY", "type": 1,
            "login": {"password": "casefolded"}
        }]));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let value = provider.get_from_password_manager("api_key", None).unwrap();
            assert_eq!(
                value.map(|s| s.expose_secret().to_string()),
                Some("casefolded".to_string())
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn get_returns_none_for_an_absent_secret() {
        // An empty vault answers Ok(None) — an absence, not an error.
        let fake = FakeBw::new();
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            assert_eq!(
                provider
                    .get_from_password_manager("Vault", None)
                    .unwrap()
                    .map(|s| s.expose_secret().to_string()),
                None
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn get_reports_ambiguous_items_instead_of_answering() {
        // Two items with the same name cannot be told apart by the address;
        // answering either one could serve the wrong secret, so the read must
        // fail and say how many.
        let fake = FakeBw::new().with_items(json!([
            {"id": "it1", "name": "Vault", "type": 1, "login": {"password": "a"}},
            {"id": "it2", "name": "Vault", "type": 1, "login": {"password": "b"}}
        ]));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let err = provider
                .get_from_password_manager("Vault", None)
                .unwrap_err();
            let msg = format!("{err}");
            assert!(msg.contains("are named 'Vault'"), "{msg}");
        });
    }

    #[cfg(unix)]
    #[test]
    fn get_fails_closed_when_not_authenticated() {
        // A locked vault must not be served as if the secret were absent:
        // the read fails with an authentication error instead.
        let fake = FakeBw::new().with_status(json!({
            "serverUrl": null, "status": "locked", "authenticated": true
        }));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let err = provider
                .get_from_password_manager("Vault", None)
                .unwrap_err();
            assert!(
                format!("{err}").contains("Bitwarden authentication required"),
                "{err}"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn reflect_lists_the_addressed_collection_without_copying_values() {
        let fake = FakeBw::new()
            .with_organizations(json!([{"id": "org-id", "name": "Acme"}]))
            .with_collections(json!([{
                "id": "collection-id",
                "name": "dev-secrets",
                "organizationId": "org-id"
            }]))
            .with_items(json!([{
                "id": "item-id",
                "name": "API_KEY",
                "type": 1,
                "login": {"password": "must-not-appear"}
            }]));

        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig {
                collection_id: Some("dev-secrets".to_string()),
                ..Default::default()
            });
            let declarations = provider
                .reflect(DiscoveryContext::new("ignored", "ignored"))
                .unwrap();

            assert_eq!(declarations.len(), 1);
            assert_eq!(
                declarations["API_KEY"].description.as_deref(),
                Some("API_KEY Bitwarden secret")
            );
            assert!(!format!("{:?}", declarations["API_KEY"]).contains("must-not-appear"));

            let log = fake.invocations();
            assert!(log.contains("<status>"), "{log}");
            assert!(log.contains("<list> <organizations>"), "{log}");
            assert!(log.contains("<list> <collections>"), "{log}");
            assert!(
                log.contains("<list> <items> <--collectionid> <collection-id>"),
                "{log}"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn get_through_an_organization_sends_the_resolved_scope_filter() {
        // An organization address resolves the name to a UUID once, then the
        // item listing carries `--organizationid` so the CLI acts in that
        // organization rather than the whole vault.
        let fake = FakeBw::new()
            .with_organizations(json!([{"id": "org-1", "name": "DevOps"}]))
            .with_items(json!([{
                "id": "it1", "name": "Vault", "type": 1,
                "login": {"password": "pw"}, "organizationId": "org-1"
            }]));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig {
                organization_id: Some("DevOps".to_string()),
                ..Default::default()
            });
            let value = provider.get_from_password_manager("Vault", None).unwrap();
            assert_eq!(
                value.map(|s| s.expose_secret().to_string()),
                Some("pw".to_string())
            );
            let log = fake.invocations();
            assert!(
                log.contains("<list> <items> <--search> <Vault> <--organizationid> <org-1>"),
                "{log}"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn set_updates_an_existing_item_in_place() {
        // A set against an existing item must fetch it, change the addressed
        // field, and send the whole item back through `edit item` — never
        // create a second item alongside it.
        let fake = FakeBw::new().with_items(json!([{
            "id": "it1", "name": "Vault", "type": 1,
            "login": {"username": "alice", "password": "old"}
        }]));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            provider
                .set_to_password_manager("Vault", None, &SecretString::new("new".into()))
                .unwrap();
        });
        let log = fake.invocations();
        assert!(
            log.contains("argv: <--nointeraction> <get> <item> <it1>"),
            "{log}"
        );
        assert!(
            log.contains("argv: <--nointeraction> <edit> <item> <it1>"),
            "{log}"
        );
        assert!(
            !log.contains("<create>"),
            "must not create a second item: {log}"
        );
        let sent = decode_stdin_line(&fake, "edit");
        assert_eq!(sent["login"]["password"], "new");
        assert_eq!(sent["login"]["username"], "alice");
    }

    #[cfg(unix)]
    #[test]
    fn set_creates_a_new_item_when_none_matches() {
        // A set against an empty vault must create a Login (the type
        // default) with the value in the type's default field, so a later
        // unqualified get finds it.
        let fake = FakeBw::new();
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            provider
                .set_to_password_manager("Vault", None, &SecretString::new("s3cret".into()))
                .unwrap();
        });
        let log = fake.invocations();
        assert!(
            log.contains("argv: <--nointeraction> <create> <item>"),
            "{log}"
        );
        let sent = decode_stdin_line(&fake, "create");
        assert_eq!(sent["name"], "Vault");
        assert_eq!(sent["type"], 1);
        assert_eq!(sent["login"]["password"], "s3cret");
    }

    #[cfg(unix)]
    #[test]
    fn set_with_an_explicit_field_writes_that_field() {
        // `set --field username` updates the built-in login member, leaving
        // the password alone: a write to one secret is never a write to
        // another.
        let fake = FakeBw::new().with_items(json!([{
            "id": "it1", "name": "Vault", "type": 1,
            "login": {"username": "old-user", "password": "pw"}
        }]));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            provider
                .set_to_password_manager(
                    "Vault",
                    Some("username"),
                    &SecretString::new("new-user".into()),
                )
                .unwrap();
        });
        let sent = decode_stdin_line(&fake, "edit");
        assert_eq!(sent["login"]["username"], "new-user");
        assert_eq!(sent["login"]["password"], "pw");
    }

    #[cfg(unix)]
    #[test]
    fn set_fails_closed_when_not_authenticated() {
        let fake = FakeBw::new().with_status(json!({
            "serverUrl": null, "status": "locked", "authenticated": true
        }));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let err = provider
                .set_to_password_manager("Vault", None, &SecretString::new("x".into()))
                .unwrap_err();
            assert!(
                format!("{err}").contains("Bitwarden authentication required"),
                "{err}"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn create_new_item_builds_a_card_item_for_a_card_address() {
        // A `?type=card` address creates a Card with the value in the card
        // number slot, not a Login.
        let fake = FakeBw::new();
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig {
                default_item_type: Some(BitwardenItemType::Card),
                ..Default::default()
            });
            provider
                .create_new_item("NewCard", None, "4111 1111 1111 1111")
                .unwrap();
        });
        let sent = decode_stdin_line(&fake, "create");
        assert_eq!(sent["name"], "NewCard");
        assert_eq!(sent["type"], 3);
        assert_eq!(sent["card"]["number"], "4111 1111 1111 1111");
    }

    /// Decodes the single base64 JSON payload the fake `bw` logged on stdin
    /// for the given command (`create` or `edit`), for tests that assert what
    /// the provider actually sent.
    #[cfg(unix)]
    fn decode_stdin_line(fake: &FakeBw, command: &str) -> serde_json::Value {
        use base64::{Engine as _, engine::general_purpose};
        let log = fake.invocations();
        let cmd_line = log
            .lines()
            .find(|line| line.contains(&format!("<{command}> <item>")))
            .unwrap_or_else(|| panic!("no {command} invocation in log:\n{log}"));
        // The stdin line immediately follows the command's argv line.
        let stdin_line = log
            .lines()
            .skip_while(|line| *line != cmd_line)
            .nth(1)
            .and_then(|line| line.strip_prefix(" stdin="))
            .unwrap_or_else(|| panic!("no stdin recorded for {command}:\n{log}"));
        let bytes = general_purpose::STANDARD
            .decode(stdin_line)
            .expect("stdin must be base64");
        serde_json::from_slice(&bytes).expect("stdin must decode as an item")
    }

    // -- last error paths and trait wrappers -------------------------------

    #[cfg(unix)]
    #[test]
    fn create_item_from_template_reports_a_missing_cli() {
        // The creation spawn carries its own NotFound handling with install
        // instructions, separate from `execute_bw_command`'s.
        let provider = provider_without_bw();
        let err = provider
            .create_item_from_template(&json!({ "name": "Vault" }))
            .unwrap_err();
        assert!(
            format!("{err}").contains("Bitwarden CLI (bw) is not installed"),
            "{err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn update_item_with_json_reports_a_missing_cli() {
        let provider = provider_without_bw();
        let err = provider
            .update_item_with_json("it1", &json!({ "id": "it1" }))
            .unwrap_err();
        assert!(
            format!("{err}").contains("Bitwarden CLI (bw) is not installed"),
            "{err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn look_up_scope_reports_an_organizations_listing_failure() {
        // A failed `bw list organizations` is surfaced with its own context
        // so the operator knows which call failed.
        let fake = FakeBw::new().with_failure(1, "", "boom");
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig {
                organization_id: Some("DevOps".to_string()),
                ..Default::default()
            });
            let err = provider.look_up_scope().unwrap_err();
            assert!(
                err.contains("could not list Bitwarden organizations"),
                "{err}"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn look_up_scope_reports_a_collections_listing_failure() {
        // Only the collections listing fails here; the organizations listing
        // must still succeed, or its own earlier error would shadow this one.
        let fake = FakeBw::new().with_failure_on(1, "", "boom", "collections");
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig {
                organization_id: Some("DevOps".to_string()),
                ..Default::default()
            });
            let err = provider.look_up_scope().unwrap_err();
            assert!(
                err.contains("could not list Bitwarden collections"),
                "{err}"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn provider_get_resolves_a_convention_address() {
        // The Provider trait entry point maps the convention address onto
        // the item name and delegates to the password-manager read.
        let fake = FakeBw::new().with_items(json!([{
            "id": "it1", "name": "Vault", "type": 1,
            "login": {"password": "pw"}
        }]));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let addr = Address::convention("myapp", "production", "Vault");
            let value = provider.get(addr).unwrap();
            assert_eq!(
                value.map(|s| s.expose_secret().to_string()),
                Some("pw".to_string())
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn provider_get_resolves_a_native_address_with_a_field() {
        // A native `ref` can name the item *and* a field coordinate, which
        // the convention scheme has no room for.
        let fake = FakeBw::new().with_items(json!([{
            "id": "it1", "name": "Vault", "type": 1,
            "login": {"username": "alice", "password": "pw"}
        }]));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let native = crate::config::NativeAddress {
                item: "Vault".to_string(),
                field: Some("username".to_string()),
                ..Default::default()
            };
            let value = provider.get(Address::Native(&native)).unwrap();
            assert_eq!(
                value.map(|s| s.expose_secret().to_string()),
                Some("alice".to_string())
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn provider_set_resolves_a_convention_address() {
        let fake = FakeBw::new(); // empty vault: the write must create
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let addr = Address::convention("myapp", "production", "Vault");
            provider
                .set(addr, &SecretString::new("s3cret".into()))
                .unwrap();
        });
        assert!(
            fake.invocations()
                .contains("argv: <--nointeraction> <create> <item>"),
            "{}",
            fake.invocations()
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_new_item_with_an_explicit_field_writes_that_field() {
        // A named field on creation is resolved the same way as on update:
        // a login created with `--field username` stores the value in the
        // login member, not in a custom field.
        let fake = FakeBw::new();
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            provider
                .create_new_item("New", Some("username"), "alice")
                .unwrap();
        });
        let sent = decode_stdin_line(&fake, "create");
        assert_eq!(sent["login"]["username"], "alice");
    }

    #[cfg(unix)]
    #[test]
    fn get_returns_secure_note_body_when_no_value_field_exists() {
        // A secure note's body is where the updater writes, so an unqualified
        // read falls back to it only after the legacy "value" custom field;
        // naming the body explicitly reads it directly.
        let fake = FakeBw::new().with_items(json!([{
            "id": "n1", "name": "Note", "type": 2, "notes": "body", "fields": []
        }]));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let unqualified = provider.get_from_password_manager("Note", None).unwrap();
            assert_eq!(
                unqualified.map(|s| s.expose_secret().to_string()),
                Some("body".to_string())
            );
            let named = provider
                .get_from_password_manager("Note", Some("notes"))
                .unwrap();
            assert_eq!(
                named.map(|s| s.expose_secret().to_string()),
                Some("body".to_string())
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn an_item_with_an_unknown_type_fails_to_parse() {
        // A listing `bw` could never produce must not deserialize into a
        // defaulted item: the parse fails and the read reports it.
        let fake = FakeBw::new().with_items(json!([{
            "id": "x", "name": "Bad", "type": 99
        }]));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let err = provider.get_from_password_manager("Bad", None).unwrap_err();
            assert!(format!("{err}").contains("Unknown item type"), "{err}");
        });
    }

    #[cfg(unix)]
    #[test]
    fn an_item_with_an_unknown_field_type_fails_to_parse() {
        let fake = FakeBw::new().with_items(json!([{
            "id": "x", "name": "Bad", "type": 1,
            "login": {"password": "pw"},
            "fields": [{"name": "f", "value": "v", "type": 99}]
        }]));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig::default());
            let err = provider.get_from_password_manager("Bad", None).unwrap_err();
            assert!(format!("{err}").contains("Unknown field type"), "{err}");
        });
    }

    #[test]
    fn from_value_rejects_an_unknown_item_type() {
        // The `Value` deserializer instantiation (used when an item is built
        // from already-parsed JSON) enforces the same bounds as the listing
        // parser.
        let err = serde_json::from_value::<BitwardenItem>(json!({ "type": 99 })).unwrap_err();
        assert!(err.to_string().contains("Unknown item type"), "{err}");
    }

    #[test]
    fn from_value_rejects_an_unknown_field_type() {
        let err = serde_json::from_value::<BitwardenItem>(json!({
            "type": 1, "fields": [{"name": "f", "type": 99}]
        }))
        .unwrap_err();
        assert!(err.to_string().contains("Unknown field type"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn look_up_scope_keeps_a_collection_without_an_organization() {
        // A collection whose fixture omits `organizationId` resolves with the
        // organization slot left empty (no org was addressed to inherit one).
        let fake = FakeBw::new().with_collections(json!([{
            "id": "col-1", "name": "dev"
        }]));
        fake.run(|| {
            let provider = BitwardenProvider::new(BitwardenConfig {
                collection_id: Some("dev".to_string()),
                ..Default::default()
            });
            let scope = provider.look_up_scope().unwrap();
            assert_eq!(scope.organization_id, None);
            assert_eq!(scope.collection_id.as_deref(), Some("col-1"));
        });
    }

    // -- login items --------------------------------------------------------

    #[test]
    fn reading_totp_returns_the_totp_seed() {
        // `totp` is a built-in login slot, not a custom field: reading it must
        // answer with the seed rather than falling through to the password.
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "l1", "name": "Vault", "type": 1,
            "login": { "username": "alice", "password": "pw", "totp": "JBSWY3DPEHPK3PXP" }
        }));
        assert_eq!(
            read_naming_a_field(&provider, &item, "totp").as_deref(),
            Some("JBSWY3DPEHPK3PXP"),
        );
    }

    #[test]
    fn a_login_without_a_password_defaults_to_the_username() {
        // The unqualified read prefers password, then username: a login with
        // no password must not become unreadable.
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "l2", "name": "Vault", "type": 1,
            "login": { "username": "alice", "password": null }
        }));
        assert_eq!(
            read_without_naming_a_field(&provider, &item).as_deref(),
            Some("alice"),
        );
    }

    #[test]
    fn an_unknown_login_field_that_is_absent_returns_nothing() {
        // A misspelled or absent field must not fall through to the password:
        // a request for one secret is never answered with a different one.
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "l3", "name": "Vault", "type": 1,
            "login": { "username": "alice", "password": "pw" }
        }));
        assert_eq!(read_naming_a_field(&provider, &item, "totp"), None);
        assert_eq!(read_naming_a_field(&provider, &item, "api_key"), None);
    }

    // -- card items ---------------------------------------------------------

    #[test]
    fn card_aliases_read_the_same_slot() {
        // Every documented spelling of a card slot names the same member.
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "c1", "name": "Card", "type": 3,
            "card": { "cardholderName": "Ada L", "number": "4242", "brand": "Visa",
                       "expMonth": "12", "expYear": "2030", "code": "123" }
        }));
        for alias in ["code", "cvv", "cvc"] {
            assert_eq!(
                read_naming_a_field(&provider, &item, alias).as_deref(),
                Some("123"),
                "{alias}"
            );
        }
        for alias in ["cardholder", "name"] {
            assert_eq!(
                read_naming_a_field(&provider, &item, alias).as_deref(),
                Some("Ada L"),
                "{alias}",
            );
        }
        for alias in ["expmonth", "exp_month"] {
            assert_eq!(
                read_naming_a_field(&provider, &item, alias).as_deref(),
                Some("12"),
                "{alias}"
            );
        }
        assert_eq!(
            read_naming_a_field(&provider, &item, "exp_year").as_deref(),
            Some("2030")
        );
        assert_eq!(
            read_naming_a_field(&provider, &item, "brand").as_deref(),
            Some("Visa")
        );
    }

    #[test]
    fn a_card_read_is_case_insensitive() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "c2", "name": "Card", "type": 3,
            "card": { "cardholderName": "Ada L", "number": "4242", "brand": "Visa" }
        }));
        assert_eq!(
            read_naming_a_field(&provider, &item, "BRAND").as_deref(),
            Some("Visa")
        );
    }

    #[test]
    fn an_unknown_card_field_that_is_absent_returns_nothing() {
        // An explicit selector resolves to that slot or to nothing; it is not
        // answered with the card number.
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "c3", "name": "Card", "type": 3,
            "card": { "cardholderName": "Ada L", "number": "4242" }
        }));
        assert_eq!(read_naming_a_field(&provider, &item, "exp_month"), None);
        assert_eq!(read_naming_a_field(&provider, &item, "cvv"), None);
    }

    #[test]
    fn a_card_without_a_number_falls_back_to_its_value_field() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "c4", "name": "Card", "type": 3,
            "card": { "cardholderName": "Ada", "number": null },
            "fields": [ { "name": "value", "value": "legacy", "type": 0 } ]
        }));
        assert_eq!(
            read_without_naming_a_field(&provider, &item).as_deref(),
            Some("legacy"),
        );
    }

    // -- identity items -----------------------------------------------------

    #[test]
    fn identity_aliases_read_the_same_slot() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "i1", "name": "Person", "type": 4,
            "identity": { "firstName": "Ada", "lastName": "Lovelace", "username": "ada",
                           "company": "Analytical Engine", "email": "ada@example.test",
                           "phone": "+1-555-0100" }
        }));
        for alias in ["firstname", "first_name"] {
            assert_eq!(
                read_naming_a_field(&provider, &item, alias).as_deref(),
                Some("Ada"),
                "{alias}"
            );
        }
        for alias in ["lastname", "last_name"] {
            assert_eq!(
                read_naming_a_field(&provider, &item, alias).as_deref(),
                Some("Lovelace"),
                "{alias}",
            );
        }
        assert_eq!(
            read_naming_a_field(&provider, &item, "username").as_deref(),
            Some("ada")
        );
        assert_eq!(
            read_naming_a_field(&provider, &item, "company").as_deref(),
            Some("Analytical Engine"),
        );
        assert_eq!(
            read_naming_a_field(&provider, &item, "email").as_deref(),
            Some("ada@example.test"),
        );
        assert_eq!(
            read_naming_a_field(&provider, &item, "phone").as_deref(),
            Some("+1-555-0100")
        );
    }

    #[test]
    fn an_unknown_identity_field_that_is_absent_returns_nothing() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "i2", "name": "Person", "type": 4,
            "identity": { "firstName": "Ada", "lastName": "Lovelace", "email": "ada@example.test" }
        }));
        assert_eq!(read_naming_a_field(&provider, &item, "company"), None);
    }

    #[test]
    fn an_identity_without_builtin_slots_falls_back_to_its_value_field() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "i3", "name": "Person", "type": 4,
            "identity": { "firstName": null, "email": null },
            "fields": [ { "name": "value", "value": "legacy", "type": 0 } ]
        }));
        assert_eq!(
            read_without_naming_a_field(&provider, &item).as_deref(),
            Some("legacy"),
        );
    }

    // -- ssh key items ------------------------------------------------------

    #[test]
    fn ssh_aliases_read_the_same_slot() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "s1", "name": "Key", "type": 5,
            "sshKey": { "privateKey": "PRIV", "publicKey": "PUB", "keyFingerprint": "SHA256:fp" }
        }));
        for alias in ["private_key", "privatekey", "private"] {
            assert_eq!(
                read_naming_a_field(&provider, &item, alias).as_deref(),
                Some("PRIV"),
                "{alias}"
            );
        }
        for alias in ["public_key", "publickey", "public"] {
            assert_eq!(
                read_naming_a_field(&provider, &item, alias).as_deref(),
                Some("PUB"),
                "{alias}"
            );
        }
        for alias in ["fingerprint", "key_fingerprint"] {
            assert_eq!(
                read_naming_a_field(&provider, &item, alias).as_deref(),
                Some("SHA256:fp"),
                "{alias}",
            );
        }
    }

    #[test]
    fn a_public_key_request_is_never_answered_with_the_private_key() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "s2", "name": "Key", "type": 5,
            "sshKey": { "privateKey": "PRIV", "publicKey": "PUB" }
        }));
        assert_eq!(
            read_naming_a_field(&provider, &item, "public").as_deref(),
            Some("PUB")
        );
    }

    // -- secure notes -------------------------------------------------------

    #[test]
    fn an_explicit_secure_note_field_that_is_absent_returns_nothing() {
        // R8: an explicit selector resolves to that field or to nothing; the
        // note body is not a fallback for a misspelled custom field.
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "n1", "name": "Note", "type": 2, "notes": "body",
            "fields": [ { "name": "value", "value": "legacy", "type": 0 } ]
        }));
        assert_eq!(read_naming_a_field(&provider, &item, "missing"), None);
    }

    #[test]
    fn a_secure_note_with_neither_value_field_nor_body_reads_as_nothing() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({ "id": "n2", "name": "Empty Note", "type": 2 }));
        assert_eq!(read_without_naming_a_field(&provider, &item), None);
    }

    // -- custom fields ------------------------------------------------------

    #[test]
    fn an_exact_custom_field_match_wins_over_a_partial_one() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "f1", "name": "API Keys", "type": 1,
            "login": { "username": "alice", "password": "pw" },
            "fields": [
                { "name": "API_KEY_OLD", "value": "stale", "type": 0 },
                { "name": "API_KEY", "value": "fresh", "type": 0 }
            ]
        }));
        assert_eq!(
            read_naming_a_field(&provider, &item, "API_KEY").as_deref(),
            Some("fresh")
        );
    }

    #[test]
    fn a_partial_custom_field_match_resolves_to_the_first_containing_field() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "f2", "name": "Notes", "type": 2, "notes": "body",
            "fields": [ { "name": "My API Key", "value": "sk-123", "type": 0 } ]
        }));
        assert_eq!(
            read_naming_a_field(&provider, &item, "api").as_deref(),
            Some("sk-123")
        );
    }

    // -- custom-field writes ------------------------------------------------

    #[test]
    fn adding_a_custom_field_creates_it_in_the_fields_array() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let mut item_json = serde_json::json!({ "id": "t1", "name": "Item", "type": 1 });
        provider
            .update_custom_field_in_json(&mut item_json, "api_key", "sk-1")
            .unwrap();
        let fields = item_json["fields"]
            .as_array()
            .expect("a fields array is created");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0]["name"].as_str(), Some("api_key"));
        assert_eq!(fields[0]["value"].as_str(), Some("sk-1"));
    }

    #[test]
    fn secret_like_field_names_are_stored_hidden_and_others_as_text() {
        // Hidden (type 1) fields are masked in the vault UI; a field holding a
        // secret must not be stored as visible plaintext.
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let mut item_json = serde_json::json!({ "id": "t2", "name": "Item", "type": 1 });
        provider
            .update_custom_field_in_json(&mut item_json, "api_key", "sk")
            .unwrap();
        provider
            .update_custom_field_in_json(&mut item_json, "display_name", "prod")
            .unwrap();
        let fields = item_json["fields"].as_array().unwrap();
        let by_name = |n: &str| fields.iter().find(|f| f["name"] == n).unwrap();
        assert_eq!(
            by_name("api_key")["type"].as_u64(),
            Some(1),
            "api_key holds a secret"
        );
        assert_eq!(
            by_name("display_name")["type"].as_u64(),
            Some(0),
            "display_name does not"
        );
    }

    #[test]
    fn a_non_array_fields_value_is_reported_not_ignored() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let mut item_json =
            serde_json::json!({ "id": "t3", "name": "Item", "type": 1, "fields": "oops" });
        let err = provider
            .update_custom_field_in_json(&mut item_json, "x", "y")
            .expect_err("fields must be an array");
        assert!(err.to_string().contains("Invalid fields array"), "{err}");
    }

    // -- addressing and placement -------------------------------------------

    #[test]
    fn convention_address_names_the_secret_key_as_the_item() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let address = provider
            .convention_address("project", "default", "DATABASE_URL")
            .unwrap();
        assert_eq!(address.item, "DATABASE_URL");
    }

    #[test]
    fn items_support_field_coordinates() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        assert_eq!(provider.supported_coords(), &["field"]);
    }

    #[test]
    fn same_entries_treats_an_implicit_login_field_as_password() {
        with_clean_env(|| {
            let provider = BitwardenProvider::new(BitwardenConfig {
                default_item_type: Some(BitwardenItemType::Login),
                ..Default::default()
            });
            let implicit = crate::config::NativeAddress {
                item: "shared".into(),
                ..Default::default()
            };
            let explicit = crate::config::NativeAddress {
                item: "shared".into(),
                field: Some("password".into()),
                ..Default::default()
            };

            assert!(
                provider
                    .same_entries(
                        Address::Native(&implicit),
                        &provider,
                        Address::Native(&explicit),
                    )
                    .unwrap()
            );
        });
    }

    #[test]
    fn same_entries_uses_explicit_fields_instead_of_provider_defaults() {
        with_clean_env(|| {
            let left = BitwardenProvider::new(BitwardenConfig {
                default_field: Some("left".into()),
                ..Default::default()
            });
            let right = BitwardenProvider::new(BitwardenConfig {
                default_field: Some("right".into()),
                ..Default::default()
            });
            let address = crate::config::NativeAddress {
                item: "shared".into(),
                field: Some("password".into()),
                ..Default::default()
            };

            assert!(
                left.same_entries(Address::Native(&address), &right, Address::Native(&address),)
                    .unwrap()
            );
        });
    }

    #[test]
    fn placement_from_a_scope_carries_its_organization_and_collection() {
        let scoped = VaultScope {
            organization_id: Some("org-1".to_string()),
            collection_id: Some("col-2".to_string()),
        };
        let placement = ItemPlacement::from(&scoped);
        assert_eq!(placement.organization_id.as_deref(), Some("org-1"));
        assert_eq!(
            placement.collection_ids.as_deref(),
            Some(&["col-2".to_string()][..]),
        );

        let org_only = VaultScope {
            organization_id: Some("org-1".to_string()),
            collection_id: None,
        };
        let placement = ItemPlacement::from(&org_only);
        assert_eq!(placement.organization_id.as_deref(), Some("org-1"));
        assert_eq!(placement.collection_ids, None);
    }

    #[test]
    fn an_unscoped_provider_places_items_nowhere() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        with_clean_env(|| {
            let placement = provider.item_placement().expect("unscoped: no CLI call");
            assert_eq!(placement.organization_id, None);
            assert_eq!(placement.collection_ids, None);
        });
    }

    // -- scope / type resolution --------------------------------------------

    #[test]
    fn the_environment_overrides_the_configured_scope() {
        let provider = BitwardenProvider::new(BitwardenConfig {
            organization_id: Some("cfg-org".to_string()),
            collection_id: Some("cfg-col".to_string()),
            ..Default::default()
        });
        with_clean_env(|| {
            assert_eq!(provider.requested_org().as_deref(), Some("cfg-org"));
            assert_eq!(provider.requested_collection().as_deref(), Some("cfg-col"));
        });
        with_env("BITWARDEN_ORGANIZATION", "env-org", || {
            assert_eq!(provider.requested_org().as_deref(), Some("env-org"));
        });
        with_env("BITWARDEN_COLLECTION", "env-col", || {
            assert_eq!(provider.requested_collection().as_deref(), Some("env-col"));
        });
    }

    #[test]
    fn resolved_item_type_prefers_the_environment_and_falls_back_to_config() {
        let provider = BitwardenProvider::new(BitwardenConfig {
            default_item_type: Some(BitwardenItemType::Card),
            ..Default::default()
        });
        with_clean_env(|| {
            assert_eq!(
                provider.resolved_item_type().unwrap(),
                Some(BitwardenItemType::Card)
            );
        });
        with_env("BITWARDEN_DEFAULT_TYPE", "ssh", || {
            assert_eq!(
                provider.resolved_item_type().unwrap(),
                Some(BitwardenItemType::SshKey)
            );
        });

        let bare = BitwardenProvider::new(BitwardenConfig::default());
        with_clean_env(|| assert_eq!(bare.resolved_item_type().unwrap(), None));
    }

    // -- enums and error rendering ------------------------------------------

    #[test]
    fn every_item_type_round_trips_through_as_str() {
        // `as_str` must emit a spelling `from_str` accepts, or a `type=` a
        // `uri()` emits could never be read back as the same item type.
        for item_type in ALL_ITEM_TYPES {
            assert_eq!(
                BitwardenItemType::from_str(item_type.as_str()),
                Some(item_type)
            );
        }
    }

    #[test]
    fn field_types_have_readable_names() {
        assert_eq!(BitwardenFieldType::Text.as_str(), "text");
        assert_eq!(BitwardenFieldType::Hidden.as_str(), "hidden");
        assert_eq!(BitwardenFieldType::Boolean.as_str(), "boolean");
        assert_eq!(BitwardenFieldType::Linked.as_str(), "linked");
    }

    #[test]
    fn describe_org_prefers_the_listed_name_and_falls_back_to_the_id() {
        let orgs = vec![BitwardenNamedObject {
            id: "o1".to_string(),
            name: "Acme Inc".to_string(),
            organization_id: None,
        }];
        assert_eq!(describe_org(Some("o1"), &orgs), "'Acme Inc' (o1)");
        assert_eq!(describe_org(Some("unknown"), &orgs), "'unknown'");
        assert_eq!(describe_org(None, &orgs), "your personal vault");
    }

    #[test]
    fn list_organizations_names_them_or_says_none_are_visible() {
        let none = list_organizations(&[]);
        assert!(none.contains("listed no organizations"), "{none}");

        let orgs = vec![BitwardenNamedObject {
            id: "o1".to_string(),
            name: "Acme Inc".to_string(),
            organization_id: None,
        }];
        let listing = list_organizations(&orgs);
        assert!(listing.contains("Available organizations:"), "{listing}");
        assert!(listing.contains("Acme Inc (o1)"), "{listing}");
    }

    // -- remaining pure-path gaps (issue #5, survey pass) -------------------

    #[test]
    fn reading_password_explicitly_returns_the_login_password() {
        // The explicit "password" selector is a real coordinate, not just the
        // unqualified default: it must answer with the password.
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "l5", "name": "Vault", "type": 1,
            "login": { "username": "alice", "password": "pw" }
        }));
        assert_eq!(
            read_naming_a_field(&provider, &item, "password").as_deref(),
            Some("pw")
        );
    }

    #[test]
    fn a_login_with_neither_password_nor_username_falls_back_to_custom_fields() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "l6", "name": "Vault", "type": 1,
            "login": { "username": null, "password": null },
            "fields": [ { "name": "value", "value": "legacy", "type": 0 } ]
        }));
        assert_eq!(
            read_without_naming_a_field(&provider, &item).as_deref(),
            Some("legacy"),
        );
    }

    #[test]
    fn an_item_type_without_its_data_object_falls_back_to_custom_fields() {
        // A login/card/identity/ssh item whose data sub-object is absent: the
        // unqualified read still answers from the legacy "value" field.
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        for (item_type, id) in [
            (BitwardenItemType::Login, "no-login"),
            (BitwardenItemType::Card, "no-card"),
            (BitwardenItemType::Identity, "no-identity"),
            (BitwardenItemType::SshKey, "no-ssh"),
        ] {
            let item = item_from(json!({
                "id": id, "name": "Bare", "type": item_type.to_u8(),
                "fields": [ { "name": "value", "value": "legacy", "type": 0 } ]
            }));
            assert_eq!(
                read_without_naming_a_field(&provider, &item).as_deref(),
                Some("legacy"),
                "{item_type:?}",
            );
        }
    }

    #[test]
    fn a_non_builtin_card_field_reads_a_custom_field_or_nothing() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "c5", "name": "Card", "type": 3,
            "card": { "cardholderName": "Ada", "number": "4242" },
            "fields": [ { "name": "api_token", "value": "tok-1", "type": 0 } ]
        }));
        assert_eq!(
            read_naming_a_field(&provider, &item, "api_token").as_deref(),
            Some("tok-1")
        );
        assert_eq!(read_naming_a_field(&provider, &item, "missing"), None);
    }

    #[test]
    fn a_non_builtin_identity_field_reads_a_custom_field_or_nothing() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "i4", "name": "Person", "type": 4,
            "identity": { "firstName": "Ada", "email": "ada@example.test" },
            "fields": [ { "name": "employee_id", "value": "EMP001", "type": 0 } ]
        }));
        assert_eq!(
            read_naming_a_field(&provider, &item, "employee_id").as_deref(),
            Some("EMP001"),
        );
        assert_eq!(read_naming_a_field(&provider, &item, "missing"), None);
    }

    #[test]
    fn a_non_builtin_ssh_field_reads_a_custom_field_or_nothing() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "s3", "name": "Key", "type": 5,
            "sshKey": { "privateKey": "PRIV", "publicKey": "PUB" },
            "fields": [ { "name": "passphrase", "value": "secret", "type": 0 } ]
        }));
        assert_eq!(
            read_naming_a_field(&provider, &item, "passphrase").as_deref(),
            Some("secret"),
        );
        assert_eq!(read_naming_a_field(&provider, &item, "missing"), None);
    }

    #[test]
    fn an_identity_without_an_email_defaults_to_the_username() {
        let provider = BitwardenProvider::new(BitwardenConfig::default());
        let item = item_from(json!({
            "id": "i5", "name": "Person", "type": 4,
            "identity": { "firstName": "Ada", "email": null, "username": "ada" }
        }));
        assert_eq!(
            read_without_naming_a_field(&provider, &item).as_deref(),
            Some("ada")
        );
    }

    #[test]
    fn an_ambiguous_organization_name_is_reported_with_a_remedy() {
        // Two organizations sharing a name cannot be resolved by name; the
        // error must say so and point at the UUID rather than silently pick one.
        let orgs = vec![
            BitwardenNamedObject {
                id: "o1".to_string(),
                name: "Acme Inc".to_string(),
                organization_id: None,
            },
            BitwardenNamedObject {
                id: "o2".to_string(),
                name: "Acme Inc".to_string(),
                organization_id: None,
            },
        ];
        let err = resolve_organization(&orgs, "Acme Inc").expect_err("duplicate name");
        assert!(err.contains("ambiguous"), "{err}");
        assert!(err.contains("UUID"), "{err}");
    }
}
