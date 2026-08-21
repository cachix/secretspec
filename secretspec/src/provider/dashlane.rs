//! Dashlane provider backed by the Dashlane CLI (`dcli`).
//!
//! Dashlane's vault is **read-only** through `dcli`: it has no `create`,
//! `add`, `set`, `update` or `delete` subcommand for any item type. Items are
//! authored in a Dashlane app and read from here, so this provider implements
//! [`Provider::get`] and refuses every write.

use crate::provider::{Address, Provider, ProviderUrl};
use crate::{Result, SecretSpecError};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const DCLI_NOT_INSTALLED_HELP: &str = "\
Dashlane CLI (dcli) is not installed.

To install it:
  - macOS:  brew install dashlane/tap/dashlane-cli
  - Linux:  download the dcli-linux-x64 binary from
            https://github.com/Dashlane/dashlane-cli/releases

After installation, run 'dcli sync' to register this device and log in.";

const AUTH_REQUIRED_HELP: &str = "\
Dashlane authentication required. Run 'dcli sync' to register this device and \
log in, or set DASHLANE_SERVICE_DEVICE_KEYS for a non-interactive device \
registered with 'dcli devices register'.";

/// `dcli` asked for something interactive and the closed stdin refused it.
const INPUT_REQUIRED_HELP: &str = "\
Dashlane CLI asked for input SecretSpec cannot supply: this device is not \
registered, or the vault is locked. Run 'dcli sync' to register and unlock it, \
or set DASHLANE_SERVICE_DEVICE_KEYS for a non-interactive device registered \
with 'dcli devices register'.";

const LOCKED_HELP: &str = "\
The Dashlane vault is locked. Run any 'dcli' command to unlock it with your \
master password, or re-enable 'dcli configure save-master-password true'.";

/// Injected credentials need somewhere private to keep `dcli`'s state, and
/// there is nowhere safe to fall back to.
const NO_CACHE_DIR_HELP: &str = "\
Cannot locate a cache directory to hold the private Dashlane CLI state that \
DASHLANE_SERVICE_DEVICE_KEYS requires. Set XDG_CACHE_HOME (or HOME) to a \
writable directory, or log in with 'dcli sync' and drop the credential.";

/// The environment variable holding non-interactive device credentials, as
/// printed by `dcli devices register`.
const DEVICE_KEYS_ENV: &str = "DASHLANE_SERVICE_DEVICE_KEYS";

/// The semantic credential name for [`DEVICE_KEYS_ENV`].
const SERVICE_DEVICE_KEYS: &str = "service_device_keys";

/// A Dashlane content type, each with its own `dcli` lister subcommand.
///
/// `dcli` exposes exactly three listers, and they are not interchangeable:
/// `password` defaults to writing the secret to the system clipboard, while
/// `note` and `secret` default to unparseable prose. Every invocation passes
/// `-o json` explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemType {
    /// Dashlane's developer "Secret" content type (`dcli secret`).
    Secret,
    /// A secure note (`dcli note`).
    Note,
    /// A login (`dcli password`).
    Password,
}

impl ItemType {
    /// The type's name, which is also the `dcli` subcommand that lists it.
    fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Note => "note",
            Self::Password => "password",
        }
    }

    /// The JSON field holding the secret value when a `ref` names no `field`.
    ///
    /// `content` for a secret comes from `VaultSecret` in `dcli`'s own types
    /// rather than from an observed vault: Dashlane Secrets are a Business-plan
    /// feature, so the shape is unverifiable without one.
    fn default_field(self) -> &'static str {
        match self {
            Self::Secret | Self::Note => "content",
            Self::Password => "password",
        }
    }

    /// The search order used when the URI pins no single type.
    ///
    /// `dcli read` resolves a name as `secrets[0] ?? credentials[0] ??
    /// notes[0]`, so a login outranks a note of the same title. Matching that
    /// keeps a title that resolves one way through `dcli` from resolving
    /// another way here.
    fn search_order() -> &'static [Self] {
        &[Self::Secret, Self::Password, Self::Note]
    }

    fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "secret" | "secrets" => Some(Self::Secret),
            "note" | "notes" => Some(Self::Note),
            // Dashlane's UI calls a password item a login.
            "password" | "passwords" | "login" | "logins" => Some(Self::Password),
            _ => None,
        }
    }
}

/// Configuration for the Dashlane provider.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DashlaneConfig {
    /// The single content type to search, or `None` to search secrets, then
    /// logins, then notes.
    pub item_type: Option<ItemType>,
}

impl TryFrom<&ProviderUrl> for DashlaneConfig {
    type Error = SecretSpecError;

    /// Parses `dashlane://[item-type]`, where the optional authority pins the
    /// content type to `secret`, `note` or `password`.
    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "dashlane" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for dashlane provider",
                url.scheme()
            )));
        }

        let item_type = match url.host().filter(|h| !h.is_empty()) {
            Some(host) => Some(ItemType::parse(&host).ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "unknown Dashlane item type '{host}'. Use dashlane://secret, \
                     dashlane://note or dashlane://password, or plain dashlane:// \
                     to search all three."
                ))
            })?),
            None => None,
        };

        let path = url.path();
        if !path.is_empty() && path != "/" {
            let trimmed = path.trim_start_matches('/');
            let hint = crate::config::ref_table_hint(None, trimmed, None, None);
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "dashlane:// takes no path: the authority selects the item type, \
                 not an item. To name one specific item, use {hint} on the secret \
                 instead"
            )));
        }

        Ok(Self { item_type })
    }
}

/// Reads secrets from a Dashlane vault through the `dcli` CLI.
///
/// Reads are served from a local vault copy, so an item added moments ago
/// stays invisible until `dcli` syncs. SecretSpec never asks it to, but `dcli`
/// syncs itself: every lister enters `connectAndPrepare`, which contacts
/// Dashlane when the last sync is over an hour old. A read is therefore usually
/// local and occasionally a network round-trip, unless the user has run
/// `dcli configure disable-auto-sync true`. That setting is recorded against
/// the device in the state directory it was run from, so it does not reach the
/// per-credential state directory injected keys are read in; those reads sync
/// on `dcli`'s own schedule.
///
/// Installation and authentication are covered at
/// <https://secretspec.dev/providers/dashlane/>.
pub struct DashlaneProvider {
    config: DashlaneConfig,
    credentials: crate::provider::ProviderCredentials,
}

crate::register_provider! {
    struct: DashlaneProvider,
    config: DashlaneConfig,
    name: "dashlane",
    description: "Dashlane password manager, read-only (0.18+)",
    schemes: ["dashlane"],
    examples: ["dashlane://", "dashlane://note", "dashlane://password"],
    credential_names: [SERVICE_DEVICE_KEYS],
    preflight: check_auth,
}

/// One vault item, as `dcli`'s `-o json` listers emit it.
///
/// Every value in that JSON is a string — booleans, counters and epoch
/// timestamps included — so fields stay untyped here and are read by name.
/// Only `id` is reliably present; `title` is missing on a small share of real
/// items.
#[derive(Debug, Deserialize)]
struct VaultItem {
    id: String,
    title: Option<String>,
    #[serde(flatten)]
    fields: HashMap<String, serde_json::Value>,
}

impl VaultItem {
    /// The item's identifier without the braces `dcli` wraps it in.
    fn bare_id(&self) -> &str {
        self.id.trim_start_matches('{').trim_end_matches('}')
    }

    /// Whether this item is the one `name` addresses.
    ///
    /// A name matches either the identifier — in braced or bare form, since
    /// `dcli` emits one and accepts the other — or the title. Titles fold with
    /// `to_lowercase`, not `eq_ignore_ascii_case`, because `dcli` compares them
    /// with JavaScript's `toLowerCase`: an ASCII-only fold would leave
    /// `Überblick` unreachable as `überblick`.
    fn matches(&self, name: &str) -> bool {
        let bare = name.trim_start_matches('{').trim_end_matches('}');
        // Identifiers are UUIDs, so ASCII folding is exact for them.
        if !bare.is_empty() && self.bare_id().eq_ignore_ascii_case(bare) {
            return true;
        }
        self.title
            .as_deref()
            .is_some_and(|title| title.to_lowercase() == name.to_lowercase())
    }

    /// Reads one field, treating an absent or empty value as no value.
    fn field(&self, field: &str) -> Option<String> {
        let raw = self.fields.get(field)?;
        let value = match raw {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Null => return None,
            other => other.to_string(),
        };
        (!value.is_empty()).then_some(value)
    }
}

/// What one content type's listing had to say about an address.
///
/// Separating the two misses matters when no single type is pinned: an item
/// titled the same as the one wanted, in a type searched earlier, must not
/// abort the search before the type that actually holds the field.
enum Found {
    Value(SecretString),
    /// Nothing to read here: no item of this content type is named that, or
    /// the one that is holds nothing in its default field.
    NoItem,
    /// An item is, but it carries no such field.
    NoField,
}

/// A private `dcli` state directory for one set of device keys.
///
/// Named after a hash of the keys, never the keys themselves: a directory name
/// is visible to anyone who can list the cache or read the process's
/// environment.
fn scoped_state_dir(keys: &str) -> Result<PathBuf> {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    keys.hash(&mut hasher);
    let cache = crate::config::cache_dir()
        .ok_or_else(|| SecretSpecError::ProviderOperationFailed(NO_CACHE_DIR_HELP.to_string()))?;
    Ok(cache
        .join("dashlane")
        .join(format!("{:016x}", hasher.finish())))
}

/// Creates a state directory only its owner can enter.
///
/// Left to `dcli`, the tree is world-readable: its recursive `mkdir` asks for
/// mode `0777` and SQLite creates the database `0666`, both merely masked by
/// the umask. Observed with dcli 6.2628.1 on Linux under a `022` umask, a run
/// against an empty `HOME` leaves `dashlane-cli/` at `0755` and its
/// `userdata.db` at `0644` -- a database holding the service device row and
/// the synced vault. An owner-only directory above them is what keeps both out
/// of reach, so it is created here rather than by `dcli`.
#[cfg(unix)]
fn create_private_dir(dir: &std::path::Path) -> Result<()> {
    use std::fs::{DirBuilder, Permissions, metadata, set_permissions};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let private = |e: std::io::Error| {
        SecretSpecError::ProviderOperationFailed(format!(
            "could not prepare a private dcli state directory at {}: {e}",
            dir.display()
        ))
    };

    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(private)?;
    // `mode` governs only the directories that call created. One left by an
    // earlier SecretSpec, or by a `dcli` that got there first, keeps whatever
    // mode it already has, so tighten it.
    let mode = metadata(dir).map_err(private)?.permissions().mode();
    if mode & 0o077 != 0 {
        set_permissions(dir, Permissions::from_mode(0o700)).map_err(private)?;
    }
    Ok(())
}

/// Creates the state directory on platforms without Unix permission bits.
///
/// Windows inherits the ACL of the parent, and the cache directory lives under
/// the user's profile, which grants no access to other users by default.
#[cfg(not(unix))]
fn create_private_dir(dir: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| {
        SecretSpecError::ProviderOperationFailed(format!(
            "could not prepare a private dcli state directory at {}: {e}",
            dir.display()
        ))
    })
}

/// Whether a `dcli` failure means the subcommand does not exist.
///
/// Verified against 6.2628.1: an unknown subcommand exits 1 with an empty
/// stdout and `error: unknown command '<name>'` on stderr.
fn is_unknown_command(message: &str) -> bool {
    message.contains("unknown command")
}

/// Strips ANSI escape sequences from `dcli`'s coloured stderr.
fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        // Consume through the final byte of the escape sequence.
        for c in chars.by_ref() {
            if c.is_ascii_alphabetic() {
                break;
            }
        }
    }
    out
}

impl DashlaneProvider {
    pub fn new(config: DashlaneConfig) -> Self {
        Self {
            config,
            credentials: Default::default(),
        }
    }

    /// Runs a `dcli` subcommand and returns its raw stdout.
    ///
    /// Returns bytes rather than a `String`: on the lister path stdout is a
    /// plaintext dump of vault items, so it must never reach a log or an error
    /// message.
    fn run(&self, args: &[&str]) -> Result<Vec<u8>> {
        let mut cmd = Command::new("dcli");
        // Injected credentials reach `dcli` the only way it reads them,
        // without touching this process's own environment.
        if let Some(keys) = self.device_keys() {
            // ...but only where no device is already registered. `dcli` reads
            // DASHLANE_SERVICE_DEVICE_KEYS inside `getLocalConfigurationWithoutDB`,
            // which upstream calls only when its state directory holds no device
            // row; with one present, `getLocalConfiguration` takes that row's
            // login instead and the variable is ignored. On a machine already
            // logged in interactively, or across two aliases carrying different
            // keys, that silently reads the wrong identity's vault. Giving each
            // credential its own state directory keeps the identities apart.
            //
            // Failing to prepare that directory has to abort the read: running
            // anyway would hand the keys to a `dcli` pointed at the inherited
            // HOME, which is the very state this isolates against.
            let dir = scoped_state_dir(&keys)?;
            create_private_dir(&dir)?;
            // `dcli` derives its state path from APPDATA, else HOME.
            cmd.env("HOME", &dir);
            cmd.env("APPDATA", &dir);
            cmd.env(DEVICE_KEYS_ENV, keys);
        }
        cmd.args(args);
        // An unauthenticated `dcli` starts device registration and prompts for
        // an email and a second factor. With stdin closed it fails immediately
        // instead of hanging a `secretspec run`.
        cmd.stdin(Stdio::null());

        let output = match cmd.output() {
            Ok(output) => output,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(SecretSpecError::ProviderOperationFailed(
                    DCLI_NOT_INSTALLED_HELP.to_string(),
                ));
            }
            Err(e) => return Err(e.into()),
        };

        if !output.status.success() {
            let stderr = strip_ansi(&String::from_utf8_lossy(&output.stderr));
            let stderr = stderr.trim();
            // Verified against dcli 6.2628.1: an unregistered CLI prompts for
            // an email, and the closed stdin turns that into
            // `error: User force closed the prompt with 0 null`. Every other
            // interactive step -- a second factor, the master password of a
            // locked vault -- fails the same way.
            if stderr.contains("force closed the prompt") {
                return Err(SecretSpecError::ProviderOperationFailed(
                    INPUT_REQUIRED_HELP.to_string(),
                ));
            }
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "dcli {} failed: {stderr}",
                args.join(" ")
            )));
        }

        Ok(output.stdout)
    }

    /// Lists every item of one content type.
    ///
    /// The listers filter by case-insensitive substring, which cannot express
    /// "this exact item", so no filter is passed and matching happens here.
    /// The read is local — `dcli` decrypts an already-synced SQLite vault — so
    /// this is one decrypt, not one network call per secret.
    fn list(&self, item_type: ItemType) -> Result<Vec<VaultItem>> {
        let stdout = match self.run(&[item_type.as_str(), "-o", "json"]) {
            Ok(stdout) => stdout,
            // A `dcli` predating this content type has none of it to list, so
            // the remaining listers still get their turn instead of the whole
            // read failing. `secret` is the one that bites: it arrived in
            // October 2023, and Dashlane Secrets are a Business-plan feature,
            // so it is both the newest lister and the one most users have
            // nothing in.
            Err(SecretSpecError::ProviderOperationFailed(message))
                if is_unknown_command(&message) =>
            {
                return Ok(Vec::new());
            }
            Err(e) => return Err(e),
        };

        // serde's parse errors quote the offending value, which here would be
        // vault contents. Only the position is reported.
        serde_json::from_slice(&stdout).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "could not parse the output of 'dcli {} -o json' (line {}, column {})",
                item_type.as_str(),
                e.line(),
                e.column()
            ))
        })
    }

    /// Finds the one item named `name` among `items`.
    ///
    /// Refuses an ambiguous name rather than picking one: Dashlane titles are
    /// not unique, and `dcli read` resolves a collision by silently returning
    /// an arbitrary item.
    fn find_unique<'a>(
        items: &'a [VaultItem],
        name: &str,
        item_type: ItemType,
    ) -> Result<Option<&'a VaultItem>> {
        let mut matches = items.iter().filter(|item| item.matches(name));
        let Some(first) = matches.next() else {
            return Ok(None);
        };
        let extra = matches.count();
        if extra > 0 {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} Dashlane {} items are titled '{name}'. Rename them, or point \
                 the secret at one identifier with ref = {{ item = \"{}\" }}.",
                extra + 1,
                item_type.as_str(),
                first.bare_id(),
            )));
        }
        Ok(Some(first))
    }

    /// The content types to search, in order.
    fn types_to_search(&self) -> &'static [ItemType] {
        match self.config.item_type {
            Some(ItemType::Secret) => &[ItemType::Secret],
            Some(ItemType::Note) => &[ItemType::Note],
            Some(ItemType::Password) => &[ItemType::Password],
            None => ItemType::search_order(),
        }
    }

    /// Non-interactive device credentials, from an injected credential or the
    /// environment.
    fn device_keys(&self) -> Option<String> {
        crate::provider::credential_or_env(&self.credentials, SERVICE_DEVICE_KEYS, DEVICE_KEYS_ENV)
    }

    /// Verifies the local `dcli` is registered and unlocked, before any read.
    ///
    /// `dcli status` is a purely local check: it reads the device row and the
    /// OS keychain without decrypting the vault or touching the network.
    pub(crate) fn check_auth(&self) -> Result<()> {
        // A registered service device authenticates from the environment and
        // has no local device row until its first sync, so `dcli status` would
        // report it as logged out. The credential is the check.
        if self.device_keys().is_some() {
            return Ok(());
        }

        let stdout = self.run(&["status"])?;
        let status = String::from_utf8_lossy(&stdout);

        let mut logged_in = false;
        let mut locked = false;
        for line in status.lines() {
            match line.split_once(':').map(|(k, v)| (k.trim(), v.trim())) {
                Some(("Logged in", value)) => logged_in = value == "yes",
                Some(("Locked", value)) => locked = value == "yes",
                _ => {}
            }
        }

        if !logged_in {
            return Err(SecretSpecError::ProviderOperationFailed(
                AUTH_REQUIRED_HELP.to_string(),
            ));
        }
        if locked {
            return Err(SecretSpecError::ProviderOperationFailed(
                LOCKED_HELP.to_string(),
            ));
        }
        Ok(())
    }

    /// Resolves one address against an already-listed content type.
    fn lookup(
        &self,
        items: &[VaultItem],
        item_type: ItemType,
        name: &str,
        field: Option<&str>,
    ) -> Result<Found> {
        let Some(item) = Self::find_unique(items, name, item_type)? else {
            return Ok(Found::NoItem);
        };
        match item.field(field.unwrap_or_else(|| item_type.default_field())) {
            Some(value) => Ok(Found::Value(SecretString::new(value.into()))),
            // An empty default field just means the item holds nothing. A `ref`
            // naming a field is different: no other item can satisfy it, so the
            // caller reports it once every content type has been searched.
            None if field.is_some() => Ok(Found::NoField),
            None => Ok(Found::NoItem),
        }
    }

    /// The error for a `ref` whose `field` no matching item carries.
    ///
    /// A typo in `secretspec.toml`, not a missing secret, so it is surfaced
    /// rather than reported as unset — the distinction `dcli read` draws.
    fn missing_field(name: &str, field: &str) -> SecretSpecError {
        SecretSpecError::ProviderOperationFailed(format!(
            "no Dashlane item named '{name}' has a '{field}' field"
        ))
    }
}

impl Provider for DashlaneProvider {
    /// The same `secretspec/{project}/{profile}/{key}` layout the other
    /// item-based providers use, carried by the item's title.
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: format!("secretspec/{project}/{profile}/{key}"),
            ..Default::default()
        })
    }

    fn name(&self) -> &str {
        Self::PROVIDER_NAME
    }

    /// Dashlane items carry named fields, so a `ref` can read a login's
    /// `login` or a note's `content` instead of the type's default field.
    fn supported_coords(&self) -> &'static [&'static str] {
        &["field"]
    }

    fn with_credentials(&mut self, credentials: crate::provider::ProviderCredentials) {
        self.credentials = credentials;
    }

    /// `dcli` holds one device registration per machine, so instances reading
    /// the same one share a single preflight probe. Injected device keys
    /// select a different identity, so they scope the probe.
    fn auth_scope_key(&self) -> Option<String> {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.device_keys().hash(&mut hasher);
        Some(format!("{:x}", hasher.finish()))
    }

    fn uri(&self) -> String {
        match self.config.item_type {
            Some(item_type) => format!("dashlane://{}", item_type.as_str()),
            None => "dashlane".to_string(),
        }
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let coords = self.resolve_coords(addr)?;
        let mut lacked_field = false;
        for &item_type in self.types_to_search() {
            let items = self.list(item_type)?;
            match self.lookup(&items, item_type, &coords.item, coords.field.as_deref())? {
                Found::Value(value) => return Ok(Some(value)),
                Found::NoField => lacked_field = true,
                Found::NoItem => {}
            }
        }
        match (lacked_field, coords.field.as_deref()) {
            (true, Some(field)) => Err(Self::missing_field(&coords.item, field)),
            _ => Ok(None),
        }
    }

    /// Reads every requested secret from one listing per content type.
    ///
    /// The default shells out once per secret, and each call decrypts the whole
    /// local vault; a `secretspec run` over twenty secrets pays that once.
    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        let mut resolved = Vec::with_capacity(requests.len());
        for (name, addr) in requests {
            resolved.push((*name, self.resolve_coords(*addr)?));
        }

        let mut found = HashMap::new();
        let mut lacked_field: Vec<&str> = Vec::new();
        for &item_type in self.types_to_search() {
            if resolved.len() == found.len() {
                break;
            }
            let items = self.list(item_type)?;
            for (name, coords) in &resolved {
                if found.contains_key(*name) {
                    continue;
                }
                match self.lookup(&items, item_type, &coords.item, coords.field.as_deref())? {
                    Found::Value(value) => {
                        found.insert((*name).to_string(), value);
                    }
                    Found::NoField => lacked_field.push(name),
                    Found::NoItem => {}
                }
            }
        }

        // A field miss only counts once no content type has produced the value.
        for (name, coords) in &resolved {
            if !found.contains_key(*name) && lacked_field.contains(name) {
                let field = coords.field.as_deref().unwrap_or_default();
                return Err(Self::missing_field(&coords.item, field));
            }
        }
        Ok(found)
    }

    fn set(&self, addr: Address<'_>, _value: &SecretString) -> Result<()> {
        self.check_writable(addr)
    }

    /// Stating the refusal here, not only in `set`, lets the CLI decline the
    /// write before prompting for a value it cannot store.
    fn check_writable(&self, _addr: Address<'_>) -> Result<()> {
        Err(SecretSpecError::ProviderOperationFailed(
            "The Dashlane provider is read-only: dcli cannot create or edit vault \
             items. Add the item in a Dashlane app, run 'dcli sync', then read it \
             here."
                .to_string(),
        ))
    }
}

impl Default for DashlaneProvider {
    fn default() -> Self {
        Self::new(DashlaneConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn config(spec: &str) -> Result<DashlaneConfig> {
        DashlaneConfig::try_from(&ProviderUrl::new(Url::parse(spec).unwrap()))
    }

    fn item(id: &str, title: &str, field: &str, value: &str) -> VaultItem {
        VaultItem {
            id: id.to_string(),
            title: Some(title.to_string()),
            fields: HashMap::from([(
                field.to_string(),
                serde_json::Value::String(value.to_string()),
            )]),
        }
    }

    #[test]
    fn plain_uri_searches_every_type() {
        let provider = DashlaneProvider::new(config("dashlane://").unwrap());
        assert_eq!(provider.types_to_search(), ItemType::search_order());
        assert_eq!(provider.uri(), "dashlane");
    }

    #[test]
    fn authority_pins_the_item_type() {
        let provider = DashlaneProvider::new(config("dashlane://note").unwrap());
        assert_eq!(provider.types_to_search(), &[ItemType::Note]);
        assert_eq!(provider.uri(), "dashlane://note");
    }

    /// `login` is what Dashlane's UI calls a password item.
    #[test]
    fn login_is_an_alias_for_password() {
        let provider = DashlaneProvider::new(config("dashlane://login").unwrap());
        assert_eq!(provider.types_to_search(), &[ItemType::Password]);
        assert_eq!(provider.uri(), "dashlane://password");
    }

    #[test]
    fn unknown_item_type_is_rejected() {
        let err = config("dashlane://passkey").unwrap_err();
        assert!(
            err.to_string().contains("unknown Dashlane item type"),
            "{err}"
        );
    }

    /// A path looks like it names an item; it does not, so it is rejected with
    /// a pointer at the `ref` table rather than silently ignored.
    #[test]
    fn path_is_rejected_with_ref_hint() {
        let err = config("dashlane://note/my-item").unwrap_err();
        assert!(
            err.to_string().contains("ref = { item = \"my-item\" }"),
            "{err}"
        );
    }

    #[test]
    fn foreign_scheme_is_rejected() {
        let err = config("keyring://").unwrap_err();
        assert!(err.to_string().contains("Invalid scheme"), "{err}");
    }

    #[test]
    fn convention_items_use_the_shared_layout() {
        let provider = DashlaneProvider::default();
        let addr = provider
            .convention_address("myproject", "production", "API_KEY")
            .unwrap();
        assert_eq!(addr.item, "secretspec/myproject/production/API_KEY");
    }

    /// A native address names the item directly, bypassing the convention
    /// layout.
    #[test]
    fn native_address_names_the_item() {
        let provider = DashlaneProvider::default();
        let addr = crate::config::NativeAddress {
            item: "GitHub token".into(),
            ..Default::default()
        };
        let coords = provider.resolve_coords(Address::Native(&addr)).unwrap();
        assert_eq!(coords.item, "GitHub token");
    }

    /// Dashlane items have named fields, so a `field` coordinate resolves
    /// instead of being rejected.
    #[test]
    fn native_address_accepts_field() {
        let provider = DashlaneProvider::default();
        let addr = crate::config::NativeAddress {
            item: "GitHub".into(),
            field: Some("login".into()),
            ..Default::default()
        };
        let coords = provider.resolve_coords(Address::Native(&addr)).unwrap();
        assert_eq!(coords.field.as_deref(), Some("login"));
    }

    /// Dashlane has no vaults, so a `vault` coordinate written for another
    /// store fails loudly.
    #[test]
    fn native_address_rejects_vault() {
        let provider = DashlaneProvider::default();
        let addr = crate::config::NativeAddress {
            item: "GitHub".into(),
            vault: Some("Private".into()),
            ..Default::default()
        };
        let err = provider.resolve_coords(Address::Native(&addr)).unwrap_err();
        assert!(err.to_string().contains("`vault`"), "{err}");
    }

    #[test]
    fn titles_match_case_insensitively() {
        let items = vec![item("{ABC}", "My Token", "content", "v")];
        assert!(
            DashlaneProvider::find_unique(&items, "my token", ItemType::Secret)
                .unwrap()
                .is_some()
        );
    }

    /// `dcli` emits identifiers braced but accepts them bare, so both forms
    /// address the same item.
    #[test]
    fn identifiers_match_braced_or_bare() {
        let items = vec![item(
            "{D47734C4-0ABE-423A-8633-6B9F10A38905}",
            "My Token",
            "content",
            "v",
        )];
        for name in [
            "D47734C4-0ABE-423A-8633-6B9F10A38905",
            "{D47734C4-0ABE-423A-8633-6B9F10A38905}",
        ] {
            assert!(
                DashlaneProvider::find_unique(&items, name, ItemType::Secret)
                    .unwrap()
                    .is_some(),
                "{name}"
            );
        }
    }

    /// A partial identifier must not match: `dcli`'s own filters are substring
    /// matches, which is exactly the behaviour this provider replaces.
    #[test]
    fn partial_names_do_not_match() {
        let items = vec![item("{ABC}", "production-token", "content", "v")];
        assert!(
            DashlaneProvider::find_unique(&items, "production", ItemType::Secret)
                .unwrap()
                .is_none()
        );
    }

    /// Dashlane titles are not unique. `dcli read` would return one of them
    /// arbitrarily; an ambiguous name is refused instead.
    #[test]
    fn duplicate_titles_are_refused() {
        let items = vec![
            item("{ONE}", "shared", "content", "a"),
            item("{TWO}", "shared", "content", "b"),
        ];
        let err = DashlaneProvider::find_unique(&items, "shared", ItemType::Note).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("2 Dashlane note items"), "{msg}");
        assert!(msg.contains("ONE"), "{msg}");
    }

    /// Every value in `dcli`'s JSON is a string, timestamps and booleans
    /// included, so a field is read without assuming its type.
    #[test]
    fn fields_are_read_as_strings() {
        let json = r#"[{"id":"{A}","title":"t","content":"v","numberUse":"7"}]"#;
        let items: Vec<VaultItem> = serde_json::from_str(json).unwrap();
        assert_eq!(items[0].field("content").as_deref(), Some("v"));
        assert_eq!(items[0].field("numberUse").as_deref(), Some("7"));
        assert_eq!(items[0].field("missing"), None);
    }

    /// A real vault has items with no title; they must not crash a lookup.
    #[test]
    fn untitled_items_are_tolerated() {
        let json = r#"[{"id":"{A}","password":"v"}]"#;
        let items: Vec<VaultItem> = serde_json::from_str(json).unwrap();
        assert!(
            DashlaneProvider::find_unique(&items, "anything", ItemType::Password)
                .unwrap()
                .is_none()
        );
        assert!(
            DashlaneProvider::find_unique(&items, "A", ItemType::Password)
                .unwrap()
                .is_some()
        );
    }

    /// A `ref` naming a field the matched item lacks is reported as such, not
    /// conflated with the item being absent.
    #[test]
    fn a_missing_referenced_field_is_distinguished() {
        let provider = DashlaneProvider::default();
        let items = vec![item("{A}", "GitHub", "password", "v")];
        assert!(matches!(
            provider
                .lookup(&items, ItemType::Password, "GitHub", Some("otpSecret"))
                .unwrap(),
            Found::NoField
        ));
        assert!(
            DashlaneProvider::missing_field("GitHub", "otpSecret")
                .to_string()
                .contains("has a 'otpSecret' field")
        );
    }

    /// When no content type is pinned, a same-titled item in an earlier-searched
    /// type must not abort the search.
    ///
    /// A note and a login are easily given the same title — both named after the
    /// service. Searching secrets, then notes, then logins, the note matches the
    /// title but has no `login` field; the login that does must still be found.
    #[test]
    fn an_earlier_type_lacking_the_field_does_not_end_the_search() {
        let provider = DashlaneProvider::default();
        let notes = vec![item("{N}", "Production database", "content", "notes")];
        let logins = vec![item("{L}", "Production database", "login", "app_user")];

        assert!(matches!(
            provider
                .lookup(&notes, ItemType::Note, "Production database", Some("login"))
                .unwrap(),
            Found::NoField
        ));
        let found = provider
            .lookup(
                &logins,
                ItemType::Password,
                "Production database",
                Some("login"),
            )
            .unwrap();
        match found {
            Found::Value(value) => {
                use secrecy::ExposeSecret;
                assert_eq!(value.expose_secret(), "app_user");
            }
            _ => panic!("the login carries the field and must resolve"),
        }
    }

    /// An item with nothing in its default field is simply unset, so the
    /// fallback chain gets a chance.
    #[test]
    fn an_empty_default_field_reads_as_unset() {
        let provider = DashlaneProvider::default();
        let items = vec![item("{A}", "GitHub", "content", "")];
        assert!(matches!(
            provider
                .lookup(&items, ItemType::Note, "GitHub", None)
                .unwrap(),
            Found::NoItem
        ));
    }

    /// `dcli read` resolves `secrets[0] ?? credentials[0] ?? notes[0]`, so a
    /// login must outrank a note of the same title. Getting this backwards
    /// silently returns a different value than `dcli` would for the same name.
    #[test]
    fn logins_outrank_notes_in_the_search_order() {
        let order = ItemType::search_order();
        let pos = |t: ItemType| order.iter().position(|&o| o == t).unwrap();
        assert!(pos(ItemType::Secret) < pos(ItemType::Password));
        assert!(pos(ItemType::Password) < pos(ItemType::Note));
    }

    /// `dcli` folds titles with JavaScript's `toLowerCase`, which is Unicode
    /// aware. An ASCII-only fold leaves a non-ASCII title unreachable in any
    /// case but the one it was stored in.
    #[test]
    fn titles_fold_beyond_ascii() {
        let items = vec![item("{A}", "Überblick", "content", "v")];
        assert!(
            DashlaneProvider::find_unique(&items, "überblick", ItemType::Note)
                .unwrap()
                .is_some()
        );
    }

    /// The state directory is named after a hash, never the keys: a directory
    /// name is readable by anyone who can list the cache.
    #[test]
    fn the_scoped_state_dir_never_contains_the_keys() {
        let keys = "dls_ACCESS_SECRETPAYLOAD";
        let dir = scoped_state_dir(keys).expect("a cache dir should resolve");
        let shown = dir.display().to_string();
        assert!(!shown.contains("SECRETPAYLOAD"), "{shown}");
        assert!(shown.contains("dashlane"), "{shown}");
        // Stable across calls, so a synced vault is reused rather than refetched.
        assert_eq!(dir, scoped_state_dir(keys).unwrap());
        assert_ne!(dir, scoped_state_dir("dls_OTHER_IDENTITY").unwrap());
    }

    /// The state directory holds a device row and a decrypted-on-demand vault,
    /// so no other user may enter it -- including when `dcli`, or an earlier
    /// SecretSpec, created it world-traversable first.
    #[cfg(unix)]
    #[test]
    fn the_scoped_state_dir_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("dashlane").join("0123456789abcdef");
        let mode =
            |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;

        create_private_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700, "a newly created state directory");

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        create_private_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700, "a state directory that already existed");
    }

    #[test]
    fn each_type_reads_its_own_default_field() {
        assert_eq!(ItemType::Secret.default_field(), "content");
        assert_eq!(ItemType::Note.default_field(), "content");
        assert_eq!(ItemType::Password.default_field(), "password");
    }

    /// The message a closed stdin produces, verbatim from dcli 6.2628.1 with
    /// no device registered. Without this match a user sees only
    /// "User force closed the prompt with 0 null".
    #[test]
    fn an_unregistered_cli_is_reported_as_needing_setup() {
        let stderr = "\u{1b}[31merror: User force closed the prompt with 0 null\u{1b}[0m";
        assert!(strip_ansi(stderr).contains("force closed the prompt"));
    }

    /// A `dcli` without the `secret` subcommand must not fail the whole read:
    /// the message is verbatim from 6.2628.1.
    #[test]
    fn an_unknown_lister_is_not_a_failure() {
        assert!(is_unknown_command(&strip_ansi(
            "\u{1b}[31merror: unknown command 'secret'\u{1b}[0m"
        )));
        assert!(!is_unknown_command("error: User force closed the prompt"));
    }

    /// `dcli` colours its errors; the escapes must not reach the user.
    #[test]
    fn ansi_escapes_are_stripped() {
        assert_eq!(
            strip_ansi("\u{1b}[31merror: No matching item found\u{1b}[0m"),
            "error: No matching item found"
        );
    }

    #[test]
    fn writes_are_refused_with_the_reason() {
        let provider = DashlaneProvider::default();
        let addr = Address::convention("p", "default", "K");
        let err = provider.check_writable(addr).unwrap_err();
        assert!(err.to_string().contains("read-only"), "{err}");
        assert!(provider.set(addr, &SecretString::new("v".into())).is_err());
    }
}

/// Smoke tests against a real Dashlane vault, run by hand:
///
/// ```console
/// cargo test -p secretspec provider::dashlane::live -- --ignored --nocapture
/// ```
///
/// The tests above prove this code against *fabricated* fixtures. These prove
/// it against a real vault, which is a different claim: the JSON shape, the
/// `dcli status` wording, and the fields a live item carries are outside this
/// repository's control.
///
/// They stay ignored permanently, not until CI can run them: `dcli` cannot
/// register a device without a real Dashlane account, and the read-only vault
/// means a test cannot create the item it would then read.
///
/// No secret value is ever printed — lengths and counts only.
#[cfg(test)]
mod live {
    use super::*;

    /// A name no vault will hold, used to drive a full miss.
    const ABSENT: &str = "secretspec-live-test-item-that-does-not-exist";

    /// `dcli status` prints prose, not JSON, so the `Logged in:` / `Locked:`
    /// contract is the one thing no fixture can pin down: a reworded release
    /// breaks it silently and every read then reports the vault as logged out.
    #[test]
    #[ignore = "needs an authenticated dcli and a real vault"]
    fn preflight_accepts_a_registered_unlocked_cli() {
        let provider = DashlaneProvider::default();
        // `check_auth` short-circuits on device keys by design, so on a service
        // device this would pass without reading `dcli status` at all. Say so
        // rather than report a vacuous success.
        if provider.device_keys().is_some() {
            println!(
                "{DEVICE_KEYS_ENV} is set, so the status probe is skipped; \
                 unset it to exercise the `dcli status` parser"
            );
            return;
        }
        provider.check_auth().unwrap_or_else(|e| {
            panic!("`dcli status` did not read as registered and unlocked: {e}")
        });
    }

    /// Every live item deserializes, one lister at a time so a failure names
    /// the content type. A personal account has no `secret` items at all, which
    /// the counts distinguish from a parse failure.
    #[test]
    #[ignore = "needs an authenticated dcli and a real vault"]
    fn every_lister_parses_the_live_vault() {
        let provider = DashlaneProvider::default();
        for &item_type in ItemType::search_order() {
            let items = provider.list(item_type).unwrap_or_else(|e| {
                panic!("`dcli {} -o json` did not parse: {e}", item_type.as_str())
            });

            // Counts and presence flags only; no title or value is printed,
            // since a title can itself be sensitive.
            println!(
                "{}: {} items ({} titled, {} with a default field)",
                item_type.as_str(),
                items.len(),
                items.iter().filter(|i| i.title.is_some()).count(),
                items
                    .iter()
                    .filter(|i| i.field(item_type.default_field()).is_some())
                    .count(),
            );

            for item in &items {
                assert!(!item.id.is_empty(), "every live item carries an id");
                assert!(
                    !item.bare_id().contains(['{', '}']),
                    "bare_id should strip the braces dcli wraps an id in"
                );
            }
        }
    }

    /// A miss returns `Ok(None)`, leaving the fallback chain its turn.
    #[test]
    #[ignore = "needs an authenticated dcli and a real vault"]
    fn an_absent_item_reads_as_unset() {
        let provider = DashlaneProvider::default();
        let addr = crate::config::NativeAddress {
            item: ABSENT.into(),
            ..Default::default()
        };
        match provider.get(Address::Native(&addr)) {
            Ok(None) => {}
            Ok(Some(_)) => panic!("no vault should hold an item named {ABSENT}"),
            Err(e) => panic!("an absent item must read as unset, not as an error: {e}"),
        }
    }

    /// Reads one item the operator names, since the provider cannot create it:
    ///
    /// ```console
    /// SECRETSPEC_DASHLANE_TEST_ITEM="My API token" cargo test ...
    /// ```
    ///
    /// `SECRETSPEC_DASHLANE_TEST_FIELD` exercises the `field` coordinate, and
    /// `SECRETSPEC_DASHLANE_TEST_TYPE` pins the content type.
    #[test]
    #[ignore = "needs an authenticated dcli and a real vault"]
    fn reads_an_item_named_by_the_operator() {
        let Ok(item) = std::env::var("SECRETSPEC_DASHLANE_TEST_ITEM") else {
            println!("SECRETSPEC_DASHLANE_TEST_ITEM is unset; skipping");
            return;
        };
        let field = std::env::var("SECRETSPEC_DASHLANE_TEST_FIELD").ok();
        let config = DashlaneConfig {
            item_type: std::env::var("SECRETSPEC_DASHLANE_TEST_TYPE")
                .ok()
                .map(|t| {
                    ItemType::parse(&t)
                        .expect("SECRETSPEC_DASHLANE_TEST_TYPE is not a Dashlane item type")
                }),
        };

        let addr = crate::config::NativeAddress {
            item: item.clone(),
            field: field.clone(),
            ..Default::default()
        };
        let value = DashlaneProvider::new(config)
            .get(Address::Native(&addr))
            .unwrap_or_else(|e| panic!("reading the named item failed: {e}"))
            .unwrap_or_else(|| {
                panic!(
                    "the named item resolved to nothing. Check the title matches \
                     exactly, that its content type is being searched, and that \
                     `dcli sync` has run."
                )
            });

        use secrecy::ExposeSecret;
        let len = value.expose_secret().len();
        assert!(len > 0, "the named item resolved to an empty value");
        println!(
            "read the named item{}: {len} bytes",
            field.map(|f| format!(" (field '{f}')")).unwrap_or_default(),
        );

        // The value must not survive into a Debug rendering of the wrapper.
        assert!(
            !format!("{value:?}").contains(value.expose_secret()),
            "the secret leaked through Debug"
        );
    }
}
