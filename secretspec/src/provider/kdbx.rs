//! KeePass KDBX provider.
//!
//! Entries are addressed by their group path and title. SecretSpec's convention
//! stores an entry at `secretspec/{project}/{profile}/{key}`; a native `ref`
//! supplies that complete path as `item`. The entry's `Password` field is used
//! by default, while `field` can select another standard or custom field.

use super::{Address, Provider, ProviderCredentials, ProviderUrl, credential_or_env};
use crate::config::NativeAddress;
use crate::{Result, SecretSpecError};
use keepass::DatabaseKey;
use keepass::config::DatabaseVersion;
use keepass::db::{Database, EntryId, GroupId, fields};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const DEFAULT_PREFIX: &str = "secretspec/{project}/{profile}/{key}";
const PASSWORD_CREDENTIAL: &str = "password";
const PASSWORD_ENV: &str = "SECRETSPEC_KDBX_PASSWORD";

/// Serializes access across provider instances in this process.
///
/// Secret resolution constructs multiple instances for one alias. Without one
/// shared lock, concurrent setters could both read the same database and let
/// the last atomic replacement discard the other's change.
static KDBX_IO_LOCK: Mutex<()> = Mutex::new(());

/// Configuration for a KeePass KDBX database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdbxConfig {
    /// Path to the `.kdbx` database.
    pub path: PathBuf,
    /// Optional KeePass key file, combined with the password when both exist.
    pub keyfile: Option<PathBuf>,
    /// Entry path template used for convention addresses.
    pub prefix: String,
}

impl TryFrom<&ProviderUrl> for KdbxConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> Result<Self> {
        if url.scheme() != "kdbx" {
            return Err(operation_error(format!(
                "Invalid scheme '{}' for kdbx provider",
                url.scheme()
            )));
        }

        let uri_path = url.path();
        let path = match url.host() {
            Some(host) => format!("{host}{uri_path}"),
            None => uri_path,
        };
        if path.is_empty() || path == "/" {
            return Err(operation_error(
                "No KDBX database path given. Use kdbx:./secrets.kdbx or \
                 kdbx:/absolute/path/secrets.kdbx.",
            ));
        }

        let mut keyfile = None;
        let mut prefix = None;
        for (name, value) in url.query_pairs() {
            let value = value.into_owned();
            match name.as_ref() {
                "keyfile" => {
                    if keyfile.is_some() {
                        return Err(operation_error(
                            "The KDBX `keyfile` query parameter may only be specified once.",
                        ));
                    }
                    if value.is_empty() {
                        return Err(operation_error(
                            "The KDBX `keyfile` query parameter cannot be empty.",
                        ));
                    }
                    keyfile = Some(PathBuf::from(value));
                }
                "prefix" => {
                    if prefix.is_some() {
                        return Err(operation_error(
                            "The KDBX `prefix` query parameter may only be specified once.",
                        ));
                    }
                    if value.is_empty() {
                        return Err(operation_error(
                            "The KDBX `prefix` query parameter cannot be empty.",
                        ));
                    }
                    prefix = Some(value);
                }
                other => {
                    return Err(operation_error(format!(
                        "Unknown KDBX query parameter `{other}`. Supported parameters are \
                         `keyfile` and `prefix`."
                    )));
                }
            }
        }

        Ok(Self {
            path: PathBuf::from(path),
            keyfile,
            prefix: prefix.unwrap_or_else(|| DEFAULT_PREFIX.to_string()),
        })
    }
}

/// A provider backed by a KeePass KDBX 3 or KDBX 4 database.
///
/// Reads support both KDBX 3 and KDBX 4. Writes create KDBX 4 databases and
/// update existing KDBX 4 databases; the `keepass` crate cannot save KDBX 3.
pub struct KdbxProvider {
    config: KdbxConfig,
    credentials: ProviderCredentials,
}

crate::register_provider! {
    struct: KdbxProvider,
    config: KdbxConfig,
    name: "kdbx",
    description: "KeePass KDBX databases (0.17+)",
    schemes: ["kdbx"],
    examples: [
        "kdbx:./secrets.kdbx",
        "kdbx:./secrets.kdbx?keyfile=./secrets.key",
    ],
    credential_names: [PASSWORD_CREDENTIAL],
}

impl KdbxProvider {
    pub fn new(config: KdbxConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
        }
    }

    fn location(&self, addr: Address<'_>) -> Result<Location> {
        let coords = self.resolve_coords(addr)?;
        Location::parse(
            &coords.item,
            coords.field.as_deref().unwrap_or(fields::PASSWORD),
        )
    }

    fn key(&self) -> Result<DatabaseKey> {
        let password = credential_or_env(&self.credentials, PASSWORD_CREDENTIAL, PASSWORD_ENV);
        if password.is_none() && self.config.keyfile.is_none() {
            return Err(operation_error(format!(
                "The KDBX database needs a master password or key file. Configure the \
                 `{PASSWORD_CREDENTIAL}` provider credential, set {PASSWORD_ENV}, or add \
                 `?keyfile=PATH` to the provider URI."
            )));
        }

        let mut key = DatabaseKey::new();
        if let Some(password) = password.as_deref() {
            key = key.with_password(password);
        }
        if let Some(path) = self.config.keyfile.as_deref() {
            let mut file = File::open(path).map_err(|error| {
                operation_error(format!(
                    "Failed to open KDBX key file '{}': {error}",
                    path.display()
                ))
            })?;
            key = key.with_keyfile(&mut file).map_err(|error| {
                operation_error(format!(
                    "Failed to read KDBX key file '{}': {error}",
                    path.display()
                ))
            })?;
        }
        Ok(key)
    }

    fn load(&self) -> Result<Option<Database>> {
        let mut file = match File::open(&self.config.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(operation_error(format!(
                    "Failed to open KDBX database '{}': {error}",
                    self.config.path.display()
                )));
            }
        };

        Database::open(&mut file, self.key()?)
            .map(Some)
            .map_err(|error| {
                operation_error(format!(
                    "Failed to unlock KDBX database '{}': {error}",
                    self.config.path.display()
                ))
            })
    }

    fn save(&self, database: &Database) -> Result<()> {
        if !matches!(database.config.version, DatabaseVersion::KDB4(_)) {
            return Err(write_version_error());
        }

        let parent = self
            .config
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
            operation_error(format!(
                "Failed to create a temporary KDBX database next to '{}': {error}",
                self.config.path.display()
            ))
        })?;

        database
            .save(temporary.as_file_mut(), self.key()?)
            .map_err(|error| {
                operation_error(format!("Failed to encrypt KDBX database: {error}"))
            })?;
        temporary.as_file().sync_all().map_err(|error| {
            operation_error(format!(
                "Failed to flush KDBX database '{}': {error}",
                self.config.path.display()
            ))
        })?;
        temporary.persist(&self.config.path).map_err(|error| {
            operation_error(format!(
                "Failed to atomically replace KDBX database '{}': {}",
                self.config.path.display(),
                error.error
            ))
        })?;
        Ok(())
    }

    fn get_from_database(
        &self,
        database: &Database,
        addr: Address<'_>,
    ) -> Result<Option<SecretString>> {
        let location = self.location(addr)?;
        let Some(entry_id) = find_entry(database, &location)? else {
            return Ok(None);
        };
        Ok(database
            .entry(entry_id)
            .and_then(|entry| entry.get(&location.field).map(str::to_owned))
            .map(|value| SecretString::new(value.into())))
    }
}

impl Provider for KdbxProvider {
    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
        let item = self
            .config
            .prefix
            .replace("{project}", project)
            .replace("{profile}", profile)
            .replace("{key}", key);
        Location::parse(&item, fields::PASSWORD)?;
        Ok(NativeAddress {
            item,
            ..Default::default()
        })
    }

    fn supported_coords(&self) -> &'static [&'static str] {
        &["field"]
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let _guard = KDBX_IO_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match self.load()? {
            Some(database) => self.get_from_database(&database, addr),
            None => Ok(None),
        }
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        self.check_writable(addr)?;
        let location = self.location(addr)?;
        let _guard = KDBX_IO_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut database = self.load()?.unwrap_or_else(|| {
            let mut database = Database::new();
            database.meta.database_name = Some("SecretSpec".to_string());
            database
        });

        if !matches!(database.config.version, DatabaseVersion::KDB4(_)) {
            return Err(write_version_error());
        }

        let group_id = find_or_create_group(&mut database, &location.groups)?;
        match find_entry_in_group(&database, group_id, &location.title)? {
            Some(entry_id) => {
                let mut entry = database.entry_mut(entry_id).ok_or_else(|| {
                    operation_error("KDBX entry disappeared while it was being updated.")
                })?;
                entry.edit_tracking(|entry| {
                    entry.set_protected(&location.field, value.expose_secret());
                });
            }
            None => {
                let mut group = database.group_mut(group_id).ok_or_else(|| {
                    operation_error("KDBX group disappeared while an entry was being created.")
                })?;
                group.add_entry().edit(|entry| {
                    entry.set_unprotected(fields::TITLE, &location.title);
                    entry.set_protected(&location.field, value.expose_secret());
                });
            }
        }

        self.save(&database)
    }

    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        let location = self.location(addr)?;
        if location.field.eq_ignore_ascii_case(fields::TITLE) {
            return Err(operation_error(
                "The kdbx provider cannot write the `Title` field because the title is \
                 part of the entry address. Change `ref.item` to rename an entry in KeePass.",
            ));
        }

        let mut file = match File::open(&self.config.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(operation_error(format!(
                    "Failed to open KDBX database '{}': {error}",
                    self.config.path.display()
                )));
            }
        };
        let version = Database::get_version(&mut file).map_err(|error| {
            operation_error(format!(
                "Failed to inspect KDBX database '{}': {error}",
                self.config.path.display()
            ))
        })?;
        if !matches!(version, DatabaseVersion::KDB4(_)) {
            return Err(write_version_error());
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let mut uri = format!(
            "kdbx:{}",
            ProviderUrl::encode(&self.config.path.display().to_string())
        );
        let mut separator = '?';
        if let Some(keyfile) = self.config.keyfile.as_deref() {
            uri.push(separator);
            separator = '&';
            uri.push_str("keyfile=");
            uri.push_str(&ProviderUrl::encode_query(&keyfile.display().to_string()));
        }
        if self.config.prefix != DEFAULT_PREFIX {
            uri.push(separator);
            uri.push_str("prefix=");
            uri.push_str(&ProviderUrl::encode_query(&self.config.prefix));
        }
        uri
    }

    fn with_base_dir(&mut self, base_dir: &Path) {
        if self.config.path.is_relative() {
            self.config.path = base_dir.join(&self.config.path);
        }
        if let Some(keyfile) = self.config.keyfile.as_mut()
            && keyfile.is_relative()
        {
            *keyfile = base_dir.join(&*keyfile);
        }
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        let _guard = KDBX_IO_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(database) = self.load()? else {
            return Ok(HashMap::new());
        };

        let mut results = HashMap::new();
        for (name, addr) in requests {
            if let Some(value) = self.get_from_database(&database, *addr)? {
                results.insert((*name).to_string(), value);
            }
        }
        Ok(results)
    }
}

#[derive(Debug)]
struct Location {
    groups: Vec<String>,
    title: String,
    field: String,
}

impl Location {
    fn parse(item: &str, field: &str) -> Result<Self> {
        if item.is_empty() {
            return Err(operation_error("A KDBX entry path cannot be empty."));
        }
        if field.is_empty() {
            return Err(operation_error("A KDBX field name cannot be empty."));
        }

        let mut parts: Vec<&str> = item.split('/').collect();
        if parts.iter().any(|part| part.is_empty()) {
            return Err(operation_error(format!(
                "Invalid KDBX entry path `{item}`: group and entry names cannot be empty."
            )));
        }
        let title = parts
            .pop()
            .expect("a non-empty split always contains an entry title")
            .to_string();
        Ok(Self {
            groups: parts.into_iter().map(str::to_owned).collect(),
            title,
            field: field.to_string(),
        })
    }
}

fn find_entry(database: &Database, location: &Location) -> Result<Option<EntryId>> {
    let mut group_id = database.root().id();
    for name in &location.groups {
        let Some(next) = unique_group(database, group_id, name)? else {
            return Ok(None);
        };
        group_id = next;
    }
    find_entry_in_group(database, group_id, &location.title)
}

fn unique_group(database: &Database, parent: GroupId, name: &str) -> Result<Option<GroupId>> {
    let group = database
        .group(parent)
        .ok_or_else(|| operation_error("KDBX group tree contains a missing group."))?;
    let matches: Vec<GroupId> = group
        .groups()
        .filter(|group| group.name == name)
        .map(|group| group.id())
        .collect();
    match matches.as_slice() {
        [] => Ok(None),
        [id] => Ok(Some(*id)),
        _ => Err(operation_error(format!(
            "KDBX group `{name}` is ambiguous: its parent contains multiple groups with that name."
        ))),
    }
}

fn find_entry_in_group(
    database: &Database,
    group_id: GroupId,
    title: &str,
) -> Result<Option<EntryId>> {
    let group = database
        .group(group_id)
        .ok_or_else(|| operation_error("KDBX group tree contains a missing group."))?;
    let matches: Vec<EntryId> = group
        .entries()
        .filter(|entry| entry.get_title() == Some(title))
        .map(|entry| entry.id())
        .collect();
    match matches.as_slice() {
        [] => Ok(None),
        [id] => Ok(Some(*id)),
        _ => Err(operation_error(format!(
            "KDBX entry `{title}` is ambiguous: its group contains multiple entries with that title."
        ))),
    }
}

fn find_or_create_group(database: &mut Database, groups: &[String]) -> Result<GroupId> {
    let mut current = database.root().id();
    for name in groups {
        current = match unique_group(database, current, name)? {
            Some(id) => id,
            None => {
                let mut parent = database
                    .group_mut(current)
                    .ok_or_else(|| operation_error("KDBX group tree contains a missing group."))?;
                let mut group = parent.add_group();
                group.name = name.clone();
                group.id()
            }
        };
    }
    Ok(current)
}

fn operation_error(message: impl Into<String>) -> SecretSpecError {
    SecretSpecError::ProviderOperationFailed(message.into())
}

fn write_version_error() -> SecretSpecError {
    operation_error(
        "The kdbx provider can read KDBX 3 databases but cannot write them. \
         Upgrade the database to KDBX 4 with KeePass or KeePassXC first.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::Value;
    use secrecy::ExposeSecret;
    use tempfile::TempDir;
    use url::Url;

    fn provider_url(value: &str) -> ProviderUrl {
        ProviderUrl::new(Url::parse(value).unwrap())
    }

    fn config(path: PathBuf) -> KdbxConfig {
        KdbxConfig {
            path,
            keyfile: None,
            prefix: DEFAULT_PREFIX.to_string(),
        }
    }

    fn provider(path: PathBuf, password: &str) -> KdbxProvider {
        let mut provider = KdbxProvider::new(config(path));
        let mut credentials = ProviderCredentials::new();
        credentials.insert(
            PASSWORD_CREDENTIAL.to_string(),
            SecretString::new(password.to_string().into()),
        );
        provider.with_credentials(credentials);
        provider
    }

    fn convention<'a>(key: &'a str) -> Address<'a> {
        Address::convention("project", "production", key)
    }

    #[test]
    fn config_parses_relative_and_absolute_paths() {
        let relative = KdbxConfig::try_from(&provider_url("kdbx://./vault.kdbx")).unwrap();
        assert_eq!(relative.path, PathBuf::from("./vault.kdbx"));

        let absolute = KdbxConfig::try_from(&provider_url("kdbx:///var/lib/vault.kdbx")).unwrap();
        assert_eq!(absolute.path, PathBuf::from("/var/lib/vault.kdbx"));
    }

    #[test]
    fn config_parses_keyfile_and_prefix() {
        let config = KdbxConfig::try_from(&provider_url(
            "kdbx://./vault.kdbx?keyfile=keys/team.key&prefix=team/{profile}/{key}",
        ))
        .unwrap();
        assert_eq!(config.keyfile, Some(PathBuf::from("keys/team.key")));
        assert_eq!(config.prefix, "team/{profile}/{key}");
    }

    #[test]
    fn registry_builds_documented_uri_and_advertises_password_credential() {
        let provider = Box::<dyn Provider>::try_from(
            "kdbx:./vault.kdbx?keyfile=keys/team.key&prefix=team/{profile}/{key}",
        )
        .unwrap();
        assert_eq!(provider.name(), "kdbx");
        assert_eq!(
            crate::provider::credential_names_for_spec("kdbx:./vault.kdbx"),
            &[PASSWORD_CREDENTIAL]
        );
    }

    #[test]
    fn config_rejects_missing_path_unknown_and_duplicate_parameters() {
        for uri in [
            "kdbx://",
            "kdbx://./vault.kdbx?typo=value",
            "kdbx://./vault.kdbx?keyfile=a&keyfile=b",
            "kdbx://./vault.kdbx?prefix=",
        ] {
            assert!(KdbxConfig::try_from(&provider_url(uri)).is_err(), "{uri}");
        }
    }

    #[test]
    fn convention_and_native_addresses_map_to_entry_fields() {
        let provider = KdbxProvider::new(config(PathBuf::from("vault.kdbx")));
        let coords = provider
            .convention_address("app", "prod", "DATABASE_URL")
            .unwrap();
        assert_eq!(coords.item, "secretspec/app/prod/DATABASE_URL");
        assert_eq!(
            provider
                .location(Address::Native(&NativeAddress {
                    item: "shared/database".into(),
                    field: Some("UserName".into()),
                    ..Default::default()
                }))
                .unwrap()
                .field,
            "UserName"
        );
    }

    #[test]
    fn invalid_entry_paths_and_title_writes_are_rejected() {
        let provider = KdbxProvider::new(config(PathBuf::from("vault.kdbx")));
        for item in ["", "/entry", "group/", "group//entry"] {
            let addr = NativeAddress {
                item: item.into(),
                ..Default::default()
            };
            assert!(provider.location(Address::Native(&addr)).is_err(), "{item}");
        }
        let title = NativeAddress {
            item: "group/entry".into(),
            field: Some("Title".into()),
            ..Default::default()
        };
        assert!(provider.check_writable(Address::Native(&title)).is_err());
    }

    #[test]
    fn writable_check_rejects_kdbx3_before_requesting_a_value() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("vault.kdbx");
        let provider = provider(path.clone(), "master");
        provider
            .set(convention("TOKEN"), &SecretString::new("value".into()))
            .unwrap();

        // KDBX stores its little-endian major version in header bytes 10..12.
        // Changing only that header is enough for the value-free pre-check to
        // identify this as KDBX 3; it deliberately does not try to decrypt it.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[10] = 3;
        std::fs::write(path, bytes).unwrap();

        let error = provider
            .check_writable(convention("TOKEN"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("read KDBX 3"), "{error}");
    }

    #[test]
    fn base_dir_rebases_database_and_keyfile_paths() {
        let mut provider = KdbxProvider::new(KdbxConfig {
            path: "data/vault.kdbx".into(),
            keyfile: Some("keys/vault.key".into()),
            prefix: DEFAULT_PREFIX.into(),
        });
        provider.with_base_dir(Path::new("/project"));
        assert_eq!(
            provider.config.path,
            PathBuf::from("/project/data/vault.kdbx")
        );
        assert_eq!(
            provider.config.keyfile,
            Some(PathBuf::from("/project/keys/vault.key"))
        );
    }

    #[test]
    fn uri_round_trips_without_password() {
        let mut provider = provider(PathBuf::from("./my vault.kdbx"), "do-not-leak");
        provider.config.keyfile = Some(PathBuf::from("./my key.key"));
        provider.config.prefix = "team/{profile}/{key}".into();
        let uri = provider.uri();
        assert_eq!(
            uri,
            "kdbx:./my%20vault.kdbx?keyfile=./my%20key.key&prefix=team/{profile}/{key}"
        );
        assert!(!uri.contains("do-not-leak"));
    }

    #[test]
    fn set_creates_database_and_get_reads_secret() {
        let temp = TempDir::new().unwrap();
        let provider = provider(temp.path().join("vault.kdbx"), "master password");

        assert!(provider.get(convention("API_KEY")).unwrap().is_none());
        provider
            .set(
                convention("API_KEY"),
                &SecretString::new("first value".into()),
            )
            .unwrap();
        assert_eq!(
            provider
                .get(convention("API_KEY"))
                .unwrap()
                .unwrap()
                .expose_secret(),
            "first value"
        );
    }

    #[test]
    fn set_updates_existing_entry_and_preserves_other_fields() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("vault.kdbx");
        let provider = provider(path.clone(), "master");
        provider
            .set(convention("API_KEY"), &SecretString::new("old".into()))
            .unwrap();

        let custom = NativeAddress {
            item: "secretspec/project/production/API_KEY".into(),
            field: Some("Account".into()),
            ..Default::default()
        };
        provider
            .set(
                Address::Native(&custom),
                &SecretString::new("service-user".into()),
            )
            .unwrap();
        provider
            .set(convention("API_KEY"), &SecretString::new("new".into()))
            .unwrap();

        assert_eq!(
            provider
                .get(convention("API_KEY"))
                .unwrap()
                .unwrap()
                .expose_secret(),
            "new"
        );
        assert_eq!(
            provider
                .get(Address::Native(&custom))
                .unwrap()
                .unwrap()
                .expose_secret(),
            "service-user"
        );

        let mut file = File::open(path).unwrap();
        let database =
            Database::open(&mut file, DatabaseKey::new().with_password("master")).unwrap();
        let location = provider.location(convention("API_KEY")).unwrap();
        let entry = database
            .entry(find_entry(&database, &location).unwrap().unwrap())
            .unwrap();
        assert!(
            entry
                .history
                .as_ref()
                .is_some_and(|history| !history.get_entries().is_empty())
        );
    }

    #[test]
    fn keyfile_only_database_round_trips() {
        let temp = TempDir::new().unwrap();
        let keyfile = temp.path().join("vault.key");
        std::fs::write(&keyfile, b"test key material").unwrap();
        let mut provider = KdbxProvider::new(KdbxConfig {
            path: temp.path().join("vault.kdbx"),
            keyfile: Some(keyfile),
            prefix: DEFAULT_PREFIX.into(),
        });
        provider.with_credentials(ProviderCredentials::new());

        provider
            .set(convention("TOKEN"), &SecretString::new("value".into()))
            .unwrap();
        assert_eq!(
            provider
                .get(convention("TOKEN"))
                .unwrap()
                .unwrap()
                .expose_secret(),
            "value"
        );
    }

    #[test]
    fn wrong_password_and_missing_credentials_are_actionable() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("vault.kdbx");
        provider(path.clone(), "right")
            .set(convention("TOKEN"), &SecretString::new("value".into()))
            .unwrap();

        let error = provider(path.clone(), "wrong")
            .get(convention("TOKEN"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("Failed to unlock KDBX database"), "{error}");
        assert!(!error.contains("wrong"), "{error}");

        let error = KdbxProvider::new(config(path))
            .get(convention("TOKEN"))
            .unwrap_err()
            .to_string();
        assert!(error.contains(PASSWORD_ENV), "{error}");
    }

    #[test]
    fn get_many_reads_fields_and_omits_missing_entries() {
        let temp = TempDir::new().unwrap();
        let provider = provider(temp.path().join("vault.kdbx"), "master");
        provider
            .set(convention("ONE"), &SecretString::new("one".into()))
            .unwrap();
        provider
            .set(convention("TWO"), &SecretString::new("two".into()))
            .unwrap();

        let results = provider
            .get_many(&[
                ("FIRST", convention("ONE")),
                ("SECOND", convention("TWO")),
                ("MISSING", convention("THREE")),
            ])
            .unwrap();
        assert_eq!(results["FIRST"].expose_secret(), "one");
        assert_eq!(results["SECOND"].expose_secret(), "two");
        assert!(!results.contains_key("MISSING"));
    }

    #[test]
    fn duplicate_entry_titles_are_rejected_as_ambiguous() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("vault.kdbx");
        let provider = provider(path.clone(), "master");
        let mut database = Database::new();
        {
            let mut root = database.root_mut();
            for password in ["one", "two"] {
                root.add_entry().edit(|entry| {
                    entry.set_unprotected(fields::TITLE, "duplicate");
                    entry.set_protected(fields::PASSWORD, password);
                });
            }
        }
        provider.save(&database).unwrap();

        let address = NativeAddress {
            item: "duplicate".into(),
            ..Default::default()
        };
        let error = provider
            .get(Address::Native(&address))
            .unwrap_err()
            .to_string();
        assert!(error.contains("ambiguous"), "{error}");
    }

    #[test]
    fn concurrent_writes_preserve_both_entries() {
        let temp = TempDir::new().unwrap();
        let provider = std::sync::Arc::new(provider(temp.path().join("vault.kdbx"), "master"));
        std::thread::scope(|scope| {
            for (name, value) in [("ONE", "one"), ("TWO", "two")] {
                let provider = std::sync::Arc::clone(&provider);
                scope.spawn(move || {
                    provider
                        .set(convention(name), &SecretString::new(value.into()))
                        .unwrap();
                });
            }
        });
        assert_eq!(
            provider
                .get(convention("ONE"))
                .unwrap()
                .unwrap()
                .expose_secret(),
            "one"
        );
        assert_eq!(
            provider
                .get(convention("TWO"))
                .unwrap()
                .unwrap()
                .expose_secret(),
            "two"
        );
    }

    #[test]
    fn existing_non_secret_fields_survive_updates() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("vault.kdbx");
        let provider = provider(path, "master");
        let mut database = Database::new();
        database.root_mut().add_entry().edit(|entry| {
            entry.set_unprotected(fields::TITLE, "existing");
            entry.set_unprotected(fields::URL, "https://example.com");
            entry.set(fields::PASSWORD, Value::protected("old"));
        });
        provider.save(&database).unwrap();

        let address = NativeAddress {
            item: "existing".into(),
            ..Default::default()
        };
        provider
            .set(Address::Native(&address), &SecretString::new("new".into()))
            .unwrap();
        let loaded = provider.load().unwrap().unwrap();
        let location = provider.location(Address::Native(&address)).unwrap();
        let entry = loaded
            .entry(find_entry(&loaded, &location).unwrap().unwrap())
            .unwrap();
        assert_eq!(entry.get_url(), Some("https://example.com"));
        assert_eq!(entry.get_password(), Some("new"));
    }
}
