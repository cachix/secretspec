//! Keeper Secrets Manager provider.
//!
//! This provider uses Keeper's official Rust SDK. A Keeper Secrets Manager
//! application must have access to the shared folder named by the provider URI.
//! Convention secrets are stored as login records titled
//! `secretspec/{project}/{profile}/{key}`, with the value in the `password`
//! field.

use super::{Address, Provider, ProviderCredentials, ProviderUrl, credential_or_env};
use crate::config::NativeAddress;
use crate::{Result, SecretSpecError};
use keeper_secrets_manager_core::core::{ClientOptions, SecretsManager};
use keeper_secrets_manager_core::dto::dtos::{Record, RecordCreate};
use keeper_secrets_manager_core::dto::field_structs::KeeperField;
use keeper_secrets_manager_core::enums::KvStoreType;
use keeper_secrets_manager_core::storage::{FileKeyValueStorage, InMemoryKeyValueStorage};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

const CONFIG: &str = "config";
const TOKEN: &str = "token";
const KSM_CONFIG_ENV: &str = "KSM_CONFIG";
const KSM_TOKEN_ENV: &str = "KSM_TOKEN";
const DEFAULT_FIELD: &str = "password";

/// Configuration for Keeper Secrets Manager.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeeperConfig {
    /// UID of a shared folder, or one of its subfolders, available to the KSM
    /// application. New convention records are created here.
    pub folder_uid: String,
    /// Optional path to the SDK client configuration file.
    pub config_file: Option<String>,
}

impl TryFrom<&ProviderUrl> for KeeperConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "keeper" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for Keeper provider. Expected 'keeper'.",
                url.scheme()
            )));
        }

        if !url.path().trim_matches('/').is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Keeper provider URIs take no path. \
                 Use keeper://SHARED_FOLDER_UID."
                    .to_string(),
            ));
        }

        let folder_uid = url
            .host()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(
                    "Keeper shared folder UID is required. \
                 Use keeper://SHARED_FOLDER_UID."
                        .to_string(),
                )
            })?;

        if url.query_value("folder").is_some() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Keeper's folder UID belongs in the URI authority, not the `folder` query \
                 parameter. Use keeper://SHARED_FOLDER_UID."
                    .to_string(),
            ));
        }

        Ok(Self {
            folder_uid,
            config_file: url.query_value("config_file"),
        })
    }
}

trait KeeperApi: Send {
    fn get_secrets(&mut self) -> std::result::Result<Vec<Record>, String>;
    fn update_secret(&mut self, record: Record) -> std::result::Result<(), String>;
    fn create_secret(
        &mut self,
        folder_uid: &str,
        record: RecordCreate,
    ) -> std::result::Result<String, String>;
    fn delete_secret(&mut self, record_uid: &str) -> std::result::Result<(), String>;
}

impl KeeperApi for SecretsManager {
    fn get_secrets(&mut self) -> std::result::Result<Vec<Record>, String> {
        SecretsManager::get_secrets(self, Vec::new()).map_err(|error| error.to_string())
    }

    fn update_secret(&mut self, record: Record) -> std::result::Result<(), String> {
        SecretsManager::update_secret(self, record).map_err(|error| error.to_string())
    }

    fn create_secret(
        &mut self,
        folder_uid: &str,
        record: RecordCreate,
    ) -> std::result::Result<String, String> {
        SecretsManager::create_secret(self, folder_uid, record).map_err(|error| error.to_string())
    }

    fn delete_secret(&mut self, record_uid: &str) -> std::result::Result<(), String> {
        SecretsManager::delete_secret(self, vec![record_uid.to_string()])
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

type KeeperClient = Mutex<Box<dyn KeeperApi>>;

/// Keeper Secrets Manager provider backed by Keeper's official Rust SDK.
pub struct KeeperProvider {
    config: KeeperConfig,
    credentials: ProviderCredentials,
    client: OnceLock<std::result::Result<KeeperClient, String>>,
}

crate::register_provider! {
    struct: KeeperProvider,
    config: KeeperConfig,
    name: "keeper",
    description: "Keeper Secrets Manager (0.18+) via official Rust SDK",
    schemes: ["keeper"],
    examples: ["keeper://SHARED_FOLDER_UID"],
    credential_names: [CONFIG, TOKEN],
    deletes: true,
}

#[derive(Clone)]
struct KeeperTarget {
    item: String,
    field: String,
    native: bool,
}

#[derive(Clone, Copy)]
enum FieldSection {
    Standard,
    Custom,
}

struct LocatedField {
    section: FieldSection,
    value: Value,
}

impl KeeperProvider {
    /// Creates a Keeper provider with lazy SDK initialization.
    pub fn new(config: KeeperConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
            client: OnceLock::new(),
        }
    }

    fn config_value(&self) -> Option<String> {
        credential_or_env(&self.credentials, CONFIG, KSM_CONFIG_ENV)
    }

    fn token(&self) -> Option<String> {
        credential_or_env(&self.credentials, TOKEN, KSM_TOKEN_ENV)
    }

    fn sanitize(&self, message: &str) -> String {
        let mut sanitized = message.to_string();
        for secret in [self.config_value(), self.token()].into_iter().flatten() {
            if !secret.is_empty() {
                sanitized = sanitized.replace(&secret, "[REDACTED]");
            }
        }
        sanitized
    }

    fn operation_error(&self, action: &str, detail: impl AsRef<str>) -> SecretSpecError {
        SecretSpecError::ProviderOperationFailed(
            self.sanitize(&format!("Keeper failed to {action}: {}", detail.as_ref())),
        )
    }

    fn build_client(&self) -> std::result::Result<KeeperClient, String> {
        let storage = match self.config_value() {
            Some(config) => InMemoryKeyValueStorage::new_config_storage(Some(config)),
            None => {
                FileKeyValueStorage::new(self.config.config_file.clone()).map(KvStoreType::File)
            }
        }
        .map_err(|error| error.to_string())?;

        let options = match self.token() {
            Some(token) => ClientOptions::new_client_options_with_token(token, storage),
            None => ClientOptions::new_client_options(storage),
        };
        let client = SecretsManager::new(options).map_err(|error| error.to_string())?;
        Ok(Mutex::new(Box::new(client)))
    }

    fn client(&self) -> Result<&KeeperClient> {
        match self.client.get_or_init(|| self.build_client()) {
            Ok(client) => Ok(client),
            Err(error) => Err(self.operation_error("initialize the SDK client", error)),
        }
    }

    fn with_client<T>(
        &self,
        action: &str,
        operation: impl FnOnce(&mut dyn KeeperApi) -> std::result::Result<T, String> + Send,
    ) -> Result<T>
    where
        T: Send,
    {
        let result = std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    let mut client = self.client()?.lock().map_err(|_| {
                        SecretSpecError::ProviderOperationFailed(
                            "Keeper SDK client lock was poisoned by an earlier failure".to_string(),
                        )
                    })?;
                    operation(client.as_mut()).map_err(|error| self.operation_error(action, error))
                })
                .join()
        });
        result
            .unwrap_or_else(|_| Err(self.operation_error(action, "the SDK worker thread panicked")))
    }

    fn target(&self, addr: Address<'_>) -> Result<KeeperTarget> {
        let native = matches!(addr, Address::Native(_));
        let coords = self.entry_coordinates(addr)?;
        Ok(KeeperTarget {
            item: coords.item.clone(),
            field: coords
                .field
                .clone()
                .expect("entry coordinates always contain the Keeper field"),
            native,
        })
    }

    fn records(&self) -> Result<Vec<Record>> {
        self.with_client("retrieve records", |client| client.get_secrets())
    }

    fn record_index(&self, records: &[Record], target: &KeeperTarget) -> Result<Option<usize>> {
        if target.native
            && let Some(index) = records.iter().position(|record| record.uid == target.item)
        {
            return Ok(Some(index));
        }

        let matches: Vec<usize> = records
            .iter()
            .enumerate()
            .filter_map(|(index, record)| (record.title == target.item).then_some(index))
            .collect();

        match matches.as_slice() {
            [] => Ok(None),
            [index] => Ok(Some(*index)),
            _ => Err(SecretSpecError::ProviderOperationFailed(format!(
                "Keeper record name '{}' is ambiguous; use its unique record UID in `ref.item`",
                target.item
            ))),
        }
    }

    fn fields<'a>(record: &'a Record, key: &str, section: &str) -> Option<&'a Value> {
        let fields = record.record_dict.get(section)?.as_array()?;
        fields
            .iter()
            .find(|field| field.get("label").and_then(Value::as_str) == Some(key))
            .or_else(|| {
                fields.iter().find(|field| {
                    field
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|field_type| field_type.eq_ignore_ascii_case(key))
                })
            })
    }

    fn locate_field(record: &Record, key: &str) -> Option<LocatedField> {
        let (section, field) = Self::fields(record, key, "fields")
            .map(|field| (FieldSection::Standard, field))
            .or_else(|| {
                Self::fields(record, key, "custom").map(|field| (FieldSection::Custom, field))
            })?;
        let value = match field.get("value") {
            Some(Value::Array(values)) => values
                .first()
                .cloned()
                .unwrap_or_else(|| Value::String(String::new())),
            Some(value) => value.clone(),
            None => Value::String(String::new()),
        };
        Some(LocatedField { section, value })
    }

    fn secret_value(record: &Record, field: &str) -> Result<SecretString> {
        let located = Self::locate_field(record, field).ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Keeper record '{}' has no standard or custom field named '{}'",
                record.title, field
            ))
        })?;
        let value = match located.value {
            Value::String(value) => value,
            value => serde_json::to_string(&value).map_err(|error| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Keeper field '{}' in record '{}' could not be represented as text: {error}",
                    field, record.title
                ))
            })?,
        };
        Ok(SecretString::new(value.into()))
    }

    fn updated_field_value(
        record: &Record,
        field: &str,
        current: &Value,
        value: &SecretString,
    ) -> Result<Value> {
        if current.is_string() {
            return Ok(Value::String(value.expose_secret().to_string()));
        }

        let updated: Value = serde_json::from_str(value.expose_secret()).map_err(|error| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Keeper field '{}' in record '{}' stores a {}; \
                 the new value must be valid JSON with the same type: {error}",
                field,
                record.title,
                Self::value_type(current),
            ))
        })?;
        if std::mem::discriminant(current) != std::mem::discriminant(&updated) {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Keeper field '{}' in record '{}' stores a {}; \
                 the new value must be valid JSON with the same type",
                field,
                record.title,
                Self::value_type(current),
            )));
        }
        Ok(updated)
    }

    fn value_type(value: &Value) -> &'static str {
        match value {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }

    fn update_record(&self, mut record: Record, field: &str, value: &SecretString) -> Result<()> {
        if !record.is_editable {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Keeper record '{}' is not editable by this application",
                record.title
            )));
        }

        let located = Self::locate_field(&record, field).ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Keeper record '{}' has no standard or custom field named '{}'",
                record.title, field
            ))
        })?;
        let value = Self::updated_field_value(&record, field, &located.value, value)?;
        let update = match located.section {
            FieldSection::Standard => record.set_standard_field_value_mut(field, value),
            FieldSection::Custom => record.set_custom_field_value_mut(field, value),
        };
        update.map_err(|error| self.operation_error("update a record field", error.to_string()))?;

        self.with_client("save a record", |client| client.update_secret(record))
    }

    fn create_record(&self, title: &str, value: &SecretString) -> Result<()> {
        let mut record =
            RecordCreate::new("login", title, Some("Managed by SecretSpec".to_string()));
        let mut password = KeeperField::new(DEFAULT_FIELD, None);
        password.value = Value::Array(vec![Value::String(value.expose_secret().to_string())]);
        password.privacy_screen = true;
        record.append_standard_fields(password);

        self.with_client("create a record", |client| {
            client
                .create_secret(&self.config.folder_uid, record)
                .map(|_| ())
        })
    }
}

impl Provider for KeeperProvider {
    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
        Ok(NativeAddress {
            item: format!("secretspec/{project}/{profile}/{key}"),
            field: Some(DEFAULT_FIELD.to_string()),
            ..Default::default()
        })
    }

    fn supported_coords(&self) -> &'static [&'static str] {
        &["field"]
    }

    fn entry_coordinates<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<std::borrow::Cow<'a, NativeAddress>> {
        let mut coords = self.resolve_coords(addr)?.into_owned();
        if coords.field.is_none() {
            coords.field = Some(DEFAULT_FIELD.to_string());
        }
        Ok(std::borrow::Cow::Owned(coords))
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    fn with_base_dir(&mut self, base_dir: &Path) {
        let Some(config_file) = self.config.config_file.as_ref() else {
            return;
        };
        let path = Path::new(config_file);
        if path.is_relative() {
            self.config.config_file = Some(base_dir.join(path).to_string_lossy().into_owned());
        }
    }

    fn name(&self) -> &str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let mut uri = format!("keeper://{}", ProviderUrl::encode(&self.config.folder_uid));
        if let Some(config_file) = &self.config.config_file {
            uri.push_str("?config_file=");
            uri.push_str(&ProviderUrl::encode_query(config_file));
        }
        uri
    }

    /// Authentication configuration does not change the Keeper shared folder
    /// in which convention-owned records live.
    fn entry_container_identity(&self) -> String {
        format!("keeper://{}", self.config.folder_uid)
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let target = self.target(addr)?;
        let records = self.records()?;
        let Some(index) = self.record_index(&records, &target)? else {
            return Ok(None);
        };
        Self::secret_value(&records[index], &target.field).map(Some)
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        self.check_writable(addr)?;
        let target = self.target(addr)?;
        let mut records = self.records()?;
        match self.record_index(&records, &target)? {
            Some(index) => self.update_record(records.swap_remove(index), &target.field, value),
            None if target.native => Err(SecretSpecError::ProviderOperationFailed(format!(
                "Keeper record '{}' referenced by `ref.item` does not exist; \
                 create it in Keeper before writing this secret",
                target.item
            ))),
            None => self.create_record(&target.item, value),
        }
    }

    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        self.entry_coordinates(addr).map(|_| ())
    }

    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        if matches!(addr, Address::Native(_)) {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Keeper secret references cannot be deleted: a reference names a record managed outside SecretSpec, and deleting it would remove the whole record"
                    .to_string(),
            ));
        }
        let target = self.target(addr)?;
        let mut records = self.records()?;
        let Some(index) = self.record_index(&records, &target)? else {
            return Ok(false);
        };
        let record = records.swap_remove(index);
        if !record.is_editable {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Keeper record '{}' is not editable by this application",
                record.title
            )));
        }
        self.with_client("delete a record", |client| {
            client.delete_secret(&record.uid)
        })?;
        Ok(true)
    }

    fn supports_delete(&self) -> bool {
        true
    }

    fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
        if matches!(addr, Address::Native(_)) {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Keeper secret references cannot be deleted: a reference names a record managed outside SecretSpec, and deleting it would remove the whole record"
                    .to_string(),
            ));
        }
        let target = self.target(addr)?;
        let records = self.records()?;
        if let Some(index) = self.record_index(&records, &target)?
            && !records[index].is_editable
        {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Keeper record '{}' is not editable by this application",
                records[index].title
            )));
        }
        Ok(())
    }

    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        if requests.is_empty() {
            return Ok(HashMap::new());
        }

        let targets: Vec<(&str, KeeperTarget)> = requests
            .iter()
            .map(|(name, addr)| Ok((*name, self.target(*addr)?)))
            .collect::<Result<_>>()?;
        let records = self.records()?;
        let mut values = HashMap::new();
        for (name, target) in targets {
            if let Some(index) = self.record_index(&records, &target)? {
                values.insert(
                    name.to_string(),
                    Self::secret_value(&records[index], &target.field)?,
                );
            }
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::sync::Arc;
    use url::Url;

    fn provider_url(value: &str) -> ProviderUrl {
        ProviderUrl::new(Url::parse(value).unwrap())
    }

    fn record(uid: &str, title: &str, editable: bool, fields: Value, custom: Value) -> Record {
        Record {
            uid: uid.to_string(),
            title: title.to_string(),
            is_editable: editable,
            record_dict: HashMap::from([
                ("type".to_string(), Value::String("login".to_string())),
                ("title".to_string(), Value::String(title.to_string())),
                ("fields".to_string(), fields),
                ("custom".to_string(), custom),
            ]),
            ..Default::default()
        }
    }

    #[derive(Default)]
    struct MockState {
        records: Vec<Record>,
        gets: usize,
        updated: Vec<Record>,
        created: Vec<(String, HashMap<String, Value>)>,
        deleted: Vec<String>,
    }

    struct MockApi {
        state: Arc<Mutex<MockState>>,
    }

    fn assert_outside_tokio_runtime() {
        assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "Keeper SDK calls must run outside Tokio runtimes"
        );
    }

    impl KeeperApi for MockApi {
        fn get_secrets(&mut self) -> std::result::Result<Vec<Record>, String> {
            assert_outside_tokio_runtime();
            let mut state = self.state.lock().unwrap();
            state.gets += 1;
            Ok(state.records.clone())
        }

        fn update_secret(&mut self, record: Record) -> std::result::Result<(), String> {
            assert_outside_tokio_runtime();
            self.state.lock().unwrap().updated.push(record);
            Ok(())
        }

        fn create_secret(
            &mut self,
            folder_uid: &str,
            record: RecordCreate,
        ) -> std::result::Result<String, String> {
            assert_outside_tokio_runtime();
            self.state
                .lock()
                .unwrap()
                .created
                .push((folder_uid.to_string(), record.to_dict().unwrap()));
            Ok("new-record-uid".to_string())
        }

        fn delete_secret(&mut self, record_uid: &str) -> std::result::Result<(), String> {
            assert_outside_tokio_runtime();
            self.state
                .lock()
                .unwrap()
                .deleted
                .push(record_uid.to_string());
            Ok(())
        }
    }

    fn provider_with_records(records: Vec<Record>) -> (KeeperProvider, Arc<Mutex<MockState>>) {
        let state = Arc::new(Mutex::new(MockState {
            records,
            ..Default::default()
        }));
        let provider = KeeperProvider::new(KeeperConfig {
            folder_uid: "FolderUID".to_string(),
            config_file: None,
        });
        provider
            .client
            .set(Ok(Mutex::new(Box::new(MockApi {
                state: Arc::clone(&state),
            }))))
            .ok()
            .unwrap();
        (provider, state)
    }

    #[test]
    fn config_requires_folder_authority() {
        let error = KeeperConfig::try_from(&provider_url("keeper://")).unwrap_err();
        assert!(error.to_string().contains("folder UID"), "{error}");

        let error =
            KeeperConfig::try_from(&provider_url("keeper://?folder=LegacyFolderUID")).unwrap_err();
        assert!(
            error.to_string().contains("keeper://SHARED_FOLDER_UID"),
            "{error}"
        );

        let error = KeeperConfig::try_from(&provider_url("keeper:///FolderUID")).unwrap_err();
        assert!(error.to_string().contains("take no path"), "{error}");

        let error =
            KeeperConfig::try_from(&provider_url("keeper://FolderUID?folder=OtherFolderUID"))
                .unwrap_err();
        assert!(
            error.to_string().contains("not the `folder` query"),
            "{error}"
        );
    }

    #[test]
    fn config_and_uri_round_trip_case_sensitive_values() {
        let config = KeeperConfig::try_from(&provider_url(
            "keeper://AbC_123-xYz?config_file=.keeper%2Fclient.json",
        ))
        .unwrap();
        assert_eq!(config.folder_uid, "AbC_123-xYz");
        assert_eq!(config.config_file.as_deref(), Some(".keeper/client.json"));
        assert_eq!(
            KeeperProvider::new(config).uri(),
            "keeper://AbC_123-xYz?config_file=.keeper/client.json"
        );
    }

    #[test]
    fn convention_uses_profile_aware_title_and_password_field() {
        let provider = KeeperProvider::new(KeeperConfig {
            folder_uid: "folder".to_string(),
            config_file: None,
        });
        let address = provider
            .convention_address("demo", "production", "DATABASE_URL")
            .unwrap();
        assert_eq!(address.item, "secretspec/demo/production/DATABASE_URL");
        assert_eq!(address.field.as_deref(), Some("password"));
    }

    #[test]
    fn same_entries_treats_an_implicit_field_as_the_password_field() {
        let provider = KeeperProvider::new(KeeperConfig {
            folder_uid: "folder".to_string(),
            config_file: None,
        });
        let implicit = NativeAddress {
            item: "RecordUID".to_string(),
            ..Default::default()
        };
        let explicit = NativeAddress {
            item: "RecordUID".to_string(),
            field: Some(DEFAULT_FIELD.to_string()),
            ..Default::default()
        };

        assert!(
            provider
                .same_entries(
                    Address::Native(&implicit),
                    &provider,
                    Address::Native(&explicit),
                )
                .unwrap(),
            "addresses that operations send to one Keeper field must compare equal"
        );
    }

    #[test]
    fn get_reads_convention_and_native_custom_fields() {
        let (provider, _) = provider_with_records(vec![record(
            "RecordUID",
            "secretspec/demo/default/API_KEY",
            true,
            serde_json::json!([
                {"type": "password", "label": "", "value": ["convention-value"]}
            ]),
            serde_json::json!([
                {"type": "text", "label": "API token", "value": ["native-value"]}
            ]),
        )]);

        let convention = provider
            .get(Address::convention("demo", "default", "API_KEY"))
            .unwrap()
            .unwrap();
        assert_eq!(convention.expose_secret(), "convention-value");

        let native = NativeAddress {
            item: "RecordUID".to_string(),
            field: Some("API token".to_string()),
            ..Default::default()
        };
        let native = provider.get(Address::Native(&native)).unwrap().unwrap();
        assert_eq!(native.expose_secret(), "native-value");
    }

    #[test]
    fn native_uid_wins_over_a_colliding_record_title() {
        let (provider, _) = provider_with_records(vec![
            record(
                "RecordUID",
                "wanted",
                true,
                serde_json::json!([
                    {"type": "password", "label": "", "value": ["by-uid"]}
                ]),
                serde_json::json!([]),
            ),
            record(
                "other",
                "RecordUID",
                true,
                serde_json::json!([
                    {"type": "password", "label": "", "value": ["by-title"]}
                ]),
                serde_json::json!([]),
            ),
        ]);
        let native = NativeAddress {
            item: "RecordUID".to_string(),
            field: Some("password".to_string()),
            ..Default::default()
        };

        let value = provider.get(Address::Native(&native)).unwrap().unwrap();
        assert_eq!(value.expose_secret(), "by-uid");
    }

    #[test]
    fn get_many_fetches_the_keeper_vault_once() {
        let (provider, state) = provider_with_records(vec![
            record(
                "one",
                "secretspec/demo/default/ONE",
                true,
                serde_json::json!([
                    {"type": "password", "label": "", "value": ["first"]}
                ]),
                serde_json::json!([]),
            ),
            record(
                "two",
                "secretspec/demo/default/TWO",
                true,
                serde_json::json!([
                    {"type": "password", "label": "", "value": ["second"]}
                ]),
                serde_json::json!([]),
            ),
        ]);

        let values = provider
            .get_many(&[
                ("ONE", Address::convention("demo", "default", "ONE")),
                ("TWO", Address::convention("demo", "default", "TWO")),
                ("MISSING", Address::convention("demo", "default", "MISSING")),
            ])
            .unwrap();

        assert_eq!(values["ONE"].expose_secret(), "first");
        assert_eq!(values["TWO"].expose_secret(), "second");
        assert!(!values.contains_key("MISSING"));
        assert_eq!(state.lock().unwrap().gets, 1);
    }

    #[test]
    fn set_updates_existing_standard_and_custom_fields() {
        let (provider, state) = provider_with_records(vec![record(
            "RecordUID",
            "existing",
            true,
            serde_json::json!([
                {"type": "password", "label": "", "value": ["old"]}
            ]),
            serde_json::json!([
                {"type": "text", "label": "API token", "value": ["old-token"]}
            ]),
        )]);

        let native = NativeAddress {
            item: "RecordUID".to_string(),
            field: Some("API token".to_string()),
            ..Default::default()
        };
        provider
            .set(
                Address::Native(&native),
                &SecretString::new("new-token".to_string().into()),
            )
            .unwrap();

        let state = state.lock().unwrap();
        assert_eq!(state.updated.len(), 1);
        assert_eq!(
            KeeperProvider::secret_value(&state.updated[0], "API token")
                .unwrap()
                .expose_secret(),
            "new-token"
        );
        assert!(matches!(
            KeeperProvider::locate_field(&state.updated[0], "API token")
                .unwrap()
                .value,
            Value::String(_)
        ));
    }

    #[test]
    fn set_preserves_typed_field_values() {
        let (provider, state) = provider_with_records(vec![record(
            "RecordUID",
            "typed fields",
            true,
            serde_json::json!([
                {"type": "date", "label": "Renewal", "value": [1700000000000_u64]}
            ]),
            serde_json::json!([
                {"type": "checkbox", "label": "Enabled", "value": [true]},
                {
                    "type": "host",
                    "label": "Server",
                    "value": [{"hostName": "db.example.com", "port": "5432"}]
                },
                {
                    "type": "name",
                    "label": "Owner",
                    "value": [{"first": "Ada", "last": "Lovelace"}]
                }
            ]),
        )]);
        let updates = [
            ("Renewal", "1700000000001"),
            ("Enabled", "false"),
            (
                "Server",
                r#"{"hostName":"replica.example.com","port":"5433"}"#,
            ),
            ("Owner", r#"{"first":"Grace","last":"Hopper"}"#),
        ];

        for (field, value) in updates {
            let native = NativeAddress {
                item: "RecordUID".to_string(),
                field: Some(field.to_string()),
                ..Default::default()
            };
            provider
                .set(
                    Address::Native(&native),
                    &SecretString::new(value.to_string().into()),
                )
                .unwrap();
        }

        let state = state.lock().unwrap();
        let expected = [
            serde_json::json!(1700000000001_u64),
            serde_json::json!(false),
            serde_json::json!({"hostName": "replica.example.com", "port": "5433"}),
            serde_json::json!({"first": "Grace", "last": "Hopper"}),
        ];
        for ((field, _), (record, expected)) in updates
            .iter()
            .zip(state.updated.iter().zip(expected.iter()))
        {
            assert_eq!(
                KeeperProvider::locate_field(record, field).unwrap().value,
                *expected
            );
        }
    }

    #[test]
    fn set_rejects_a_different_type_for_a_typed_field() {
        let (provider, state) = provider_with_records(vec![record(
            "RecordUID",
            "typed fields",
            true,
            serde_json::json!([
                {"type": "date", "label": "Renewal", "value": [1700000000000_u64]}
            ]),
            serde_json::json!([]),
        )]);
        let native = NativeAddress {
            item: "RecordUID".to_string(),
            field: Some("Renewal".to_string()),
            ..Default::default()
        };

        let error = provider
            .set(
                Address::Native(&native),
                &SecretString::new("\"1700000000001\"".to_string().into()),
            )
            .unwrap_err();

        assert!(error.to_string().contains("stores a number"), "{error}");
        assert!(state.lock().unwrap().updated.is_empty());
    }

    #[test]
    fn sdk_client_initializes_when_called_from_a_tokio_runtime() {
        const MOCK_TOKEN: &str = "US:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut provider = KeeperProvider::new(KeeperConfig {
                folder_uid: "FolderUID".to_string(),
                config_file: None,
            });
            provider.credentials.insert(
                TOKEN.to_string(),
                SecretString::new(MOCK_TOKEN.to_string().into()),
            );
            provider.credentials.insert(
                CONFIG.to_string(),
                SecretString::new("{}".to_string().into()),
            );

            provider
                .with_client("initialize the SDK client", |_| Ok(()))
                .unwrap();
        });
    }

    #[test]
    fn sdk_operations_run_outside_tokio_runtimes() {
        let (provider, state) = provider_with_records(vec![record(
            "RecordUID",
            "secretspec/demo/default/existing",
            true,
            serde_json::json!([
                {"type": "password", "label": "", "value": ["old"]}
            ]),
            serde_json::json!([]),
        )]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        runtime.block_on(async {
            let native = NativeAddress {
                item: "RecordUID".to_string(),
                field: Some("password".to_string()),
                ..Default::default()
            };
            provider.get(Address::Native(&native)).unwrap();
            provider
                .set(
                    Address::Native(&native),
                    &SecretString::new("new".to_string().into()),
                )
                .unwrap();
            provider
                .set(
                    Address::convention("demo", "default", "new"),
                    &SecretString::new("created".to_string().into()),
                )
                .unwrap();
            provider
                .delete(Address::convention("demo", "default", "existing"))
                .unwrap();
        });

        let state = state.lock().unwrap();
        assert_eq!(state.updated.len(), 1);
        assert_eq!(state.created.len(), 1);
        assert_eq!(state.deleted, ["RecordUID"]);
    }

    #[test]
    fn delete_rejects_native_references_before_touching_the_record() {
        let (provider, state) = provider_with_records(vec![record(
            "RecordUID",
            "external-record",
            true,
            serde_json::json!([
                {"type": "password", "label": "", "value": ["value"]}
            ]),
            serde_json::json!([]),
        )]);
        let native = NativeAddress {
            item: "RecordUID".to_string(),
            field: Some("password".to_string()),
            ..Default::default()
        };

        let error = provider.delete(Address::Native(&native)).unwrap_err();
        assert!(error.to_string().contains("whole record"), "{error}");
        assert!(state.lock().unwrap().deleted.is_empty());
    }

    #[test]
    fn set_creates_missing_convention_record_in_configured_folder() {
        let (provider, state) = provider_with_records(Vec::new());
        provider
            .set(
                Address::convention("demo", "production", "API_KEY"),
                &SecretString::new("new-value".to_string().into()),
            )
            .unwrap();

        let state = state.lock().unwrap();
        let (folder, record) = &state.created[0];
        assert_eq!(folder, "FolderUID");
        assert_eq!(
            record.get("title").and_then(Value::as_str),
            Some("secretspec/demo/production/API_KEY")
        );
        assert_eq!(
            record
                .get("fields")
                .and_then(Value::as_array)
                .and_then(|fields| fields[0].get("value"))
                .and_then(Value::as_array)
                .and_then(|values| values[0].as_str()),
            Some("new-value")
        );
    }

    #[test]
    fn set_does_not_create_a_missing_native_reference() {
        let (provider, state) = provider_with_records(Vec::new());
        let native = NativeAddress {
            item: "missing-record".to_string(),
            field: Some("password".to_string()),
            ..Default::default()
        };
        let error = provider
            .set(
                Address::Native(&native),
                &SecretString::new("value".to_string().into()),
            )
            .unwrap_err();
        assert!(error.to_string().contains("create it in Keeper"), "{error}");
        assert!(state.lock().unwrap().created.is_empty());
    }

    #[test]
    fn delete_is_idempotent_and_uses_the_record_uid() {
        let (provider, state) = provider_with_records(vec![record(
            "RecordUID",
            "secretspec/demo/default/API_KEY",
            true,
            serde_json::json!([
                {"type": "password", "label": "", "value": ["value"]}
            ]),
            serde_json::json!([]),
        )]);
        assert!(
            provider
                .delete(Address::convention("demo", "default", "API_KEY"))
                .unwrap()
        );
        assert_eq!(state.lock().unwrap().deleted, ["RecordUID"]);

        let (provider, _) = provider_with_records(Vec::new());
        assert!(
            !provider
                .delete(Address::convention("demo", "default", "API_KEY"))
                .unwrap()
        );
    }
}
