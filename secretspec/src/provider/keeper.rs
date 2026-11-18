//! Keeper Secrets Manager provider.
//!
//! This provider uses Keeper's official Rust SDK. A Keeper Secrets Manager
//! application must have access to the shared folder named by the provider URI.
//! Convention secrets are stored as login records titled
//! `secretspec/{project}/{profile}/{key}`, with the value in the `password`
//! field.

use super::{Address, Provider, ProviderCredentials, ProviderUrl, credential_or_env};
use crate::SecretBytes;
use crate::config::NativeAddress;
use crate::{Result, SecretSpecError};
use keeper_secrets_manager_core::core::{ClientOptions, SecretsManager};
use keeper_secrets_manager_core::custom_error::KSMRError;
use keeper_secrets_manager_core::dto::dtos::{Record, RecordCreate};
use keeper_secrets_manager_core::dto::field_structs::KeeperField;
use keeper_secrets_manager_core::dto::{EncryptedPayload, KsmHttpResponse, TransmissionKey};
use keeper_secrets_manager_core::enums::KvStoreType;
use keeper_secrets_manager_core::storage::{FileKeyValueStorage, InMemoryKeyValueStorage};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

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

/// Replace only the SDK's blocking HTTP call; the SDK still builds and signs
/// each encrypted payload and interprets status/body for binding and retries.
struct KeeperTransport {
    request: crate::request::RequestContext,
    client: OnceLock<reqwest::Client>,
}

impl KeeperTransport {
    fn send(
        &self,
        url: String,
        key: TransmissionKey,
        payload: EncryptedPayload,
    ) -> std::result::Result<KsmHttpResponse, KSMRError> {
        use keeper_secrets_manager_core::utils::bytes_to_base64;
        self.request
            .block_on(async {
                let client = self.client.get().ok_or_else(|| {
                    SecretSpecError::ProviderOperationFailed(
                        "Keeper transport not initialized".into(),
                    )
                })?;
                let http_error = |error: reqwest::Error| {
                    SecretSpecError::ProviderOperationFailed(error.without_url().to_string())
                };
                let response = client
                    .post(url)
                    .header("Content-Type", "application/octet-stream")
                    .header("Content-Length", payload.encrypted_payload.len())
                    .header(
                        "Authorization",
                        format!(
                            "Signature {}",
                            bytes_to_base64(payload.signature.as_bytes())
                        ),
                    )
                    .header("TransmissionKey", bytes_to_base64(&key.encrypted_key))
                    .header("PublicKeyId", key.public_key_id)
                    .header("Accept-Encoding", "gzip, deflate")
                    .body(payload.encrypted_payload)
                    .send()
                    .await
                    .map_err(http_error)?;
                let status = response.status().as_u16();
                let data = response.bytes().await.map_err(http_error)?;
                Ok(KsmHttpResponse::new(
                    status,
                    data.to_vec(),
                    String::from_utf8_lossy(&data).into_owned(),
                ))
            })
            .map_err(|error| KSMRError::HTTPError(error.to_string()))
    }
}

/// Keeper Secrets Manager provider backed by Keeper's official Rust SDK.
pub struct KeeperProvider {
    request: Option<crate::request::RequestContext>,
    config: KeeperConfig,
    credentials: ProviderCredentials,
    client: OnceLock<KeeperClient>,
    client_initialization: Mutex<()>,
}

crate::register_provider! {
    struct: KeeperProvider,
    config: KeeperConfig,
    metadata: &super::catalog::KEEPER,
}

super::managed_read::register!(["keeper"], |url, credentials, request| {
    let mut provider = KeeperProvider::new(KeeperConfig::try_from(url)?);
    provider.with_credentials(credentials);
    provider.request = Some(request.clone());
    Ok(Box::new(provider))
});

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
            request: None,
            config,
            credentials: ProviderCredentials::new(),
            client: OnceLock::new(),
            client_initialization: Mutex::new(()),
        }
    }

    fn config_value(&self) -> Option<SecretBytes> {
        credential_or_env(&self.credentials, CONFIG, KSM_CONFIG_ENV)
    }

    fn token(&self) -> Option<SecretBytes> {
        credential_or_env(&self.credentials, TOKEN, KSM_TOKEN_ENV)
    }

    fn sanitize(&self, message: &str) -> String {
        let mut sanitized = message.to_string();
        for secret in [self.config_value(), self.token()].into_iter().flatten() {
            if !secret.expose_secret().is_empty() {
                sanitized = sanitized.replace(
                    String::from_utf8_lossy(secret.expose_secret()).as_ref(),
                    "[REDACTED]",
                );
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
            Some(config) => InMemoryKeyValueStorage::new_config_storage(Some(
                config
                    .try_as_utf8()
                    .map_err(|error| error.to_string())?
                    .to_owned(),
            )),
            None => {
                FileKeyValueStorage::new(self.config.config_file.clone()).map(KvStoreType::File)
            }
        }
        .map_err(|error| error.to_string())?;

        let mut options = match self.token() {
            Some(token) => ClientOptions::new_client_options_with_token(
                token
                    .try_as_utf8()
                    .map_err(|error| error.to_string())?
                    .to_owned(),
                storage,
            ),
            None => ClientOptions::new_client_options(storage),
        };
        let transport = self.request.as_ref().map(|request| {
            let transport = Arc::new(KeeperTransport {
                request: request.clone(),
                client: OnceLock::new(),
            });
            let post = Arc::clone(&transport);
            options.set_custom_post_function(move |url, key, payload| post.send(url, key, payload));
            transport
        });
        let mut client = SecretsManager::new(options).map_err(|error| error.to_string())?;
        if let Some(transport) = transport {
            // Let the SDK resolve and validate its SSL/proxy settings first.
            // Its constructor performs no POST; signing, encryption, binding
            // and retries remain inside the SDK after installing this hook.
            let mut http = reqwest::Client::builder()
                // Match the SDK's reqwest::blocking default timeout.
                .timeout(std::time::Duration::from_secs(30))
                .danger_accept_invalid_certs(!client.verify_ssl_certs);
            if let Some(proxy) = &client.proxy_url {
                http = http.proxy(reqwest::Proxy::all(proxy).map_err(|e| e.to_string())?);
            }
            transport
                .client
                .set(http.build().map_err(|e| e.to_string())?)
                .expect("Keeper transport initialized once");
            client.set_custom_sleep_function(move |delay| {
                // The SDK's sleep hook cannot return an error. The next POST
                // checks cancellation before any I/O, and with_client restores
                // the typed cancellation error after the SDK unwinds.
                let _ = transport.request.wait(delay);
            });
        }
        Ok(Mutex::new(Box::new(client)))
    }

    fn client(&self) -> Result<&KeeperClient> {
        if let Some(client) = self.client.get() {
            return Ok(client);
        }
        let _initialization = if self.request.is_some() {
            crate::managed_io::lock(&self.client_initialization, self.request.as_ref())?
        } else {
            self.client_initialization.lock().map_err(|_| {
                self.operation_error(
                    "initialize the SDK client",
                    "initialization lock was poisoned",
                )
            })?
        };
        if let Some(client) = self.client.get() {
            return Ok(client);
        }
        let client = self
            .build_client()
            .map_err(|error| self.operation_error("initialize the SDK client", error))?;
        Ok(self.client.get_or_init(|| client))
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
                    if let Some(request) = &self.request {
                        request.checkpoint()?;
                    }
                    let mut client = if self.request.is_some() {
                        crate::managed_io::lock(self.client()?, self.request.as_ref())?
                    } else {
                        self.client()?.lock().map_err(|_| {
                            SecretSpecError::ProviderOperationFailed(
                                "Keeper SDK client lock was poisoned by an earlier failure"
                                    .to_string(),
                            )
                        })?
                    };
                    if let Some(request) = &self.request {
                        request.checkpoint()?;
                    }
                    let result = operation(client.as_mut());
                    if let Some(request) = &self.request {
                        request.checkpoint()?;
                    }
                    result.map_err(|error| self.operation_error(action, error))
                })
                .join()
        });
        result.unwrap_or_else(|_| {
            Err(if self.request.is_some() {
                SecretSpecError::ResolutionPanicked
            } else {
                self.operation_error(action, "the SDK worker thread panicked")
            })
        })
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

    fn secret_value(record: &Record, field: &str) -> Result<SecretBytes> {
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
        Ok(SecretBytes::from_utf8(value))
    }

    fn updated_field_value(
        record: &Record,
        field: &str,
        current: &Value,
        value: &SecretBytes,
    ) -> Result<Value> {
        let value = super::require_utf8("keeper", value)?;
        if current.is_string() {
            return Ok(Value::String(value.to_string()));
        }

        let updated: Value = serde_json::from_str(value).map_err(|error| {
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

    fn update_record(&self, mut record: Record, field: &str, value: &SecretBytes) -> Result<()> {
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

    fn create_record(&self, title: &str, value: &SecretBytes) -> Result<()> {
        let value = super::require_utf8("keeper", value)?;
        let mut record =
            RecordCreate::new("login", title, Some("Managed by SecretSpec".to_string()));
        let mut password = KeeperField::new(DEFAULT_FIELD, None);
        password.value = Value::Array(vec![Value::String(value.to_string())]);
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

    fn configured_entry_coordinates<'a>(
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

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
        let target = self.target(addr)?;
        let records = self.records()?;
        let Some(index) = self.record_index(&records, &target)? else {
            return Ok(None);
        };
        Self::secret_value(&records[index], &target.field).map(Some)
    }

    fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()> {
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

    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretBytes>> {
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
            .set(Mutex::new(Box::new(MockApi {
                state: Arc::clone(&state),
            })))
            .ok()
            .unwrap();
        (provider, state)
    }

    #[tokio::test]
    async fn managed_sdk_panic_is_terminal() {
        crate::request::run(&crate::CancellationHandle::new(), |request| {
            let (mut provider, _) = provider_with_records(Vec::new());
            provider.request = Some(request);
            let error = provider
                .with_client::<()>("retrieve records", |_| panic!("SDK fixture panic"))
                .unwrap_err();
            assert_eq!(error.kind(), "resolution_panicked");
            assert!(error.is_resolution_terminal());
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn managed_http_preserves_responses_and_cancels_header_and_body_waits() {
        use std::io::{BufRead, Read, Write};
        use std::time::Duration;
        const RESPONSE: &[u8] = b"\0\xffbody";
        for (complete_status, partial_body) in [
            (Some(200), false),
            (Some(403), false),
            (None, false),
            (None, true),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}/", listener.local_addr().unwrap());
            let (started, start) = tokio::sync::oneshot::channel();
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = std::io::BufReader::new(socket.try_clone().unwrap());
                let mut headers = String::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    headers.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                }
                let mut body = [0; 3];
                reader.read_exact(&mut body).unwrap();
                assert_eq!(body, [1, 2, 3]);
                let headers = headers.to_ascii_lowercase();
                assert!(headers.contains("authorization: signature "));
                assert!(headers.contains("transmissionkey: aqid"));
                assert!(headers.contains("publickeyid: 10"));
                if let Some(status) = complete_status {
                    write!(
                        socket,
                        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\n\r\n",
                        RESPONSE.len()
                    )
                    .unwrap();
                    socket.write_all(RESPONSE).unwrap();
                } else if partial_body {
                    socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\npartial")
                        .unwrap();
                }
                started.send(()).unwrap();
                let closed = socket.read(&mut [0]);
                assert!(
                    matches!(closed, Ok(0))
                        || closed.is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset)
                );
            });
            let handle = crate::CancellationHandle::new();
            let cancel = handle.clone();
            let task = tokio::spawn(async move {
                crate::request::run(&handle, move |request| {
                    let transport = KeeperTransport {
                        request,
                        client: OnceLock::from(
                            reqwest::Client::builder().no_proxy().build().unwrap(),
                        ),
                    };
                    let signature = [0x30, 6, 2, 1, 1, 2, 1, 1].as_slice().try_into().unwrap();
                    transport
                        .send(
                            url,
                            TransmissionKey::new("10".into(), vec![], vec![1, 2, 3]),
                            EncryptedPayload::new(vec![1, 2, 3], signature),
                        )
                        .map_err(|e| SecretSpecError::ProviderOperationFailed(e.to_string()))
                })
                .await
            });
            tokio::time::timeout(Duration::from_secs(5), start)
                .await
                .unwrap()
                .unwrap();
            if complete_status.is_none() {
                cancel.cancel();
            }
            let result = tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .unwrap()
                .unwrap();
            if let Some(status) = complete_status {
                let response = result.unwrap();
                assert_eq!(response.status_code, status);
                assert_eq!(response.data, RESPONSE);
                assert_eq!(
                    response.http_response.unwrap(),
                    String::from_utf8_lossy(RESPONSE)
                );
            } else {
                assert_eq!(result.unwrap_err().kind(), "cancelled");
            }
            server.join().unwrap();
        }
    }

    #[tokio::test]
    async fn sdk_throttle_wait_cancels_without_another_post() {
        use keeper_secrets_manager_core::{
            config_keys::ConfigKeys, crypto::CryptoUtils, storage::KeyValueStorage,
            utils::bytes_to_base64,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;
        let (started, start) = tokio::sync::oneshot::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let posts = Arc::clone(&calls);
        let handle = crate::CancellationHandle::new();
        let cancel = handle.clone();
        let task = tokio::spawn(async move {
            crate::request::run(&handle, move |request| {
                let mut storage =
                    KvStoreType::InMemory(InMemoryKeyValueStorage::new(None).unwrap());
                let key = CryptoUtils::generate_private_key_der().unwrap();
                for (key, value) in [
                    (ConfigKeys::KeyClientId, "fixture".into()),
                    (ConfigKeys::KeyPrivateKey, bytes_to_base64(&key)),
                    (ConfigKeys::KeyAppKey, bytes_to_base64(&[1; 32])),
                    (ConfigKeys::KeyServerPublicKeyId, "10".into()),
                    (ConfigKeys::KeyHostname, "keepersecurity.com".into()),
                ] {
                    storage.set(key, value).unwrap();
                }
                let mut options = ClientOptions::new_client_options(storage);
                let post_request = request.clone();
                options.set_custom_post_function(move |_, _, _| {
                    post_request
                        .checkpoint()
                        .map_err(|e| KSMRError::HTTPError(e.to_string()))?;
                    posts.fetch_add(1, Ordering::SeqCst);
                    Ok(KsmHttpResponse::new(
                        403,
                        vec![],
                        r#"{"error":"throttled","retry_after":60}"#.into(),
                    ))
                });
                let mut client = SecretsManager::new(options).unwrap();
                let started = Mutex::new(Some(started));
                let sleep_request = request.clone();
                client.set_custom_sleep_function(move |delay| {
                    if let Some(started) = started.lock().unwrap().take() {
                        started.send(()).unwrap();
                    }
                    let _ = sleep_request.wait(delay);
                });
                let mut provider = KeeperProvider::new(KeeperConfig::default());
                // with_client must join the SDK and recover cancellation from
                // its string errors, just as with the real HTTP hook.
                provider.request = Some(request);
                provider
                    .client
                    .set(Mutex::new(Box::new(client)))
                    .ok()
                    .unwrap();
                provider.records()
            })
            .await
        });
        tokio::time::timeout(Duration::from_secs(5), start)
            .await
            .unwrap()
            .unwrap();
        cancel.cancel();
        let error = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .err()
            .unwrap();
        assert_eq!(error.kind(), "cancelled");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
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
        assert_eq!(convention.expose_secret(), b"convention-value");

        let native = NativeAddress {
            item: "RecordUID".to_string(),
            field: Some("API token".to_string()),
            ..Default::default()
        };
        let native = provider.get(Address::Native(&native)).unwrap().unwrap();
        assert_eq!(native.expose_secret(), b"native-value");
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
        assert_eq!(value.expose_secret(), b"by-uid");
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

        assert_eq!(values["ONE"].expose_secret(), b"first");
        assert_eq!(values["TWO"].expose_secret(), b"second");
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
                &SecretBytes::from_utf8("new-token"),
            )
            .unwrap();

        let state = state.lock().unwrap();
        assert_eq!(state.updated.len(), 1);
        assert_eq!(
            KeeperProvider::secret_value(&state.updated[0], "API token")
                .unwrap()
                .expose_secret(),
            b"new-token"
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
                    &SecretBytes::from_utf8(value.to_string()),
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
                &SecretBytes::from_utf8("\"1700000000001\""),
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
                SecretBytes::from_utf8(MOCK_TOKEN.to_string()),
            );
            provider
                .credentials
                .insert(CONFIG.to_string(), SecretBytes::from_utf8("{}"));

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
                .set(Address::Native(&native), &SecretBytes::from_utf8("new"))
                .unwrap();
            provider
                .set(
                    Address::convention("demo", "default", "new"),
                    &SecretBytes::from_utf8("created"),
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
                &SecretBytes::from_utf8("new-value"),
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
            .set(Address::Native(&native), &SecretBytes::from_utf8("value"))
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
