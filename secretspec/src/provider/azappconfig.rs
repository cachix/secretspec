//! Azure App Configuration provider, available in SecretSpec 0.19+.
//!
//! Reads and manages ordinary App Configuration key-values and resolves
//! canonical Azure Key Vault references through SecretSpec's existing Azure
//! Key Vault provider.
//!
//! # Authentication
//!
//! `auth=env` is the default. The `tenant_id`, `client_id`, and
//! `client_secret` provider credentials override `AZURE_TENANT_ID`,
//! `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET`; a complete triple uses a
//! service principal, no values fall back to `az login`, and a partial triple
//! is rejected. `auth=cli`, `auth=managed_identity`, and
//! `auth=workload_identity` select those identities explicitly.
//!
//! `auth=connection_string` reads the `connection_string` provider credential
//! or `AZURE_APPCONFIG_CONNECTION_STRING`. That environment variable is a
//! SecretSpec convention. A connection string authenticates only App
//! Configuration; Key Vault references require an explicit Entra identity via
//! `key_vault_auth`.
//!
//! # URI format
//!
//! ```text
//! azappconfig://STORE[?auth=env|cli|managed_identity|workload_identity|connection_string]
//!   [&suffix=DNS_SUFFIX][&audience=TOKEN_AUDIENCE]
//!   [&key_vault_auth=inherit|env|cli|managed_identity|workload_identity]
//!   [&key_vault_suffix=DNS_SUFFIX]
//!   [&label=LABEL][&prefix=PREFIX][&tag=NAME=VALUE]...
//! ```
//!
//! Bare store names use `.azconfig.io`. A dotted hostname is used verbatim.
//! Non-public hosts require an explicit Entra `audience`. `label` selects one
//! exact label; omission selects the null label. Up to five `tag` parameters
//! are exact AND filters. `prefix` is concatenated literally, so include any
//! intended separator: `prefix=payments:orders:`.
//!
//! # Naming and references
//!
//! Convention keys are
//! `{prefix}secretspec:{project}:{profile}:{key}`. Native `ref.item` values
//! address one existing App Configuration key and remain read-only.
//!
//! Values with the canonical Azure Key Vault-reference media type are resolved
//! from their HTTPS secret URI. The reference host must be a direct subdomain
//! of `key_vault_suffix` (default `vault.azure.net`). Direct values remain
//! opaque strings; feature flags, snapshot references, and unknown Azure
//! special types are rejected.
//!
//! # Security boundary
//!
//! Labels, prefixes, and tags select values but do not authorize access.
//! App Configuration readers can see direct values, metadata, reference URIs,
//! and retained revisions within their data-plane permissions. Key Vault
//! references keep the resolved value behind separate Key Vault permissions.
//!
//! # Examples
//!
//! ```bash
//! secretspec check --provider azappconfig://payments-prod
//! secretspec check --provider 'azappconfig://shared?label=production&prefix=payments:'
//! secretspec check --provider 'azappconfig://shared?tag=app=payments&tag=stage=production'
//! ```

use super::{
    Address, DiscoveryContext, Provider, ProviderCredentials, ProviderUrl, credential_or_env,
    get_each_concurrency, map_concurrently,
};
use crate::config::NativeAddress;
use crate::{Result, SecretSpecError};
use azure_core::credentials::{Secret as AzureSecret, TokenCredential};
use reqwest::header::{
    AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, IF_MATCH, IF_NONE_MATCH,
};
use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use url::Url;

const API_VERSION: &str = "2026-04-01";
const DEFAULT_SUFFIX: &str = "azconfig.io";
const DEFAULT_AUDIENCE: &str = "https://appconfig.azure.com";
const DEFAULT_KEY_VAULT_SUFFIX: &str = "vault.azure.net";
const KEY_VAULT_REFERENCE_TYPE: &str = "application/vnd.microsoft.appconfig.keyvaultref+json";
const AZURE_SPECIAL_PREFIX: &str = "application/vnd.microsoft.appconfig.";
const AZURE_APPCONFIG_CONNECTION_STRING_ENV: &str = "AZURE_APPCONFIG_CONNECTION_STRING";
const TENANT_ID: &str = "tenant_id";
const CLIENT_ID: &str = "client_id";
const CLIENT_SECRET: &str = "client_secret";
const CONNECTION_STRING: &str = "connection_string";
const MAX_TAG_FILTERS: usize = 5;
const MAX_ERROR_BODY: usize = 8 * 1024;
const MAX_VAULT_CLIENTS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
enum AppConfigAuth {
    #[default]
    Env,
    Cli,
    ManagedIdentity,
    WorkloadIdentity,
    ConnectionString,
}

impl AppConfigAuth {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "env" => Ok(Self::Env),
            "cli" => Ok(Self::Cli),
            "managed_identity" => Ok(Self::ManagedIdentity),
            "workload_identity" => Ok(Self::WorkloadIdentity),
            "connection_string" => Ok(Self::ConnectionString),
            other => Err(operation_error(format!(
                "unknown azappconfig auth method '{other}': expected env, cli, \
                 managed_identity, workload_identity, or connection_string"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Cli => "cli",
            Self::ManagedIdentity => "managed_identity",
            Self::WorkloadIdentity => "workload_identity",
            Self::ConnectionString => "connection_string",
        }
    }

    fn entra_method(self) -> Option<super::akv::AuthMethod> {
        match self {
            Self::Env => Some(super::akv::AuthMethod::Env),
            Self::Cli => Some(super::akv::AuthMethod::Cli),
            Self::ManagedIdentity => Some(super::akv::AuthMethod::ManagedIdentity),
            Self::WorkloadIdentity => Some(super::akv::AuthMethod::WorkloadIdentity),
            Self::ConnectionString => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum KeyVaultAuth {
    Inherit,
    Entra(super::akv::AuthMethod),
}

impl KeyVaultAuth {
    fn parse(value: &str) -> Result<Self> {
        if value == "inherit" {
            Ok(Self::Inherit)
        } else {
            value.parse().map(Self::Entra)
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Inherit => "inherit",
            Self::Entra(auth) => auth.as_str(),
        }
    }
}

/// Credential-free Azure App Configuration provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzAppConfigConfig {
    store_host: String,
    endpoint: String,
    auth: AppConfigAuth,
    suffix: Option<String>,
    audience: String,
    audience_explicit: bool,
    key_vault_auth: Option<KeyVaultAuth>,
    key_vault_suffix: String,
    key_vault_suffix_explicit: bool,
    label: Option<String>,
    prefix: Option<String>,
    tags: Vec<(String, String)>,
}

impl TryFrom<&ProviderUrl> for AzAppConfigConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> Result<Self> {
        if url.scheme() != "azappconfig" {
            return Err(operation_error(format!(
                "invalid scheme '{}' for azappconfig provider: expected azappconfig",
                url.scheme()
            )));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(operation_error(
                "azappconfig URIs cannot contain user information".to_string(),
            ));
        }
        if url.port().is_some() {
            return Err(operation_error(
                "azappconfig endpoints cannot contain an explicit port".to_string(),
            ));
        }

        let store_host = url.host().filter(|host| !host.is_empty()).ok_or_else(|| {
            operation_error(
                "Azure App Configuration store is required: use azappconfig://STORE".to_string(),
            )
        })?;
        let path = url.path();
        let item = path.trim_start_matches('/');
        if !item.is_empty() {
            let hint = crate::config::ref_table_hint(None, item, None, None);
            return Err(operation_error(format!(
                "azappconfig URIs take no path: address the key with {hint} on the secret instead"
            )));
        }

        let mut singleton = BTreeMap::<String, String>::new();
        let mut tags = Vec::new();
        for (name, value) in url.query_pairs() {
            let name = name.into_owned();
            let value = value.into_owned();
            if name == "tag" {
                tags.push(parse_tag(&value)?);
                continue;
            }
            if !matches!(
                name.as_str(),
                "auth"
                    | "suffix"
                    | "audience"
                    | "key_vault_auth"
                    | "key_vault_suffix"
                    | "label"
                    | "prefix"
            ) {
                return Err(operation_error(format!(
                    "unknown azappconfig parameter '{name}'"
                )));
            }
            if value.is_empty() {
                return Err(operation_error(format!(
                    "azappconfig parameter '{name}' cannot be empty"
                )));
            }
            if singleton.insert(name.clone(), value).is_some() {
                return Err(operation_error(format!(
                    "azappconfig parameter '{name}' may appear only once"
                )));
            }
        }

        if tags.len() > MAX_TAG_FILTERS {
            return Err(operation_error(format!(
                "azappconfig accepts at most {MAX_TAG_FILTERS} tag filters"
            )));
        }
        tags.sort_by(|left, right| left.0.cmp(&right.0));
        for pair in tags.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(operation_error(format!(
                    "azappconfig tag name '{}' may appear only once",
                    pair[0].0
                )));
            }
        }

        let auth = singleton
            .get("auth")
            .map(|value| AppConfigAuth::parse(value))
            .transpose()?
            .unwrap_or_default();
        let suffix = singleton
            .get("suffix")
            .map(|value| normalize_dns_suffix(value))
            .transpose()?;
        if store_host.contains('.') && suffix.is_some() {
            return Err(operation_error(
                "azappconfig suffix is valid only with a bare store name".to_string(),
            ));
        }
        let effective_host = if store_host.contains('.') {
            store_host.clone()
        } else {
            format!(
                "{store_host}.{}",
                suffix.as_deref().unwrap_or(DEFAULT_SUFFIX)
            )
        };
        let endpoint = canonical_https_endpoint(&effective_host)?;
        let is_public = effective_host == DEFAULT_SUFFIX
            || effective_host.ends_with(&format!(".{DEFAULT_SUFFIX}"));
        let audience_explicit = singleton.contains_key("audience");
        let audience = singleton
            .get("audience")
            .map(|value| normalize_audience(value))
            .transpose()?
            .unwrap_or_else(|| DEFAULT_AUDIENCE.to_string());
        if !is_public && !audience_explicit {
            return Err(operation_error(format!(
                "azappconfig host '{effective_host}' is outside Azure public cloud; set audience explicitly"
            )));
        }

        let key_vault_auth = singleton
            .get("key_vault_auth")
            .map(|value| KeyVaultAuth::parse(value))
            .transpose()?;
        if auth == AppConfigAuth::ConnectionString && key_vault_auth == Some(KeyVaultAuth::Inherit)
        {
            return Err(operation_error(
                "key_vault_auth=inherit cannot be used with auth=connection_string; choose an Entra Key Vault identity"
                    .to_string(),
            ));
        }
        let key_vault_suffix_explicit = singleton.contains_key("key_vault_suffix");
        let key_vault_suffix = singleton
            .get("key_vault_suffix")
            .map(|value| normalize_dns_suffix(value))
            .transpose()?
            .unwrap_or_else(|| DEFAULT_KEY_VAULT_SUFFIX.to_string());
        let label = singleton.get("label").cloned();
        let prefix = singleton.get("prefix").cloned();
        if let Some(prefix) = &prefix {
            validate_appconfig_key(prefix, "prefix")?;
        }

        Ok(Self {
            store_host,
            endpoint,
            auth,
            suffix,
            audience,
            audience_explicit,
            key_vault_auth,
            key_vault_suffix,
            key_vault_suffix_explicit,
            label,
            prefix,
            tags,
        })
    }
}

fn operation_error(message: String) -> SecretSpecError {
    SecretSpecError::ProviderOperationFailed(message)
}

fn parse_tag(value: &str) -> Result<(String, String)> {
    let (name, value) = value
        .split_once('=')
        .ok_or_else(|| operation_error("azappconfig tags use tag=NAME=VALUE".to_string()))?;
    if name.is_empty() || value.is_empty() {
        return Err(operation_error(
            "azappconfig tag names and values cannot be empty".to_string(),
        ));
    }
    Ok((name.to_string(), value.to_string()))
}

fn normalize_dns_suffix(value: &str) -> Result<String> {
    let value = value.trim().trim_matches('.').to_ascii_lowercase();
    if value.is_empty() || value.contains('/') || value.contains(':') {
        return Err(operation_error(format!(
            "invalid Azure DNS suffix '{value}'"
        )));
    }
    let url = Url::parse(&format!("https://probe.{value}/"))
        .map_err(|_| operation_error(format!("invalid Azure DNS suffix '{value}'")))?;
    let host = url
        .host_str()
        .and_then(|host| host.strip_prefix("probe."))
        .ok_or_else(|| operation_error(format!("invalid Azure DNS suffix '{value}'")))?;
    Ok(host.to_string())
}

fn canonical_https_endpoint(host: &str) -> Result<String> {
    let url = Url::parse(&format!("https://{host}/"))
        .map_err(|error| operation_error(format!("invalid Azure endpoint host: {error}")))?;
    if url.host_str().is_none() || url.port().is_some() {
        return Err(operation_error("invalid Azure endpoint host".to_string()));
    }
    Ok(url.to_string())
}

fn normalize_audience(value: &str) -> Result<String> {
    let url = Url::parse(value)
        .map_err(|error| operation_error(format!("invalid azappconfig audience: {error}")))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || (url.path() != "/" && !url.path().is_empty())
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(operation_error(
            "azappconfig audience must be an HTTPS origin without credentials, port, path, query, or fragment"
                .to_string(),
        ));
    }
    Ok(value.trim_end_matches('/').to_string())
}

fn validate_name_component(name: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(operation_error(format!("{name} cannot be empty")));
    }
    if let Some(character) = value.chars().find(|character| {
        !character.is_ascii_alphanumeric() && *character != '_' && *character != '-'
    }) {
        return Err(operation_error(format!(
            "{name} contains invalid character '{character}': only ASCII letters, digits, underscores, and hyphens are allowed"
        )));
    }
    Ok(())
}

fn validate_appconfig_key(key: &str, name: &str) -> Result<()> {
    if key.is_empty() {
        return Err(operation_error(format!("{name} cannot be empty")));
    }
    if key.contains('%') || key == "." || key == ".." {
        return Err(operation_error(format!(
            "{name} '{key}' is not a valid Azure App Configuration key: percent signs and whole keys '.' or '..' are not allowed"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct ConnectionStringAuth {
    id: String,
    secret: AzureSecret,
}

enum ResolvedAuth {
    Entra(Arc<dyn TokenCredential>),
    ConnectionString(ConnectionStringAuth),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SyncToken {
    sequence: Option<u64>,
    value: String,
}

/// Azure App Configuration provider, available in SecretSpec 0.19+.
pub struct AzAppConfigProvider {
    config: AzAppConfigConfig,
    credentials: ProviderCredentials,
    http: OnceLock<reqwest::Client>,
    auth: OnceLock<ResolvedAuth>,
    key_vault_credential: OnceLock<Arc<dyn TokenCredential>>,
    sync_tokens: Mutex<BTreeMap<String, SyncToken>>,
    vaults: Mutex<HashMap<String, Arc<super::akv::AkvProvider>>>,
    initial_request: super::akv::InitialRequestGate,
}

crate::register_provider! {
    struct: AzAppConfigProvider,
    config: AzAppConfigConfig,
    name: "azappconfig",
    description: "Azure App Configuration (0.19+)",
    schemes: ["azappconfig"],
    examples: [
        "azappconfig://payments-production",
        "azappconfig://shared?label=production&prefix=payments:",
        "azappconfig://shared?tag=app=payments&tag=stage=production",
    ],
    credential_names: [TENANT_ID, CLIENT_ID, CLIENT_SECRET, CONNECTION_STRING],
    deletes: true,
}

impl AzAppConfigProvider {
    pub fn new(config: AzAppConfigConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
            http: OnceLock::new(),
            auth: OnceLock::new(),
            key_vault_credential: OnceLock::new(),
            sync_tokens: Mutex::new(BTreeMap::new()),
            vaults: Mutex::new(HashMap::new()),
            initial_request: super::akv::InitialRequestGate::default(),
        }
    }

    fn http(&self) -> Result<&reqwest::Client> {
        if let Some(client) = self.http.get() {
            return Ok(client);
        }
        let client = reqwest::Client::builder()
            .https_only(true)
            .build()
            .map_err(|error| {
                operation_error(format!(
                    "failed to create Azure App Configuration HTTP client: {error}"
                ))
            })?;
        Ok(self.http.get_or_init(|| client))
    }

    fn resolve_auth(&self) -> Result<ResolvedAuth> {
        if let Some(method) = self.config.auth.entra_method() {
            return super::akv::resolve_azure_credential(method, &self.credentials)
                .map(ResolvedAuth::Entra);
        }

        let connection_string = credential_or_env(
            &self.credentials,
            CONNECTION_STRING,
            AZURE_APPCONFIG_CONNECTION_STRING_ENV,
        )
        .ok_or_else(|| {
            operation_error(format!(
                "auth=connection_string requires the connection_string provider credential or {AZURE_APPCONFIG_CONNECTION_STRING_ENV}"
            ))
        })?;
        parse_connection_string(&connection_string, &self.config.endpoint)
            .map(ResolvedAuth::ConnectionString)
    }

    fn auth(&self) -> Result<&ResolvedAuth> {
        if let Some(auth) = self.auth.get() {
            return Ok(auth);
        }
        let auth = self.resolve_auth()?;
        Ok(self.auth.get_or_init(|| auth))
    }

    fn token_scope(&self) -> String {
        format!("{}/.default", self.config.audience.trim_end_matches('/'))
    }

    fn current_sync_token(&self) -> Option<String> {
        let tokens = self.sync_tokens.lock().unwrap();
        (!tokens.is_empty()).then(|| {
            tokens
                .values()
                .map(|token| token.value.as_str())
                .collect::<Vec<_>>()
                .join(",")
        })
    }

    fn merge_sync_tokens(&self, headers: &HeaderMap) {
        let name = HeaderName::from_static("sync-token");
        let mut tokens = self.sync_tokens.lock().unwrap();
        for value in headers.get_all(name) {
            let Ok(value) = value.to_str() else {
                continue;
            };
            for raw in value
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
            {
                let Some((id, _)) = raw.split_once('=') else {
                    continue;
                };
                let sequence = raw
                    .split(';')
                    .find_map(|part| part.strip_prefix("sn="))
                    .and_then(|value| value.parse::<u64>().ok());
                let replace =
                    tokens
                        .get(id)
                        .is_none_or(|current| match (sequence, current.sequence) {
                            (Some(next), Some(existing)) => next >= existing,
                            (Some(_), None) => true,
                            (None, Some(_)) => false,
                            (None, None) => true,
                        });
                if replace {
                    tokens.insert(
                        id.to_string(),
                        SyncToken {
                            sequence,
                            value: raw.to_string(),
                        },
                    );
                }
            }
        }
    }

    async fn send(
        &self,
        method: Method,
        url: Url,
        body: Option<Vec<u8>>,
        conditional: Option<(HeaderName, &str)>,
    ) -> Result<reqwest::Response> {
        if url.scheme() != "https" || url.origin() != self.endpoint_url()?.origin() {
            return Err(operation_error(
                "refusing Azure App Configuration request outside configured HTTPS endpoint"
                    .to_string(),
            ));
        }
        let body = body.unwrap_or_default();
        let mut request = self.http()?.request(method.clone(), url.clone());
        if !body.is_empty() {
            request = request
                .header(CONTENT_TYPE, "application/vnd.microsoft.appconfig.kv+json")
                .body(body.clone());
        }
        if let Some((name, value)) = conditional {
            request = request.header(name, value);
        }
        if let Some(sync_token) = self.current_sync_token() {
            request = request.header("sync-token", sync_token);
        }

        request = match self.auth()? {
            ResolvedAuth::Entra(credential) => {
                let scope = self.token_scope();
                let token = credential
                    .get_token(&[scope.as_str()], None)
                    .await
                    .map_err(|error| {
                        operation_error(format!(
                            "failed to acquire Azure App Configuration token: {}",
                            crate::error::display_error_chain(&error)
                        ))
                    })?;
                request.bearer_auth(token.token.secret())
            }
            ResolvedAuth::ConnectionString(auth) => {
                let date =
                    azure_core::time::to_rfc7231(&azure_core::time::OffsetDateTime::now_utc());
                let content_hash = azure_core::base64::encode(sha256(&body));
                let path_and_query = match url.query() {
                    Some(query) => format!("{}?{query}", url.path()),
                    None => url.path().to_string(),
                };
                let host = url.host_str().expect("validated endpoint has a host");
                let string_to_sign = format!(
                    "{}\n{}\n{};{};{}",
                    method.as_str(),
                    path_and_query,
                    date,
                    host,
                    content_hash
                );
                let signature = azure_core::hmac::hmac_sha256(&string_to_sign, &auth.secret)
                    .map_err(|error| {
                        operation_error(format!(
                            "failed to sign Azure App Configuration request: {}",
                            crate::error::display_error_chain(&error)
                        ))
                    })?;
                request
                    .header("x-ms-date", date)
                    .header("x-ms-content-sha256", content_hash)
                    .header(
                        AUTHORIZATION,
                        format!(
                            "HMAC-SHA256 Credential={}&SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature={signature}",
                            auth.id
                        ),
                    )
            }
        };

        let response = request.send().await.map_err(|error| {
            operation_error(format!(
                "Azure App Configuration request failed for {}: {error}",
                safe_request_target(&url)
            ))
        })?;
        self.merge_sync_tokens(response.headers());
        Ok(response)
    }

    fn endpoint_url(&self) -> Result<Url> {
        Url::parse(&self.config.endpoint).map_err(|error| {
            operation_error(format!(
                "invalid configured Azure App Configuration endpoint: {error}"
            ))
        })
    }
}

fn parse_connection_string(value: &str, configured_endpoint: &str) -> Result<ConnectionStringAuth> {
    let mut parts = BTreeMap::new();
    for part in value.split(';').filter(|part| !part.is_empty()) {
        let (name, value) = part.split_once('=').ok_or_else(|| {
            operation_error("invalid Azure App Configuration connection string".to_string())
        })?;
        if !matches!(name, "Endpoint" | "Id" | "Secret")
            || value.is_empty()
            || parts.insert(name, value).is_some()
        {
            return Err(operation_error(
                "invalid Azure App Configuration connection string".to_string(),
            ));
        }
    }
    let endpoint = parts.get("Endpoint").ok_or_else(|| {
        operation_error("Azure App Configuration connection string is missing Endpoint".to_string())
    })?;
    let endpoint = Url::parse(endpoint).map_err(|_| {
        operation_error(
            "Azure App Configuration connection string has an invalid Endpoint".to_string(),
        )
    })?;
    if endpoint.scheme() != "https"
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.port().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path() != "/"
        || endpoint.as_str() != configured_endpoint
    {
        return Err(operation_error(
            "Azure App Configuration connection string Endpoint does not match the provider endpoint"
                .to_string(),
        ));
    }
    let id = parts
        .get("Id")
        .ok_or_else(|| {
            operation_error("Azure App Configuration connection string is missing Id".to_string())
        })?
        .to_string();
    let secret = parts.get("Secret").ok_or_else(|| {
        operation_error("Azure App Configuration connection string is missing Secret".to_string())
    })?;
    Ok(ConnectionStringAuth {
        id,
        secret: AzureSecret::new(secret.to_string()),
    })
}

fn safe_request_target(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    }
}

// SHA-256 is needed for Azure's HMAC content header. Azure Core exposes HMAC
// signing but not its underlying digest, so this small fixed implementation
// keeps connection-string support dependency-neutral.
fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let padded_len = (input.len() + 9).div_ceil(64) * 64;
    let mut message = Vec::with_capacity(padded_len);
    message.extend_from_slice(input);
    message.push(0x80);
    message.resize(padded_len - 8, 0);
    message.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = INITIAL;
    for chunk in message.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (word, bytes) in words.iter_mut().zip(chunk.chunks_exact(4)) {
            *word = u32::from_be_bytes(bytes.try_into().expect("four-byte SHA-256 word"));
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }

    let mut digest = [0_u8; 32];
    for (bytes, value) in digest.chunks_exact_mut(4).zip(state) {
        bytes.copy_from_slice(&value.to_be_bytes());
    }
    digest
}

#[derive(Debug, Clone, Deserialize)]
struct KeyValue {
    etag: Option<String>,
    key: String,
    label: Option<String>,
    content_type: Option<String>,
    value: Option<String>,
    #[serde(default)]
    tags: BTreeMap<String, Option<String>>,
    description: Option<String>,
    #[serde(default)]
    locked: bool,
}

#[derive(Serialize)]
struct KeyValueWrite<'a> {
    value: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<&'a str>,
    tags: &'a BTreeMap<String, Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct AzureProblem {
    title: Option<String>,
    name: Option<String>,
    detail: Option<String>,
}

#[derive(Debug, Deserialize)]
struct KeyValueList {
    #[serde(default)]
    items: Vec<KeyValue>,
    #[serde(rename = "@nextLink")]
    next_link: Option<String>,
}

enum ValueType {
    Direct,
    KeyVaultReference,
    AzureSpecial(String),
}

enum SelectedValue {
    Direct(SecretString),
    Reference(VaultReference),
}

impl AzAppConfigProvider {
    fn convention_key(&self, project: &str, profile: &str, key: &str) -> Result<String> {
        validate_name_component("project", project)?;
        validate_name_component("profile", profile)?;
        validate_name_component("key", key)?;
        let native = format!(
            "{}secretspec:{project}:{profile}:{key}",
            self.config.prefix.as_deref().unwrap_or_default()
        );
        validate_appconfig_key(&native, "convention key")?;
        Ok(native)
    }

    fn resolve_key(&self, addr: Address<'_>) -> Result<String> {
        let coordinates = self.resolve_coords(addr)?;
        validate_appconfig_key(&coordinates.item, "App Configuration key")?;
        Ok(coordinates.item.clone())
    }

    fn item_url(&self, key: &str, include_tags: bool) -> Result<Url> {
        let mut url = self.endpoint_url()?;
        url.path_segments_mut()
            .map_err(|_| operation_error("invalid App Configuration endpoint".to_string()))?
            .extend(["kv", key]);
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("api-version", API_VERSION);
            query.append_pair("label", self.config.label.as_deref().unwrap_or("\0"));
            if include_tags {
                for (name, value) in &self.config.tags {
                    query.append_pair(
                        "tags",
                        &format!("{}={}", escape_filter(name), escape_filter(value)),
                    );
                }
            }
        }
        Ok(url)
    }

    fn list_url(&self, context: DiscoveryContext<'_>) -> Result<Url> {
        let base = format!(
            "{}secretspec:{}:{}:",
            self.config.prefix.as_deref().unwrap_or_default(),
            context.project,
            context.profile
        );
        validate_name_component("project", context.project)?;
        validate_name_component("profile", context.profile)?;
        validate_appconfig_key(&base, "discovery prefix")?;

        let mut url = self.endpoint_url()?;
        url.path_segments_mut()
            .map_err(|_| operation_error("invalid App Configuration endpoint".to_string()))?
            .push("kv");
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("api-version", API_VERSION);
            query.append_pair("key", &format!("{}*", escape_filter(&base)));
            query.append_pair("label", self.config.label.as_deref().unwrap_or("\0"));
            for (name, value) in &self.config.tags {
                query.append_pair(
                    "tags",
                    &format!("{}={}", escape_filter(name), escape_filter(value)),
                );
            }
            query.append_pair("$select", "key,label,content_type");
        }
        Ok(url)
    }

    async fn response_error(&self, action: &str, response: reqwest::Response) -> SecretSpecError {
        let status = response.status();
        let bytes = response.bytes().await.unwrap_or_default();
        let bytes = &bytes[..bytes.len().min(MAX_ERROR_BODY)];
        let detail = serde_json::from_slice::<AzureProblem>(bytes)
            .ok()
            .and_then(|problem| {
                [problem.title, problem.name, problem.detail]
                    .into_iter()
                    .flatten()
                    .find(|value| !value.is_empty())
            });
        let detail = detail.map_or_else(String::new, |detail| format!(": {detail}"));
        operation_error(format!(
            "Azure App Configuration {action} failed with HTTP {}{detail}",
            status.as_u16()
        ))
    }

    async fn parse_key_value(&self, action: &str, response: reqwest::Response) -> Result<KeyValue> {
        let bytes = response.bytes().await.map_err(|error| {
            operation_error(format!(
                "failed to read Azure App Configuration {action} response: {error}"
            ))
        })?;
        serde_json::from_slice(&bytes).map_err(|error| {
            operation_error(format!(
                "Azure App Configuration {action} returned invalid key-value JSON: {error}"
            ))
        })
    }

    async fn fetch_key_value(&self, key: &str, include_tags: bool) -> Result<Option<KeyValue>> {
        let response = self
            .send(Method::GET, self.item_url(key, include_tags)?, None, None)
            .await?;
        match response.status() {
            StatusCode::OK => {
                let record = self.parse_key_value("read", response).await?;
                self.validate_selected_record(key, &record)?;
                Ok(Some(record))
            }
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(self.response_error("read", response).await),
        }
    }

    fn validate_selected_record(&self, key: &str, record: &KeyValue) -> Result<()> {
        if record.key != key || record.label.as_deref() != self.config.label.as_deref() {
            return Err(operation_error(format!(
                "Azure App Configuration returned a different key or label while reading '{key}'"
            )));
        }
        Ok(())
    }

    fn matches_tags(&self, record: &KeyValue) -> bool {
        self.config.tags.iter().all(|(name, value)| {
            record.tags.get(name).and_then(Option::as_deref) == Some(value.as_str())
        })
    }

    fn value_type(content_type: Option<&str>) -> ValueType {
        let Some(content_type) = content_type
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return ValueType::Direct;
        };
        let mut parts = content_type.split(';');
        let base = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
        if base == KEY_VAULT_REFERENCE_TYPE {
            let utf8 = parts.any(|parameter| {
                parameter.split_once('=').is_some_and(|(name, value)| {
                    name.trim().eq_ignore_ascii_case("charset")
                        && value.trim().trim_matches('"').eq_ignore_ascii_case("utf-8")
                })
            });
            return if utf8 {
                ValueType::KeyVaultReference
            } else {
                ValueType::AzureSpecial(content_type.to_string())
            };
        }
        if base.starts_with(AZURE_SPECIAL_PREFIX) {
            ValueType::AzureSpecial(content_type.to_string())
        } else {
            ValueType::Direct
        }
    }

    fn select_record(&self, key: &str, record: KeyValue) -> Result<SelectedValue> {
        match Self::value_type(record.content_type.as_deref()) {
            ValueType::Direct => record
                .value
                .map(|value| SelectedValue::Direct(SecretString::new(value.into())))
                .ok_or_else(|| {
                    operation_error(format!(
                        "Azure App Configuration key '{key}' has no direct value"
                    ))
                }),
            ValueType::KeyVaultReference => {
                let value = record.value.ok_or_else(|| {
                    operation_error(format!(
                        "Azure App Configuration Key Vault reference '{key}' has no value"
                    ))
                })?;
                parse_vault_reference(&value, &self.config.key_vault_suffix)
                    .map(SelectedValue::Reference)
            }
            ValueType::AzureSpecial(content_type) => Err(operation_error(format!(
                "Azure App Configuration key '{key}' uses unsupported special content type '{content_type}'"
            ))),
        }
    }

    async fn selected_value_async(&self, addr: Address<'_>) -> Result<Option<SelectedValue>> {
        let key = self.resolve_key(addr)?;
        let Some(record) = self.fetch_key_value(&key, true).await? else {
            return Ok(None);
        };
        self.select_record(&key, record).map(Some)
    }

    async fn mutation_record(&self, key: &str) -> Result<Option<KeyValue>> {
        let Some(record) = self.fetch_key_value(key, false).await? else {
            return Ok(None);
        };
        if !self.matches_tags(&record) {
            return Err(operation_error(format!(
                "refusing to mutate Azure App Configuration key '{key}': existing entry does not match configured tag selectors"
            )));
        }
        if record.locked {
            return Err(operation_error(format!(
                "refusing to mutate locked Azure App Configuration key '{key}'"
            )));
        }
        match Self::value_type(record.content_type.as_deref()) {
            ValueType::Direct => {}
            ValueType::KeyVaultReference => {
                return Err(operation_error(format!(
                    "refusing to mutate Azure App Configuration key '{key}' with special content type '{KEY_VAULT_REFERENCE_TYPE}'"
                )));
            }
            ValueType::AzureSpecial(content_type) => {
                return Err(operation_error(format!(
                    "refusing to mutate Azure App Configuration key '{key}' with special content type '{content_type}'"
                )));
            }
        }
        if record.etag.as_deref().is_none_or(str::is_empty) {
            return Err(operation_error(format!(
                "Azure App Configuration key '{key}' did not include an ETag"
            )));
        }
        Ok(Some(record))
    }

    async fn set_async(&self, key: &str, value: &SecretString) -> Result<()> {
        let existing = self.mutation_record(key).await?;
        let created_tags;
        let (tags, content_type, description, conditional) = match &existing {
            Some(record) => (
                &record.tags,
                record.content_type.as_deref(),
                record.description.as_deref(),
                (IF_MATCH, record.etag.as_deref().expect("validated ETag")),
            ),
            None => {
                created_tags = self
                    .config
                    .tags
                    .iter()
                    .map(|(name, value)| (name.clone(), Some(value.clone())))
                    .collect::<BTreeMap<_, _>>();
                (&created_tags, None, None, (IF_NONE_MATCH, "*"))
            }
        };
        let body = serde_json::to_vec(&KeyValueWrite {
            value: value.expose_secret(),
            content_type,
            tags,
            description,
        })
        .map_err(|error| {
            operation_error(format!("failed to encode App Configuration write: {error}"))
        })?;
        let response = self
            .send(
                Method::PUT,
                self.item_url(key, false)?,
                Some(body),
                Some((conditional.0, conditional.1)),
            )
            .await?;
        match response.status() {
            StatusCode::OK => Ok(()),
            StatusCode::PRECONDITION_FAILED => Err(operation_error(format!(
                "Azure App Configuration key '{key}' changed concurrently; retry the write"
            ))),
            _ => Err(self.response_error("write", response).await),
        }
    }

    async fn delete_async(&self, key: &str) -> Result<bool> {
        let Some(record) = self.mutation_record(key).await? else {
            return Ok(false);
        };
        let response = self
            .send(
                Method::DELETE,
                self.item_url(key, false)?,
                None,
                Some((IF_MATCH, record.etag.as_deref().expect("validated ETag"))),
            )
            .await?;
        match response.status() {
            StatusCode::OK => Ok(true),
            StatusCode::NO_CONTENT | StatusCode::NOT_FOUND => Ok(false),
            StatusCode::PRECONDITION_FAILED => Err(operation_error(format!(
                "Azure App Configuration key '{key}' changed concurrently; retry the delete"
            ))),
            _ => Err(self.response_error("delete", response).await),
        }
    }
}

fn escape_filter(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '*' | ',' | '\\') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VaultReference {
    canonical_uri: String,
    vault_host: String,
    secret_name: String,
    version: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultReferenceDocument {
    uri: String,
}

fn parse_vault_reference(value: &str, allowed_suffix: &str) -> Result<VaultReference> {
    let document: VaultReferenceDocument = serde_json::from_str(value).map_err(|_| {
        operation_error(
            "Azure App Configuration contains a malformed Key Vault reference".to_string(),
        )
    })?;
    if document.uri.is_empty() {
        return Err(operation_error(
            "Azure App Configuration Key Vault reference URI cannot be empty".to_string(),
        ));
    }
    let authority = document
        .uri
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .ok_or_else(|| operation_error("Azure Key Vault reference must use HTTPS".to_string()))?;
    if authority.contains(':') {
        return Err(operation_error(
            "Azure Key Vault reference cannot contain an explicit port".to_string(),
        ));
    }

    let parsed = Url::parse(&document.uri).map_err(|_| {
        operation_error(
            "Azure App Configuration contains an invalid Key Vault reference URI".to_string(),
        )
    })?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(operation_error(
            "Azure Key Vault reference must be HTTPS without credentials, port, query, or fragment"
                .to_string(),
        ));
    }
    let vault_host = parsed
        .host_str()
        .ok_or_else(|| operation_error("Azure Key Vault reference has no host".to_string()))?
        .to_ascii_lowercase();
    let prefix = vault_host
        .strip_suffix(allowed_suffix)
        .and_then(|prefix| prefix.strip_suffix('.'))
        .filter(|prefix| !prefix.is_empty() && !prefix.contains('.'))
        .ok_or_else(|| {
            operation_error(format!(
                "Azure Key Vault reference host must be a direct subdomain of {allowed_suffix}"
            ))
        })?;
    if !prefix
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        return Err(operation_error(
            "Azure Key Vault reference has an invalid vault host".to_string(),
        ));
    }

    let encoded_segments = parsed
        .path_segments()
        .ok_or_else(|| operation_error("Azure Key Vault reference has no path".to_string()))?
        .collect::<Vec<_>>();
    if !matches!(encoded_segments.len(), 2 | 3) || encoded_segments.first() != Some(&"secrets") {
        return Err(operation_error(
            "Azure Key Vault reference path must be /secrets/{name} or /secrets/{name}/{version}"
                .to_string(),
        ));
    }
    let decode = |segment: &str, part: &str| -> Result<String> {
        let decoded = percent_encoding::percent_decode_str(segment)
            .decode_utf8()
            .map_err(|_| operation_error(format!("Azure Key Vault reference has invalid {part}")))?
            .into_owned();
        if decoded.is_empty()
            || decoded.contains('/')
            || decoded == "."
            || decoded == ".."
            || decoded.contains('%')
        {
            return Err(operation_error(format!(
                "Azure Key Vault reference has invalid {part}"
            )));
        }
        Ok(decoded)
    };
    let secret_name = decode(encoded_segments[1], "secret name")?;
    if secret_name.len() > 127
        || !secret_name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        return Err(operation_error(
            "Azure Key Vault reference has an invalid secret name".to_string(),
        ));
    }
    let version = encoded_segments
        .get(2)
        .map(|segment| decode(segment, "secret version"))
        .transpose()?;
    if let Some(version) = &version
        && (version.len() != 32
            || !version
                .chars()
                .all(|character| character.is_ascii_alphanumeric()))
    {
        return Err(operation_error(
            "Azure Key Vault reference version must be a 32-character ASCII identifier".to_string(),
        ));
    }
    let mut canonical =
        Url::parse(&format!("https://{vault_host}/")).expect("validated vault host forms a URL");
    canonical
        .path_segments_mut()
        .expect("HTTPS URL supports path segments")
        .extend(
            std::iter::once("secrets")
                .chain(std::iter::once(secret_name.as_str()))
                .chain(version.as_deref()),
        );
    Ok(VaultReference {
        canonical_uri: canonical.to_string(),
        vault_host,
        secret_name,
        version,
    })
}

impl AzAppConfigProvider {
    fn key_vault_credential(&self) -> Result<Arc<dyn TokenCredential>> {
        if let Some(credential) = self.key_vault_credential.get() {
            return Ok(Arc::clone(credential));
        }
        let credential = match self.config.key_vault_auth {
            Some(KeyVaultAuth::Entra(auth)) => {
                super::akv::resolve_azure_credential(auth, &self.credentials)?
            }
            Some(KeyVaultAuth::Inherit) | None => match self.auth()? {
                ResolvedAuth::Entra(credential) => Arc::clone(credential),
                ResolvedAuth::ConnectionString(_) => {
                    return Err(operation_error(
                        "Azure Key Vault references require key_vault_auth=env, cli, managed_identity, or workload_identity when App Configuration uses a connection string"
                            .to_string(),
                    ));
                }
            },
        };
        Ok(Arc::clone(
            self.key_vault_credential.get_or_init(|| credential),
        ))
    }

    fn vault_provider(&self, reference: &VaultReference) -> Result<Arc<super::akv::AkvProvider>> {
        let mut vaults = self.vaults.lock().unwrap();
        if let Some(provider) = vaults.get(&reference.vault_host) {
            return Ok(Arc::clone(provider));
        }
        if vaults.len() >= MAX_VAULT_CLIENTS {
            return Err(operation_error(format!(
                "one azappconfig provider can resolve at most {MAX_VAULT_CLIENTS} Key Vault hosts; split this workload across provider aliases"
            )));
        }
        let credential = self.key_vault_credential()?;
        let config = super::akv::AkvConfig::from_validated_vault_host(
            reference.vault_host.clone(),
            super::akv::AuthMethod::Env,
        );
        let provider = Arc::new(super::akv::AkvProvider::with_token_credential(
            config, credential,
        ));
        vaults.insert(reference.vault_host.clone(), Arc::clone(&provider));
        Ok(provider)
    }

    fn resolve_vault_reference(&self, reference: &VaultReference) -> Result<SecretString> {
        let provider = self.vault_provider(reference)?;
        let address = NativeAddress {
            item: reference.secret_name.clone(),
            version: reference.version.clone(),
            ..Default::default()
        };
        provider.get(Address::Native(&address))?.ok_or_else(|| {
            operation_error(format!(
                "Azure App Configuration contains a dangling Key Vault reference to host '{}'",
                reference.vault_host
            ))
        })
    }

    fn get_selected(&self, addr: Address<'_>) -> Result<Option<SelectedValue>> {
        self.initial_request
            .run(|| super::block_on(self.selected_value_async(addr)))
    }

    fn get_many_selected(
        &self,
        requests: &[(&str, Address<'_>)],
    ) -> Result<HashMap<String, SecretString>> {
        let mut groups: HashMap<Address<'_>, Vec<&str>> = HashMap::new();
        for (name, address) in requests {
            groups.entry(*address).or_default().push(name);
        }
        let groups = groups.into_iter().collect::<Vec<_>>();
        let selected = map_concurrently(&groups, get_each_concurrency(), |(address, names)| {
            (names.clone(), self.get_selected(*address))
        });

        let mut values = HashMap::new();
        let mut references: HashMap<VaultReference, Vec<&str>> = HashMap::new();
        for (names, result) in selected {
            match result? {
                Some(SelectedValue::Direct(value)) => {
                    for name in names {
                        values.insert(name.to_string(), value.clone());
                    }
                }
                Some(SelectedValue::Reference(reference)) => {
                    references.entry(reference).or_default().extend(names);
                }
                None => {}
            }
        }

        let references = references.into_iter().collect::<Vec<_>>();
        let resolved =
            map_concurrently(&references, get_each_concurrency(), |(reference, names)| {
                let result = self.resolve_vault_reference(reference).map_err(|error| {
                    operation_error(format!(
                        "failed to resolve Azure Key Vault reference for {}: {error}",
                        names.join(", ")
                    ))
                });
                (names.clone(), result)
            });
        for (names, result) in resolved {
            let value = result?;
            for name in names {
                values.insert(name.to_string(), value.clone());
            }
        }
        Ok(values)
    }

    fn validate_continuation(&self, initial: &Url, next_link: &str) -> Result<Url> {
        let next = initial.join(next_link).map_err(|_| {
            operation_error(
                "Azure App Configuration returned an invalid continuation link".to_string(),
            )
        })?;
        if next.scheme() != "https"
            || next.origin() != initial.origin()
            || next.path() != initial.path()
            || next.fragment().is_some()
        {
            return Err(operation_error(
                "Azure App Configuration continuation changed endpoint or operation".to_string(),
            ));
        }
        let scope = |url: &Url| {
            let mut pairs = url
                .query_pairs()
                .filter(|(name, _)| !name.eq_ignore_ascii_case("after"))
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect::<Vec<_>>();
            pairs.sort();
            pairs
        };
        if scope(&next) != scope(initial) {
            return Err(operation_error(
                "Azure App Configuration continuation broadened discovery filters".to_string(),
            ));
        }
        Ok(next)
    }

    fn declaration_from_record(
        &self,
        context: DiscoveryContext<'_>,
        record: KeyValue,
    ) -> Result<Option<(String, crate::Secret)>> {
        if record.label.as_deref() != self.config.label.as_deref() {
            return Err(operation_error(format!(
                "Azure App Configuration discovery returned key '{}' from a different label",
                record.key
            )));
        }
        let marker = format!(
            "{}secretspec:",
            self.config.prefix.as_deref().unwrap_or_default()
        );
        let Some(rest) = record.key.strip_prefix(&marker) else {
            return Ok(None);
        };
        let parts = rest.split(':').collect::<Vec<_>>();
        if parts.len() != 3 || parts[0] != context.project || parts[1] != context.profile {
            return Ok(None);
        }
        let key = parts[2];
        if !crate::config::is_valid_identifier(key) {
            return Err(operation_error(format!(
                "Azure App Configuration key '{}' maps to invalid SecretSpec name '{key}'",
                record.key
            )));
        }
        match Self::value_type(record.content_type.as_deref()) {
            ValueType::Direct | ValueType::KeyVaultReference => {}
            ValueType::AzureSpecial(content_type) => {
                return Err(operation_error(format!(
                    "Azure App Configuration key '{}' uses unsupported special content type '{content_type}'",
                    record.key
                )));
            }
        }
        Ok(Some((
            key.to_string(),
            crate::Secret {
                description: Some(format!("{key} secret")),
                required: Some(true),
                ..Default::default()
            },
        )))
    }

    async fn reflect_async(
        &self,
        context: DiscoveryContext<'_>,
    ) -> Result<HashMap<String, crate::Secret>> {
        let initial = self.list_url(context)?;
        let mut next = Some(initial.clone());
        let mut visited = HashSet::new();
        let mut declarations = HashMap::new();
        while let Some(url) = next.take() {
            if !visited.insert(url.to_string()) {
                return Err(operation_error(
                    "Azure App Configuration returned a cyclic continuation link".to_string(),
                ));
            }
            let response = self.send(Method::GET, url, None, None).await?;
            if response.status() != StatusCode::OK {
                return Err(self.response_error("discovery", response).await);
            }
            let bytes = response.bytes().await.map_err(|error| {
                operation_error(format!(
                    "failed to read Azure App Configuration discovery response: {error}"
                ))
            })?;
            let page: KeyValueList = serde_json::from_slice(&bytes).map_err(|error| {
                operation_error(format!(
                    "Azure App Configuration discovery returned invalid JSON: {error}"
                ))
            })?;
            for record in page.items {
                if let Some((name, declaration)) = self.declaration_from_record(context, record)?
                    && declarations.insert(name.clone(), declaration).is_some()
                {
                    return Err(operation_error(format!(
                        "Azure App Configuration discovery mapped more than one entry to '{name}'"
                    )));
                }
            }
            next = page
                .next_link
                .as_deref()
                .map(|link| self.validate_continuation(&initial, link))
                .transpose()?;
        }
        Ok(declarations)
    }
}

impl Provider for AzAppConfigProvider {
    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
        Ok(NativeAddress {
            item: self.convention_key(project, profile, key)?,
            ..Default::default()
        })
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        match self.get_selected(addr)? {
            Some(SelectedValue::Direct(value)) => Ok(Some(value)),
            Some(SelectedValue::Reference(reference)) => {
                self.resolve_vault_reference(&reference).map(Some)
            }
            None => Ok(None),
        }
    }

    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        self.get_many_selected(requests)
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        if matches!(addr, Address::Native(_)) {
            return self.check_writable(addr);
        }
        let key = self.resolve_key(addr)?;
        self.initial_request
            .run(|| super::block_on(self.set_async(&key, value)))
    }

    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        self.resolve_coords(addr)?;
        if matches!(addr, Address::Native(_)) {
            return Err(operation_error(
                "azappconfig native references are read-only and cannot be written".to_string(),
            ));
        }
        let key = self.resolve_key(addr)?;
        self.initial_request
            .run(|| super::block_on(self.mutation_record(&key)).map(|_| ()))
    }

    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        if matches!(addr, Address::Native(_)) {
            self.check_deletable(addr)?;
            unreachable!("native deletion check always fails");
        }
        let key = self.resolve_key(addr)?;
        self.initial_request
            .run(|| super::block_on(self.delete_async(&key)))
    }

    fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
        self.resolve_coords(addr)?;
        if matches!(addr, Address::Native(_)) {
            return Err(operation_error(
                "azappconfig native references are read-only and cannot be deleted".to_string(),
            ));
        }
        let key = self.resolve_key(addr)?;
        self.initial_request
            .run(|| super::block_on(self.mutation_record(&key)).map(|_| ()))
    }

    fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
        let key = self.resolve_key(addr)?;
        let label = self.config.label.as_deref().unwrap_or("<no label>");
        Ok(format!(
            "Azure App Configuration key '{key}' with label '{label}' at {}",
            self.config.endpoint
        ))
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let mut parameters = Vec::new();
        if self.config.auth != AppConfigAuth::default() {
            parameters.push(format!("auth={}", self.config.auth.as_str()));
        }
        if let Some(suffix) = &self.config.suffix {
            parameters.push(format!("suffix={}", ProviderUrl::encode_query(suffix)));
        }
        if self.config.audience_explicit {
            parameters.push(format!(
                "audience={}",
                ProviderUrl::encode_query(&self.config.audience)
            ));
        }
        if let Some(auth) = self.config.key_vault_auth {
            parameters.push(format!("key_vault_auth={}", auth.as_str()));
        }
        if self.config.key_vault_suffix_explicit {
            parameters.push(format!(
                "key_vault_suffix={}",
                ProviderUrl::encode_query(&self.config.key_vault_suffix)
            ));
        }
        if let Some(label) = &self.config.label {
            parameters.push(format!("label={}", ProviderUrl::encode_query(label)));
        }
        if let Some(prefix) = &self.config.prefix {
            parameters.push(format!("prefix={}", ProviderUrl::encode_query(prefix)));
        }
        for (name, value) in &self.config.tags {
            parameters.push(format!(
                "tag={}",
                ProviderUrl::encode_query(&format!("{name}={value}"))
            ));
        }
        let base = format!("azappconfig://{}", self.config.store_host);
        if parameters.is_empty() {
            base
        } else {
            format!("{base}?{}", parameters.join("&"))
        }
    }

    fn storage_identity(&self) -> String {
        format!(
            "{}|label={:?}|prefix={:?}",
            self.config.endpoint, self.config.label, self.config.prefix
        )
    }

    fn entry_container_identity(&self) -> String {
        format!("{}|label={:?}", self.config.endpoint, self.config.label)
    }

    fn reflect(&self, context: DiscoveryContext<'_>) -> Result<HashMap<String, crate::Secret>> {
        self.initial_request
            .run(|| super::block_on(self.reflect_async(context)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    fn config(uri: &str) -> AzAppConfigConfig {
        AzAppConfigConfig::try_from(&ProviderUrl::new(Url::parse(uri).unwrap())).unwrap()
    }

    fn provider(uri: &str) -> AzAppConfigProvider {
        AzAppConfigProvider::new(config(uri))
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn default_store_uses_public_endpoint_and_current_audience() {
        let config = config("azappconfig://payments");
        assert_eq!(config.endpoint, "https://payments.azconfig.io/");
        assert_eq!(config.audience, "https://appconfig.azure.com");
        assert_eq!(config.label, None);
        assert_eq!(config.tags, Vec::<(String, String)>::new());
    }

    #[test]
    fn sovereign_host_requires_and_round_trips_audience() {
        let error = AzAppConfigConfig::try_from(&ProviderUrl::new(
            Url::parse("azappconfig://payments.azconfig.azure.cn").unwrap(),
        ))
        .unwrap_err();
        assert!(
            error.to_string().contains("set audience explicitly"),
            "{error}"
        );

        let provider = provider(
            "azappconfig://payments.azconfig.azure.cn?audience=https%3A%2F%2Fappconfig.azure.cn",
        );
        assert_eq!(
            provider.uri(),
            "azappconfig://payments.azconfig.azure.cn?audience=https://appconfig.azure.cn"
        );
        assert_eq!(config(&provider.uri()).endpoint, provider.config.endpoint);
    }

    #[test]
    fn bare_store_supports_explicit_suffix() {
        let provider = provider(
            "azappconfig://payments?suffix=azconfig.azure.us&audience=https%3A%2F%2Fappconfig.azure.us",
        );
        assert_eq!(
            provider.config.endpoint,
            "https://payments.azconfig.azure.us/"
        );
        assert_eq!(
            provider.uri(),
            "azappconfig://payments?suffix=azconfig.azure.us&audience=https://appconfig.azure.us"
        );
    }

    #[test]
    fn uri_rejects_paths_unknowns_duplicates_and_conflicts() {
        for uri in [
            "azappconfig://store/existing",
            "azappconfig://store?unknown=value",
            "azappconfig://store?label=prod&label=stage",
            "azappconfig://store?label=",
            "azappconfig://store.example?suffix=azconfig.io&audience=https%3A%2F%2Fappconfig.example",
            "azappconfig://store?auth=connection_string&key_vault_auth=inherit",
        ] {
            let error = AzAppConfigConfig::try_from(&ProviderUrl::new(Url::parse(uri).unwrap()));
            assert!(error.is_err(), "expected invalid URI: {uri}");
        }
    }

    #[test]
    fn tags_are_exact_unique_bounded_and_stably_ordered() {
        let provider =
            provider("azappconfig://shared?tag=stage=prod&tag=app=payments&label=production");
        assert_eq!(
            provider.config.tags,
            vec![
                ("app".to_string(), "payments".to_string()),
                ("stage".to_string(), "prod".to_string())
            ]
        );
        assert_eq!(
            provider.uri(),
            "azappconfig://shared?label=production&tag=app=payments&tag=stage=prod"
        );

        for uri in [
            "azappconfig://shared?tag=app",
            "azappconfig://shared?tag==prod",
            "azappconfig://shared?tag=app=",
            "azappconfig://shared?tag=app=one&tag=app=two",
            "azappconfig://shared?tag=a=1&tag=b=2&tag=c=3&tag=d=4&tag=e=5&tag=f=6",
        ] {
            assert!(
                AzAppConfigConfig::try_from(&ProviderUrl::new(Url::parse(uri).unwrap())).is_err(),
                "expected invalid tags: {uri}"
            );
        }
    }

    #[test]
    fn filter_values_escape_azure_metacharacters_before_url_encoding() {
        assert_eq!(escape_filter(r"a*b,c\d"), r"a\*b\,c\\d");
        let provider = provider("azappconfig://shared?tag=group=a*b%2Cc%5Cd");
        let url = provider.item_url("key", true).unwrap();
        assert_eq!(
            url.query_pairs()
                .find(|(name, _)| name == "tags")
                .map(|(_, value)| value.into_owned()),
            Some(r"group=a\*b\,c\\d".to_string())
        );
    }

    #[test]
    fn convention_key_is_readable_reversible_and_exactly_prefixed() {
        let provider = provider("azappconfig://shared?prefix=payments%3Aorders%3A");
        let address = provider
            .convention_address("checkout", "production", "DATABASE_URL")
            .unwrap();
        assert_eq!(
            address.item,
            "payments:orders:secretspec:checkout:production:DATABASE_URL"
        );
        let components = address
            .item
            .strip_prefix("payments:orders:secretspec:")
            .unwrap()
            .split(':')
            .collect::<Vec<_>>();
        assert_eq!(components, ["checkout", "production", "DATABASE_URL"]);
    }

    #[test]
    fn convention_rejects_invalid_components_and_azure_keys() {
        let provider = provider("azappconfig://shared");
        for (project, profile, key) in [
            ("", "prod", "KEY"),
            ("app", "", "KEY"),
            ("app", "prod", ""),
            ("my app", "prod", "KEY"),
            ("app", "prod", "KEY.PART"),
        ] {
            assert!(provider.convention_key(project, profile, key).is_err());
        }
        assert!(
            AzAppConfigConfig::try_from(&ProviderUrl::new(
                Url::parse("azappconfig://shared?prefix=%25").unwrap()
            ))
            .is_err()
        );
    }

    #[test]
    fn identity_includes_label_and_prefix_but_not_tags_or_auth() {
        let base = provider("azappconfig://shared");
        let cli = provider("azappconfig://shared?auth=cli");
        let tagged = provider("azappconfig://shared?tag=app=payments");
        let labeled = provider("azappconfig://shared?label=production");
        let prefixed = provider("azappconfig://shared?prefix=payments%3A");
        assert_eq!(base.storage_identity(), cli.storage_identity());
        assert_eq!(base.storage_identity(), tagged.storage_identity());
        assert_ne!(base.storage_identity(), labeled.storage_identity());
        assert_ne!(base.storage_identity(), prefixed.storage_identity());
        assert_eq!(
            base.entry_container_identity(),
            prefixed.entry_container_identity()
        );
        assert_ne!(
            base.entry_container_identity(),
            labeled.entry_container_identity()
        );
    }

    #[test]
    fn item_urls_select_null_or_exact_label_and_tags() {
        let null = provider("azappconfig://shared");
        let null_url = null.item_url("secretspec:app:prod:KEY", true).unwrap();
        assert!(null_url.as_str().contains("label=%00"), "{null_url}");

        let selected =
            provider("azappconfig://shared?label=production&tag=app=payments&tag=stage=prod");
        let pairs = selected
            .item_url("key", true)
            .unwrap()
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();
        assert!(pairs.contains(&("label".to_string(), "production".to_string())));
        assert_eq!(pairs.iter().filter(|(name, _)| name == "tags").count(), 2);
    }

    #[test]
    fn sha256_matches_standard_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn connection_string_requires_exact_endpoint_and_redacts_secret() {
        let parsed = parse_connection_string(
            "Endpoint=https://shared.azconfig.io;Id=credential;Secret=c2VjcmV0",
            "https://shared.azconfig.io/",
        )
        .unwrap();
        assert_eq!(parsed.id, "credential");
        assert_eq!(parsed.secret.secret(), "c2VjcmV0");

        let error = parse_connection_string(
            "Endpoint=https://other.azconfig.io;Id=credential;Secret=c2VjcmV0",
            "https://shared.azconfig.io/",
        )
        .unwrap_err();
        assert!(!error.to_string().contains("c2VjcmV0"));
        assert!(error.to_string().contains("does not match"), "{error}");
    }

    #[test]
    fn content_type_detection_is_strict_but_parameter_order_independent() {
        for content_type in [
            "application/vnd.microsoft.appconfig.keyvaultref+json;charset=utf-8",
            "APPLICATION/VND.MICROSOFT.APPCONFIG.KEYVAULTREF+JSON; foo=bar; CHARSET = UTF-8",
        ] {
            assert!(matches!(
                AzAppConfigProvider::value_type(Some(content_type)),
                ValueType::KeyVaultReference
            ));
        }
        assert!(matches!(
            AzAppConfigProvider::value_type(Some(
                "application/vnd.microsoft.appconfig.keyvaultref+json"
            )),
            ValueType::AzureSpecial(_)
        ));
        assert!(matches!(
            AzAppConfigProvider::value_type(Some("application/json")),
            ValueType::Direct
        ));
    }

    #[test]
    fn key_vault_reference_accepts_latest_and_pinned_versions() {
        let latest = parse_vault_reference(
            r#"{"uri":"https://Shared.Vault.Azure.Net/secrets/database"}"#,
            "vault.azure.net",
        )
        .unwrap();
        assert_eq!(latest.vault_host, "shared.vault.azure.net");
        assert_eq!(latest.secret_name, "database");
        assert_eq!(latest.version, None);

        let pinned = parse_vault_reference(
            r#"{"uri":"https://shared.vault.azure.net/secrets/database/0123456789abcdef0123456789abcdef"}"#,
            "vault.azure.net",
        )
        .unwrap();
        assert_eq!(
            pinned.version.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn key_vault_reference_rejects_unsafe_or_malformed_targets() {
        for value in [
            r#"{"uri":"http://vault.vault.azure.net/secrets/name"}"#,
            r#"{"uri":"https://vault.vault.azure.net:443/secrets/name"}"#,
            r#"{"uri":"https://vault.vault.azure.net.evil.example/secrets/name"}"#,
            r#"{"uri":"https://nested.vault.vault.azure.net/secrets/name"}"#,
            r#"{"uri":"https://vault.vault.azure.net/secrets/name%2Fother"}"#,
            r#"{"uri":"https://vault.vault.azure.net/secrets/name?version=1"}"#,
            r#"{"uri":"https://vault.vault.azure.net/secrets/name","extra":true}"#,
            r#"{"uri":"https://vault.vault.azure.net/secrets/name","uri":"https://other.vault.azure.net/secrets/name"}"#,
        ] {
            assert!(
                parse_vault_reference(value, "vault.azure.net").is_err(),
                "expected invalid reference: {value}"
            );
        }
    }

    #[test]
    fn sync_tokens_keep_newest_sequence_per_id() {
        let provider = provider("azappconfig://shared");
        let mut first = HeaderMap::new();
        first.insert(
            "sync-token",
            HeaderValue::from_static("abc=one;sn=1,def=x;sn=3"),
        );
        provider.merge_sync_tokens(&first);
        let mut second = HeaderMap::new();
        second.insert(
            "sync-token",
            HeaderValue::from_static("abc=old;sn=0,def=y;sn=4"),
        );
        provider.merge_sync_tokens(&second);
        assert_eq!(
            provider.current_sync_token().as_deref(),
            Some("abc=one;sn=1,def=y;sn=4")
        );
    }

    #[test]
    fn continuation_must_preserve_endpoint_and_scope() {
        let provider = provider("azappconfig://shared?label=prod&tag=app=payments");
        let initial = provider
            .list_url(DiscoveryContext::new("checkout", "prod"))
            .unwrap();
        let mut valid = initial.clone();
        valid.query_pairs_mut().append_pair("After", "cursor");
        assert!(
            provider
                .validate_continuation(&initial, valid.as_str())
                .is_ok()
        );

        let broadened = "https://shared.azconfig.io/kv?api-version=2026-04-01&After=cursor";
        assert!(provider.validate_continuation(&initial, broadened).is_err());
        assert!(
            provider
                .validate_continuation(&initial, "https://evil.example/kv?After=cursor")
                .is_err()
        );
    }

    #[test]
    fn reflection_skips_foreign_keys_and_rejects_invalid_in_scope_names() {
        let provider = provider("azappconfig://shared?prefix=payments%3A");
        let context = DiscoveryContext::new("checkout", "prod");
        let record = |key: &str, content_type: Option<&str>| KeyValue {
            etag: None,
            key: key.to_string(),
            label: None,
            content_type: content_type.map(str::to_string),
            value: None,
            tags: BTreeMap::new(),
            description: None,
            locked: false,
        };
        assert!(
            provider
                .declaration_from_record(context, record("foreign:key", None))
                .unwrap()
                .is_none()
        );
        let (name, declaration) = provider
            .declaration_from_record(
                context,
                record("payments:secretspec:checkout:prod:DATABASE_URL", None),
            )
            .unwrap()
            .unwrap();
        assert_eq!(name, "DATABASE_URL");
        assert_eq!(declaration.required, Some(true));
        assert!(
            provider
                .declaration_from_record(
                    context,
                    record("payments:secretspec:checkout:prod:api-key", None),
                )
                .is_err()
        );
    }
}
