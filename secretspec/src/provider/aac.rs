//! Azure App Configuration provider, available in SecretSpec 0.20+.
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
//! aac://STORE[?auth=env|cli|managed_identity|workload_identity|connection_string]
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
//! secretspec check --provider aac://payments-prod
//! secretspec check --provider 'aac://shared?label=production&prefix=payments:'
//! secretspec check --provider 'aac://shared?tag=app=payments&tag=stage=production'
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
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use url::Url;

const API_VERSION: &str = "2026-04-01";
const DEFAULT_SUFFIX: &str = "azconfig.io";
// https://learn.microsoft.com/azure/azure-app-configuration/concept-enable-rbac#app-configuration-audience
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
const MAX_VAULT_CLIENTS: usize = 16;
const MAX_ERROR_RESPONSE_BYTES: usize = 8 * 1024;

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
                "unknown aac auth method '{other}': expected env, cli, \
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
pub struct AacConfig {
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

impl TryFrom<&ProviderUrl> for AacConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> Result<Self> {
        if url.scheme() != "aac" {
            return Err(operation_error(format!(
                "invalid scheme '{}' for aac provider: expected aac",
                url.scheme()
            )));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(operation_error(
                "aac URIs cannot contain user information".to_string(),
            ));
        }
        if url.port().is_some() {
            return Err(operation_error(
                "aac endpoints cannot contain an explicit port".to_string(),
            ));
        }

        let store_host = url.host().filter(|host| !host.is_empty()).ok_or_else(|| {
            operation_error(
                "Azure App Configuration store is required: use aac://STORE".to_string(),
            )
        })?;
        let path = url.path();
        let item = path.trim_start_matches('/');
        if !item.is_empty() {
            let hint = crate::config::ref_table_hint(None, item, None, None);
            return Err(operation_error(format!(
                "aac URIs take no path: address the key with {hint} on the secret instead"
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
                return Err(operation_error(format!("unknown aac parameter '{name}'")));
            }
            if value.is_empty() {
                return Err(operation_error(format!(
                    "aac parameter '{name}' cannot be empty"
                )));
            }
            if singleton.insert(name.clone(), value).is_some() {
                return Err(operation_error(format!(
                    "aac parameter '{name}' may appear only once"
                )));
            }
        }

        if tags.len() > MAX_TAG_FILTERS {
            return Err(operation_error(format!(
                "aac accepts at most {MAX_TAG_FILTERS} tag filters"
            )));
        }
        tags.sort_by(|left, right| left.0.cmp(&right.0));
        for pair in tags.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(operation_error(format!(
                    "aac tag name '{}' may appear only once",
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
                "aac suffix is valid only with a bare store name".to_string(),
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
                "aac host '{effective_host}' is outside Azure public cloud; set audience explicitly"
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
        .ok_or_else(|| operation_error("aac tags use tag=NAME=VALUE".to_string()))?;
    if name.is_empty() || value.is_empty() || name.contains('\0') || value.contains('\0') {
        return Err(operation_error(
            "aac tag names and values cannot be empty or null".to_string(),
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
        .map_err(|error| operation_error(format!("invalid aac audience: {error}")))?;
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
            "aac audience must be an HTTPS origin without credentials, port, path, query, or fragment"
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

fn is_valid_secret_name(value: &str) -> bool {
    value != "defaults" && value.is_ascii() && crate::config::is_valid_identifier(value)
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

/// Azure App Configuration provider, available in SecretSpec 0.20+.
pub struct AacProvider {
    config: AacConfig,
    credentials: ProviderCredentials,
    http: OnceLock<reqwest::Client>,
    auth: OnceLock<ResolvedAuth>,
    key_vault_credential: OnceLock<Arc<dyn TokenCredential>>,
    sync_tokens: Mutex<BTreeMap<String, SyncToken>>,
    vaults: Mutex<HashMap<String, Arc<super::akv::AkvProvider>>>,
    initial_request: super::akv::InitialRequestGate,
    #[cfg(test)]
    allow_insecure_loopback: bool,
}

crate::register_provider! {
    struct: AacProvider,
    config: AacConfig,
    name: "aac",
    description: "Azure App Configuration (0.20+)",
    schemes: ["aac"],
    examples: [
        "aac://payments-production",
        "aac://shared?label=production&prefix=payments:",
        "aac://shared?tag=app=payments&tag=stage=production",
    ],
    credential_names: [TENANT_ID, CLIENT_ID, CLIENT_SECRET, CONNECTION_STRING],
    deletes: true,
}

impl AacProvider {
    pub fn new(config: AacConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
            http: OnceLock::new(),
            auth: OnceLock::new(),
            key_vault_credential: OnceLock::new(),
            sync_tokens: Mutex::new(BTreeMap::new()),
            vaults: Mutex::new(HashMap::new()),
            initial_request: super::akv::InitialRequestGate::default(),
            #[cfg(test)]
            allow_insecure_loopback: false,
        }
    }

    fn http_client_builder() -> reqwest::ClientBuilder {
        reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
    }

    fn http(&self) -> Result<&reqwest::Client> {
        if let Some(client) = self.http.get() {
            return Ok(client);
        }
        let client = Self::http_client_builder()
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
                    let request_value = raw.split(';').next().unwrap_or(raw);
                    tokens.insert(
                        id.to_string(),
                        SyncToken {
                            sequence,
                            value: request_value.to_string(),
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
        #[cfg(not(test))]
        let allowed_scheme = url.scheme() == "https";
        #[cfg(test)]
        let allowed_scheme = url.scheme() == "https"
            || (self.allow_insecure_loopback
                && url.scheme() == "http"
                && url.host_str() == Some("127.0.0.1"));
        if !allowed_scheme || url.origin() != self.endpoint_url()?.origin() {
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
                let host = &url[url::Position::BeforeHost..url::Position::AfterPort];
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
struct KeyValueList {
    #[serde(default)]
    items: Vec<KeyValue>,
    #[serde(rename = "@nextLink")]
    next_link: Option<String>,
}

#[derive(Deserialize)]
struct AppConfigError {
    name: Option<String>,
}

enum ValueType {
    Direct,
    KeyVaultReference,
    AzureSpecial(String),
}

enum SelectedValue {
    Direct(SecretString),
    Reference {
        key: String,
        reference: VaultReference,
    },
}

impl AacProvider {
    fn convention_key(&self, project: &str, profile: &str, key: &str) -> Result<String> {
        validate_name_component("project", project)?;
        validate_name_component("profile", profile)?;
        if !is_valid_secret_name(key) {
            return Err(operation_error(format!(
                "key '{key}' cannot become a SecretSpec declaration: use an ASCII letter or underscore first, followed by ASCII letters, digits, or underscores, and avoid the reserved name 'defaults'"
            )));
        }
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
            if let Some(label) = &self.config.label {
                query.append_pair("label", label);
            }
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

    fn discovery_prefix(&self, context: DiscoveryContext<'_>) -> Result<String> {
        let base = format!(
            "{}secretspec:{}:{}:",
            self.config.prefix.as_deref().unwrap_or_default(),
            context.project,
            context.profile
        );
        validate_name_component("project", context.project)?;
        validate_name_component("profile", context.profile)?;
        validate_appconfig_key(&base, "discovery prefix")?;
        Ok(base)
    }

    fn list_url(&self, context: DiscoveryContext<'_>) -> Result<Url> {
        let base = self.discovery_prefix(context)?;
        let mut url = self.endpoint_url()?;
        url.path_segments_mut()
            .map_err(|_| operation_error("invalid App Configuration endpoint".to_string()))?
            .push("kv");
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("api-version", API_VERSION);
            query.append_pair("key", &format!("{}*", escape_filter(&base)));
            query.append_pair(
                "label",
                &escape_filter(self.config.label.as_deref().unwrap_or("\0")),
            );
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

    async fn response_error(
        &self,
        action: &str,
        mut response: reqwest::Response,
    ) -> SecretSpecError {
        let status = response.status();
        let mut body = Vec::new();
        let mut complete = true;
        loop {
            match response.chunk().await {
                Ok(Some(chunk))
                    if chunk.len() <= MAX_ERROR_RESPONSE_BYTES.saturating_sub(body.len()) =>
                {
                    body.extend_from_slice(&chunk);
                }
                Ok(Some(_)) | Err(_) => {
                    complete = false;
                    break;
                }
                Ok(None) => break,
            }
        }
        let parameter = complete
            .then(|| serde_json::from_slice::<AppConfigError>(&body).ok())
            .flatten()
            .and_then(|error| error.name)
            .filter(|name| {
                matches!(
                    name.as_str(),
                    "api-version" | "key" | "label" | "tags" | "$select" | "after" | "snapshot"
                )
            })
            .map(|name| format!(" for parameter '{name}'"))
            .unwrap_or_default();
        operation_error(format!(
            "Azure App Configuration {action} failed with HTTP {}{parameter}",
            status.as_u16(),
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
                if include_tags && !self.matches_tags(&record) {
                    return Ok(None);
                }
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
                let reference = parse_vault_reference(&value, &self.config.key_vault_suffix)
                    .map_err(|error| {
                        operation_error(format!(
                            "invalid Key Vault reference in Azure App Configuration key '{key}': {error}"
                        ))
                    })?;
                Ok(SelectedValue::Reference {
                    key: key.to_string(),
                    reference,
                })
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
        // Azure emits 32-character object versions; reject other shapes before authentication.
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

impl AacProvider {
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
        {
            let vaults = self.vaults.lock().unwrap();
            if let Some(provider) = vaults.get(&reference.vault_host) {
                return Ok(Arc::clone(provider));
            }
            if vaults.len() >= MAX_VAULT_CLIENTS {
                return Err(operation_error(format!(
                    "one aac provider can resolve at most {MAX_VAULT_CLIENTS} Key Vault hosts; split this workload across provider aliases"
                )));
            }
        }
        let credential = self.key_vault_credential()?;
        let config = super::akv::AkvConfig::from_validated_vault_host(
            reference.vault_host.clone(),
            super::akv::AuthMethod::Env,
        );
        let provider = Arc::new(super::akv::AkvProvider::with_token_credential(
            config, credential,
        ));
        let mut vaults = self.vaults.lock().unwrap();
        if let Some(existing) = vaults.get(&reference.vault_host) {
            return Ok(Arc::clone(existing));
        }
        if vaults.len() >= MAX_VAULT_CLIENTS {
            return Err(operation_error(format!(
                "one aac provider can resolve at most {MAX_VAULT_CLIENTS} Key Vault hosts; split this workload across provider aliases"
            )));
        }
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

    fn resolve_selected_reference(
        &self,
        key: &str,
        reference: &VaultReference,
    ) -> Result<SecretString> {
        self.resolve_vault_reference(reference).map_err(|error| {
            operation_error(format!(
                "failed to resolve Key Vault reference from Azure App Configuration key '{key}' through vault '{}': {error}",
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
        let mut references: HashMap<VaultReference, (Vec<&str>, BTreeSet<String>)> = HashMap::new();
        for (names, result) in selected {
            match result? {
                Some(SelectedValue::Direct(value)) => {
                    for name in names {
                        values.insert(name.to_string(), value.clone());
                    }
                }
                Some(SelectedValue::Reference { key, reference }) => {
                    let entry = references.entry(reference).or_default();
                    entry.0.extend(names);
                    entry.1.insert(key);
                }
                None => {}
            }
        }

        let references = references
            .into_iter()
            .map(|(reference, (names, keys))| (reference, names, keys))
            .collect::<Vec<_>>();
        let resolved = map_concurrently(
            &references,
            get_each_concurrency(),
            |(reference, names, keys)| {
                let result = self.resolve_vault_reference(reference).map_err(|error| {
                    operation_error(format!(
                        "failed to resolve Key Vault reference for {} from Azure App Configuration key(s) {} through vault '{}': {error}",
                        names.join(", "),
                        keys.iter().map(|key| format!("'{key}'")).collect::<Vec<_>>().join(", "),
                        reference.vault_host
                    ))
                });
                (names.clone(), result)
            },
        );
        for (names, result) in resolved {
            let value = result?;
            for name in names {
                values.insert(name.to_string(), value.clone());
            }
        }
        Ok(values)
    }

    fn validate_continuation(&self, initial: &Url, next_link: &str) -> Result<Url> {
        if Url::parse(next_link).is_ok() {
            return Err(operation_error(
                "Azure App Configuration returned an absolute continuation link".to_string(),
            ));
        }
        let next = initial.join(next_link).map_err(|_| {
            operation_error(
                "Azure App Configuration returned an invalid continuation link".to_string(),
            )
        })?;
        #[cfg(not(test))]
        let allowed_scheme = next.scheme() == "https";
        #[cfg(test)]
        let allowed_scheme = next.scheme() == "https"
            || (self.allow_insecure_loopback
                && next.scheme() == "http"
                && next.host_str() == Some("127.0.0.1"));
        if !allowed_scheme
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
        let prefix = self.discovery_prefix(context)?;
        let Some(key) = record.key.strip_prefix(&prefix) else {
            return Ok(None);
        };
        if key.contains(':') {
            return Err(operation_error(format!(
                "Azure App Configuration key '{}' is nested inside the SecretSpec discovery namespace",
                record.key
            )));
        }
        if !is_valid_secret_name(key) {
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
            crate::Secret::required(format!("{key} secret")),
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

impl Provider for AacProvider {
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
            Some(SelectedValue::Reference { key, reference }) => {
                self.resolve_selected_reference(&key, &reference).map(Some)
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
                "aac native references are read-only and cannot be written".to_string(),
            ));
        }
        let key = self.resolve_key(addr)?;
        self.initial_request
            .run(|| super::block_on(self.mutation_record(&key)).map(|_| ()))
    }

    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        if matches!(addr, Address::Native(_)) {
            self.check_deletable(addr)?;
            return Err(operation_error(
                "aac native deletion is not implemented".to_string(),
            ));
        }
        let key = self.resolve_key(addr)?;
        self.initial_request
            .run(|| super::block_on(self.delete_async(&key)))
    }

    fn supports_delete(&self) -> bool {
        true
    }

    fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
        self.resolve_coords(addr)?;
        if matches!(addr, Address::Native(_)) {
            return Err(operation_error(
                "aac native references are read-only and cannot be deleted".to_string(),
            ));
        }
        let key = self.resolve_key(addr)?;
        self.initial_request
            .run(|| super::block_on(self.mutation_record(&key)).map(|_| ()))
    }

    fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
        if matches!(addr, Address::Native(_)) {
            self.resolve_coords(addr)?;
            return Err(operation_error(
                "aac native references are read-only and cannot be written".to_string(),
            ));
        }
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
        let base = format!("aac://{}", self.config.store_host);
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
    use azure_core::http::{
        AsyncRawResponse, ClientOptions, HttpClient, Request, StatusCode as HttpStatusCode,
        Transport, headers::Headers,
    };
    use azure_identity::DeveloperToolsCredential;
    use azure_security_keyvault_secrets::{SecretClient, SecretClientOptions};
    use reqwest::header::HeaderValue;
    use serde_json::{Value, json};
    use std::future::Future;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    #[derive(Debug)]
    struct CapturedRequest {
        method: String,
        target: String,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
    }

    impl CapturedRequest {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .get(&name.to_ascii_lowercase())
                .map(String::as_str)
        }
    }

    struct StubResponse {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        request_key: bool,
    }

    impl StubResponse {
        fn empty(status: u16) -> Self {
            Self {
                status,
                headers: Vec::new(),
                body: Vec::new(),
                request_key: false,
            }
        }

        fn json(status: u16, body: Value) -> Self {
            Self {
                status,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: serde_json::to_vec(&body).unwrap(),
                request_key: false,
            }
        }

        fn header(mut self, name: &str, value: &str) -> Self {
            self.headers.push((name.to_string(), value.to_string()));
            self
        }

        fn with_request_key(mut self) -> Self {
            self.request_key = true;
            self
        }

        fn prepare_for(&mut self, request: &CapturedRequest) {
            if !self.request_key {
                return;
            }
            let url = Url::parse("http://fixture.invalid")
                .unwrap()
                .join(&request.target)
                .unwrap();
            let encoded = url.path_segments().unwrap().next_back().unwrap();
            let key = percent_encoding::percent_decode_str(encoded)
                .decode_utf8()
                .unwrap()
                .into_owned();
            let mut body: Value = serde_json::from_slice(&self.body).unwrap();
            body["key"] = Value::String(key);
            self.body = serde_json::to_vec(&body).unwrap();
        }
    }

    struct HttpFixture {
        endpoint: String,
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
        stop: Arc<AtomicBool>,
        handle: Option<JoinHandle<()>>,
    }

    impl HttpFixture {
        fn start(build: impl FnOnce(&str) -> Vec<StubResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let endpoint = format!("http://{}/", listener.local_addr().unwrap());
            let responses = build(&endpoint);
            let requests = Arc::new(Mutex::new(Vec::new()));
            let captured = Arc::clone(&requests);
            let stop = Arc::new(AtomicBool::new(false));
            let stopped = Arc::clone(&stop);
            let handle = thread::spawn(move || {
                for mut response in responses {
                    let mut stream = loop {
                        match listener.accept() {
                            Ok((stream, _)) => break stream,
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                if stopped.load(Ordering::Acquire) {
                                    return;
                                }
                                thread::sleep(Duration::from_millis(1));
                            }
                            Err(error) => panic!("fixture accept failed: {error}"),
                        }
                    };
                    let request = read_request(&mut stream);
                    response.prepare_for(&request);
                    captured.lock().unwrap().push(request);
                    write_response(&mut stream, response);
                }
            });
            Self {
                endpoint,
                requests,
                stop,
                handle: Some(handle),
            }
        }

        fn finish(mut self) -> Vec<CapturedRequest> {
            self.stop.store(true, Ordering::Release);
            self.handle.take().unwrap().join().unwrap();
            std::mem::take(&mut *self.requests.lock().unwrap())
        }
    }

    impl Drop for HttpFixture {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(handle) = self.handle.take() {
                handle.join().unwrap();
            }
        }
    }

    fn read_request(stream: &mut TcpStream) -> CapturedRequest {
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut raw = Vec::new();
        let mut buffer = [0_u8; 4096];
        let header_end = loop {
            let read = read_fixture_bytes(stream, &mut buffer, deadline);
            assert!(read > 0, "request ended before headers");
            raw.extend_from_slice(&buffer[..read]);
            if let Some(index) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let head = std::str::from_utf8(&raw[..header_end]).unwrap();
        let mut lines = head.split("\r\n");
        let mut request_line = lines.next().unwrap().split_whitespace();
        let method = request_line.next().unwrap().to_string();
        let target = request_line.next().unwrap().to_string();
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
            .collect::<BTreeMap<_, _>>();
        let content_length = headers
            .get("content-length")
            .map(|value| value.parse::<usize>().unwrap())
            .unwrap_or_default();
        while raw.len() < header_end + content_length {
            let read = read_fixture_bytes(stream, &mut buffer, deadline);
            assert!(read > 0, "request ended before body");
            raw.extend_from_slice(&buffer[..read]);
        }
        CapturedRequest {
            method,
            target,
            headers,
            body: raw[header_end..header_end + content_length].to_vec(),
        }
    }

    fn read_fixture_bytes(stream: &mut TcpStream, buffer: &mut [u8], deadline: Instant) -> usize {
        loop {
            match stream.read(buffer) {
                Ok(read) => return read,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) && Instant::now() < deadline => {}
                Err(error) => panic!("fixture request read failed: {error}"),
            }
        }
    }

    fn write_response(stream: &mut TcpStream, response: StubResponse) {
        write!(
            stream,
            "HTTP/1.1 {} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n",
            response.status,
            response.body.len()
        )
        .unwrap();
        for (name, value) in response.headers {
            write!(stream, "{name}: {value}\r\n").unwrap();
        }
        stream.write_all(b"\r\n").unwrap();
        stream.write_all(&response.body).unwrap();
        stream.flush().unwrap();
    }

    fn config(uri: &str) -> AacConfig {
        AacConfig::try_from(&ProviderUrl::new(Url::parse(uri).unwrap())).unwrap()
    }

    fn provider(uri: &str) -> AacProvider {
        AacProvider::new(config(uri))
    }

    fn fixture_provider(endpoint: &str, uri: &str) -> AacProvider {
        let mut provider = provider(uri);
        provider.config.endpoint = endpoint.to_string();
        provider.allow_insecure_loopback = true;
        provider
            .http
            .set(AacProvider::http_client_builder().build().unwrap())
            .unwrap();
        provider
            .auth
            .set(ResolvedAuth::ConnectionString(ConnectionStringAuth {
                id: "fixture-id".to_string(),
                secret: AzureSecret::new("c2lnbmluZy1zZWNyZXQ=".to_string()),
            }))
            .map_err(|_| ())
            .unwrap();
        provider
    }

    fn key_value(key: &str, value: &str) -> Value {
        json!({
            "etag": "etag-1",
            "key": key,
            "label": null,
            "content_type": null,
            "value": value,
            "tags": {},
            "locked": false
        })
    }

    fn key_vault_value(uri: &str) -> Value {
        let mut record = key_value("", &json!({"uri": uri}).to_string());
        record["content_type"] = Value::String(format!("{KEY_VAULT_REFERENCE_TYPE};charset=utf-8"));
        record
    }

    #[derive(Debug)]
    struct RecordingKeyVaultClient {
        paths: Mutex<Vec<String>>,
        value: String,
    }

    impl RecordingKeyVaultClient {
        fn new(value: &str) -> Arc<Self> {
            Arc::new(Self {
                paths: Mutex::new(Vec::new()),
                value: value.to_string(),
            })
        }
    }

    impl HttpClient for RecordingKeyVaultClient {
        fn execute_request<'life0, 'life1, 'async_trait>(
            &'life0 self,
            request: &'life1 Request,
        ) -> Pin<Box<dyn Future<Output = azure_core::Result<AsyncRawResponse>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            self.paths.lock().unwrap().push(request.url().path().into());
            let body = json!({"value": self.value}).to_string();
            Box::pin(async move {
                Ok(AsyncRawResponse::from_bytes(
                    HttpStatusCode::Ok,
                    Headers::new(),
                    body,
                ))
            })
        }
    }

    fn key_vault_provider(
        host: &str,
        transport: Arc<RecordingKeyVaultClient>,
    ) -> Arc<super::super::akv::AkvProvider> {
        let credential = DeveloperToolsCredential::new(None).unwrap();
        let vault_url = format!("https://{host}/");
        let client = SecretClient::new(
            &vault_url,
            credential,
            Some(SecretClientOptions {
                client_options: ClientOptions {
                    transport: Some(Transport::new(transport)),
                    ..Default::default()
                },
                ..Default::default()
            }),
        )
        .unwrap();
        let config = super::super::akv::AkvConfig::from_validated_vault_host(
            host.to_string(),
            super::super::akv::AuthMethod::Env,
        );
        Arc::new(super::super::akv::AkvProvider::with_client(config, client))
    }

    fn discovery_target(endpoint: &str, after: Option<&str>) -> String {
        let mut provider = provider("aac://shared");
        provider.config.endpoint = endpoint.to_string();
        let mut url = provider
            .list_url(DiscoveryContext::new("checkout", "prod"))
            .unwrap();
        if let Some(after) = after {
            url.query_pairs_mut().append_pair("After", after);
        }
        safe_request_target(&url)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn default_store_uses_public_endpoint_and_current_audience() {
        let config = config("aac://payments");
        assert_eq!(config.endpoint, "https://payments.azconfig.io/");
        assert_eq!(config.audience, "https://appconfig.azure.com");
        assert_eq!(config.label, None);
        assert_eq!(config.tags, Vec::<(String, String)>::new());
    }

    #[test]
    fn sovereign_host_requires_and_round_trips_audience() {
        let error = AacConfig::try_from(&ProviderUrl::new(
            Url::parse("aac://payments.azconfig.azure.cn").unwrap(),
        ))
        .unwrap_err();
        assert!(
            error.to_string().contains("set audience explicitly"),
            "{error}"
        );

        let provider =
            provider("aac://payments.azconfig.azure.cn?audience=https%3A%2F%2Fappconfig.azure.cn");
        assert_eq!(
            provider.uri(),
            "aac://payments.azconfig.azure.cn?audience=https://appconfig.azure.cn"
        );
        assert_eq!(config(&provider.uri()).endpoint, provider.config.endpoint);
    }

    #[test]
    fn bare_store_supports_explicit_suffix() {
        let provider = provider(
            "aac://payments?suffix=azconfig.azure.us&audience=https%3A%2F%2Fappconfig.azure.us",
        );
        assert_eq!(
            provider.config.endpoint,
            "https://payments.azconfig.azure.us/"
        );
        assert_eq!(
            provider.uri(),
            "aac://payments?suffix=azconfig.azure.us&audience=https://appconfig.azure.us"
        );
    }

    #[test]
    fn uri_rejects_paths_unknowns_duplicates_and_conflicts() {
        for uri in [
            "aac://store/existing",
            "aac://store?unknown=value",
            "aac://store?label=prod&label=stage",
            "aac://store?label=",
            "aac://store.example?suffix=azconfig.io&audience=https%3A%2F%2Fappconfig.example",
            "aac://store?auth=connection_string&key_vault_auth=inherit",
        ] {
            let error = AacConfig::try_from(&ProviderUrl::new(Url::parse(uri).unwrap()));
            assert!(error.is_err(), "expected invalid URI: {uri}");
        }
    }

    #[test]
    fn tags_are_exact_unique_bounded_and_stably_ordered() {
        let provider = provider("aac://shared?tag=stage=prod&tag=app=payments&label=production");
        assert_eq!(
            provider.config.tags,
            vec![
                ("app".to_string(), "payments".to_string()),
                ("stage".to_string(), "prod".to_string())
            ]
        );
        assert_eq!(
            provider.uri(),
            "aac://shared?label=production&tag=app=payments&tag=stage=prod"
        );

        for uri in [
            "aac://shared?tag=app",
            "aac://shared?tag==prod",
            "aac://shared?tag=app=",
            "aac://shared?tag=app=one&tag=app=two",
            "aac://shared?tag=app=%00",
            "aac://shared?tag=a=1&tag=b=2&tag=c=3&tag=d=4&tag=e=5&tag=f=6",
        ] {
            assert!(
                AacConfig::try_from(&ProviderUrl::new(Url::parse(uri).unwrap())).is_err(),
                "expected invalid tags: {uri}"
            );
        }
    }

    #[test]
    fn filter_values_escape_azure_metacharacters_before_url_encoding() {
        assert_eq!(escape_filter(r"a*b,c\d"), r"a\*b\,c\\d");
        let provider = provider("aac://shared?tag=group=a*b%2Cc%5Cd");
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
        let provider = provider("aac://shared?prefix=payments%3Aorders%3A");
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
        let provider = provider("aac://shared");
        for (project, profile, key) in [
            ("", "prod", "KEY"),
            ("app", "", "KEY"),
            ("app", "prod", ""),
            ("my app", "prod", "KEY"),
            ("app", "prod", "KEY.PART"),
            ("app", "prod", "api-key"),
            ("app", "prod", "9KEY"),
            ("app", "prod", "KÉY"),
            ("app", "prod", "defaults"),
        ] {
            assert!(provider.convention_key(project, profile, key).is_err());
        }
        assert!(
            AacConfig::try_from(&ProviderUrl::new(
                Url::parse("aac://shared?prefix=%25").unwrap()
            ))
            .is_err()
        );
    }

    #[test]
    fn identity_includes_label_and_prefix_but_not_tags_or_auth() {
        let base = provider("aac://shared");
        let cli = provider("aac://shared?auth=cli");
        let tagged = provider("aac://shared?tag=app=payments");
        let labeled = provider("aac://shared?label=production");
        let prefixed = provider("aac://shared?prefix=payments%3A");
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
        let null = provider("aac://shared");
        let null_url = null.item_url("secretspec:app:prod:KEY", true).unwrap();
        assert!(!null_url.query_pairs().any(|(name, _)| name == "label"));
        let null_list = null.list_url(DiscoveryContext::new("app", "prod")).unwrap();
        assert!(null_list.as_str().contains("label=%00"), "{null_list}");

        let selected =
            provider("aac://shared?label=prod%2A%2C%5Cblue&tag=app=payments&tag=stage=prod");
        let pairs = selected
            .item_url("key", true)
            .unwrap()
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();
        assert!(pairs.contains(&("label".to_string(), r"prod*,\blue".to_string())));
        assert_eq!(pairs.iter().filter(|(name, _)| name == "tags").count(), 2);

        let list = selected
            .list_url(DiscoveryContext::new("app", "prod"))
            .unwrap();
        assert_eq!(
            list.query_pairs()
                .find(|(name, _)| name == "label")
                .map(|(_, value)| value.into_owned()),
            Some(r"prod\*\,\\blue".to_string())
        );
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
        for (length, expected) in [
            (
                55,
                "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
            ),
            (
                56,
                "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
            ),
            (
                64,
                "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
            ),
            (
                119,
                "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb",
            ),
            (
                120,
                "2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c",
            ),
        ] {
            assert_eq!(hex(&sha256(&vec![b'a'; length])), expected);
        }
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
    fn reads_treat_only_404_as_missing_and_reject_invalid_responses() {
        let missing = HttpFixture::start(|_| vec![StubResponse::empty(404)]);
        let provider = fixture_provider(&missing.endpoint, "aac://shared");
        assert!(
            super::super::block_on(provider.fetch_key_value("missing", true))
                .unwrap()
                .is_none()
        );
        assert_eq!(missing.finish().len(), 1);

        for status in [400, 401, 403, 409, 412, 429] {
            let failure = HttpFixture::start(|_| {
                vec![StubResponse::json(
                    status,
                    json!({
                        "name": "tags",
                        "title": "request failed",
                        "detail": "sensitive response detail"
                    }),
                )]
            });
            let provider = fixture_provider(&failure.endpoint, "aac://shared");
            let error =
                super::super::block_on(provider.fetch_key_value("failed", true)).unwrap_err();
            assert!(
                error.to_string().contains(&format!("HTTP {status}")),
                "{error}"
            );
            assert!(error.to_string().contains("parameter 'tags'"), "{error}");
            assert!(!error.to_string().contains("request failed"), "{error}");
            assert!(!error.to_string().contains("sensitive"), "{error}");
            assert_eq!(failure.finish().len(), 1);
        }

        let oversized = HttpFixture::start(|_| {
            vec![StubResponse {
                status: 400,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: serde_json::to_vec(&json!({
                    "name": "tags",
                    "detail": "s".repeat(MAX_ERROR_RESPONSE_BYTES)
                }))
                .unwrap(),
                request_key: false,
            }]
        });
        let provider = fixture_provider(&oversized.endpoint, "aac://shared");
        let error = super::super::block_on(provider.fetch_key_value("failed", true)).unwrap_err();
        assert!(error.to_string().contains("HTTP 400"), "{error}");
        assert!(!error.to_string().contains("parameter"), "{error}");
        assert_eq!(oversized.finish().len(), 1);

        let unrecognized = HttpFixture::start(|_| {
            vec![StubResponse::json(
                400,
                json!({"name": "secret-bearing-name", "detail": "sensitive detail"}),
            )]
        });
        let provider = fixture_provider(&unrecognized.endpoint, "aac://shared");
        let error = super::super::block_on(provider.fetch_key_value("failed", true)).unwrap_err();
        assert!(error.to_string().contains("HTTP 400"), "{error}");
        assert!(
            !error.to_string().contains("secret-bearing-name"),
            "{error}"
        );
        assert!(!error.to_string().contains("sensitive"), "{error}");
        assert_eq!(unrecognized.finish().len(), 1);

        let malformed = HttpFixture::start(|_| {
            vec![StubResponse {
                status: 200,
                headers: Vec::new(),
                body: b"not-json".to_vec(),
                request_key: false,
            }]
        });
        let provider = fixture_provider(&malformed.endpoint, "aac://shared");
        let error = super::super::block_on(provider.fetch_key_value("broken", true)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("returned invalid key-value JSON"),
            "{error}"
        );
        assert_eq!(malformed.finish().len(), 1);
    }

    #[test]
    fn reads_do_not_follow_redirects() {
        let redirected = HttpFixture::start(|_| vec![StubResponse::empty(200)]);
        let location = format!("{}stolen", redirected.endpoint);
        let origin = HttpFixture::start(move |_| {
            vec![StubResponse::empty(307).header("Location", &location)]
        });
        let provider = fixture_provider(&origin.endpoint, "aac://shared");

        let error =
            super::super::block_on(provider.fetch_key_value("redirected", true)).unwrap_err();
        assert!(error.to_string().contains("HTTP 307"), "{error}");
        assert_eq!(origin.finish().len(), 1);
        assert!(redirected.finish().is_empty());
    }

    #[test]
    fn reads_reject_records_outside_configured_tag_scope() {
        let fixture = HttpFixture::start(|_| {
            let mut record = key_value("shared-key", "secret-value");
            record["tags"] = json!({"stage": "test"});
            vec![StubResponse::json(200, record)]
        });
        let provider = fixture_provider(&fixture.endpoint, "aac://shared?tag=stage=production");
        let address = NativeAddress {
            item: "shared-key".to_string(),
            ..Default::default()
        };
        assert!(
            super::super::block_on(provider.selected_value_async(Address::Native(&address)))
                .unwrap()
                .is_none()
        );
        assert_eq!(fixture.finish().len(), 1);
    }

    #[test]
    fn create_is_conditional_signed_and_carries_response_sync_token() {
        let fixture = HttpFixture::start(|_| {
            vec![
                StubResponse::empty(404).header("Sync-Token", "sync=created;sn=7"),
                StubResponse::empty(200),
            ]
        });
        let provider = fixture_provider(
            &fixture.endpoint,
            "aac://shared?label=prod%2A%2C%5Cblue&tag=app=payments",
        );
        super::super::block_on(provider.set_async(
            "secretspec:checkout:prod:API_KEY",
            &SecretString::new("new-value".to_string().into()),
        ))
        .unwrap();

        let requests = fixture.finish();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[1].method, "PUT");
        assert_eq!(requests[1].header("if-none-match"), Some("*"));
        assert_eq!(requests[1].header("sync-token"), Some("sync=created"));
        let target = provider
            .endpoint_url()
            .unwrap()
            .join(&requests[1].target)
            .unwrap();
        assert_eq!(
            target
                .query_pairs()
                .find(|(name, _)| name == "label")
                .map(|(_, value)| value.into_owned()),
            Some(r"prod*,\blue".to_string())
        );
        let body: Value = serde_json::from_slice(&requests[1].body).unwrap();
        assert_eq!(body["value"], "new-value");
        assert_eq!(body["tags"], json!({"app": "payments"}));

        let date = requests[1].header("x-ms-date").unwrap();
        let content_hash = requests[1].header("x-ms-content-sha256").unwrap();
        assert_eq!(
            content_hash,
            azure_core::base64::encode(sha256(&requests[1].body))
        );
        let canonical = format!(
            "PUT\n{}\n{};{};{}",
            requests[1].target,
            date,
            requests[1].header("host").unwrap(),
            content_hash
        );
        let signature = azure_core::hmac::hmac_sha256(
            &canonical,
            &AzureSecret::new("c2lnbmluZy1zZWNyZXQ=".to_string()),
        )
        .unwrap();
        let expected_authorization = format!(
            "HMAC-SHA256 Credential=fixture-id&SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature={signature}"
        );
        assert_eq!(
            requests[1].header("authorization"),
            Some(expected_authorization.as_str())
        );
        assert!(
            requests
                .iter()
                .flat_map(|request| request.headers.values())
                .all(|value| !value.contains("c2lnbmluZy1zZWNyZXQ="))
        );
    }

    #[test]
    fn writes_do_not_replay_secret_bodies_across_redirects() {
        let redirected = HttpFixture::start(|_| vec![StubResponse::empty(200)]);
        let location = format!("{}stolen", redirected.endpoint);
        let origin = HttpFixture::start(move |_| {
            vec![
                StubResponse::empty(404),
                StubResponse::empty(307).header("Location", &location),
            ]
        });
        let provider = fixture_provider(&origin.endpoint, "aac://shared");
        let secret = "redirect-secret-value";

        let error = super::super::block_on(
            provider.set_async("redirected", &SecretString::new(secret.to_string().into())),
        )
        .unwrap_err();
        assert!(error.to_string().contains("HTTP 307"), "{error}");

        let requests = origin.finish();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].method, "PUT");
        assert!(String::from_utf8_lossy(&requests[1].body).contains(secret));
        assert!(redirected.finish().is_empty());
    }

    #[test]
    fn update_preserves_metadata_and_reports_precondition_failure() {
        let fixture = HttpFixture::start(|_| {
            vec![
                StubResponse::json(
                    200,
                    json!({
                        "etag": "etag-existing",
                        "key": "key",
                        "label": null,
                        "content_type": "text/plain",
                        "value": "old",
                        "tags": {"app": "payments", "owner": null},
                        "description": "kept",
                        "locked": false
                    }),
                ),
                StubResponse::empty(412),
            ]
        });
        let provider = fixture_provider(&fixture.endpoint, "aac://shared?tag=app=payments");
        let error = super::super::block_on(
            provider.set_async("key", &SecretString::new("new".to_string().into())),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("changed concurrently"),
            "{error}"
        );

        let requests = fixture.finish();
        assert_eq!(requests[1].header("if-match"), Some("etag-existing"));
        let body: Value = serde_json::from_slice(&requests[1].body).unwrap();
        assert_eq!(body["value"], "new");
        assert_eq!(body["content_type"], "text/plain");
        assert_eq!(body["tags"], json!({"app": "payments", "owner": null}));
        assert_eq!(body["description"], "kept");
    }

    #[test]
    fn mutations_refuse_mismatched_tags_before_writing() {
        let fixture = HttpFixture::start(|_| {
            let mut record = key_value("key", "old");
            record["tags"] = json!({"app": "other"});
            vec![StubResponse::json(200, record)]
        });
        let provider = fixture_provider(&fixture.endpoint, "aac://shared?tag=app=payments");
        let error = super::super::block_on(
            provider.set_async("key", &SecretString::new("new".to_string().into())),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("does not match configured tag"),
            "{error}"
        );
        let requests = fixture.finish();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
    }

    #[test]
    fn mutations_refuse_locked_special_and_etagless_records_before_writing() {
        let cases = [
            ("locked", json!({"locked": true})),
            (
                "special content type",
                json!({"content_type": format!("{KEY_VAULT_REFERENCE_TYPE};charset=utf-8")}),
            ),
            ("did not include an ETag", json!({"etag": null})),
        ];
        for (expected, patch) in cases {
            let fixture = HttpFixture::start(|_| {
                let mut record = key_value("key", "old");
                for (name, value) in patch.as_object().unwrap() {
                    record[name] = value.clone();
                }
                vec![StubResponse::json(200, record)]
            });
            let provider = fixture_provider(&fixture.endpoint, "aac://shared");
            let error = super::super::block_on(
                provider.set_async("key", &SecretString::new("new".to_string().into())),
            )
            .unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
            let requests = fixture.finish();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].method, "GET");
        }
    }

    #[test]
    fn delete_uses_etag_and_reports_concurrent_change() {
        let fixture = HttpFixture::start(|_| {
            vec![
                StubResponse::json(200, key_value("key", "old")),
                StubResponse::empty(412),
            ]
        });
        let provider = fixture_provider(&fixture.endpoint, "aac://shared");
        let error = super::super::block_on(provider.delete_async("key")).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("changed concurrently; retry the delete"),
            "{error}"
        );
        let requests = fixture.finish();
        assert_eq!(requests[1].method, "DELETE");
        assert_eq!(requests[1].header("if-match"), Some("etag-1"));
    }

    #[test]
    fn delete_distinguishes_absent_deleted_and_no_content() {
        let absent = HttpFixture::start(|_| vec![StubResponse::empty(404)]);
        let provider = fixture_provider(&absent.endpoint, "aac://shared");
        assert!(!super::super::block_on(provider.delete_async("key")).unwrap());
        assert_eq!(absent.finish().len(), 1);

        for (status, expected) in [(200, true), (204, false)] {
            let fixture = HttpFixture::start(|_| {
                vec![
                    StubResponse::json(200, key_value("key", "old")),
                    StubResponse::empty(status),
                ]
            });
            let provider = fixture_provider(&fixture.endpoint, "aac://shared");
            assert_eq!(
                super::super::block_on(provider.delete_async("key")).unwrap(),
                expected
            );
            let requests = fixture.finish();
            assert_eq!(requests[1].method, "DELETE");
            assert_eq!(requests[1].header("if-match"), Some("etag-1"));
        }
    }

    #[test]
    fn delete_preflight_and_delete_refuse_special_entries_identically() {
        let physical_key = "secretspec:app:prod:KEY";
        let fixture = HttpFixture::start(|_| {
            let mut record = key_value(physical_key, "reference");
            record["content_type"] = json!(format!("{KEY_VAULT_REFERENCE_TYPE};charset=utf-8"));
            vec![
                StubResponse::json(200, record.clone()),
                StubResponse::json(200, record),
            ]
        });
        let provider = fixture_provider(&fixture.endpoint, "aac://shared");
        assert!(provider.supports_delete());
        let address = Address::Convention {
            project: "app",
            profile: "prod",
            key: "KEY",
        };
        let preflight = provider.check_deletable(address).unwrap_err().to_string();
        let deletion = provider.delete(address).unwrap_err().to_string();
        assert_eq!(preflight, deletion);
        let requests = fixture.finish();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|request| request.method == "GET"));
    }

    #[test]
    fn hmac_reads_succeed_while_guarded_write_and_delete_denials_remain_errors() {
        let fixture = HttpFixture::start(|_| {
            vec![
                StubResponse::json(200, key_value("key", "value")),
                StubResponse::json(200, key_value("key", "old")),
                StubResponse::json(403, json!({"detail": "must stay private"})),
                StubResponse::json(200, key_value("key", "old")),
                StubResponse::json(403, json!({"detail": "must stay private"})),
            ]
        });
        let provider = fixture_provider(&fixture.endpoint, "aac://shared");
        let read = super::super::block_on(provider.fetch_key_value("key", true))
            .unwrap()
            .unwrap();
        assert_eq!(read.value.as_deref(), Some("value"));

        let write_error = super::super::block_on(
            provider.set_async("key", &SecretString::new("new".to_string().into())),
        )
        .unwrap_err();
        assert!(write_error.to_string().contains("HTTP 403"));
        assert!(!write_error.to_string().contains("must stay private"));

        let delete_error = super::super::block_on(provider.delete_async("key")).unwrap_err();
        assert!(delete_error.to_string().contains("HTTP 403"));
        assert!(!delete_error.to_string().contains("must stay private"));

        let requests = fixture.finish();
        assert_eq!(
            requests
                .iter()
                .map(|request| request.method.as_str())
                .collect::<Vec<_>>(),
            ["GET", "GET", "PUT", "GET", "DELETE"]
        );
        assert!(
            requests
                .iter()
                .all(|request| request.header("authorization").is_some())
        );
    }

    #[test]
    fn content_type_detection_is_strict_but_parameter_order_independent() {
        for content_type in [
            "application/vnd.microsoft.appconfig.keyvaultref+json;charset=utf-8",
            "APPLICATION/VND.MICROSOFT.APPCONFIG.KEYVAULTREF+JSON; foo=bar; CHARSET = UTF-8",
        ] {
            assert!(matches!(
                AacProvider::value_type(Some(content_type)),
                ValueType::KeyVaultReference
            ));
        }
        assert!(matches!(
            AacProvider::value_type(Some("application/vnd.microsoft.appconfig.keyvaultref+json")),
            ValueType::AzureSpecial(_)
        ));
        assert!(matches!(
            AacProvider::value_type(Some("application/json")),
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
        let provider = provider("aac://shared");
        let mut first = HeaderMap::new();
        first.append("sync-token", HeaderValue::from_static("abc=one;sn=1"));
        first.append("sync-token", HeaderValue::from_static("def=x;sn=3"));
        provider.merge_sync_tokens(&first);
        let mut second = HeaderMap::new();
        second.insert(
            "sync-token",
            HeaderValue::from_static("abc=old;sn=0,def=y;sn=4"),
        );
        provider.merge_sync_tokens(&second);
        assert_eq!(
            provider.current_sync_token().as_deref(),
            Some("abc=one,def=y")
        );
    }

    #[test]
    fn get_many_deduplicates_addresses_and_maps_every_declaration() {
        let fixture = HttpFixture::start(|_| {
            vec![StubResponse::json(
                200,
                key_value("shared-key", "secret-value"),
            )]
        });
        let provider = fixture_provider(&fixture.endpoint, "aac://shared");
        let address = NativeAddress {
            item: "shared-key".to_string(),
            ..Default::default()
        };
        let values = provider
            .get_many(&[
                ("FIRST", Address::Native(&address)),
                ("SECOND", Address::Native(&address)),
            ])
            .unwrap();
        assert_eq!(values["FIRST"].expose_secret(), "secret-value");
        assert_eq!(values["SECOND"].expose_secret(), "secret-value");
        assert_eq!(fixture.finish().len(), 1);
    }

    #[test]
    fn get_many_deduplicates_key_vault_references() {
        let fixture = HttpFixture::start(|_| {
            let record = key_vault_value("https://shared.vault.azure.net/secrets/api-key");
            vec![
                StubResponse::json(200, record.clone()).with_request_key(),
                StubResponse::json(200, record).with_request_key(),
            ]
        });
        let provider = fixture_provider(&fixture.endpoint, "aac://shared");
        let transport = RecordingKeyVaultClient::new("resolved-value");
        provider.vaults.lock().unwrap().insert(
            "shared.vault.azure.net".to_string(),
            key_vault_provider("shared.vault.azure.net", Arc::clone(&transport)),
        );
        let first = NativeAddress {
            item: "first-key".to_string(),
            ..Default::default()
        };
        let second = NativeAddress {
            item: "second-key".to_string(),
            ..Default::default()
        };
        let values = provider
            .get_many(&[
                ("FIRST", Address::Native(&first)),
                ("SECOND", Address::Native(&second)),
            ])
            .unwrap();
        assert_eq!(values["FIRST"].expose_secret(), "resolved-value");
        assert_eq!(values["SECOND"].expose_secret(), "resolved-value");
        assert_eq!(transport.paths.lock().unwrap().len(), 1);
        assert_eq!(fixture.finish().len(), 2);
    }

    #[test]
    fn get_many_reference_failure_names_every_affected_declaration() {
        let fixture = HttpFixture::start(|_| {
            let record = key_vault_value("https://shared.vault.azure.net/secrets/api-key");
            vec![
                StubResponse::json(200, record.clone()).with_request_key(),
                StubResponse::json(200, record).with_request_key(),
            ]
        });
        let provider = fixture_provider(&fixture.endpoint, "aac://shared");
        let first = NativeAddress {
            item: "first-key".to_string(),
            ..Default::default()
        };
        let second = NativeAddress {
            item: "second-key".to_string(),
            ..Default::default()
        };
        let error = provider
            .get_many(&[
                ("FIRST", Address::Native(&first)),
                ("SECOND", Address::Native(&second)),
            ])
            .unwrap_err();
        let message = error.to_string();
        for expected in ["FIRST", "SECOND", "first-key", "second-key"] {
            assert!(message.contains(expected), "{message}");
        }
        assert!(message.contains("require key_vault_auth"), "{message}");
        assert_eq!(fixture.finish().len(), 2);
    }

    #[test]
    fn get_many_resolves_references_across_vaults() {
        let fixture = HttpFixture::start(|_| {
            vec![
                StubResponse::json(
                    200,
                    key_vault_value("https://first.vault.azure.net/secrets/api-key"),
                )
                .with_request_key(),
                StubResponse::json(
                    200,
                    key_vault_value("https://second.vault.azure.net/secrets/api-key"),
                )
                .with_request_key(),
            ]
        });
        let provider = fixture_provider(&fixture.endpoint, "aac://shared");
        let first_transport = RecordingKeyVaultClient::new("first-value");
        let second_transport = RecordingKeyVaultClient::new("second-value");
        let mut vaults = provider.vaults.lock().unwrap();
        vaults.insert(
            "first.vault.azure.net".to_string(),
            key_vault_provider("first.vault.azure.net", Arc::clone(&first_transport)),
        );
        vaults.insert(
            "second.vault.azure.net".to_string(),
            key_vault_provider("second.vault.azure.net", Arc::clone(&second_transport)),
        );
        drop(vaults);
        let first = NativeAddress {
            item: "first-key".to_string(),
            ..Default::default()
        };
        let second = NativeAddress {
            item: "second-key".to_string(),
            ..Default::default()
        };
        let values = provider
            .get_many(&[
                ("FIRST", Address::Native(&first)),
                ("SECOND", Address::Native(&second)),
            ])
            .unwrap();
        assert_eq!(
            values
                .values()
                .map(|value| value.expose_secret())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["first-value", "second-value"])
        );
        assert_eq!(first_transport.paths.lock().unwrap().len(), 1);
        assert_eq!(second_transport.paths.lock().unwrap().len(), 1);
        assert_eq!(fixture.finish().len(), 2);
    }

    #[test]
    fn key_vault_provider_cache_enforces_host_cap_before_authentication() {
        let provider = provider("aac://shared?auth=connection_string");
        let mut vaults = provider.vaults.lock().unwrap();
        for index in 0..MAX_VAULT_CLIENTS {
            let host = format!("vault-{index}.vault.azure.net");
            let config = super::super::akv::AkvConfig::from_validated_vault_host(
                host.clone(),
                super::super::akv::AuthMethod::Env,
            );
            vaults.insert(host, Arc::new(super::super::akv::AkvProvider::new(config)));
        }
        drop(vaults);

        let reference = VaultReference {
            canonical_uri: "https://overflow.vault.azure.net/secrets/api-key/".to_string(),
            vault_host: "overflow.vault.azure.net".to_string(),
            secret_name: "api-key".to_string(),
            version: None,
        };
        let error = provider.vault_provider(&reference).err().unwrap();
        assert!(
            error.to_string().contains("at most 16 Key Vault hosts"),
            "{error}"
        );
        assert!(provider.key_vault_credential.get().is_none());
    }

    #[test]
    fn native_addresses_have_no_write_target() {
        let provider = provider("aac://shared");
        let address = NativeAddress {
            item: "shared-key".to_string(),
            ..Default::default()
        };
        let writable = provider
            .check_writable(Address::Native(&address))
            .unwrap_err()
            .to_string();
        let described = provider
            .describe_write_target(Address::Native(&address))
            .unwrap_err()
            .to_string();
        assert_eq!(described, writable);

        let deletable = provider
            .check_deletable(Address::Native(&address))
            .unwrap_err()
            .to_string();
        let deleted = provider
            .delete(Address::Native(&address))
            .unwrap_err()
            .to_string();
        assert_eq!(deleted, deletable);
    }

    #[test]
    fn continuation_must_preserve_endpoint_and_scope() {
        let provider = provider("aac://shared?label=prod&tag=app=payments");
        let initial = provider
            .list_url(DiscoveryContext::new("checkout", "prod"))
            .unwrap();
        let mut valid = initial.clone();
        valid.query_pairs_mut().append_pair("After", "cursor");
        let valid = safe_request_target(&valid);
        assert!(provider.validate_continuation(&initial, &valid).is_ok());

        assert!(
            provider
                .validate_continuation(&initial, initial.as_str())
                .unwrap_err()
                .to_string()
                .contains("absolute continuation")
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
    fn test_http_escape_hatch_is_loopback_only_and_explicit() {
        let mut provider = provider("aac://shared");
        provider.config.endpoint = "http://127.0.0.1:9/".to_string();
        let loopback = Url::parse("http://127.0.0.1:9/kv?api-version=2026-04-01").unwrap();
        let error =
            super::super::block_on(provider.send(Method::GET, loopback, None, None)).unwrap_err();
        assert!(error.to_string().contains("outside configured HTTPS"));

        provider.allow_insecure_loopback = true;
        provider.config.endpoint = "http://localhost:9/".to_string();
        let localhost = Url::parse("http://localhost:9/kv?api-version=2026-04-01").unwrap();
        let error =
            super::super::block_on(provider.send(Method::GET, localhost, None, None)).unwrap_err();
        assert!(error.to_string().contains("outside configured HTTPS"));
    }

    #[test]
    fn reflection_follows_same_scope_pages_without_fetching_values() {
        let fixture = HttpFixture::start(|endpoint| {
            let next = discovery_target(endpoint, Some("cursor"));
            vec![
                StubResponse::json(
                    200,
                    json!({
                        "items": [{
                            "key": "secretspec:checkout:prod:DATABASE_URL",
                            "label": null,
                            "content_type": null
                        }],
                        "@nextLink": next
                    }),
                ),
                StubResponse::json(
                    200,
                    json!({
                        "items": [{
                            "key": "secretspec:checkout:prod:API_KEY",
                            "label": null,
                            "content_type": null
                        }]
                    }),
                ),
            ]
        });
        let provider = fixture_provider(&fixture.endpoint, "aac://shared");
        let declarations = super::super::block_on(
            provider.reflect_async(DiscoveryContext::new("checkout", "prod")),
        )
        .unwrap();
        assert_eq!(
            declarations.keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from(["API_KEY".to_string(), "DATABASE_URL".to_string()])
        );

        let requests = fixture.finish();
        assert_eq!(requests.len(), 2);
        let mut cursors = Vec::new();
        for request in requests {
            assert_eq!(request.method, "GET");
            assert!(request.body.is_empty());
            let url = provider
                .endpoint_url()
                .unwrap()
                .join(&request.target)
                .unwrap();
            assert_eq!(url.path(), "/kv");
            assert_eq!(
                url.query_pairs()
                    .find(|(name, _)| name == "$select")
                    .map(|(_, value)| value.into_owned()),
                Some("key,label,content_type".to_string())
            );
            cursors.push(
                url.query_pairs()
                    .find(|(name, _)| name.eq_ignore_ascii_case("after"))
                    .map(|(_, value)| value.into_owned()),
            );
        }
        assert_eq!(cursors, [None, Some("cursor".to_string())]);
    }

    #[test]
    fn reflection_rejects_cyclic_continuation_before_another_request() {
        let fixture = HttpFixture::start(|endpoint| {
            vec![StubResponse::json(
                200,
                json!({
                    "items": [],
                    "@nextLink": discovery_target(endpoint, None)
                }),
            )]
        });
        let provider = fixture_provider(&fixture.endpoint, "aac://shared");
        let error = super::super::block_on(
            provider.reflect_async(DiscoveryContext::new("checkout", "prod")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("cyclic continuation"), "{error}");
        assert_eq!(fixture.finish().len(), 1);
    }

    #[test]
    fn reflection_rejects_broadened_continuation_before_another_request() {
        let fixture = HttpFixture::start(|_| {
            vec![StubResponse::json(
                200,
                json!({
                    "items": [],
                    "@nextLink": "/kv?api-version=2026-04-01&After=cursor"
                }),
            )]
        });
        let provider = fixture_provider(&fixture.endpoint, "aac://shared");
        let error = super::super::block_on(
            provider.reflect_async(DiscoveryContext::new("checkout", "prod")),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("broadened discovery filters"),
            "{error}"
        );
        assert_eq!(fixture.finish().len(), 1);
    }

    #[test]
    fn key_vault_selection_and_resolution_errors_include_appconfig_context() {
        let provider = provider("aac://shared?auth=connection_string");
        let record = |value: &str| KeyValue {
            etag: Some("etag".to_string()),
            key: "reference".to_string(),
            label: None,
            content_type: Some(format!("{KEY_VAULT_REFERENCE_TYPE};charset=utf-8")),
            value: Some(value.to_string()),
            tags: BTreeMap::new(),
            description: None,
            locked: false,
        };
        let error = match provider.select_record("payments-key", record("not-json")) {
            Err(error) => error,
            Ok(_) => panic!("malformed reference was accepted"),
        };
        assert!(
            error.to_string().contains(
                "invalid Key Vault reference in Azure App Configuration key 'payments-key'"
            ),
            "{error}"
        );

        provider
            .auth
            .set(ResolvedAuth::ConnectionString(ConnectionStringAuth {
                id: "fixture-id".to_string(),
                secret: AzureSecret::new("c2lnbmluZy1zZWNyZXQ=".to_string()),
            }))
            .map_err(|_| ())
            .unwrap();
        let selected = provider
            .select_record(
                "payments-key",
                record(r#"{"uri":"https://payments.vault.azure.net/secrets/api-key"}"#),
            )
            .unwrap();
        let SelectedValue::Reference { key, reference } = selected else {
            panic!("expected Key Vault reference");
        };
        let error = provider
            .resolve_selected_reference(&key, &reference)
            .unwrap_err();
        assert!(
            error.to_string().contains(
                "failed to resolve Key Vault reference from Azure App Configuration key 'payments-key' through vault 'payments.vault.azure.net'"
            ),
            "{error}"
        );
        assert!(
            error.to_string().contains("require key_vault_auth"),
            "{error}"
        );
    }

    #[test]
    fn reflection_skips_foreign_keys_and_rejects_invalid_in_scope_names() {
        let provider = provider("aac://shared?prefix=payments%3A");
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
        assert_eq!(declaration.required_setting(), Some(true));
        assert!(
            provider
                .declaration_from_record(
                    context,
                    record("payments:secretspec:checkout:prod:api-key", None),
                )
                .is_err()
        );
        let error = provider
            .declaration_from_record(
                context,
                record("payments:secretspec:checkout:prod:defaults", None),
            )
            .unwrap_err();
        assert!(error.to_string().contains("defaults"), "{error}");
        let error = provider
            .declaration_from_record(
                context,
                record("payments:secretspec:checkout:prod:API:KEY", None),
            )
            .unwrap_err();
        assert!(error.to_string().contains("nested"), "{error}");
    }
}
