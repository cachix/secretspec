//! Cloudflare Secrets Store provider.
//!
//! Cloudflare's management API deliberately never returns stored plaintext, so
//! this provider is write-only. It publishes, replaces, deletes, and discovers
//! account-level secret names through the REST API. Authentication comes from
//! an `api_token` provider credential, `CLOUDFLARE_API_TOKEN`, or Wrangler's
//! current OAuth/API credentials via `wrangler auth token --json`.

use super::{Address, DiscoveryContext, Provider, ProviderCredentials, ProviderUrl};
use crate::SecretBytes;
use crate::config::NativeAddress;
use crate::{Result, Secret, SecretSpecError};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::borrow::Cow;
use std::collections::HashMap;
use std::io;
use std::process::Command;

const API_TOKEN: &str = "api_token";
const API_TOKEN_ENV: &str = "CLOUDFLARE_API_TOKEN";
const ACCOUNT_ID_ENV: &str = "CLOUDFLARE_ACCOUNT_ID";
const WRANGLER_PATH_ENV: &str = "SECRETSPEC_WRANGLER_PATH";
const API_BASE: &str = "https://api.cloudflare.com/client/v4";
const MAX_SECRET_BYTES: usize = 65_536;
const DEFAULT_SCOPE: &str = "workers";
const KNOWN_SCOPES: &[&str] = &[
    "workers",
    "ai_gateway",
    "dex",
    "access",
    "containers",
    "websearch",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudflareAuth {
    Auto,
    Token,
    Wrangler,
}

/// Configuration for one account-level Cloudflare Secrets Store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareConfig {
    pub store_id: String,
    pub account_id: Option<String>,
    pub scopes: Vec<String>,
    pub auth: CloudflareAuth,
    pub wrangler_profile: Option<String>,
}

impl TryFrom<&ProviderUrl> for CloudflareConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "cloudflare" {
            return Err(operation_error(format!(
                "Invalid scheme '{}' for cloudflare provider",
                url.scheme()
            )));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(operation_error(
                "cloudflare:// does not accept credentials in URI userinfo; use the api_token provider credential",
            ));
        }
        let store_id = url.host().filter(|value| !value.is_empty()).ok_or_else(|| {
            operation_error(
                "cloudflare provider requires a Secrets Store ID, for example cloudflare://0123456789abcdef0123456789abcdef",
            )
        })?;
        validate_cloudflare_id("Secrets Store ID", &store_id)?;
        if !url.path().trim_matches('/').is_empty() {
            return Err(operation_error(
                "cloudflare:// takes no path; put the Secrets Store ID in the URI authority",
            ));
        }

        let mut account_id = None;
        let mut scopes = None;
        let mut auth = None;
        let mut wrangler_profile = None;
        for (key, value) in url.query_pairs() {
            let value = value.into_owned();
            let duplicate = match key.as_ref() {
                "account_id" => set_once(&mut account_id, value),
                "scopes" => set_once(&mut scopes, value),
                "auth" => set_once(&mut auth, value),
                "wrangler_profile" => set_once(&mut wrangler_profile, value),
                unknown => {
                    return Err(operation_error(format!(
                        "unknown cloudflare query parameter '{unknown}'; supported parameters are `account_id`, `scopes`, `auth`, and `wrangler_profile`"
                    )));
                }
            };
            if duplicate {
                return Err(operation_error(format!(
                    "duplicate cloudflare query parameter '{key}'"
                )));
            }
        }

        let account_id = account_id.filter(|value| !value.is_empty());
        if let Some(account_id) = &account_id {
            validate_cloudflare_id("account ID", account_id)?;
        }
        let scopes = parse_scopes(scopes.as_deref().unwrap_or(DEFAULT_SCOPE))?;
        let auth = match auth.as_deref().unwrap_or("auto") {
            "auto" => CloudflareAuth::Auto,
            "token" => CloudflareAuth::Token,
            "wrangler" => CloudflareAuth::Wrangler,
            value => {
                return Err(operation_error(format!(
                    "cloudflare auth must be `auto`, `token`, or `wrangler`, not '{value}'"
                )));
            }
        };
        let wrangler_profile = wrangler_profile.filter(|value| !value.is_empty());
        if wrangler_profile.is_some() && auth != CloudflareAuth::Wrangler {
            return Err(operation_error(
                "cloudflare `wrangler_profile` requires `auth=wrangler`",
            ));
        }

        Ok(Self {
            store_id,
            account_id,
            scopes,
            auth,
            wrangler_profile,
        })
    }
}

fn set_once(slot: &mut Option<String>, value: String) -> bool {
    if slot.is_some() {
        true
    } else {
        *slot = Some(value);
        false
    }
}

fn parse_scopes(value: &str) -> Result<Vec<String>> {
    let mut scopes = Vec::new();
    for scope in value.split(',') {
        let scope = scope.trim();
        if scope.is_empty() {
            return Err(operation_error(
                "cloudflare scopes cannot contain an empty name",
            ));
        }
        if !KNOWN_SCOPES.contains(&scope) {
            return Err(operation_error(format!(
                "unknown Cloudflare Secrets Store scope '{scope}'; supported scopes are {}",
                KNOWN_SCOPES.join(", ")
            )));
        }
        if !scopes.iter().any(|existing| existing == scope) {
            scopes.push(scope.to_string());
        }
    }
    Ok(scopes)
}

fn validate_cloudflare_id(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(operation_error(format!(
            "Cloudflare {label} must be at most 32 ASCII letters, digits, hyphens, or underscores"
        )));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct ListedSecret {
    id: String,
    name: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct ResultInfo {
    total_pages: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ApiMessage {
    code: Option<u64>,
    message: String,
}

#[derive(Debug, Deserialize)]
struct ApiEnvelope<T> {
    success: bool,
    result: Option<T>,
    #[serde(default)]
    errors: Vec<ApiMessage>,
    result_info: Option<ResultInfo>,
}

#[derive(Debug, Serialize)]
struct CreateSecret<'a> {
    name: &'a str,
    scopes: &'a [String],
    value: &'a str,
}

#[derive(Debug, Serialize)]
struct UpdateSecret<'a> {
    scopes: &'a [String],
    value: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WranglerCredentials {
    ApiToken { token: String },
    Oauth { token: String },
    ApiKey { key: String, email: String },
}

/// A write-only Cloudflare account Secrets Store provider.
pub struct CloudflareProvider {
    config: CloudflareConfig,
    credentials: ProviderCredentials,
    api_base: String,
    wrangler_binary_path: String,
}

crate::register_provider! {
    struct: CloudflareProvider,
    config: CloudflareConfig,
    metadata: &super::catalog::CLOUDFLARE,
}

impl CloudflareProvider {
    pub fn new(config: CloudflareConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
            api_base: API_BASE.to_string(),
            wrangler_binary_path: std::env::var(WRANGLER_PATH_ENV)
                .unwrap_or_else(|_| "wrangler".to_string()),
        }
    }

    fn account_id(&self) -> Result<String> {
        let account_id = self
            .config
            .account_id
            .clone()
            .or_else(|| super::preferred_env(&[ACCOUNT_ID_ENV]))
            .ok_or_else(|| {
                operation_error(format!(
                    "No Cloudflare account ID found. Add `?account_id=...` to the provider URI or set {ACCOUNT_ID_ENV}."
                ))
            })?;
        validate_cloudflare_id("account ID", &account_id)?;
        Ok(account_id)
    }

    fn api_token(&self) -> Option<String> {
        super::credential_or_env(&self.credentials, API_TOKEN, API_TOKEN_ENV)
    }

    fn wrangler_credentials(&self) -> Result<WranglerCredentials> {
        let mut command = Command::new(&self.wrangler_binary_path);
        command.args(["auth", "token", "--json"]);
        if let Some(profile) = &self.config.wrangler_profile {
            command.args(["--profile", profile]);
        }
        let output = command
            .output()
            .map_err(|error| self.wrangler_spawn_error(error))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(operation_error(format!(
                "wrangler could not resolve Cloudflare credentials: {}",
                if stderr.trim().is_empty() {
                    "command exited unsuccessfully"
                } else {
                    stderr.trim()
                }
            )));
        }
        serde_json::from_slice(&output.stdout).map_err(|error| {
            operation_error(format!(
                "wrangler auth token --json returned invalid credentials JSON: {error}"
            ))
        })
    }

    fn wrangler_spawn_error(&self, error: io::Error) -> SecretSpecError {
        if error.kind() == io::ErrorKind::NotFound {
            operation_error(format!(
                "wrangler executable '{}' was not found; configure the `{API_TOKEN}` provider credential, set {API_TOKEN_ENV}, install Wrangler, or select it with {WRANGLER_PATH_ENV}",
                self.wrangler_binary_path
            ))
        } else {
            operation_error(format!(
                "failed to execute '{}': {error}",
                self.wrangler_binary_path
            ))
        }
    }

    fn auth_headers(&self) -> Result<HeaderMap> {
        let credentials = match self.config.auth {
            CloudflareAuth::Auto => self.api_token().map_or_else(
                || self.wrangler_credentials(),
                |token| Ok(WranglerCredentials::ApiToken { token }),
            )?,
            CloudflareAuth::Token => WranglerCredentials::ApiToken {
                token: self.api_token().ok_or_else(|| {
                    operation_error(format!(
                        "Cloudflare auth=token requires the `{API_TOKEN}` provider credential or {API_TOKEN_ENV}"
                    ))
                })?,
            },
            CloudflareAuth::Wrangler => self.wrangler_credentials()?,
        };

        let mut headers = HeaderMap::new();
        match credentials {
            WranglerCredentials::ApiToken { token } | WranglerCredentials::Oauth { token } => {
                let mut value =
                    HeaderValue::from_str(&format!("Bearer {token}")).map_err(|error| {
                        operation_error(format!("invalid Cloudflare token: {error}"))
                    })?;
                value.set_sensitive(true);
                headers.insert(AUTHORIZATION, value);
            }
            WranglerCredentials::ApiKey { key, email } => {
                let mut key = HeaderValue::from_str(&key).map_err(|error| {
                    operation_error(format!("invalid Cloudflare API key: {error}"))
                })?;
                key.set_sensitive(true);
                let email = HeaderValue::from_str(&email).map_err(|error| {
                    operation_error(format!("invalid Cloudflare account email: {error}"))
                })?;
                headers.insert(HeaderName::from_static("x-auth-key"), key);
                headers.insert(HeaderName::from_static("x-auth-email"), email);
            }
        }
        Ok(headers)
    }

    fn client(&self) -> Result<reqwest::Client> {
        reqwest::Client::builder()
            .default_headers(self.auth_headers()?)
            // Account-secret values must remain confined to Cloudflare's fixed
            // API origin. In particular, never replay a PATCH/POST body after
            // a 307/308 redirect to an origin selected by a response.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| {
                operation_error(format!(
                    "failed to build Cloudflare HTTP client: {}",
                    crate::error::display_error_chain(&error)
                ))
            })
    }

    fn secrets_url(&self, account_id: &str) -> String {
        format!(
            "{}/accounts/{account_id}/secrets_store/stores/{}/secrets",
            self.api_base.trim_end_matches('/'),
            self.config.store_id
        )
    }

    fn secret_name<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, str>> {
        let name = super::flat_item(self, addr)?;
        if name.is_empty() || name.chars().any(char::is_whitespace) || name.contains('\0') {
            return Err(operation_error(format!(
                "'{name}' is not a valid Cloudflare secret name: names must be non-empty and cannot contain whitespace or NUL"
            )));
        }
        Ok(name)
    }

    async fn list_secrets(
        &self,
        client: &reqwest::Client,
        account_id: &str,
        search: Option<&str>,
    ) -> Result<Vec<ListedSecret>> {
        let url = self.secrets_url(account_id);
        let mut page = 1_u64;
        let mut listed = Vec::new();
        loop {
            let page_string = page.to_string();
            let mut query = vec![("page", page_string.as_str()), ("per_page", "100")];
            if let Some(search) = search {
                query.push(("search", search));
            }
            let response = client
                .get(&url)
                .query(&query)
                .send()
                .await
                .map_err(|error| reach_error("listing secrets", error))?;
            let envelope: ApiEnvelope<Vec<ListedSecret>> =
                parse_envelope(response, "listing secrets").await?;
            let page_results = envelope.result.ok_or_else(|| {
                operation_error("Cloudflare returned no result while listing secrets")
            })?;
            let result_count = page_results.len();
            listed.extend(
                page_results
                    .into_iter()
                    .filter(|secret| secret.status != "deleted"),
            );
            let total_pages = envelope
                .result_info
                .and_then(|info| info.total_pages)
                .unwrap_or_else(|| if result_count < 100 { page } else { page + 1 });
            if page >= total_pages || result_count == 0 {
                break;
            }
            page += 1;
        }
        Ok(listed)
    }

    async fn lookup_secret(
        &self,
        client: &reqwest::Client,
        account_id: &str,
        name: &str,
    ) -> Result<Option<ListedSecret>> {
        let mut exact = self
            .list_secrets(client, account_id, Some(name))
            .await?
            .into_iter()
            .filter(|secret| secret.name == name);
        let found = exact.next();
        if exact.next().is_some() {
            return Err(operation_error(format!(
                "Cloudflare returned more than one active secret named '{name}'"
            )));
        }
        Ok(found)
    }

    async fn update_secret(
        &self,
        client: &reqwest::Client,
        account_id: &str,
        secret_id: &str,
        value: &str,
    ) -> Result<()> {
        validate_cloudflare_id("secret ID", secret_id)?;
        let url = format!("{}/{}", self.secrets_url(account_id), secret_id);
        let response = client
            .patch(url)
            .json(&UpdateSecret {
                scopes: &self.config.scopes,
                value,
            })
            .send()
            .await
            .map_err(|error| reach_error("updating secret", error))?;
        let _: ApiEnvelope<serde_json::Value> = parse_envelope(response, "updating secret").await?;
        Ok(())
    }

    async fn set_async(&self, name: &str, value: &SecretBytes) -> Result<()> {
        let value = super::require_utf8("cloudflare", value)?;
        let account_id = self.account_id()?;
        let client = self.client()?;
        if let Some(existing) = self.lookup_secret(&client, &account_id, name).await? {
            return self
                .update_secret(&client, &account_id, &existing.id, value)
                .await;
        }

        let response = client
            .post(self.secrets_url(&account_id))
            .json(&[CreateSecret {
                name,
                scopes: &self.config.scopes,
                value,
            }])
            .send()
            .await
            .map_err(|error| reach_error("creating secret", error))?;
        if response.status() == reqwest::StatusCode::CONFLICT {
            if let Some(existing) = self.lookup_secret(&client, &account_id, name).await? {
                return self
                    .update_secret(&client, &account_id, &existing.id, value)
                    .await;
            }
            return Err(operation_error(format!(
                "Cloudflare reported a conflict creating secret '{name}', but the secret could not be found for an update"
            )));
        }
        let _: ApiEnvelope<Vec<ListedSecret>> = parse_envelope(response, "creating secret").await?;
        Ok(())
    }

    async fn delete_async(&self, name: &str) -> Result<bool> {
        let account_id = self.account_id()?;
        let client = self.client()?;
        let Some(existing) = self.lookup_secret(&client, &account_id, name).await? else {
            return Ok(false);
        };
        validate_cloudflare_id("secret ID", &existing.id)?;
        let url = format!("{}/{}", self.secrets_url(&account_id), existing.id);
        let response = client
            .delete(url)
            .send()
            .await
            .map_err(|error| reach_error("deleting secret", error))?;
        let _: ApiEnvelope<serde_json::Value> = parse_envelope(response, "deleting secret").await?;
        Ok(true)
    }
}

impl Provider for CloudflareProvider {
    /// The selected store supplies project/environment isolation; convention
    /// writes use the SecretSpec key directly as the account-secret name.
    fn convention_address(
        &self,
        _project: &str,
        _profile: &str,
        key: &str,
    ) -> Result<NativeAddress> {
        Ok(NativeAddress {
            item: key.to_string(),
            ..Default::default()
        })
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let mut query = Vec::new();
        if let Some(account_id) = &self.config.account_id {
            query.push(format!(
                "account_id={}",
                ProviderUrl::encode_query(account_id)
            ));
        }
        if self.config.scopes != [DEFAULT_SCOPE] {
            query.push(format!(
                "scopes={}",
                ProviderUrl::encode_query(&self.config.scopes.join(","))
            ));
        }
        match self.config.auth {
            CloudflareAuth::Auto => {}
            CloudflareAuth::Token => query.push("auth=token".to_string()),
            CloudflareAuth::Wrangler => query.push("auth=wrangler".to_string()),
        }
        if let Some(profile) = &self.config.wrangler_profile {
            query.push(format!(
                "wrangler_profile={}",
                ProviderUrl::encode_query(profile)
            ));
        }
        let base = format!("cloudflare://{}", self.config.store_id);
        if query.is_empty() {
            base
        } else {
            format!("{base}?{}", query.join("&"))
        }
    }

    fn storage_identity(&self) -> String {
        let account_id = self
            .config
            .account_id
            .clone()
            .or_else(|| super::preferred_env(&[ACCOUNT_ID_ENV]))
            .unwrap_or_default();
        format!("cloudflare://{account_id}/{}", self.config.store_id)
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
        let _ = self.secret_name(addr)?;
        Err(operation_error(
            "Cloudflare Secrets Store is write-only at the management API: plaintext values can only be read by bound Cloudflare services; use this provider with `secretspec set`, `secretspec delete`, or `secretspec init --from`",
        ))
    }

    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        self.secret_name(addr).map(|_| ())
    }

    fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()> {
        self.check_writable(addr)?;
        if value.expose_secret().len() > MAX_SECRET_BYTES {
            return Err(operation_error(format!(
                "Cloudflare secret values cannot exceed {MAX_SECRET_BYTES} bytes"
            )));
        }
        let name = self.secret_name(addr)?;
        super::block_on(self.set_async(&name, value))
    }

    fn supports_delete(&self) -> bool {
        true
    }

    fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
        self.secret_name(addr).map(|_| ())
    }

    fn delete(&self, addr: Address<'_>) -> Result<bool> {
        self.check_deletable(addr)?;
        let name = self.secret_name(addr)?;
        super::block_on(self.delete_async(&name))
    }

    fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
        let name = self.secret_name(addr)?;
        Ok(format!(
            "Cloudflare account '{}' Secrets Store '{}' secret '{}' with scopes [{}]",
            self.account_id()?,
            self.config.store_id,
            name,
            self.config.scopes.join(", ")
        ))
    }

    fn reflect(&self, _context: DiscoveryContext<'_>) -> Result<HashMap<String, Secret>> {
        let account_id = self.account_id()?;
        let client = self.client()?;
        Ok(
            super::block_on(self.list_secrets(&client, &account_id, None))?
                .into_iter()
                .map(|listed| {
                    let name = listed.name;
                    let secret =
                        Secret::required(format!("{name} Cloudflare Secrets Store secret"));
                    (name, secret)
                })
                .collect(),
        )
    }
}

async fn parse_envelope<T: DeserializeOwned>(
    response: reqwest::Response,
    action: &str,
) -> Result<ApiEnvelope<T>> {
    let status = response.status();
    let envelope: ApiEnvelope<T> = response.json().await.map_err(|error| {
        operation_error(format!(
            "Cloudflare returned invalid JSON while {action} (HTTP {}): {}",
            status.as_u16(),
            crate::error::display_error_chain(&error)
        ))
    })?;
    if status.is_success() && envelope.success {
        return Ok(envelope);
    }
    let details = if envelope.errors.is_empty() {
        "request failed without an API error message".to_string()
    } else {
        envelope
            .errors
            .iter()
            .map(|error| match error.code {
                Some(code) => format!("{code}: {}", error.message),
                None => error.message.clone(),
            })
            .collect::<Vec<_>>()
            .join("; ")
    };
    Err(operation_error(format!(
        "Cloudflare returned HTTP {} while {action}: {details}",
        status.as_u16()
    )))
}

fn reach_error(action: &str, error: reqwest::Error) -> SecretSpecError {
    operation_error(format!(
        "failed to reach Cloudflare while {action}: {}",
        crate::error::display_error_chain(&error)
    ))
}

fn operation_error(message: impl Into<String>) -> SecretSpecError {
    SecretSpecError::ProviderOperationFailed(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use url::Url;

    const STORE: &str = "0123456789abcdef0123456789abcdef";
    const ACCOUNT: &str = "abcdef0123456789abcdef0123456789";

    #[derive(Debug)]
    struct RecordedRequest {
        line: String,
        headers: HashMap<String, String>,
        body: String,
    }

    fn config(spec: &str) -> CloudflareConfig {
        CloudflareConfig::try_from(&ProviderUrl::new(Url::parse(spec).unwrap())).unwrap()
    }

    fn provider_with_token(endpoint: SocketAddr) -> CloudflareProvider {
        let mut provider = CloudflareProvider::new(config(&format!(
            "cloudflare://{STORE}?account_id={ACCOUNT}&auth=token"
        )));
        provider.api_base = format!("http://{endpoint}");
        provider.with_credentials(ProviderCredentials::from([(
            API_TOKEN.to_string(),
            SecretBytes::new("test-token".into()),
        )]));
        provider
    }

    fn response_server(
        responses: Vec<(&'static str, &'static str)>,
    ) -> (SocketAddr, std::thread::JoinHandle<Vec<RecordedRequest>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut recorded = Vec::new();
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut headers = HashMap::new();
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    if header == "\r\n" || header.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = header.trim_end().split_once(':') {
                        headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
                    }
                }
                let content_length = headers
                    .get("content-length")
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                let mut request_body = vec![0; content_length];
                reader.read_exact(&mut request_body).unwrap();
                recorded.push(RecordedRequest {
                    line: line.trim_end().to_string(),
                    headers,
                    body: String::from_utf8(request_body).unwrap(),
                });
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
            recorded
        });
        (endpoint, server)
    }

    fn list_body(secrets: &str, total_pages: u64) -> String {
        format!(
            r#"{{"success":true,"result":{secrets},"errors":[],"result_info":{{"total_pages":{total_pages}}}}}"#
        )
    }

    #[test]
    fn parses_and_round_trips_configuration() {
        let encoded = format!(
            "cloudflare://{STORE}?account_id={ACCOUNT}&scopes=workers%2Ccontainers&auth=wrangler&wrangler_profile=production"
        );
        let canonical = format!(
            "cloudflare://{STORE}?account_id={ACCOUNT}&scopes=workers,containers&auth=wrangler&wrangler_profile=production"
        );
        let provider = CloudflareProvider::new(config(&encoded));
        assert_eq!(provider.uri(), canonical);
        assert_eq!(config(&provider.uri()), provider.config);
        assert_eq!(provider.config.scopes, ["workers", "containers"]);
    }

    #[test]
    fn rejects_invalid_configuration() {
        for spec in [
            "cloudflare://",
            &format!("cloudflare://{STORE}/path"),
            &format!("cloudflare://{STORE}?unknown=true"),
            &format!("cloudflare://{STORE}?scopes=unknown"),
            &format!("cloudflare://{STORE}?auth=bad"),
            &format!("cloudflare://{STORE}?wrangler_profile=prod"),
            &format!("cloudflare://{STORE}?auth=token&auth=auto"),
        ] {
            assert!(
                CloudflareConfig::try_from(&ProviderUrl::new(Url::parse(spec).unwrap())).is_err(),
                "{spec}"
            );
        }
    }

    #[test]
    fn convention_is_flat_and_reads_explain_the_limitation() {
        let provider = CloudflareProvider::new(config(&format!("cloudflare://{STORE}")));
        let address = provider
            .convention_address("project", "production", "DATABASE_URL")
            .unwrap();
        assert_eq!(address.item, "DATABASE_URL");
        let error = provider
            .get(Address::convention("project", "production", "DATABASE_URL"))
            .unwrap_err();
        assert!(error.to_string().contains("write-only"), "{error}");
        assert!(
            error.to_string().contains("bound Cloudflare services"),
            "{error}"
        );
    }

    #[test]
    fn registration_declares_write_only_delete_and_credentials() {
        let registration = crate::provider::PROVIDER_REGISTRY
            .iter()
            .find(|registration| registration.metadata.info.name == "cloudflare")
            .unwrap();
        assert_eq!(registration.metadata.credential_names, &[API_TOKEN]);
        assert!(!registration.metadata.reads);
        assert!(registration.metadata.deletes);
    }

    #[test]
    fn rejects_values_larger_than_cloudflares_limit_before_authentication() {
        let provider = CloudflareProvider::new(config(&format!("cloudflare://{STORE}")));
        let oversized = SecretBytes::new("x".repeat(MAX_SECRET_BYTES + 1).into());
        let error = provider
            .set(
                Address::convention("project", "production", "API_KEY"),
                &oversized,
            )
            .unwrap_err();
        assert!(error.to_string().contains("65536 bytes"), "{error}");
    }

    #[test]
    fn creates_a_missing_secret_with_bearer_auth_and_scopes() {
        let empty = Box::leak(list_body("[]", 1).into_boxed_str());
        let created = r#"{"success":true,"result":[{"id":"secret-id","name":"API_KEY","status":"pending"}],"errors":[]}"#;
        let (endpoint, server) = response_server(vec![("200 OK", empty), ("200 OK", created)]);
        let provider = provider_with_token(endpoint);

        provider
            .set(
                Address::convention("project", "production", "API_KEY"),
                &SecretBytes::new("super-secret".into()),
            )
            .unwrap();

        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].line.starts_with("GET /accounts/"));
        assert_eq!(
            requests[0].headers.get("authorization").map(String::as_str),
            Some("Bearer test-token")
        );
        assert!(requests[1].line.starts_with("POST /accounts/"));
        let body: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
        assert_eq!(body[0]["name"], "API_KEY");
        assert_eq!(body[0]["value"], "super-secret");
        assert_eq!(body[0]["scopes"], serde_json::json!(["workers"]));
    }

    #[test]
    fn updates_an_existing_secret_by_id() {
        let listed = Box::leak(
            list_body(
                r#"[{"id":"existing-id","name":"API_KEY","status":"active"}]"#,
                1,
            )
            .into_boxed_str(),
        );
        let updated = r#"{"success":true,"result":{"id":"existing-id","name":"API_KEY","status":"pending"},"errors":[]}"#;
        let (endpoint, server) = response_server(vec![("200 OK", listed), ("200 OK", updated)]);
        let provider = provider_with_token(endpoint);

        provider
            .set(
                Address::convention("project", "production", "API_KEY"),
                &SecretBytes::new("replacement".into()),
            )
            .unwrap();

        let requests = server.join().unwrap();
        assert!(requests[1].line.contains("PATCH "));
        assert!(requests[1].line.contains("/secrets/existing-id"));
        let body: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
        assert_eq!(body["value"], "replacement");
    }

    #[test]
    fn deletes_by_id_and_missing_deletion_is_idempotent() {
        let listed = Box::leak(
            list_body(
                r#"[{"id":"existing-id","name":"API_KEY","status":"active"}]"#,
                1,
            )
            .into_boxed_str(),
        );
        let deleted = r#"{"success":true,"result":null,"errors":[]}"#;
        let (endpoint, server) = response_server(vec![("200 OK", listed), ("200 OK", deleted)]);
        let provider = provider_with_token(endpoint);
        assert!(
            provider
                .delete(Address::convention("project", "production", "API_KEY"))
                .unwrap()
        );
        let requests = server.join().unwrap();
        assert!(requests[1].line.contains("DELETE "));
        assert!(requests[1].line.contains("/secrets/existing-id"));

        let empty = Box::leak(list_body("[]", 1).into_boxed_str());
        let (endpoint, server) = response_server(vec![("200 OK", empty)]);
        let provider = provider_with_token(endpoint);
        assert!(
            !provider
                .delete(Address::convention("project", "production", "MISSING"))
                .unwrap()
        );
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[test]
    fn reflection_paginates_and_excludes_deleted_entries() {
        let first = Box::leak(
            list_body(
                r#"[{"id":"1","name":"FIRST","status":"active"},{"id":"gone","name":"GONE","status":"deleted"}]"#,
                2,
            )
            .into_boxed_str(),
        );
        let second = Box::leak(
            list_body(r#"[{"id":"2","name":"SECOND","status":"pending"}]"#, 2).into_boxed_str(),
        );
        let (endpoint, server) = response_server(vec![("200 OK", first), ("200 OK", second)]);
        let provider = provider_with_token(endpoint);
        let reflected = provider
            .reflect(DiscoveryContext::new("project", "production"))
            .unwrap();
        assert!(reflected.contains_key("FIRST"));
        assert!(reflected.contains_key("SECOND"));
        assert!(!reflected.contains_key("GONE"));
        let requests = server.join().unwrap();
        assert!(requests[0].line.contains("page=1"));
        assert!(requests[1].line.contains("page=2"));
    }

    #[cfg(unix)]
    #[test]
    fn wrangler_auth_supports_oauth_and_named_profiles() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("wrangler");
        std::fs::write(
            &binary,
            r#"#!/bin/sh
printf '%s' "$*" > "$(dirname "$0")/args"
printf '%s' '{"type":"oauth","token":"oauth-token"}'
"#,
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&binary, permissions).unwrap();

        let mut provider = CloudflareProvider::new(config(&format!(
            "cloudflare://{STORE}?account_id={ACCOUNT}&auth=wrangler&wrangler_profile=production"
        )));
        provider.wrangler_binary_path = binary.to_string_lossy().into_owned();
        let headers = provider.auth_headers().unwrap();
        assert_eq!(
            headers.get(AUTHORIZATION).unwrap().to_str().unwrap(),
            "Bearer oauth-token"
        );
        assert_eq!(
            std::fs::read_to_string(directory.path().join("args")).unwrap(),
            "auth token --json --profile production"
        );
    }
}
