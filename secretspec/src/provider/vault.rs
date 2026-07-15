//! HashiCorp Vault / OpenBao provider
//!
//! This provider integrates with HashiCorp Vault and OpenBao to store and retrieve
//! secrets using the KV (Key-Value) secrets engine (v1 and v2).
//!
//! # Authentication
//!
//! Supports two authentication methods, selected via the `auth` query parameter:
//!
//! - Token (default) -- uses `VAULT_TOKEN` environment variable or `~/.vault-token` file
//! - AppRole (`?auth=approle`) -- uses `VAULT_ROLE_ID` and `VAULT_SECRET_ID` environment
//!   variables to perform an AppRole login
//!
//! # URI Format
//!
//! `vault://[namespace@]host[:port][/mount][?key=value&...]`
//! `openbao://[namespace@]host[:port][/mount][?key=value&...]`
//!
//! Query parameters:
//! - `auth` -- authentication method: `token` (default) or `approle`
//! - `kv` -- KV engine version: `1` or `2` (default)
//! - `tls` -- enable TLS: `true` (default) or `false`
//!
//! # Examples
//!
//! - `vault://vault.example.com:8200/secret` -- KV v2, token auth
//! - `vault://vault.example.com:8200/secret?auth=approle` -- AppRole auth
//! - `vault://ns1@vault.example.com:8200/secret` -- with Vault namespace
//! - `openbao://bao.internal:8200/secret` -- OpenBao server
//! - `vault://127.0.0.1:8200/secret?kv=1` -- KV v1 engine
//! - `vault://vault.example.com:8200/secret?tls=false` -- disable TLS (dev mode)
//!
//! When no host is provided, falls back to the `VAULT_ADDR` environment variable.
//!
//! # Secret Naming
//!
//! Secrets are stored at the path: `secretspec/{project}/{profile}/{key}`
//! Each secret is stored as a KV entry with a `value` field.
//!
//! # Example
//!
//! ```bash
//! # Set a secret
//! secretspec set DATABASE_URL --provider vault://vault.example.com:8200/secret
//!
//! # Use with a namespace
//! secretspec check --provider vault://team-a@vault.example.com:8200/secret
//! ```

use super::{Address, Provider, ProviderCredentials, ProviderUrl, credential_or_env};
use crate::{Result, SecretSpecError};
use reqwest::header::{HeaderMap, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// KV secrets engine version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KvVersion {
    /// KV version 1 (no versioning).
    V1,
    /// KV version 2 (versioned, default).
    V2,
}

impl Default for KvVersion {
    fn default() -> Self {
        KvVersion::V2
    }
}

/// Authentication method for the Vault / OpenBao provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AuthMethod {
    /// Token-based authentication via `VAULT_TOKEN` or `~/.vault-token`.
    #[default]
    Token,
    /// AppRole authentication via `VAULT_ROLE_ID` and `VAULT_SECRET_ID`.
    AppRole,
}

/// Configuration for the Vault / OpenBao provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// The Vault server endpoint URL (e.g., `https://vault.example.com:8200`).
    pub endpoint: String,
    /// The KV secrets engine mount path (default: `secret`).
    pub mount: String,
    /// The KV engine version (default: V2).
    pub kv_version: KvVersion,
    /// Optional Vault namespace.
    pub namespace: Option<String>,
    /// Authentication method (default: Token).
    pub auth: AuthMethod,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://127.0.0.1:8200".to_string(),
            mount: "secret".to_string(),
            kv_version: KvVersion::default(),
            namespace: None,
            auth: AuthMethod::default(),
        }
    }
}

impl TryFrom<&ProviderUrl> for VaultConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        let scheme = url.scheme();
        if scheme != "vault" && scheme != "openbao" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for vault provider. Expected 'vault' or 'openbao'.",
                scheme
            )));
        }

        // Determine TLS setting from query parameter (default: true)
        let use_tls = url
            .query_pairs()
            .find(|(k, _)| k == "tls")
            .map(|(_, v)| v != "false" && v != "0")
            .unwrap_or(true);

        let http_scheme = if use_tls { "https" } else { "http" };

        // Resolve endpoint: from URI host or VAULT_ADDR env var
        let endpoint = match url.host().filter(|s| !s.is_empty()) {
            Some(host) => {
                if let Some(port) = url.port() {
                    format!("{}://{}:{}", http_scheme, host, port)
                } else {
                    format!("{}://{}", http_scheme, host)
                }
            }
            None => std::env::var("VAULT_ADDR")
                .ok()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    SecretSpecError::ProviderOperationFailed(
                        "No Vault address provided. Either specify a host in the URI \
                         (e.g., vault://vault.example.com:8200) or set the VAULT_ADDR \
                         environment variable."
                            .to_string(),
                    )
                })?,
        };

        // Mount path from URL path (strip leading slash, default to "secret").
        // Mount paths may contain slashes; specific KV paths are addressed with
        // a secret's `ref`, never in the provider URI.
        let path = url.path();
        let trimmed = path.trim_start_matches('/').trim_end_matches('/');
        let mount = if trimmed.is_empty() {
            "secret".to_string()
        } else {
            trimmed.to_string()
        };

        // KV version from query parameter (default: V2)
        let kv_version = url
            .query_pairs()
            .find(|(k, _)| k == "kv")
            .map(|(_, v)| match v.as_ref() {
                "1" | "v1" => KvVersion::V1,
                _ => KvVersion::V2,
            })
            .unwrap_or_default();

        // Namespace from URI username or VAULT_NAMESPACE env var
        let namespace = {
            let username = url.username();
            if !username.is_empty() {
                Some(username)
            } else {
                std::env::var("VAULT_NAMESPACE")
                    .ok()
                    .filter(|s| !s.is_empty())
            }
        };

        let auth = url
            .query_pairs()
            .find(|(k, _)| k == "auth")
            .map(|(_, v)| match v.as_ref() {
                "approle" => Ok(AuthMethod::AppRole),
                "token" => Ok(AuthMethod::Token),
                other => Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Unknown auth method '{}'. Expected 'token' or 'approle'.",
                    other
                ))),
            })
            .transpose()?
            .unwrap_or_default();

        // The `?field=` reference form from earlier iterations is rejected
        // with a pointer at the `ref` table, instead of being silently ignored
        // and reading the conventional layout.
        if let Some(field) = url.query_value("field") {
            let hint = crate::config::ref_table_hint(None, "<kv-path>", None, Some(&field));
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "vault URIs take no `field` query: address the KV entry with \
                 {hint} on the secret instead"
            )));
        }

        Ok(Self {
            endpoint,
            mount,
            kv_version,
            namespace,
            auth,
        })
    }
}

/// HashiCorp Vault / OpenBao provider.
///
/// Stores and retrieves secrets from a Vault or OpenBao server using the
/// KV secrets engine (v1 or v2) with token-based authentication.
pub struct VaultProvider {
    config: VaultConfig,
    /// Credentials supplied by the provider alias.
    credentials: ProviderCredentials,
}

const ROLE_ID: &str = "role_id";
const SECRET_ID: &str = "secret_id";
const TOKEN: &str = "token";
const VAULT_ROLE_ID_ENV: &str = "VAULT_ROLE_ID";
const VAULT_SECRET_ID_ENV: &str = "VAULT_SECRET_ID";
const VAULT_TOKEN_ENV: &str = "VAULT_TOKEN";

crate::register_provider! {
    struct: VaultProvider,
    config: VaultConfig,
    name: "vault",
    description: "HashiCorp Vault / OpenBao secret management",
    schemes: ["vault", "openbao"],
    examples: ["vault://vault.example.com:8200/secret", "openbao://bao.internal:8200/secret"],
    credential_names: [ROLE_ID, SECRET_ID, TOKEN],
}

impl VaultProvider {
    /// Creates a new VaultProvider with the given configuration.
    pub fn new(config: VaultConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
        }
    }

    /// Formats the secret path within the KV engine.
    ///
    /// Uses the pattern: `secretspec/{project}/{profile}/{key}`
    fn format_secret_path(project: &str, profile: &str, key: &str) -> Result<String> {
        if project.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "project cannot be empty".to_string(),
            ));
        }
        if profile.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "profile cannot be empty".to_string(),
            ));
        }
        if key.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "key cannot be empty".to_string(),
            ));
        }

        Ok(format!("secretspec/{}/{}/{}", project, profile, key))
    }

    /// Resolves the Vault token using the configured authentication method.
    fn resolve_token(&self) -> Result<SecretString> {
        match self.config.auth {
            AuthMethod::Token => self.resolve_token_auth(),
            AuthMethod::AppRole => super::block_on(self.resolve_approle_auth()),
        }
    }

    /// Resolves a token via static token sources.
    fn resolve_token_auth(&self) -> Result<SecretString> {
        // `credential_or_env` never yields an empty value.
        if let Some(token) = credential_or_env(&self.credentials, TOKEN, VAULT_TOKEN_ENV) {
            return Ok(SecretString::new(token.into()));
        }

        let token_path = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(|home| std::path::PathBuf::from(home).join(".vault-token"));

        if let Some(path) = token_path {
            if let Ok(token) = std::fs::read_to_string(&path) {
                let token = token.trim();
                if !token.is_empty() {
                    return Ok(SecretString::new(token.to_string().into()));
                }
            }
        }

        Err(SecretSpecError::ProviderOperationFailed(
            "No Vault token found. Configure the token provider credential, set the \
             VAULT_TOKEN environment variable, or create a ~/.vault-token file."
                .to_string(),
        ))
    }

    /// Authenticates via AppRole and returns a client token.
    async fn resolve_approle_auth(&self) -> Result<SecretString> {
        let role_id =
            credential_or_env(&self.credentials, ROLE_ID, VAULT_ROLE_ID_ENV).ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(
                    "Vault role_id credential is required for AppRole authentication; configure \
                     credentials.role_id or set VAULT_ROLE_ID."
                        .to_string(),
                )
            })?;

        let secret_id = credential_or_env(&self.credentials, SECRET_ID, VAULT_SECRET_ID_ENV)
            .ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(
                    "Vault secret_id credential is required for AppRole authentication; configure \
                     credentials.secret_id or set VAULT_SECRET_ID."
                        .to_string(),
                )
            })?;

        let url = format!("{}/v1/auth/approle/login", self.config.endpoint);
        let body = serde_json::json!({
            "role_id": role_id,
            "secret_id": secret_id,
        });

        let client = reqwest::Client::new();
        let response = client.post(&url).json(&body).send().await.map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!("AppRole login failed: {}", e))
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "AppRole login returned HTTP {}: {}",
                status, body
            )));
        }

        let resp: serde_json::Value = response.json().await.map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to parse AppRole login response: {}",
                e
            ))
        })?;

        let token = resp["auth"]["client_token"].as_str().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "AppRole login response missing auth.client_token".to_string(),
            )
        })?;

        Ok(SecretString::new(token.to_string().into()))
    }

    /// Builds the common HTTP headers for Vault API requests.
    fn build_headers(token: &SecretString, namespace: &Option<String>) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Vault-Token",
            HeaderValue::from_str(token.expose_secret()).map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!("Invalid token value: {}", e))
            })?,
        );
        if let Some(ns) = namespace {
            headers.insert(
                "X-Vault-Namespace",
                HeaderValue::from_str(ns).map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Invalid namespace value: {}",
                        e
                    ))
                })?,
            );
        }
        Ok(headers)
    }

    /// Builds the full Vault API URL for a secret path.
    fn build_url(&self, secret_path: &str) -> String {
        match self.config.kv_version {
            KvVersion::V2 => format!(
                "{}/v1/{}/data/{}",
                self.config.endpoint, self.config.mount, secret_path
            ),
            KvVersion::V1 => format!(
                "{}/v1/{}/{}",
                self.config.endpoint, self.config.mount, secret_path
            ),
        }
    }

    /// Reads a single field from a KV path asynchronously. SecretSpec's own layout
    /// stores every secret under a `value` field; a reference reads an arbitrary
    /// field at an arbitrary path.
    async fn get_field_async(
        &self,
        secret_path: &str,
        field: &str,
    ) -> Result<Option<SecretString>> {
        let url = self.build_url(secret_path);
        let token = self.resolve_token()?;
        let headers = Self::build_headers(&token, &self.config.namespace)?;

        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to connect to Vault at {}: {}",
                    self.config.endpoint, e
                ))
            })?;

        match response.status().as_u16() {
            200 => {
                let body: serde_json::Value = response.json().await.map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to parse Vault response: {}",
                        e
                    ))
                })?;

                let value = match self.config.kv_version {
                    KvVersion::V2 => body
                        .get("data")
                        .and_then(|d| d.get("data"))
                        .and_then(|d| d.get(field))
                        .and_then(|v| v.as_str()),
                    KvVersion::V1 => body
                        .get("data")
                        .and_then(|d| d.get(field))
                        .and_then(|v| v.as_str()),
                };

                Ok(value.map(|v| SecretString::new(v.to_string().into())))
            }
            404 => Ok(None),
            403 => Err(SecretSpecError::ProviderOperationFailed(
                "Vault authentication failed (403 Forbidden). \
                 Check your VAULT_TOKEN and ensure it has the required permissions."
                    .to_string(),
            )),
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Vault returned HTTP {}: {}",
                    status, body
                )))
            }
        }
    }

    /// Writes a secret's `value` field at a KV path asynchronously.
    async fn set_secret_async(&self, secret_path: &str, value: &SecretString) -> Result<()> {
        let url = self.build_url(secret_path);
        let token = self.resolve_token()?;
        let headers = Self::build_headers(&token, &self.config.namespace)?;

        let body = match self.config.kv_version {
            KvVersion::V2 => {
                serde_json::json!({ "data": { "value": value.expose_secret() } })
            }
            KvVersion::V1 => {
                serde_json::json!({ "value": value.expose_secret() })
            }
        };

        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to connect to Vault at {}: {}",
                    self.config.endpoint, e
                ))
            })?;

        match response.status().as_u16() {
            200 | 204 => Ok(()),
            403 => Err(SecretSpecError::ProviderOperationFailed(
                "Vault authentication failed (403 Forbidden). \
                 Check your VAULT_TOKEN and ensure it has write permissions."
                    .to_string(),
            )),
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Vault returned HTTP {} while writing secret: {}",
                    status, body
                )))
            }
        }
    }
}

impl Provider for VaultProvider {
    /// Convention secrets each live at their own KV path,
    /// `secretspec/{project}/{profile}/{key}`, under a `value` field.
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: Self::format_secret_path(project, profile, key)?,
            field: Some("value".to_string()),
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
        let host = self
            .config
            .endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let mut uri = format!("vault://{}", host);
        if self.config.mount != "secret" {
            uri.push('/');
            uri.push_str(&self.config.mount);
        }
        uri
    }

    /// `field` names the key within the KV entry's map.
    fn supported_coords(&self) -> &'static [&'static str] {
        &["field"]
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let coords = self.resolve_coords(addr)?;
        // KV entries are maps; without a field there is nothing well-defined
        // to read. Convention coordinates always carry `value`.
        let Some(field) = &coords.field else {
            return Err(SecretSpecError::ProviderOperationFailed(
                "vault references need a `field`: KV entries are maps, e.g. \
                 ref = { item = \"myapp/config\", field = \"db_password\" }"
                    .to_string(),
            ));
        };
        super::block_on(self.get_field_async(&coords.item, field))
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        self.check_writable(addr)?;
        let coords = self.resolve_coords(addr)?;
        super::block_on(self.set_secret_async(&coords.item, value))
    }

    /// Native addresses are read-only: writing a single field would clobber
    /// the other fields at the same KV path.
    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        match addr {
            Address::Convention { .. } => Ok(()),
            Address::Native(_) => Err(SecretSpecError::ProviderOperationFailed(
                "vault secret references are read-only: writing a single field would \
                 clobber the other fields at the same KV path"
                    .to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod reference_tests {
    use super::*;
    use url::Url;

    fn config(s: &str) -> VaultConfig {
        VaultConfig::try_from(&ProviderUrl::new(Url::parse(s).unwrap())).unwrap()
    }

    /// The `?field=` reference form from earlier iterations errors with a
    /// pointer at the `ref` table.
    #[test]
    fn field_query_is_rejected_with_ref_hint() {
        let err = VaultConfig::try_from(&ProviderUrl::new(
            Url::parse("vault://vault.example.com:8200/secret?field=x").unwrap(),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("field = \"x\""), "{err}");
    }

    /// KV entries are maps: a native address must say which field to read.
    #[test]
    fn native_address_requires_a_field() {
        let p = VaultProvider::new(config("vault://vault.example.com:8200/secret"));
        let addr = crate::config::NativeAddress {
            item: "myapp/config".into(),
            ..Default::default()
        };
        let err = p.get(Address::Native(&addr)).unwrap_err();
        assert!(err.to_string().contains("need a `field`"), "{err}");
    }

    /// Native addresses are read-only: a field-level write would clobber the
    /// sibling fields at the KV path.
    #[test]
    fn native_address_is_read_only() {
        let p = VaultProvider::new(config("vault://vault.example.com:8200/secret"));
        let addr = crate::config::NativeAddress {
            item: "myapp/config".into(),
            field: Some("db_password".into()),
            ..Default::default()
        };
        let refusal = p.check_writable(Address::Native(&addr)).unwrap_err();
        assert!(refusal.to_string().contains("read-only"), "{refusal}");
        // `set` refuses with the same reason, so the pre-check cannot drift.
        let err = p
            .set(
                Address::Native(&addr),
                &secrecy::SecretString::new("v".into()),
            )
            .unwrap_err();
        assert_eq!(err.to_string(), refusal.to_string());
    }

    /// Version pinning is not supported for Vault KV yet; the coordinate is
    /// rejected.
    #[test]
    fn native_address_rejects_version() {
        let p = VaultProvider::new(config("vault://vault.example.com:8200/secret"));
        let addr = crate::config::NativeAddress {
            item: "myapp/config".into(),
            field: Some("db_password".into()),
            version: Some("3".into()),
            ..Default::default()
        };
        let err = p.get(Address::Native(&addr)).unwrap_err();
        assert!(err.to_string().contains("`version`"), "{err}");
    }
}
