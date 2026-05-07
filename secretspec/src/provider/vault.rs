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

use super::{Provider, ProviderUrl};
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

        // Mount path from URL path (strip leading slash, default to "secret")
        let path = url.path();
        let mount = path
            .trim_start_matches('/')
            .split('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("secret")
            .to_string();

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
}

crate::register_provider! {
    struct: VaultProvider,
    config: VaultConfig,
    name: "vault",
    description: "HashiCorp Vault / OpenBao secret management",
    schemes: ["vault", "openbao"],
    examples: ["vault://vault.example.com:8200/secret", "openbao://bao.internal:8200/secret"],
}

impl VaultProvider {
    /// Creates a new VaultProvider with the given configuration.
    pub fn new(config: VaultConfig) -> Self {
        Self { config }
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
            AuthMethod::Token => Self::resolve_token_auth(),
            AuthMethod::AppRole => super::block_on(self.resolve_approle_auth()),
        }
    }

    /// Resolves a token via static token sources.
    fn resolve_token_auth() -> Result<SecretString> {
        if let Ok(token) = std::env::var("VAULT_TOKEN") {
            if !token.is_empty() {
                return Ok(SecretString::new(token.into()));
            }
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
            "No Vault token found. Set the VAULT_TOKEN environment variable \
             or create a ~/.vault-token file."
                .to_string(),
        ))
    }

    /// Authenticates via AppRole and returns a client token.
    async fn resolve_approle_auth(&self) -> Result<SecretString> {
        let role_id = std::env::var("VAULT_ROLE_ID").map_err(|_| {
            SecretSpecError::ProviderOperationFailed(
                "VAULT_ROLE_ID environment variable is required for AppRole authentication."
                    .to_string(),
            )
        })?;

        let secret_id = std::env::var("VAULT_SECRET_ID").map_err(|_| {
            SecretSpecError::ProviderOperationFailed(
                "VAULT_SECRET_ID environment variable is required for AppRole authentication."
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

    /// Retrieves a secret from Vault asynchronously.
    async fn get_secret_async(
        &self,
        project: &str,
        key: &str,
        profile: &str,
    ) -> Result<Option<SecretString>> {
        let secret_path = Self::format_secret_path(project, profile, key)?;
        let url = self.build_url(&secret_path);
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
                        .and_then(|d| d.get("value"))
                        .and_then(|v| v.as_str()),
                    KvVersion::V1 => body
                        .get("data")
                        .and_then(|d| d.get("value"))
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

    /// Writes a secret to Vault asynchronously.
    async fn set_secret_async(
        &self,
        project: &str,
        key: &str,
        value: &SecretString,
        profile: &str,
    ) -> Result<()> {
        let secret_path = Self::format_secret_path(project, profile, key)?;
        let url = self.build_url(&secret_path);
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
    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let mut uri = format!(
            "vault://{}",
            self.config
                .endpoint
                .trim_start_matches("https://")
                .trim_start_matches("http://")
        );
        if self.config.mount != "secret" {
            uri.push('/');
            uri.push_str(&self.config.mount);
        }
        uri
    }

    fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<SecretString>> {
        super::block_on(self.get_secret_async(project, key, profile))
    }

    fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()> {
        super::block_on(self.set_secret_async(project, key, value, profile))
    }

    fn allows_set(&self) -> bool {
        true
    }
}
