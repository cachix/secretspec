//! Shared HashiCorp Vault-compatible KV protocol implementation.
//!
//! Vault and OpenBao deliberately have separate provider identities and
//! configuration conventions. This module contains only the compatible KV,
//! authentication-exchange, and HTTP mechanics used by both providers.

use super::{Address, ProviderCredentials, ProviderUrl, credential_or_envs, preferred_env};
use crate::config::NativeAddress;
use crate::{Result, SecretSpecError};
use reqwest::header::{HeaderMap, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub(crate) const ROLE_ID: &str = "role_id";
pub(crate) const SECRET_ID: &str = "secret_id";
pub(crate) const TOKEN: &str = "token";

/// KV secrets engine version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub(crate) enum KvVersion {
    /// KV version 1 (no versioning).
    V1,
    /// KV version 2 (versioned, default).
    #[default]
    V2,
}

/// Authentication method for a Vault-compatible provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub(crate) enum AuthMethod {
    /// Token-based authentication.
    #[default]
    Token,
    /// AppRole authentication.
    AppRole,
    /// JWT/OIDC authentication using a role and a minted OIDC token.
    Jwt,
}

/// Product-specific identity and environment conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Each variant is constructed only when its Cargo feature is enabled.
pub(crate) enum Product {
    Vault,
    OpenBao,
}

impl Product {
    pub(crate) fn scheme(self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::OpenBao => "openbao",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Vault => "Vault",
            Self::OpenBao => "OpenBao",
        }
    }

    fn address_envs(self) -> &'static [&'static str] {
        match self {
            Self::Vault => &["VAULT_ADDR"],
            Self::OpenBao => &["BAO_ADDR", "VAULT_ADDR"],
        }
    }

    fn namespace_envs(self) -> &'static [&'static str] {
        match self {
            Self::Vault => &["VAULT_NAMESPACE"],
            Self::OpenBao => &["BAO_NAMESPACE", "VAULT_NAMESPACE"],
        }
    }

    fn token_envs(self) -> &'static [&'static str] {
        match self {
            Self::Vault => &["VAULT_TOKEN"],
            Self::OpenBao => &["BAO_TOKEN", "VAULT_TOKEN"],
        }
    }

    fn token_path_envs(self) -> &'static [&'static str] {
        match self {
            Self::Vault => &[],
            Self::OpenBao => &["BAO_TOKEN_PATH", "VAULT_TOKEN_PATH"],
        }
    }

    fn role_id_envs(self) -> &'static [&'static str] {
        match self {
            // These auth inputs are part of SecretSpec's existing provider
            // contract. Neither product's CLI reads them automatically.
            Self::Vault => &["VAULT_ROLE_ID"],
            // Give the first-class OpenBao provider its own product-scoped
            // name while retaining the old Vault-provider input as fallback.
            Self::OpenBao => &["BAO_ROLE_ID", "VAULT_ROLE_ID"],
        }
    }

    fn secret_id_envs(self) -> &'static [&'static str] {
        match self {
            Self::Vault => &["VAULT_SECRET_ID"],
            Self::OpenBao => &["BAO_SECRET_ID", "VAULT_SECRET_ID"],
        }
    }

    fn jwt_envs(self) -> &'static [&'static str] {
        match self {
            Self::Vault => &["VAULT_JWT"],
            Self::OpenBao => &["BAO_JWT", "VAULT_JWT"],
        }
    }

    fn jwt_role_envs(self) -> &'static [&'static str] {
        match self {
            Self::Vault => &["VAULT_JWT_ROLE"],
            Self::OpenBao => &["BAO_JWT_ROLE", "VAULT_JWT_ROLE"],
        }
    }

    fn jwt_audience_envs(self) -> &'static [&'static str] {
        match self {
            Self::Vault => &["VAULT_JWT_AUDIENCE"],
            Self::OpenBao => &["BAO_JWT_AUDIENCE", "VAULT_JWT_AUDIENCE"],
        }
    }
}

/// Configuration shared by the compatible Vault and OpenBao KV APIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KvConfig {
    /// HTTP origin used for API requests, including `http` or `https`.
    pub(crate) endpoint: String,
    /// KV secrets-engine mount, relative to `/v1` (default: `secret`).
    pub(crate) mount: String,
    /// KV API layout to use when constructing data paths and decoding replies.
    pub(crate) kv_version: KvVersion,
    /// Optional namespace sent in `X-Vault-Namespace`.
    pub(crate) namespace: Option<String>,
    /// Login flow used to obtain the token attached to data requests.
    pub(crate) auth: AuthMethod,
    /// Role sent to the JWT login endpoint.
    pub(crate) role: Option<String>,
    /// Audience requested when SecretSpec mints a CI OIDC token.
    pub(crate) audience: Option<String>,
}

impl Default for KvConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://127.0.0.1:8200".to_string(),
            mount: "secret".to_string(),
            kv_version: KvVersion::default(),
            namespace: None,
            auth: AuthMethod::default(),
            role: None,
            audience: None,
        }
    }
}

impl KvConfig {
    /// Parses the common URI grammar with the selected product's scheme and
    /// environment precedence.
    ///
    /// Keeping product selection explicit prevents a URI registered as
    /// `openbao://` from silently constructing a Vault-branded provider again.
    pub(crate) fn parse(url: &ProviderUrl, product: Product) -> Result<Self> {
        if url.scheme() != product.scheme() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for {} provider. Expected '{}'.",
                url.scheme(),
                product.display_name(),
                product.scheme()
            )));
        }

        // URI configuration wins over defaults. `tls=false` changes the
        // transport scheme rather than disabling certificate verification.
        let use_tls = url
            .query_pairs()
            .find(|(key, _)| key == "tls")
            .map(|(_, value)| value != "false" && value != "0")
            .unwrap_or(true);
        let http_scheme = if use_tls { "https" } else { "http" };

        // An explicit host wins. A scheme-only URI is useful in CI and falls
        // back through the product's conventional address variables.
        let endpoint = match url.host().filter(|host| !host.is_empty()) {
            Some(host) => match url.port() {
                Some(port) => format!("{http_scheme}://{host}:{port}"),
                None => format!("{http_scheme}://{host}"),
            },
            None => preferred_env(product.address_envs()).ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "No {} address provided. Specify a host in the URI (for example, \
                     {}://127.0.0.1:8200) or set {}.",
                    product.display_name(),
                    product.scheme(),
                    product.address_envs().join(" or ")
                ))
            })?,
        };
        // The provider path identifies only the engine mount. Per-secret KV
        // paths belong to convention coordinates or a secret's `ref`.
        let path = url.path();
        let trimmed = path.trim_start_matches('/').trim_end_matches('/');
        let mount = if trimmed.is_empty() {
            "secret".to_string()
        } else {
            trimmed.to_string()
        };

        // KV v2 is the safe default because it retains versions. Unknown
        // values preserve the historical v2 behavior rather than guessing v1.
        let kv_version = url
            .query_pairs()
            .find(|(key, _)| key == "kv")
            .map(|(_, value)| match value.as_ref() {
                "1" | "v1" => KvVersion::V1,
                _ => KvVersion::V2,
            })
            .unwrap_or_default();

        // URI attribution is explicit and therefore outranks environment
        // configuration. The username position mirrors the existing syntax.
        let namespace = match url.username() {
            username if !username.is_empty() => Some(username),
            _ => preferred_env(product.namespace_envs()),
        };

        // Authentication is selected independently from the product while its
        // credential sources retain product-specific environment precedence.
        let auth = url
            .query_pairs()
            .find(|(key, _)| key == "auth")
            .map(|(_, value)| match value.as_ref() {
                "approle" => Ok(AuthMethod::AppRole),
                "jwt" => Ok(AuthMethod::Jwt),
                "token" => Ok(AuthMethod::Token),
                other => Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Unknown auth method '{other}'. Expected 'token', 'approle', or 'jwt'."
                ))),
            })
            .transpose()?
            .unwrap_or_default();

        let role = url
            .query_pairs()
            .find(|(key, _)| key == "role")
            .map(|(_, value)| value.to_string())
            .or_else(|| preferred_env(product.jwt_role_envs()))
            .filter(|value| !value.is_empty());

        let audience = url
            .query_pairs()
            .find(|(key, _)| key == "audience")
            .map(|(_, value)| value.to_string())
            .or_else(|| preferred_env(product.jwt_audience_envs()))
            .filter(|value| !value.is_empty());

        // Older experiments placed a field in the provider URI. Reject it with
        // an actionable translation: a field varies per secret and belongs in
        // that secret's native reference.
        if let Some(field) = url.query_value("field") {
            let hint = crate::config::ref_table_hint(None, "<kv-path>", None, Some(&field));
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} URIs take no `field` query: address the KV entry with {hint} on the \
                 secret instead",
                product.scheme()
            )));
        }

        Ok(Self {
            endpoint,
            mount,
            kv_version,
            namespace,
            auth,
            role,
            audience,
        })
    }
}

/// Compatible KV client used behind the product-specific provider wrappers.
pub(crate) struct KvProvider {
    config: KvConfig,
    credentials: ProviderCredentials,
    product: Product,
}

impl KvProvider {
    /// Creates the shared protocol client while retaining the product identity
    /// needed for environment lookup, diagnostics, and URI serialization.
    pub(crate) fn new(config: KvConfig, product: Product) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
            product,
        }
    }

    /// Injects semantic credentials resolved from another SecretSpec provider.
    /// Explicit credentials outrank every environment fallback.
    pub(crate) fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    /// Compiles SecretSpec's logical address into one KV entry per secret.
    ///
    /// Storing one value per path makes convention writes safe: unlike a native
    /// multi-field KV entry, no unrelated fields can be overwritten.
    pub(crate) fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<NativeAddress> {
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

        Ok(NativeAddress {
            item: format!("secretspec/{project}/{profile}/{key}"),
            field: Some("value".to_string()),
            ..Default::default()
        })
    }

    /// Returns the credential-free provider URI used in audit records and
    /// fallback diagnostics.
    ///
    /// This retains the historical compact form while using the actual product
    /// scheme, which is the identity bug the first-class split fixes.
    pub(crate) fn uri(&self) -> String {
        let host = self
            .config
            .endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let mut uri = format!("{}://{host}", self.product.scheme());
        if self.config.mount != "secret" {
            uri.push('/');
            uri.push_str(&self.config.mount);
        }
        uri
    }

    /// Reads the requested field from a resolved native KV address.
    /// Convention addresses also arrive here after resolving to field `value`.
    pub(crate) fn get(&self, coords: &NativeAddress) -> Result<Option<SecretString>> {
        let Some(field) = &coords.field else {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} references need a `field`: KV entries are maps, e.g. \
                 ref = {{ item = \"myapp/config\", field = \"db_password\" }}",
                self.product.scheme()
            )));
        };
        super::block_on(self.get_field_async(&coords.item, field))
    }

    /// Writes a complete convention-owned KV entry.
    ///
    /// Callers must run [`Self::check_writable`] before reaching this method.
    pub(crate) fn set(&self, coords: &NativeAddress, value: &SecretString) -> Result<()> {
        super::block_on(self.set_secret_async(&coords.item, value))
    }

    /// Native references are read-only because the current write API replaces
    /// the full map. A future CAS/PATCH implementation could safely relax this.
    pub(crate) fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        match addr {
            Address::Convention { .. } => Ok(()),
            Address::Native(_) => Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} secret references are read-only: writing a single field would clobber the \
                 other fields at the same KV path",
                self.product.scheme()
            ))),
        }
    }

    /// Resolves a reusable client token with the configured authentication
    /// method.
    async fn resolve_token(&self) -> Result<SecretString> {
        match self.config.auth {
            AuthMethod::Token => self.resolve_token_auth(),
            AuthMethod::AppRole => self.resolve_approle_auth().await,
            AuthMethod::Jwt => self.resolve_jwt_auth().await,
        }
    }

    /// Resolves static token authentication in decreasing precedence:
    /// provider credential, product environment, configured token path, and
    /// finally the CLI-compatible `~/.vault-token` default.
    fn resolve_token_auth(&self) -> Result<SecretString> {
        if let Some(token) = credential_or_envs(&self.credentials, TOKEN, self.product.token_envs())
        {
            return Ok(SecretString::new(token.into()));
        }

        let token_path = preferred_env(self.product.token_path_envs())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .or_else(|| std::env::var_os("USERPROFILE"))
                    .map(|home| PathBuf::from(home).join(".vault-token"))
            });

        if let Some(path) = token_path
            && let Ok(token) = std::fs::read_to_string(&path)
        {
            let token = token.trim();
            if !token.is_empty() {
                return Ok(SecretString::new(token.to_string().into()));
            }
        }

        let token_path_hint = match self.product {
            Product::Vault => "create a ~/.vault-token file".to_string(),
            Product::OpenBao => {
                "set BAO_TOKEN_PATH (VAULT_TOKEN_PATH is also accepted), or create a \
                 ~/.vault-token file"
                    .to_string()
            }
        };
        Err(SecretSpecError::ProviderOperationFailed(format!(
            "No {} token found. Configure the token provider credential, set {}, {}, or {}.",
            self.product.display_name(),
            self.product.token_envs().join(" or "),
            token_path_hint,
            "authenticate with another supported method"
        )))
    }

    /// Exchanges AppRole credentials for the short-lived client token used by
    /// subsequent KV requests.
    async fn resolve_approle_auth(&self) -> Result<SecretString> {
        let role_id = credential_or_envs(&self.credentials, ROLE_ID, self.product.role_id_envs())
            .ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(format!(
                "{} role_id credential is required for AppRole authentication; configure \
                 credentials.role_id or set {}.",
                self.product.display_name(),
                self.product.role_id_envs().join(" or ")
            ))
        })?;

        let secret_id =
            credential_or_envs(&self.credentials, SECRET_ID, self.product.secret_id_envs())
                .ok_or_else(|| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "{} secret_id credential is required for AppRole authentication; configure \
                 credentials.secret_id or set {}.",
                        self.product.display_name(),
                        self.product.secret_id_envs().join(" or ")
                    ))
                })?;

        let url = format!("{}/v1/auth/approle/login", self.config.endpoint);
        let body = serde_json::json!({
            "role_id": role_id,
            "secret_id": secret_id,
        });

        let response = reqwest::Client::new()
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|error| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "{} AppRole login failed: {error}",
                    self.product.display_name()
                ))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} AppRole login returned HTTP {status}: {body}",
                self.product.display_name()
            )));
        }

        let response: serde_json::Value = response.json().await.map_err(|error| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to parse {} AppRole login response: {error}",
                self.product.display_name()
            ))
        })?;
        let token = response["auth"]["client_token"].as_str().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(format!(
                "{} AppRole login response missing auth.client_token",
                self.product.display_name()
            ))
        })?;

        Ok(SecretString::new(token.to_string().into()))
    }

    /// Exchanges a JWT and role at the standard `auth/jwt/login` endpoint.
    async fn resolve_jwt_auth(&self) -> Result<SecretString> {
        let role = self.config.role.clone().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(format!(
                "{} JWT authentication requires a role. Set `?role=` in the provider URI or {}.",
                self.product.display_name(),
                self.product.jwt_role_envs().join(" or ")
            ))
        })?;
        let jwt = self.resolve_jwt().await?;

        let url = format!("{}/v1/auth/jwt/login", self.config.endpoint);
        let body = serde_json::json!({
            "role": role,
            "jwt": jwt.expose_secret(),
        });
        let response = reqwest::Client::new()
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|error| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "{} JWT login failed: {error}",
                    self.product.display_name()
                ))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} JWT login returned HTTP {status}: {body}",
                self.product.display_name()
            )));
        }

        let response: serde_json::Value = response.json().await.map_err(|error| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to parse {} JWT login response: {error}",
                self.product.display_name()
            ))
        })?;
        let token = response["auth"]["client_token"].as_str().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(format!(
                "{} JWT login response missing auth.client_token",
                self.product.display_name()
            ))
        })?;

        Ok(SecretString::new(token.to_string().into()))
    }

    /// Sources a JWT directly from the product environment or mints one from
    /// the GitHub Actions / Forgejo Actions OIDC endpoint available to the job.
    async fn resolve_jwt(&self) -> Result<SecretString> {
        if let Some(jwt) = preferred_env(self.product.jwt_envs()) {
            return Ok(SecretString::new(jwt.into()));
        }

        let request_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL")
            .ok()
            .filter(|value| !value.is_empty());
        let request_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
            .ok()
            .filter(|value| !value.is_empty());
        let (request_url, request_token) = match (request_url, request_token) {
            (Some(url), Some(token)) => (url, token),
            _ => {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "No JWT available for {} JWT auth. Set {}, or run under a GitHub Actions / \
                     Forgejo job with `id-token` write permission.",
                    self.product.display_name(),
                    self.product.jwt_envs().join(" or ")
                )));
            }
        };

        let client = reqwest::Client::new();
        let mut request = client.get(&request_url).bearer_auth(&request_token);
        if let Some(audience) = &self.config.audience {
            request = request.query(&[("audience", audience.as_str())]);
        }
        let response = request.send().await.map_err(|error| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to request CI OIDC token: {error}"
            ))
        })?;
        if !response.status().is_success() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "CI OIDC token request returned HTTP {}",
                response.status()
            )));
        }

        let response: serde_json::Value = response.json().await.map_err(|error| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to parse CI OIDC token response: {error}"
            ))
        })?;
        let jwt = response["value"].as_str().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "CI OIDC token response missing `value`".to_string(),
            )
        })?;
        Ok(SecretString::new(jwt.to_string().into()))
    }

    /// Builds headers shared by authenticated Vault-compatible API requests.
    ///
    /// OpenBao intentionally retains the `X-Vault-*` wire names for protocol
    /// compatibility; using them does not collapse its provider identity.
    fn build_headers(&self, token: &SecretString) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Vault-Token",
            HeaderValue::from_str(token.expose_secret()).map_err(|error| {
                SecretSpecError::ProviderOperationFailed(format!("Invalid token value: {error}"))
            })?,
        );
        if let Some(namespace) = &self.config.namespace {
            headers.insert(
                "X-Vault-Namespace",
                HeaderValue::from_str(namespace).map_err(|error| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Invalid namespace value: {error}"
                    ))
                })?,
            );
        }
        Ok(headers)
    }

    /// Builds the raw API path, inserting KV v2's required `/data/` segment.
    fn build_url(&self, secret_path: &str) -> String {
        match self.config.kv_version {
            KvVersion::V2 => format!(
                "{}/v1/{}/data/{secret_path}",
                self.config.endpoint, self.config.mount
            ),
            KvVersion::V1 => format!(
                "{}/v1/{}/{secret_path}",
                self.config.endpoint, self.config.mount
            ),
        }
    }

    /// Fetches one KV entry and extracts one string field.
    ///
    /// A missing path maps to `None`, while authorization and protocol failures
    /// remain errors so a fallback chain cannot mistake them for absence.
    async fn get_field_async(
        &self,
        secret_path: &str,
        field: &str,
    ) -> Result<Option<SecretString>> {
        let url = self.build_url(secret_path);
        let token = self.resolve_token().await?;
        let response = reqwest::Client::new()
            .get(&url)
            .headers(self.build_headers(&token)?)
            .send()
            .await
            .map_err(|error| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to connect to {} at {}: {error}",
                    self.product.display_name(),
                    self.config.endpoint
                ))
            })?;

        match response.status().as_u16() {
            200 => {
                let body: serde_json::Value = response.json().await.map_err(|error| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to parse {} response: {error}",
                        self.product.display_name()
                    ))
                })?;
                let value = match self.config.kv_version {
                    KvVersion::V2 => body
                        .get("data")
                        .and_then(|data| data.get("data"))
                        .and_then(|data| data.get(field))
                        .and_then(|value| value.as_str()),
                    KvVersion::V1 => body
                        .get("data")
                        .and_then(|data| data.get(field))
                        .and_then(|value| value.as_str()),
                };
                Ok(value.map(|value| SecretString::new(value.to_string().into())))
            }
            404 => Ok(None),
            403 => Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} authentication failed (403 Forbidden). Check {} and ensure it has the \
                 required permissions.",
                self.product.display_name(),
                self.product.token_envs().join(" or ")
            ))),
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(SecretSpecError::ProviderOperationFailed(format!(
                    "{} returned HTTP {status}: {body}",
                    self.product.display_name()
                )))
            }
        }
    }

    /// Writes SecretSpec's single-field convention payload to KV.
    ///
    /// KV v2 wraps user data under `data`; KV v1 accepts the map directly.
    async fn set_secret_async(&self, secret_path: &str, value: &SecretString) -> Result<()> {
        let url = self.build_url(secret_path);
        let token = self.resolve_token().await?;
        let body = match self.config.kv_version {
            KvVersion::V2 => serde_json::json!({ "data": { "value": value.expose_secret() } }),
            KvVersion::V1 => serde_json::json!({ "value": value.expose_secret() }),
        };
        let response = reqwest::Client::new()
            .post(&url)
            .headers(self.build_headers(&token)?)
            .json(&body)
            .send()
            .await
            .map_err(|error| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to connect to {} at {}: {error}",
                    self.product.display_name(),
                    self.config.endpoint
                ))
            })?;

        match response.status().as_u16() {
            200 | 204 => Ok(()),
            403 => Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} authentication failed (403 Forbidden). Check {} and ensure it has write \
                 permissions.",
                self.product.display_name(),
                self.product.token_envs().join(" or ")
            ))),
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(SecretSpecError::ProviderOperationFailed(format!(
                    "{} returned HTTP {status} while writing secret: {body}",
                    self.product.display_name()
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openbao_environment_names_separate_cli_and_secretspec_conventions() {
        // These four names come from the OpenBao CLI itself.
        assert_eq!(Product::OpenBao.address_envs(), &["BAO_ADDR", "VAULT_ADDR"]);
        assert_eq!(
            Product::OpenBao.namespace_envs(),
            &["BAO_NAMESPACE", "VAULT_NAMESPACE"]
        );
        assert_eq!(Product::OpenBao.token_envs(), &["BAO_TOKEN", "VAULT_TOKEN"]);
        assert_eq!(
            Product::OpenBao.token_path_envs(),
            &["BAO_TOKEN_PATH", "VAULT_TOKEN_PATH"]
        );

        // These are SecretSpec provider inputs. OpenBao-prefixed names own the
        // new public contract; Vault-prefixed names preserve compatibility.
        assert_eq!(
            Product::OpenBao.role_id_envs(),
            &["BAO_ROLE_ID", "VAULT_ROLE_ID"]
        );
        assert_eq!(
            Product::OpenBao.secret_id_envs(),
            &["BAO_SECRET_ID", "VAULT_SECRET_ID"]
        );
        assert_eq!(Product::OpenBao.jwt_envs(), &["BAO_JWT", "VAULT_JWT"]);
        assert_eq!(
            Product::OpenBao.jwt_role_envs(),
            &["BAO_JWT_ROLE", "VAULT_JWT_ROLE"]
        );
        assert_eq!(
            Product::OpenBao.jwt_audience_envs(),
            &["BAO_JWT_AUDIENCE", "VAULT_JWT_AUDIENCE"]
        );
    }
}
