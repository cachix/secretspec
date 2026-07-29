//! Shared HashiCorp Vault-compatible KV protocol implementation.
//!
//! Vault and OpenBao deliberately have separate provider identities and
//! configuration conventions. This module contains only the compatible KV,
//! authentication-exchange, and HTTP mechanics used by both providers.

use super::{Address, Layout, ProviderCredentials, ProviderUrl, credential_or_envs, preferred_env};
use crate::config::NativeAddress;
use crate::{Result, SecretSpecError};
use reqwest::header::{HeaderMap, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::OnceLock;
use url::Url;

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
    /// How convention secrets map onto KV paths (SecretSpec 0.18+).
    #[serde(default)]
    pub(crate) layout: Layout,
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
            layout: Layout::Nested,
        }
    }
}

impl KvConfig {
    /// Parses an API address into the credential-free HTTP origin used for
    /// requests, diagnostics, and provider attribution.
    ///
    /// Vault-compatible address variables are URLs, but userinfo and arbitrary
    /// query parameters are not part of the server identity. Keeping the raw
    /// value would let credentials reach `Provider::uri()` and audit output.
    fn normalize_endpoint(endpoint: &str, product: Product) -> Result<String> {
        let mut endpoint = Url::parse(endpoint).map_err(|error| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Invalid {} address: {error}",
                product.display_name()
            ))
        })?;

        if !matches!(endpoint.scheme(), "http" | "https") || endpoint.host().is_none() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid {} address: expected an http:// or https:// URL with a host",
                product.display_name()
            )));
        }

        // Requests use token-based provider authentication, never URL basic
        // authentication. Retain only the origin so paths and unknown query
        // parameters cannot alter requests or leak through provider reporting.
        endpoint.set_password(None).map_err(|_| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Invalid {} address password",
                product.display_name()
            ))
        })?;
        endpoint.set_username("").map_err(|_| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Invalid {} address username",
                product.display_name()
            ))
        })?;
        endpoint.set_path("");
        endpoint.set_query(None);
        endpoint.set_fragment(None);

        Ok(endpoint.as_str().trim_end_matches('/').to_string())
    }

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
        // Both CLIs accept addresses with trailing slashes. Normalizing the
        // complete URL also strips unsupported components that must not reach
        // request paths, diagnostics, or audit records.
        let endpoint = Self::normalize_endpoint(&endpoint, product)?;

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

        // `layout` is the shared, cross-provider setting, parsed the same way
        // everywhere; an unreadable value is refused rather than guessed.
        let layout = url.layout()?;

        Ok(Self {
            endpoint,
            mount,
            kv_version,
            namespace,
            auth,
            role,
            audience,
            layout,
        })
    }
}

/// Compatible KV client used behind the product-specific provider wrappers.
pub(crate) struct KvProvider {
    config: KvConfig,
    credentials: ProviderCredentials,
    product: Product,
    /// Shared HTTP client for this provider instance.
    ///
    /// Mirrors the Infisical provider (`OnceLock` + `get_or_init`). A fresh
    /// reqwest client per request cannot reuse connections or h2 streams, so a
    /// concurrent `get_many` of dozens of secrets opens one TCP(+TLS) handshake
    /// each. Behind reverse proxies that has been observed to drop part of the
    /// burst (`Failed to connect to Vault`). One client per provider keeps the
    /// pool warm across those concurrent gets.
    http: OnceLock<reqwest::Client>,
}

impl KvProvider {
    /// Creates the shared protocol client while retaining the product identity
    /// needed for environment lookup, diagnostics, and URI serialization.
    pub(crate) fn new(config: KvConfig, product: Product) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
            product,
            http: OnceLock::new(),
        }
    }

    /// The shared HTTP client.
    fn http(&self) -> &reqwest::Client {
        self.http.get_or_init(reqwest::Client::new)
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
    ///
    /// Under the nested [`Layout`] the path is
    /// `secretspec/{project}/{profile}/{key}`. Under the flat layout the
    /// scaffolding is dropped and the secret is the `key` itself at the mount
    /// root -- the shape a store migrated from elsewhere already has.
    pub(crate) fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<NativeAddress> {
        if key.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "key cannot be empty".to_string(),
            ));
        }
        // Flat addresses by key alone, so the project and profile that name no
        // path segment are not required and are not validated.
        if self.config.layout == Layout::Flat {
            return Ok(NativeAddress {
                item: key.to_string(),
                field: Some("value".to_string()),
                ..Default::default()
            });
        }
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

        Ok(NativeAddress {
            item: format!("secretspec/{project}/{profile}/{key}"),
            field: Some("value".to_string()),
            ..Default::default()
        })
    }

    /// Returns the credential-free provider URI used in audit records and
    /// fallback diagnostics.
    ///
    /// The URI is canonical rather than source-preserving: implicit defaults
    /// stay implicit, while every setting that changes the effective store or
    /// authentication context is retained.
    pub(crate) fn uri(&self) -> String {
        let authority = self
            .config
            .endpoint
            .strip_prefix("https://")
            .or_else(|| self.config.endpoint.strip_prefix("http://"))
            .expect("KvConfig endpoints are normalized HTTP origins");
        let mut uri = Url::parse(&format!("{}://{authority}", self.product.scheme()))
            .expect("a normalized endpoint forms a provider URI");

        if let Some(namespace) = &self.config.namespace {
            uri.set_username(namespace)
                .expect("a provider URI supports namespace userinfo");
        }
        uri.set_path(&format!("/{}", self.config.mount));

        if self.config.endpoint.starts_with("http://") {
            uri.query_pairs_mut().append_pair("tls", "false");
        }
        if self.config.kv_version == KvVersion::V1 {
            uri.query_pairs_mut().append_pair("kv", "1");
        }
        match self.config.auth {
            AuthMethod::Token => {}
            AuthMethod::AppRole => {
                uri.query_pairs_mut().append_pair("auth", "approle");
            }
            AuthMethod::Jwt => {
                uri.query_pairs_mut().append_pair("auth", "jwt");
                if let Some(role) = &self.config.role {
                    uri.query_pairs_mut().append_pair("role", role);
                }
                if let Some(audience) = &self.config.audience {
                    uri.query_pairs_mut().append_pair("audience", audience);
                }
            }
        }
        if self.config.layout == Layout::Flat {
            uri.query_pairs_mut().append_pair("layout", "flat");
        }

        uri.into()
    }

    /// The map field a resolved address names, which a `ref` must state
    /// explicitly since a KV entry is a map rather than a single value.
    fn require_field<'a>(&self, coords: &'a NativeAddress) -> Result<&'a str> {
        coords.field.as_deref().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(format!(
                "{} references need a `field`: KV entries are maps, e.g. \
                 ref = {{ item = \"myapp/config\", field = \"db_password\" }}",
                self.product.scheme()
            ))
        })
    }

    /// Reads the requested field from a resolved native KV address.
    /// Convention addresses also arrive here after resolving to field `value`.
    pub(crate) fn get(&self, coords: &NativeAddress) -> Result<Option<SecretString>> {
        let field = self.require_field(coords)?;
        super::block_on(self.get_field_async(&coords.item, field))
    }

    /// Writes a complete convention-owned KV entry.
    ///
    /// Callers must run [`Self::check_writable`] before reaching this method.
    pub(crate) fn set(&self, coords: &NativeAddress, value: &SecretString) -> Result<()> {
        super::block_on(self.set_secret_async(&coords.item, value))
    }

    /// Writes a convention-owned KV entry the store itself will drop once
    /// `max_age` has passed.
    ///
    /// KV v2 computes a version's deletion time when the version is written,
    /// from the path's `delete_version_after` metadata, so the metadata is set
    /// first — and a failure to set it stops the write, since storing a value
    /// that will never expire is not what the caller asked for.
    ///
    /// KV v1 has no expiry at all, so it refuses: the alternative is an
    /// unexpiring copy of another store's secret.
    pub(crate) fn set_expiring(
        &self,
        coords: &NativeAddress,
        value: &SecretString,
        max_age: std::time::Duration,
    ) -> Result<()> {
        if self.config.kv_version == KvVersion::V1 {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} KV v1 cannot expire a secret; use a KV v2 mount to hold values with a \
                 maximum age",
                self.product.scheme()
            )));
        }
        super::block_on(async {
            self.set_version_ttl_async(&coords.item, max_age).await?;
            self.set_secret_async(&coords.item, value).await
        })
    }

    /// Destroys a convention-owned KV path, reporting whether it held anything.
    ///
    /// KV v2 deletes through the metadata endpoint, removing every version: an
    /// entry SecretSpec owns has no history worth keeping, and a soft-deleted
    /// version would leave the value recoverable. Both engines answer a delete
    /// with 204 whether or not the path existed, so existence is read first —
    /// one extra round trip on a path only cache maintenance takes.
    ///
    /// Callers must run [`Self::check_deletable`] before reaching this method.
    pub(crate) fn delete(&self, coords: &NativeAddress) -> Result<bool> {
        let field = self.require_field(coords)?;
        super::block_on(async {
            match self.config.kv_version {
                // An expired KV v2 version is no longer readable from the data
                // endpoint, but its metadata and recoverable version history
                // still exist. Check the metadata path so cache clearing
                // permanently destroys that history.
                KvVersion::V2 => {
                    if !self.metadata_exists_async(&coords.item).await? {
                        return Ok(false);
                    }
                }
                KvVersion::V1 => {
                    if self.get_field_async(&coords.item, field).await?.is_none() {
                        return Ok(false);
                    }
                }
            }
            self.delete_path_async(&coords.item).await?;
            Ok(true)
        })
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

    /// Refuses to delete a native reference. A `ref` names a KV path managed
    /// outside SecretSpec, and deletion here removes the whole path — every
    /// field, every version — so it is confined to entries SecretSpec owns.
    pub(crate) fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
        match addr {
            Address::Convention { .. } => Ok(()),
            Address::Native(_) => Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} secret references cannot be deleted: the KV path they name is managed outside \
                 SecretSpec, and deleting it would destroy every field in it",
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

        let response = self
            .build_login_request(&url, &body)?
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
        let response = self
            .build_login_request(&url, &body)?
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

        let mut request = self.http().get(&request_url).bearer_auth(&request_token);
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

    /// Builds an authentication request in the provider's configured namespace.
    ///
    /// Auth methods are mounted inside a namespace just like secrets engines,
    /// so their login exchanges need `X-Vault-Namespace` before a client token
    /// exists. Both products retain that wire name for protocol compatibility.
    fn build_login_request(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::RequestBuilder> {
        Ok(self
            .http()
            .post(url)
            .headers(self.build_namespace_headers()?)
            .json(body))
    }

    /// Builds headers shared by authenticated Vault-compatible API requests.
    ///
    /// OpenBao intentionally retains the `X-Vault-*` wire names for protocol
    /// compatibility; using them does not collapse its provider identity.
    fn build_headers(&self, token: &SecretString) -> Result<HeaderMap> {
        let mut headers = self.build_namespace_headers()?;
        headers.insert(
            "X-Vault-Token",
            HeaderValue::from_str(token.expose_secret()).map_err(|error| {
                SecretSpecError::ProviderOperationFailed(format!("Invalid token value: {error}"))
            })?,
        );
        Ok(headers)
    }

    /// Builds the namespace header used by login and authenticated requests.
    fn build_namespace_headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
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

    /// Sends a request, retrying a few times on connect/timeout errors only.
    ///
    /// Auth and HTTP status failures are not retried — those are not the
    /// reverse-proxy connection storm this targets. The builder is reconstructed
    /// each attempt because `RequestBuilder` is consumed by `send`.
    async fn send_with_connect_retry(
        &self,
        mut build: impl FnMut() -> Result<reqwest::RequestBuilder>,
    ) -> Result<reqwest::Response> {
        const ATTEMPTS: usize = 3;
        let mut last_error = None;
        for attempt in 1..=ATTEMPTS {
            let response = build()?.send().await;
            match response {
                Ok(response) => return Ok(response),
                Err(error) if attempt < ATTEMPTS && (error.is_connect() || error.is_timeout()) => {
                    last_error = Some(error);
                    // get_each already runs each get on its own thread, so a
                    // brief blocking backoff is fine and avoids a tokio/time
                    // feature dependency on the vault build.
                    std::thread::sleep(std::time::Duration::from_millis(25 * attempt as u64));
                }
                Err(error) => {
                    return Err(SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to connect to {} at {}: {error}",
                        self.product.display_name(),
                        self.config.endpoint
                    )));
                }
            }
        }
        Err(SecretSpecError::ProviderOperationFailed(format!(
            "Failed to connect to {} at {}: {}",
            self.product.display_name(),
            self.config.endpoint,
            last_error.expect("connect retry exhausted with an error")
        )))
    }

    /// Builds the KV v2 metadata path, which carries a path's version policy and
    /// is also the endpoint that removes every version at once. Meaningless for
    /// KV v1, whose data path is its only path.
    fn metadata_url(&self, secret_path: &str) -> String {
        format!(
            "{}/v1/{}/metadata/{secret_path}",
            self.config.endpoint, self.config.mount
        )
    }

    /// Whether a KV v2 path has metadata, including when every version is
    /// soft-deleted and therefore absent from the data endpoint.
    async fn metadata_exists_async(&self, secret_path: &str) -> Result<bool> {
        let url = self.metadata_url(secret_path);
        let token = self.resolve_token().await?;
        let headers = self.build_headers(&token)?;
        let response = self
            .send_with_connect_retry(|| Ok(self.http().get(&url).headers(headers.clone())))
            .await?;

        match response.status().as_u16() {
            200 => Ok(true),
            404 => Ok(false),
            403 => Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} authentication failed (403 Forbidden) reading version metadata. Check {} and \
                 ensure it has read access to metadata as well as delete permissions.",
                self.product.display_name(),
                self.product.token_envs().join(" or ")
            ))),
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(SecretSpecError::ProviderOperationFailed(format!(
                    "{} returned HTTP {status} while reading version metadata: {body}",
                    self.product.display_name()
                )))
            }
        }
    }

    /// Sets a KV v2 path's `delete_version_after`, which the engine applies when
    /// computing each subsequently written version's deletion time.
    async fn set_version_ttl_async(
        &self,
        secret_path: &str,
        max_age: std::time::Duration,
    ) -> Result<()> {
        let url = self.metadata_url(secret_path);
        let token = self.resolve_token().await?;
        // Seconds keep the request independent of how the duration was written
        // in the config (`8h` and `480m` are the same policy).
        let body = serde_json::json!({ "delete_version_after": format!("{}s", max_age.as_secs()) });
        let headers = self.build_headers(&token)?;
        let response = self
            .send_with_connect_retry(|| {
                Ok(self.http().post(&url).headers(headers.clone()).json(&body))
            })
            .await?;

        match response.status().as_u16() {
            200 | 204 => Ok(()),
            403 => Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} authentication failed (403 Forbidden) writing version metadata. A value with \
                 a maximum age needs write access to the path's metadata as well as its data.",
                self.product.display_name()
            ))),
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(SecretSpecError::ProviderOperationFailed(format!(
                    "{} returned HTTP {status} while setting version expiry: {body}",
                    self.product.display_name()
                )))
            }
        }
    }

    /// Removes a KV path outright: for v2 the metadata endpoint, which destroys
    /// every version; for v1 the data path, which is all there is.
    async fn delete_path_async(&self, secret_path: &str) -> Result<()> {
        let url = match self.config.kv_version {
            KvVersion::V2 => self.metadata_url(secret_path),
            KvVersion::V1 => self.build_url(secret_path),
        };
        let token = self.resolve_token().await?;
        let headers = self.build_headers(&token)?;
        let response = self
            .send_with_connect_retry(|| Ok(self.http().delete(&url).headers(headers.clone())))
            .await?;

        match response.status().as_u16() {
            // 404 keeps deletion idempotent: the path may have gone between the
            // existence check and this request.
            200 | 204 | 404 => Ok(()),
            403 => Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} authentication failed (403 Forbidden). Check {} and ensure it has delete \
                 permissions.",
                self.product.display_name(),
                self.product.token_envs().join(" or ")
            ))),
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(SecretSpecError::ProviderOperationFailed(format!(
                    "{} returned HTTP {status} while deleting secret: {body}",
                    self.product.display_name()
                )))
            }
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
        let headers = self.build_headers(&token)?;
        let response = self
            .send_with_connect_retry(|| Ok(self.http().get(&url).headers(headers.clone())))
            .await?;

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
        let headers = self.build_headers(&token)?;
        let response = self
            .send_with_connect_retry(|| {
                Ok(self.http().post(&url).headers(headers.clone()).json(&body))
            })
            .await?;

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
    use crate::tests::EnvVarGuard;

    fn provider_url(spec: &str) -> ProviderUrl {
        ProviderUrl::new(Url::parse(spec).unwrap())
    }

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

    #[test]
    fn environment_addresses_drop_trailing_slashes_before_request_paths_are_appended() {
        let _lock = crate::tests::scrub_resolution_env();

        {
            let _bao_addr = EnvVarGuard::set("BAO_ADDR", "http://127.0.0.1:8200/");
            let _vault_addr = EnvVarGuard::remove("VAULT_ADDR");
            let config = KvConfig::parse(&provider_url("openbao://"), Product::OpenBao).unwrap();
            let provider = KvProvider::new(config, Product::OpenBao);
            assert_eq!(
                provider.build_url("app/config"),
                "http://127.0.0.1:8200/v1/secret/data/app/config"
            );
        }

        {
            let _vault_addr = EnvVarGuard::set("VAULT_ADDR", "http://127.0.0.1:8200///");
            let config = KvConfig::parse(&provider_url("vault://"), Product::Vault).unwrap();
            let provider = KvProvider::new(config, Product::Vault);
            assert_eq!(
                provider.build_url("app/config"),
                "http://127.0.0.1:8200/v1/secret/data/app/config"
            );
        }
    }

    #[test]
    fn version_policy_and_deletion_address_the_metadata_path() {
        let _lock = crate::tests::scrub_resolution_env();
        let _vault_addr = EnvVarGuard::set("VAULT_ADDR", "http://127.0.0.1:8200");
        let config = KvConfig::parse(&provider_url("vault://"), Product::Vault).unwrap();
        let provider = KvProvider::new(config, Product::Vault);

        // A KV v2 path's version policy and its destroy-everything endpoint are
        // both the metadata path, distinct from the data path a read or write
        // uses.
        assert_eq!(
            provider.metadata_url("app/config"),
            "http://127.0.0.1:8200/v1/secret/metadata/app/config"
        );
        assert_eq!(
            provider.build_url("app/config"),
            "http://127.0.0.1:8200/v1/secret/data/app/config"
        );
    }

    #[test]
    fn kv_v2_delete_destroys_metadata_when_the_current_version_is_unreadable() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let _lock = crate::tests::scrub_resolution_env();
        let _token = EnvVarGuard::set("VAULT_TOKEN", "test-token");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut request_lines = Vec::new();
            for status in ["200 OK", "204 No Content"] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 8192];
                let read = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..read]);
                request_lines.push(request.lines().next().unwrap_or_default().to_string());
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
            }
            request_lines
        });

        let config = KvConfig::parse(
            &provider_url(&format!("vault://{endpoint}/secret?tls=false&kv=2")),
            Product::Vault,
        )
        .unwrap();
        let provider = KvProvider::new(config, Product::Vault);
        let coords = NativeAddress {
            item: "cache/API_KEY".to_string(),
            field: Some("value".to_string()),
            ..Default::default()
        };

        assert!(provider.delete(&coords).unwrap());
        assert_eq!(
            server.join().unwrap(),
            [
                "GET /v1/secret/metadata/cache/API_KEY HTTP/1.1",
                "DELETE /v1/secret/metadata/cache/API_KEY HTTP/1.1",
            ]
        );
    }

    #[test]
    fn kv_v1_refuses_to_hold_an_expiring_value() {
        let _lock = crate::tests::scrub_resolution_env();
        let _vault_addr = EnvVarGuard::remove("VAULT_ADDR");
        let config = KvConfig::parse(
            &provider_url("vault://127.0.0.1:8200/kv1?tls=false&kv=1"),
            Product::Vault,
        )
        .unwrap();
        let provider = KvProvider::new(config, Product::Vault);
        let coords = NativeAddress {
            item: "app/config".to_string(),
            field: Some("value".to_string()),
            ..Default::default()
        };

        // KV v1 has no expiry, and writing an unexpiring copy of another store's
        // secret is not what a cached route asked for. No request is made.
        let error = provider
            .set_expiring(
                &coords,
                &SecretString::new("value".to_string().into()),
                std::time::Duration::from_secs(3600),
            )
            .unwrap_err();
        assert!(error.to_string().contains("KV v1 cannot expire"), "{error}");
    }

    #[test]
    fn a_reference_is_never_deleted() {
        let _lock = crate::tests::scrub_resolution_env();
        let _vault_addr = EnvVarGuard::set("VAULT_ADDR", "http://127.0.0.1:8200");
        let config = KvConfig::parse(&provider_url("vault://"), Product::Vault).unwrap();
        let provider = KvProvider::new(config, Product::Vault);
        let reference = NativeAddress {
            item: "team/shared".to_string(),
            field: Some("db_password".to_string()),
            ..Default::default()
        };

        // Deleting removes the whole KV path, so a `ref` — a path someone else
        // manages, holding fields SecretSpec knows nothing about — is refused
        // before any request is made.
        let error = provider
            .check_deletable(Address::Native(&reference))
            .unwrap_err();
        assert!(error.to_string().contains("cannot be deleted"), "{error}");
        assert!(
            provider
                .check_deletable(Address::convention("proj", "default", "API_KEY"))
                .is_ok()
        );
    }

    #[test]
    fn environment_endpoints_drop_credentials_and_unsupported_url_components() {
        let _lock = crate::tests::scrub_resolution_env();
        let _bao_addr = EnvVarGuard::set(
            "BAO_ADDR",
            "https://alice:leaked-password@bao.example.com:8200/prefix?token=leaked-query#fragment",
        );
        let _vault_addr = EnvVarGuard::remove("VAULT_ADDR");

        let config = KvConfig::parse(&provider_url("openbao://"), Product::OpenBao).unwrap();
        assert_eq!(config.endpoint, "https://bao.example.com:8200");

        let provider = KvProvider::new(config, Product::OpenBao);
        assert_eq!(provider.uri(), "openbao://bao.example.com:8200/secret");
        assert_eq!(
            provider.build_url("app/config"),
            "https://bao.example.com:8200/v1/secret/data/app/config"
        );
        assert!(!provider.uri().contains("alice"));
        assert!(!provider.uri().contains("leaked-password"));
        assert!(!provider.uri().contains("leaked-query"));
    }

    #[test]
    fn uri_retains_effective_non_secret_attribution() {
        let config = KvConfig::parse(
            &provider_url(
                "openbao://team-a@bao.example.com:8200/team/secret?tls=false&kv=1&auth=jwt&role=ci-role&audience=deploy",
            ),
            Product::OpenBao,
        )
        .unwrap();
        let provider = KvProvider::new(config, Product::OpenBao);

        assert_eq!(
            provider.uri(),
            "openbao://team-a@bao.example.com:8200/team/secret?tls=false&kv=1&auth=jwt&role=ci-role&audience=deploy"
        );

        let approle = KvConfig::parse(
            &provider_url("openbao://team-a@bao.example.com:8200/secret?auth=approle"),
            Product::OpenBao,
        )
        .unwrap();
        assert_eq!(
            KvProvider::new(approle, Product::OpenBao).uri(),
            "openbao://team-a@bao.example.com:8200/secret?auth=approle"
        );
    }

    #[test]
    fn login_requests_include_the_configured_namespace() {
        let provider = KvProvider::new(
            KvConfig {
                endpoint: "https://bao.example.com:8200".to_string(),
                namespace: Some("team-a".to_string()),
                ..Default::default()
            },
            Product::OpenBao,
        );
        let request = provider
            .build_login_request(
                "https://bao.example.com:8200/v1/auth/approle/login",
                &serde_json::json!({ "role_id": "role", "secret_id": "secret" }),
            )
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(
            request
                .headers()
                .get("X-Vault-Namespace")
                .unwrap()
                .to_str()
                .unwrap(),
            "team-a"
        );
    }
}
