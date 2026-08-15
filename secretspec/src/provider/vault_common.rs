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
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use url::Url;

pub(crate) const ROLE_ID: &str = "role_id";
pub(crate) const SECRET_ID: &str = "secret_id";
pub(crate) const TOKEN: &str = "token";

/// Stable runtime for the shared Vault-compatible HTTP connection pools.
///
/// `get_many` invokes its synchronous fetch closure from several OS threads.
/// Giving each closure a temporary runtime can strand a pooled reqwest
/// connection when the runtime that owns its dispatch task is dropped. One
/// process-wide runtime keeps those tasks alive across requests and providers.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create Vault-compatible HTTP runtime")
    })
}

fn block_on<F>(future: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| runtime().block_on(future))
        }
        Ok(_) => std::thread::scope(|scope| {
            let worker = scope.spawn(move || runtime().block_on(future));
            match worker.join() {
                Ok(output) => output,
                Err(panic) => std::panic::resume_unwind(panic),
            }
        }),
        Err(_) => runtime().block_on(future),
    }
}

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

impl AuthMethod {
    /// Default mount name beneath `/v1/auth` for login-based methods.
    fn default_mount(self) -> Option<&'static str> {
        match self {
            Self::Token => None,
            Self::AppRole => Some("approle"),
            Self::Jwt => Some("jwt"),
        }
    }
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
    /// Optional non-default auth-method mount beneath `/v1/auth`.
    pub(crate) auth_mount: Option<String>,
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
            auth_mount: None,
            role: None,
            audience: None,
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

        let auth_mount = url
            .query_pairs()
            .find(|(key, _)| key == "auth_mount")
            .map(|(_, value)| Self::normalize_auth_mount(&value))
            .transpose()?;
        if auth_mount.is_some() && auth == AuthMethod::Token {
            return Err(SecretSpecError::ProviderOperationFailed(
                "`auth_mount` requires `auth=approle` or `auth=jwt`; token authentication has no login mount"
                    .to_string(),
            ));
        }
        // Canonical provider URIs omit an explicitly stated default.
        let auth_mount = auth_mount.filter(|mount| Some(mount.as_str()) != auth.default_mount());

        // Empty query values follow the provider-wide convention of being
        // absent, so `?role=` still permits the environment fallback. When
        // neither source supplies a role, the JWT auth mount may select its
        // server-side `default_role` during login.
        let role = url
            .query_value("role")
            .or_else(|| preferred_env(product.jwt_role_envs()));

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
            auth_mount,
            role,
            audience,
        })
    }

    /// Normalizes a mount name relative to `/v1/auth` while preserving valid
    /// nested mount paths. Empty and dot segments are rejected so the login URL
    /// cannot escape or ambiguously address the selected mount.
    fn normalize_auth_mount(value: &str) -> Result<String> {
        let mount = value.trim_matches('/');
        if mount.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "`auth_mount` must name a mount beneath `/v1/auth`".to_string(),
            ));
        }
        if mount.chars().any(char::is_control) {
            return Err(SecretSpecError::ProviderOperationFailed(
                "`auth_mount` cannot contain control characters".to_string(),
            ));
        }
        if mount
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        {
            return Err(SecretSpecError::ProviderOperationFailed(
                "`auth_mount` cannot contain empty, `.` or `..` path segments".to_string(),
            ));
        }
        Ok(mount.to_string())
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

/// Number of authenticated requests an issued login token can still serve.
#[derive(Clone, Copy)]
enum TokenUses {
    Unlimited,
    Limited(u64),
}

/// A client token together with the use limit reported by a login response.
struct IssuedToken {
    value: SecretString,
    uses: TokenUses,
    usable_until: Option<Instant>,
}

impl IssuedToken {
    fn static_token(value: SecretString) -> Self {
        Self {
            value,
            uses: TokenUses::Unlimited,
            usable_until: None,
        }
    }

    fn login_token(
        value: SecretString,
        num_uses: Option<u64>,
        usable_until: Option<Instant>,
        lease_known: bool,
    ) -> Self {
        let uses = match num_uses {
            Some(0) => TokenUses::Unlimited,
            Some(uses) => TokenUses::Limited(uses),
            // Vault-compatible login responses normally include
            // `num_uses`. A partial response must not make us assume a
            // token is safe to reuse.
            None => TokenUses::Limited(1),
        };
        Self {
            value,
            uses: if lease_known {
                uses
            } else {
                // A partial response without `lease_duration` may describe a
                // short-lived token. Use it once, then authenticate again.
                TokenUses::Limited(1)
            },
            usable_until,
        }
    }

    fn claim(&mut self) -> Option<SecretString> {
        if self.available_uses() == 0 {
            return None;
        }
        match &mut self.uses {
            TokenUses::Unlimited => Some(self.value.clone()),
            TokenUses::Limited(0) => None,
            TokenUses::Limited(uses) => {
                *uses -= 1;
                Some(self.value.clone())
            }
        }
    }

    fn available_uses(&self) -> usize {
        if self
            .usable_until
            .is_some_and(|usable_until| Instant::now() >= usable_until)
        {
            return 0;
        }

        match self.uses {
            TokenUses::Unlimited => usize::MAX,
            TokenUses::Limited(uses) => usize::try_from(uses).unwrap_or(usize::MAX),
        }
    }
}

/// Login tokens acquired for one operation, including capacity preflighted for
/// a multi-request mutation.
struct TokenPool {
    tokens: VecDeque<IssuedToken>,
}

impl TokenPool {
    fn new(token: IssuedToken) -> Self {
        Self {
            tokens: VecDeque::from([token]),
        }
    }

    fn discard_unusable(&mut self) {
        self.tokens.retain(|token| token.available_uses() > 0);
    }

    fn available_uses(&self) -> usize {
        self.tokens.iter().fold(0, |available, token| {
            available.saturating_add(token.available_uses())
        })
    }
}

/// Authenticated state scoped to one logical provider operation.
///
/// AppRole and JWT exchanges produce client tokens that may expire or be
/// revoked independently of this process. Keeping their reported use budget
/// here lets requests share logins safely without turning a token into
/// provider-lifetime authentication state.
pub(crate) struct KvSession<'a> {
    provider: &'a KvProvider,
    tokens: Mutex<TokenPool>,
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

    /// Authenticates for the logical operation that owns the returned session.
    /// Additional logins are performed only when the issued token's reported
    /// use budget is exhausted. Dropping the session drops all authentication
    /// state, so a later operation cannot unknowingly reuse an expired token.
    fn session(&self) -> Result<KvSession<'_>> {
        let token = block_on(self.resolve_token())?;
        Ok(KvSession {
            provider: self,
            tokens: Mutex::new(TokenPool::new(token)),
        })
    }

    /// Injects semantic credentials resolved from another SecretSpec provider.
    /// Explicit credentials outrank every environment fallback.
    pub(crate) fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    /// Native coordinates understood by the shared Vault-compatible KV API.
    pub(crate) fn supported_coords(&self) -> &'static [&'static str] {
        &["field"]
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

    /// Builds the shared authority, namespace, and mount portion of a canonical
    /// provider or storage-identity URL.
    fn base_uri(&self, scheme: &str) -> Url {
        let authority = self
            .config
            .endpoint
            .strip_prefix("https://")
            .or_else(|| self.config.endpoint.strip_prefix("http://"))
            .expect("KvConfig endpoints are normalized HTTP origins");
        let mut uri = Url::parse(&format!("{scheme}://{authority}"))
            .expect("a normalized endpoint forms a provider URI");

        if let Some(namespace) = &self.config.namespace {
            uri.set_username(namespace)
                .expect("a provider URI supports namespace userinfo");
        }
        uri.set_path(&format!("/{}", self.config.mount));

        uri
    }

    /// Returns the credential-free provider URI used in audit records and
    /// fallback diagnostics.
    ///
    /// The URI is canonical rather than source-preserving: implicit defaults
    /// stay implicit, while every setting that changes the effective store or
    /// authentication context is retained.
    pub(crate) fn uri(&self) -> String {
        let mut uri = self.base_uri(self.product.scheme());

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
                if let Some(auth_mount) = &self.config.auth_mount {
                    uri.query_pairs_mut().append_pair("auth_mount", auth_mount);
                }
            }
            AuthMethod::Jwt => {
                uri.query_pairs_mut().append_pair("auth", "jwt");
                if let Some(auth_mount) = &self.config.auth_mount {
                    uri.query_pairs_mut().append_pair("auth_mount", auth_mount);
                }
                if let Some(role) = &self.config.role {
                    uri.query_pairs_mut().append_pair("role", role);
                }
                if let Some(audience) = &self.config.audience {
                    uri.query_pairs_mut().append_pair("audience", audience);
                }
            }
        }

        uri.into()
    }

    /// Canonical identity of the Vault-compatible KV mount behind this provider.
    ///
    /// Vault and OpenBao are separate public providers, but their compatible KV
    /// clients can address the same endpoint, namespace, and mount. Authentication
    /// method, role, audience, and KV interpretation do not create a distinct
    /// physical store, so none of them may let a cache disguise its own source.
    pub(crate) fn storage_identity(&self) -> String {
        let mut uri = self.base_uri("vault-compatible");
        if self.config.endpoint.starts_with("http://") {
            uri.query_pairs_mut().append_pair("tls", "false");
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
        self.session()?.get_field(&coords.item, field)
    }

    /// Validates and resolves the parts of a read address that can fail without
    /// contacting the provider.
    fn validate_read_address(&self, addr: Address<'_>) -> Result<()> {
        match addr {
            Address::Convention {
                project,
                profile,
                key,
            } => {
                self.convention_address(project, profile, key)?;
                Ok(())
            }
            Address::Native(coords) => {
                super::address::reject_unsupported_coords(
                    self.product.scheme(),
                    coords,
                    self.supported_coords(),
                )?;
                self.require_field(coords)?;
                Ok(())
            }
        }
    }

    /// Reads a batch through one operation-scoped authentication session while
    /// retaining the provider-wide address deduplication and concurrency cap.
    pub(crate) fn get_many(
        &self,
        requests: &[(&str, Address<'_>)],
    ) -> Result<HashMap<String, SecretString>> {
        if requests.is_empty() {
            return Ok(HashMap::new());
        }
        // Login can consume a one-use AppRole SecretID. Reject every local
        // coordinate error before creating the operation session.
        for (_, addr) in requests {
            self.validate_read_address(*addr)?;
        }
        let session = self.session()?;
        super::get_each_with(requests, |addr| match addr {
            Address::Convention {
                project,
                profile,
                key,
            } => {
                let coords = self.convention_address(project, profile, key)?;
                session.get(&coords)
            }
            Address::Native(coords) => {
                super::address::reject_unsupported_coords(
                    self.product.scheme(),
                    coords,
                    self.supported_coords(),
                )?;
                session.get(coords)
            }
        })
    }

    /// Writes a complete convention-owned KV entry.
    ///
    /// Callers must run [`Self::check_writable`] before reaching this method.
    pub(crate) fn set(&self, coords: &NativeAddress, value: &SecretString) -> Result<()> {
        self.session()?.set(&coords.item, value)
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
        self.session()?.set_expiring(&coords.item, value, max_age)
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
        self.session()?.delete(&coords.item, field)
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

    /// Resolves a client token and the use budget known for its authentication
    /// method.
    async fn resolve_token(&self) -> Result<IssuedToken> {
        match self.config.auth {
            // A configured token is opaque: SecretSpec cannot mint a
            // replacement and looking it up would itself consume one use.
            AuthMethod::Token => self.resolve_token_auth().map(IssuedToken::static_token),
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
    async fn resolve_approle_auth(&self) -> Result<IssuedToken> {
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
            credential_or_envs(&self.credentials, SECRET_ID, self.product.secret_id_envs());

        let url = self.auth_login_url();
        let mut body = serde_json::json!({ "role_id": role_id });
        if let Some(secret_id) = secret_id {
            body["secret_id"] = serde_json::Value::String(secret_id);
        }

        // The server-side lease begins while the request is in flight. Anchor
        // its deadline before sending so response latency cannot extend the
        // token's perceived lifetime.
        let login_started_at = Instant::now();
        let response = self
            .build_login_request(url.as_str(), &body)?
            .send()
            .await
            .map_err(|error| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "{} AppRole login failed: {}",
                    self.product.display_name(),
                    crate::error::display_error_chain(&error)
                ))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = self.response_body(response).await?;
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} AppRole login returned HTTP {status}: {body}",
                self.product.display_name()
            )));
        }

        let response: serde_json::Value = response.json().await.map_err(|error| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to parse {} AppRole login response: {}",
                self.product.display_name(),
                crate::error::display_error_chain(&error)
            ))
        })?;
        self.parse_login_token(&response, "AppRole", login_started_at)
    }

    /// Exchanges a JWT at the configured auth mount, optionally selecting a role.
    async fn resolve_jwt_auth(&self) -> Result<IssuedToken> {
        let jwt = self.resolve_jwt().await?;

        let url = self.auth_login_url();
        let mut body = serde_json::json!({ "jwt": jwt.expose_secret() });
        if let Some(role) = &self.config.role {
            body["role"] = serde_json::Value::String(role.clone());
        }
        // The server-side lease begins while the request is in flight. Anchor
        // its deadline before sending so response latency cannot extend the
        // token's perceived lifetime.
        let login_started_at = Instant::now();
        let response = self
            .build_login_request(url.as_str(), &body)?
            .send()
            .await
            .map_err(|error| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "{} JWT login failed: {}",
                    self.product.display_name(),
                    crate::error::display_error_chain(&error)
                ))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = self.response_body(response).await?;
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} JWT login returned HTTP {status}: {body}",
                self.product.display_name()
            )));
        }

        let response: serde_json::Value = response.json().await.map_err(|error| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to parse {} JWT login response: {}",
                self.product.display_name(),
                crate::error::display_error_chain(&error)
            ))
        })?;
        self.parse_login_token(&response, "JWT", login_started_at)
    }

    /// Extracts a login token and the server-reported request budget.
    ///
    /// `num_uses = 0` is the Vault-compatible representation of an unlimited
    /// use count, not an unlimited lifetime. Missing use or lease metadata is
    /// treated conservatively so a partial response cannot cause unsafe reuse;
    /// malformed metadata is a protocol error.
    fn parse_login_token(
        &self,
        response: &serde_json::Value,
        auth_method: &str,
        login_started_at: Instant,
    ) -> Result<IssuedToken> {
        let auth = response.get("auth").ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(format!(
                "{} {auth_method} login response missing auth.client_token",
                self.product.display_name()
            ))
        })?;
        let token = auth
            .get("client_token")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "{} {auth_method} login response missing auth.client_token",
                    self.product.display_name()
                ))
            })?;
        let num_uses = match auth.get("num_uses") {
            Some(value) => Some(value.as_u64().ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "{} {auth_method} login response has invalid auth.num_uses",
                    self.product.display_name()
                ))
            })?),
            None => None,
        };
        let lease_duration = match auth.get("lease_duration") {
            Some(value) => Some(value.as_u64().ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "{} {auth_method} login response has invalid auth.lease_duration",
                    self.product.display_name()
                ))
            })?),
            None => None,
        };
        let usable_until = match lease_duration {
            Some(0) | None => None,
            Some(seconds) => {
                let ttl = Duration::from_secs(seconds);
                // Leave a small window for network transit and server-side
                // token validation, without making very short leases unusable.
                let safety_margin = std::cmp::min(Duration::from_secs(5), ttl / 10);
                let usable_for = ttl.saturating_sub(safety_margin);
                Some(login_started_at.checked_add(usable_for).ok_or_else(|| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "{} {auth_method} login response has invalid auth.lease_duration",
                        self.product.display_name()
                    ))
                })?)
            }
        };

        Ok(IssuedToken::login_token(
            SecretString::new(token.to_string().into()),
            num_uses,
            usable_until,
            lease_duration.is_some(),
        ))
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
                "Failed to request CI OIDC token: {}",
                crate::error::display_error_chain(&error)
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
                "Failed to parse CI OIDC token response: {}",
                crate::error::display_error_chain(&error)
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

    /// Builds `/v1/auth/<mount>/login`, encoding each nested mount segment as a
    /// URL path component rather than interpolating query-derived text.
    fn auth_login_url(&self) -> Url {
        let mount = self
            .config
            .auth_mount
            .as_deref()
            .or_else(|| self.config.auth.default_mount())
            .expect("only login-based authentication builds a login URL");
        let mut url = Url::parse(&self.config.endpoint)
            .expect("KvConfig endpoints are normalized HTTP origins");
        {
            let mut path = url
                .path_segments_mut()
                .expect("a normalized HTTP endpoint supports path segments");
            path.clear().push("v1").push("auth");
            for segment in mount.split('/') {
                path.push(segment);
            }
            path.push("login");
        }
        url
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

    /// Sends one authenticated request, retrying connect and timeout failures.
    ///
    /// A connect failure cannot have reached the server, so the same token
    /// claim remains valid. A later timeout is ambiguous: the server may have
    /// consumed the request before the response was lost, so a retry claims
    /// another use. HTTP status failures are not retried.
    async fn send_with_connect_retry(
        &self,
        session: &KvSession<'_>,
        mut token: SecretString,
        mut build: impl FnMut(&SecretString) -> Result<reqwest::RequestBuilder>,
    ) -> Result<reqwest::Response> {
        const ATTEMPTS: usize = 3;
        let mut last_error = None;
        for attempt in 1..=ATTEMPTS {
            let response = build(&token)?.send().await;
            match response {
                Ok(response) => return Ok(response),
                Err(error) if attempt < ATTEMPTS && (error.is_connect() || error.is_timeout()) => {
                    if error.is_timeout() && !error.is_connect() {
                        token = session.claim_token().await?;
                    }
                    last_error = Some(error);
                    // get_each already runs each get on its own thread, so a
                    // brief blocking backoff is fine and avoids a tokio/time
                    // feature dependency on the vault build.
                    std::thread::sleep(std::time::Duration::from_millis(25 * attempt as u64));
                }
                Err(error) => {
                    return Err(SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to connect to {} at {}: {}",
                        self.product.display_name(),
                        self.config.endpoint,
                        crate::error::display_error_chain(&error)
                    )));
                }
            }
        }
        Err(SecretSpecError::ProviderOperationFailed(format!(
            "Failed to connect to {} at {}: {}",
            self.product.display_name(),
            self.config.endpoint,
            crate::error::display_error_chain(
                &last_error.expect("connect retry exhausted with an error")
            )
        )))
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

    /// Reads an HTTP body without turning a transport/decompression failure
    /// into an empty service error.
    async fn response_body(&self, response: reqwest::Response) -> Result<String> {
        let status = response.status();
        response.text().await.map_err(|error| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to read {} HTTP {status} response body: {}",
                self.product.display_name(),
                crate::error::display_error_chain(&error)
            ))
        })
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
    async fn metadata_exists_async(
        &self,
        secret_path: &str,
        session: &KvSession<'_>,
        token: SecretString,
    ) -> Result<bool> {
        let url = self.metadata_url(secret_path);
        let response = self
            .send_with_connect_retry(session, token, |token| {
                Ok(self.http().get(&url).headers(self.build_headers(token)?))
            })
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
                let body = self.response_body(response).await?;
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
        session: &KvSession<'_>,
        token: SecretString,
    ) -> Result<()> {
        let url = self.metadata_url(secret_path);
        // Seconds keep the request independent of how the duration was written
        // in the config (`8h` and `480m` are the same policy).
        let body = serde_json::json!({ "delete_version_after": format!("{}s", max_age.as_secs()) });
        let response = self
            .send_with_connect_retry(session, token, |token| {
                Ok(self
                    .http()
                    .post(&url)
                    .headers(self.build_headers(token)?)
                    .json(&body))
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
                let body = self.response_body(response).await?;
                Err(SecretSpecError::ProviderOperationFailed(format!(
                    "{} returned HTTP {status} while setting version expiry: {body}",
                    self.product.display_name()
                )))
            }
        }
    }

    /// Removes a KV path outright: for v2 the metadata endpoint, which destroys
    /// every version; for v1 the data path, which is all there is.
    async fn delete_path_async(
        &self,
        secret_path: &str,
        session: &KvSession<'_>,
        token: SecretString,
    ) -> Result<()> {
        let url = match self.config.kv_version {
            KvVersion::V2 => self.metadata_url(secret_path),
            KvVersion::V1 => self.build_url(secret_path),
        };
        let response = self
            .send_with_connect_retry(session, token, |token| {
                Ok(self.http().delete(&url).headers(self.build_headers(token)?))
            })
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
                let body = self.response_body(response).await?;
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
        session: &KvSession<'_>,
        token: SecretString,
    ) -> Result<Option<SecretString>> {
        let url = self.build_url(secret_path);
        let response = self
            .send_with_connect_retry(session, token, |token| {
                Ok(self.http().get(&url).headers(self.build_headers(token)?))
            })
            .await?;

        match response.status().as_u16() {
            200 => {
                let body: serde_json::Value = response.json().await.map_err(|error| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to parse {} response: {}",
                        self.product.display_name(),
                        crate::error::display_error_chain(&error)
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
                let body = self.response_body(response).await?;
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
    async fn set_secret_async(
        &self,
        secret_path: &str,
        value: &SecretString,
        session: &KvSession<'_>,
        token: SecretString,
    ) -> Result<()> {
        let url = self.build_url(secret_path);
        let body = match self.config.kv_version {
            KvVersion::V2 => serde_json::json!({ "data": { "value": value.expose_secret() } }),
            KvVersion::V1 => serde_json::json!({ "value": value.expose_secret() }),
        };
        let response = self
            .send_with_connect_retry(session, token, |token| {
                Ok(self
                    .http()
                    .post(&url)
                    .headers(self.build_headers(token)?)
                    .json(&body))
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
                let body = self.response_body(response).await?;
                Err(SecretSpecError::ProviderOperationFailed(format!(
                    "{} returned HTTP {status} while writing secret: {body}",
                    self.product.display_name()
                )))
            }
        }
    }
}

impl KvSession<'_> {
    async fn claim_token(&self) -> Result<SecretString> {
        let mut pool = self.tokens.lock().await;
        loop {
            while let Some(token) = pool.tokens.front_mut() {
                if let Some(token) = token.claim() {
                    return Ok(token);
                }
                pool.tokens.pop_front();
            }

            // Keep the lock across the exchange so concurrent reads cannot
            // each mint a replacement for the same exhausted or expired
            // token.
            pool.tokens.push_back(self.provider.resolve_token().await?);
        }
    }

    /// Ensures a multi-request mutation can obtain all of its authentication
    /// capacity before its first side effect, without reserving tokens so early
    /// that a short lease can expire before the later request is sent.
    async fn ensure_claims(&self, count: usize) -> Result<()> {
        let mut pool = self.tokens.lock().await;
        let mut additional_logins = 0;
        loop {
            pool.discard_unusable();
            if pool.available_uses() >= count {
                return Ok(());
            }
            if additional_logins >= count {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "{} login tokens expire too quickly to safely perform a {count}-request operation",
                    self.provider.product.display_name()
                )));
            }
            pool.tokens.push_back(self.provider.resolve_token().await?);
            additional_logins += 1;
        }
    }

    /// Reads one address with authentication scoped to this operation.
    fn get(&self, coords: &NativeAddress) -> Result<Option<SecretString>> {
        let field = self.provider.require_field(coords)?;
        self.get_field(&coords.item, field)
    }

    fn get_field(&self, secret_path: &str, field: &str) -> Result<Option<SecretString>> {
        block_on(async {
            let token = self.claim_token().await?;
            self.provider
                .get_field_async(secret_path, field, self, token)
                .await
        })
    }

    fn set(&self, secret_path: &str, value: &SecretString) -> Result<()> {
        block_on(async {
            let token = self.claim_token().await?;
            self.provider
                .set_secret_async(secret_path, value, self, token)
                .await
        })
    }

    fn set_expiring(
        &self,
        secret_path: &str,
        value: &SecretString,
        max_age: std::time::Duration,
    ) -> Result<()> {
        block_on(async {
            // Ensure both request claims before changing metadata. If a
            // limited-use role can no longer log in, no partial expiry policy
            // is left behind. Claim immediately before each request so an
            // already preflighted short-lease token can still be refreshed.
            self.ensure_claims(2).await?;
            let metadata_token = self.claim_token().await?;
            self.provider
                .set_version_ttl_async(secret_path, max_age, self, metadata_token)
                .await?;
            let data_token = self.claim_token().await?;
            self.provider
                .set_secret_async(secret_path, value, self, data_token)
                .await
        })
    }

    fn delete(&self, secret_path: &str, field: &str) -> Result<bool> {
        block_on(async {
            let existence_token = self.claim_token().await?;
            match self.provider.config.kv_version {
                // An expired KV v2 version is no longer readable from the data
                // endpoint, but its metadata and recoverable version history
                // still exist. Check the metadata path so cache clearing
                // permanently destroys that history.
                KvVersion::V2 => {
                    if !self
                        .provider
                        .metadata_exists_async(secret_path, self, existence_token)
                        .await?
                    {
                        return Ok(false);
                    }
                }
                KvVersion::V1 => {
                    if self
                        .provider
                        .get_field_async(secret_path, field, self, existence_token)
                        .await?
                        .is_none()
                    {
                        return Ok(false);
                    }
                }
            }
            // The existence check is read-only. Resolve the destructive
            // request's claim before issuing the delete so an exhausted role
            // cannot turn into a post-mutation authentication failure.
            let delete_token = self.claim_token().await?;
            self.provider
                .delete_path_async(secret_path, self, delete_token)
                .await?;
            Ok(true)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Provider;
    #[cfg(feature = "openbao")]
    use crate::provider::openbao::{OpenBaoConfig, OpenBaoProvider};
    #[cfg(feature = "vault")]
    use crate::provider::vault::{VaultConfig, VaultProvider};
    use crate::tests::EnvVarGuard;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};

    fn provider_url(spec: &str) -> ProviderUrl {
        ProviderUrl::new(Url::parse(spec).unwrap())
    }

    #[cfg(feature = "vault")]
    fn batch_requests() -> [(&'static str, Address<'static>); 2] {
        [
            ("FIRST", Address::convention("project", "default", "FIRST")),
            (
                "SECOND",
                Address::convention("project", "default", "SECOND"),
            ),
        ]
    }

    fn api_key_address() -> Address<'static> {
        Address::convention("project", "default", "API_KEY")
    }

    fn approle_credentials() -> ProviderCredentials {
        ProviderCredentials::from([
            (
                ROLE_ID.to_string(),
                SecretString::new("test-role".to_string().into()),
            ),
            (
                SECRET_ID.to_string(),
                SecretString::new("test-secret".to_string().into()),
            ),
        ])
    }

    fn parse_test_login(auth: serde_json::Value) -> Result<IssuedToken> {
        KvProvider::new(KvConfig::default(), Product::Vault).parse_login_token(
            &serde_json::json!({ "auth": auth }),
            "test",
            Instant::now(),
        )
    }

    #[cfg(feature = "vault")]
    fn vault_approle_provider(endpoint: SocketAddr) -> VaultProvider {
        let config = VaultConfig::try_from(&provider_url(&format!(
            "vault://{endpoint}/secret?tls=false&auth=approle"
        )))
        .unwrap();
        let mut provider = VaultProvider::new(config);
        provider.with_credentials(approle_credentials());
        provider
    }

    #[cfg(feature = "openbao")]
    fn openbao_jwt_provider(endpoint: SocketAddr) -> OpenBaoProvider {
        let config = OpenBaoConfig::try_from(&provider_url(&format!(
            "openbao://{endpoint}/secret?tls=false&auth=jwt&role=ci"
        )))
        .unwrap();
        OpenBaoProvider::new(config)
    }

    fn read_request(stream: &mut TcpStream) -> String {
        let mut request = String::new();
        let mut content_length = 0;
        {
            let mut reader = BufReader::new(&mut *stream);
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    request.push_str(&line);
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = value.trim().parse().unwrap();
                }
                request.push_str(&line);
            }
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).unwrap();
            request.push_str(&String::from_utf8(body).unwrap());
        }
        request
    }

    fn request_json(request: &str) -> serde_json::Value {
        let (_, body) = request
            .split_once("\r\n\r\n")
            .expect("HTTP request must contain a header/body separator");
        serde_json::from_str(body).expect("HTTP request body must be JSON")
    }

    fn auth_server(
        request_count: usize,
        token_num_uses: u64,
        fail_login: Option<usize>,
    ) -> (
        SocketAddr,
        std::thread::JoinHandle<Vec<(String, Option<String>)>>,
    ) {
        auth_server_with_lease(request_count, token_num_uses, fail_login, 3600, None, None)
    }

    fn auth_server_with_lease(
        request_count: usize,
        token_num_uses: u64,
        fail_login: Option<usize>,
        lease_duration: u64,
        first_login_delay: Option<Duration>,
        first_read_delay: Option<Duration>,
    ) -> (
        SocketAddr,
        std::thread::JoinHandle<Vec<(String, Option<String>)>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut observed = Vec::new();
            let mut login_count = 0;
            let mut read_count = 0;
            for _ in 0..request_count {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_request(&mut stream);
                let request_line = request.lines().next().unwrap_or_default().to_string();
                let token = request.lines().find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("X-Vault-Token")
                            .then(|| value.trim().to_string())
                    })
                });

                let (status, body) = if request_line.contains("/v1/auth/") {
                    login_count += 1;
                    if login_count == 1
                        && let Some(delay) = first_login_delay
                    {
                        std::thread::sleep(delay);
                    }
                    if fail_login == Some(login_count) {
                        (
                            "403 Forbidden",
                            r#"{"errors":["login denied"]}"#.to_string(),
                        )
                    } else {
                        (
                            "200 OK",
                            format!(
                                r#"{{"auth":{{"client_token":"operation-token-{login_count}","num_uses":{token_num_uses},"lease_duration":{lease_duration}}}}}"#
                            ),
                        )
                    }
                } else if request_line.starts_with("GET ") && request_line.contains("/data/") {
                    read_count += 1;
                    if read_count == 1
                        && let Some(delay) = first_read_delay
                    {
                        std::thread::sleep(delay);
                    }
                    (
                        "200 OK",
                        r#"{"data":{"data":{"value":"resolved"}}}"#.to_string(),
                    )
                } else if request_line.starts_with("GET ") {
                    ("200 OK", String::new())
                } else {
                    ("204 No Content", String::new())
                };
                observed.push((request, token));
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
            observed
        });
        (endpoint, server)
    }

    #[cfg(feature = "vault")]
    #[test]
    fn approle_login_is_scoped_to_each_get_many_operation() {
        let _lock = crate::tests::scrub_resolution_env();
        let (endpoint, server) = auth_server(6, 2, None);
        let provider = vault_approle_provider(endpoint);
        let requests = batch_requests();
        for _ in 0..2 {
            let values = provider.get_many(&requests).unwrap();
            assert_eq!(values.len(), 2);
            assert_eq!(values["FIRST"].expose_secret(), "resolved");
            assert_eq!(values["SECOND"].expose_secret(), "resolved");
        }

        let observed = server.join().unwrap();
        assert!(observed[0].0.contains("/v1/auth/approle/login"));
        assert!(observed[3].0.contains("/v1/auth/approle/login"));
        assert!(
            observed[1..3]
                .iter()
                .all(|(_, token)| token.as_deref() == Some("operation-token-1"))
        );
        assert!(
            observed[4..6]
                .iter()
                .all(|(_, token)| token.as_deref() == Some("operation-token-2"))
        );
    }

    #[cfg(feature = "vault")]
    #[test]
    fn approle_get_many_runs_inside_a_current_thread_runtime() {
        let _lock = crate::tests::scrub_resolution_env();
        let (endpoint, server) = auth_server(3, 2, None);
        let provider = vault_approle_provider(endpoint);
        let requests = batch_requests();
        let outer = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let values = outer
            .block_on(async { provider.get_many(&requests) })
            .unwrap();

        assert_eq!(values.len(), 2);
        assert_eq!(server.join().unwrap().len(), 3);
    }

    #[cfg(feature = "vault")]
    #[test]
    fn approle_get_many_does_not_oversubscribe_single_use_tokens() {
        let _lock = crate::tests::scrub_resolution_env();
        let (endpoint, server) = auth_server(4, 1, None);
        let provider = vault_approle_provider(endpoint);

        let values = provider.get_many(&batch_requests()).unwrap();
        assert_eq!(values.len(), 2);

        let observed = server.join().unwrap();
        assert_eq!(
            observed
                .iter()
                .filter(|(request, _)| request.contains("/v1/auth/approle/login"))
                .count(),
            2
        );
        let mut read_tokens: Vec<_> = observed
            .iter()
            .filter(|(request, _)| request.starts_with("GET ") && request.contains("/data/"))
            .map(|(_, token)| token.as_deref().unwrap())
            .collect();
        read_tokens.sort_unstable();
        assert_eq!(read_tokens, ["operation-token-1", "operation-token-2"]);
    }

    #[cfg(feature = "vault")]
    #[test]
    fn approle_get_many_refreshes_a_token_between_slow_waves() {
        let _lock = crate::tests::scrub_resolution_env();
        let _concurrency = EnvVarGuard::set(super::super::GET_EACH_CONCURRENCY_ENV, "1");
        let (endpoint, server) =
            auth_server_with_lease(4, 0, None, 1, None, Some(Duration::from_millis(1100)));
        let provider = vault_approle_provider(endpoint);

        let values = provider.get_many(&batch_requests()).unwrap();
        assert_eq!(values.len(), 2);

        let observed = server.join().unwrap();
        assert!(observed[0].0.contains("/v1/auth/approle/login"));
        assert_eq!(observed[1].1.as_deref(), Some("operation-token-1"));
        assert!(observed[2].0.contains("/v1/auth/approle/login"));
        assert_eq!(observed[3].1.as_deref(), Some("operation-token-2"));
    }

    #[cfg(feature = "openbao")]
    #[test]
    fn jwt_login_obtains_enough_limited_use_tokens_before_an_expiring_write() {
        let _lock = crate::tests::scrub_resolution_env();
        let _jwt = EnvVarGuard::set("BAO_JWT", "test-jwt");
        let (endpoint, server) = auth_server(4, 1, None);
        let provider = openbao_jwt_provider(endpoint);

        provider
            .set_expiring(
                api_key_address(),
                &SecretString::new("value".to_string().into()),
                std::time::Duration::from_secs(3600),
            )
            .unwrap();

        let observed = server.join().unwrap();
        assert!(observed[0].0.contains("/v1/auth/jwt/login"));
        assert!(observed[1].0.contains("/v1/auth/jwt/login"));
        assert_eq!(request_json(&observed[0].0)["role"], "ci");
        assert_eq!(request_json(&observed[1].0)["role"], "ci");
        assert!(observed[2].0.contains("/v1/secret/metadata/"));
        assert_eq!(observed[2].1.as_deref(), Some("operation-token-1"));
        assert!(observed[3].0.contains("/v1/secret/data/"));
        assert_eq!(observed[3].1.as_deref(), Some("operation-token-2"));
    }

    #[test]
    fn jwt_login_omits_an_absent_role_for_the_server_default() {
        let _lock = crate::tests::scrub_resolution_env();
        let _jwt = EnvVarGuard::set("VAULT_JWT", "test-jwt");
        let _role = EnvVarGuard::remove("VAULT_JWT_ROLE");
        let (endpoint, server) = auth_server(1, 0, None);
        let config = KvConfig::parse(
            &provider_url(&format!("vault://{endpoint}/secret?tls=false&auth=jwt")),
            Product::Vault,
        )
        .unwrap();
        let provider = KvProvider::new(config, Product::Vault);

        block_on(provider.resolve_jwt_auth()).unwrap();

        let observed = server.join().unwrap();
        assert_eq!(observed.len(), 1);
        assert!(observed[0].0.contains("/v1/auth/jwt/login"));
        assert_eq!(
            request_json(&observed[0].0),
            serde_json::json!({ "jwt": "test-jwt" })
        );
    }

    #[test]
    fn approle_login_includes_a_configured_secret_id() {
        let _lock = crate::tests::scrub_resolution_env();
        let (endpoint, server) = auth_server(1, 0, None);
        let config = KvConfig::parse(
            &provider_url(&format!("vault://{endpoint}/secret?tls=false&auth=approle")),
            Product::Vault,
        )
        .unwrap();
        let mut provider = KvProvider::new(config, Product::Vault);
        provider.with_credentials(approle_credentials());

        block_on(provider.resolve_approle_auth()).unwrap();

        let observed = server.join().unwrap();
        assert_eq!(observed.len(), 1);
        assert_eq!(
            request_json(&observed[0].0),
            serde_json::json!({
                "role_id": "test-role",
                "secret_id": "test-secret"
            })
        );
    }

    #[test]
    fn approle_login_omits_an_absent_secret_id_for_an_unbound_role() {
        let _lock = crate::tests::scrub_resolution_env();
        let (endpoint, server) = auth_server(1, 0, None);
        let config = KvConfig::parse(
            &provider_url(&format!(
                "openbao://{endpoint}/secret?tls=false&auth=approle"
            )),
            Product::OpenBao,
        )
        .unwrap();
        let mut provider = KvProvider::new(config, Product::OpenBao);
        provider.with_credentials(ProviderCredentials::from([(
            ROLE_ID.to_string(),
            SecretString::new("test-role".to_string().into()),
        )]));

        block_on(provider.resolve_approle_auth()).unwrap();

        let observed = server.join().unwrap();
        assert_eq!(observed.len(), 1);
        assert_eq!(
            request_json(&observed[0].0),
            serde_json::json!({ "role_id": "test-role" })
        );
    }

    #[test]
    fn approle_login_still_requires_a_role_id() {
        let _lock = crate::tests::scrub_resolution_env();
        let config = KvConfig::parse(
            &provider_url("vault://127.0.0.1:1/secret?tls=false&auth=approle"),
            Product::Vault,
        )
        .unwrap();
        let provider = KvProvider::new(config, Product::Vault);

        let error = block_on(provider.resolve_approle_auth())
            .err()
            .expect("AppRole login without a role_id must fail");

        assert!(error.to_string().contains("role_id credential is required"));
    }

    #[test]
    fn empty_jwt_role_query_uses_the_environment_fallback() {
        let _lock = crate::tests::scrub_resolution_env();
        let _role = EnvVarGuard::set("VAULT_JWT_ROLE", "ci-from-env");
        let config = KvConfig::parse(
            &provider_url("vault://vault.example.com/secret?auth=jwt&role="),
            Product::Vault,
        )
        .unwrap();

        assert_eq!(config.role.as_deref(), Some("ci-from-env"));
    }

    #[cfg(feature = "openbao")]
    #[test]
    fn expiring_write_stops_before_metadata_when_reauthentication_fails() {
        let _lock = crate::tests::scrub_resolution_env();
        let _jwt = EnvVarGuard::set("BAO_JWT", "test-jwt");
        let (endpoint, server) = auth_server(2, 1, Some(2));
        let provider = openbao_jwt_provider(endpoint);

        let error = provider
            .set_expiring(
                api_key_address(),
                &SecretString::new("value".to_string().into()),
                std::time::Duration::from_secs(3600),
            )
            .unwrap_err();

        assert!(error.to_string().contains("JWT login returned HTTP 403"));
        let observed = server.join().unwrap();
        assert_eq!(observed.len(), 2);
        assert!(
            observed
                .iter()
                .all(|(request, _)| request.contains("/v1/auth/jwt/login"))
        );
    }

    #[cfg(feature = "vault")]
    #[test]
    fn delete_reauthenticates_after_a_limited_use_existence_check() {
        let _lock = crate::tests::scrub_resolution_env();
        let (endpoint, server) = auth_server(4, 1, None);
        let provider = vault_approle_provider(endpoint);

        assert!(provider.delete(api_key_address()).unwrap());

        let observed = server.join().unwrap();
        assert!(observed[0].0.contains("/v1/auth/approle/login"));
        assert!(observed[1].0.starts_with("GET /v1/secret/metadata/"));
        assert_eq!(observed[1].1.as_deref(), Some("operation-token-1"));
        assert!(observed[2].0.contains("/v1/auth/approle/login"));
        assert!(observed[3].0.starts_with("DELETE /v1/secret/metadata/"));
        assert_eq!(observed[3].1.as_deref(), Some("operation-token-2"));
    }

    #[test]
    fn missing_login_use_count_is_treated_as_single_use() {
        let mut token = parse_test_login(serde_json::json!({ "client_token": "limited" })).unwrap();

        assert_eq!(token.claim().unwrap().expose_secret(), "limited");
        assert!(token.claim().is_none());
    }

    #[test]
    fn malformed_login_use_count_is_rejected() {
        let error = parse_test_login(serde_json::json!({
            "client_token": "limited",
            "num_uses": "one"
        }))
        .err()
        .expect("malformed num_uses must fail");

        assert!(error.to_string().contains("invalid auth.num_uses"));
    }

    #[test]
    fn malformed_login_lease_duration_is_rejected() {
        let error = parse_test_login(serde_json::json!({
            "client_token": "limited",
            "num_uses": 0,
            "lease_duration": "brief"
        }))
        .err()
        .expect("malformed lease_duration must fail");

        assert!(error.to_string().contains("invalid auth.lease_duration"));
    }

    #[test]
    fn approle_login_latency_reduces_the_reported_lease() {
        let _lock = crate::tests::scrub_resolution_env();
        let (endpoint, server) =
            auth_server_with_lease(1, 0, None, 1, Some(Duration::from_millis(1100)), None);
        let config = KvConfig::parse(
            &provider_url(&format!("vault://{endpoint}/secret?tls=false&auth=approle")),
            Product::Vault,
        )
        .unwrap();
        let mut provider = KvProvider::new(config, Product::Vault);
        provider.with_credentials(approle_credentials());

        let mut token = block_on(provider.resolve_approle_auth()).unwrap();

        assert!(token.claim().is_none());
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[test]
    fn get_many_validates_every_address_before_authenticating() {
        let _lock = crate::tests::scrub_resolution_env();
        let config = KvConfig::parse(
            &provider_url("vault://127.0.0.1:1/secret?tls=false&auth=approle"),
            Product::Vault,
        )
        .unwrap();
        let provider = KvProvider::new(config, Product::Vault);
        let invalid = NativeAddress {
            item: "app/config".to_string(),
            ..Default::default()
        };

        let error = provider
            .get_many(&[
                ("VALID", Address::convention("project", "default", "VALID")),
                ("INVALID", Address::Native(&invalid)),
            ])
            .unwrap_err();

        assert!(error.to_string().contains("references need a `field`"));
        assert!(!error.to_string().contains("role_id credential is required"));
    }

    #[test]
    fn block_on_is_safe_inside_a_current_thread_runtime() {
        let outer = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let answer = outer.block_on(async { block_on(async { 42 }) });

        assert_eq!(answer, 42);
    }

    #[test]
    fn vault_compatible_http_work_uses_one_runtime_across_batch_threads() {
        let first = block_on(async { tokio::runtime::Handle::current().id() });
        let second =
            std::thread::spawn(|| block_on(async { tokio::runtime::Handle::current().id() }))
                .join()
                .unwrap();

        assert_eq!(first, second);
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
    fn auth_mount_is_normalized_and_defaults_stay_implicit() {
        let custom = KvConfig::parse(
            &provider_url(
                "vault://vault.example.com:8200/secret?auth=approle&auth_mount=/team/approle/",
            ),
            Product::Vault,
        )
        .unwrap();
        assert_eq!(custom.auth_mount.as_deref(), Some("team/approle"));
        let custom = KvProvider::new(custom, Product::Vault);
        assert_eq!(
            custom.uri(),
            "vault://vault.example.com:8200/secret?auth=approle&auth_mount=team%2Fapprole"
        );
        assert_eq!(
            custom.auth_login_url().as_str(),
            "https://vault.example.com:8200/v1/auth/team/approle/login"
        );

        let unicode = KvConfig::parse(
            &provider_url(
                "openbao://bao.example.com:8200/secret?auth=jwt&auth_mount=%C3%A9quipe-jwt&role=ci",
            ),
            Product::OpenBao,
        )
        .unwrap();
        assert_eq!(unicode.auth_mount.as_deref(), Some("équipe-jwt"));
        let unicode = KvProvider::new(unicode, Product::OpenBao);
        assert_eq!(
            unicode.uri(),
            "openbao://bao.example.com:8200/secret?auth=jwt&auth_mount=%C3%A9quipe-jwt&role=ci"
        );
        assert_eq!(
            unicode.auth_login_url().as_str(),
            "https://bao.example.com:8200/v1/auth/%C3%A9quipe-jwt/login"
        );

        for (spec, product) in [
            (
                "vault://vault.example.com:8200/secret?auth=approle&auth_mount=approle",
                Product::Vault,
            ),
            (
                "openbao://bao.example.com:8200/secret?auth=jwt&auth_mount=jwt&role=ci",
                Product::OpenBao,
            ),
        ] {
            let config = KvConfig::parse(&provider_url(spec), product).unwrap();
            assert_eq!(config.auth_mount, None);
            assert!(
                !KvProvider::new(config, product)
                    .uri()
                    .contains("auth_mount")
            );
        }
    }

    #[test]
    fn login_urls_use_the_auth_method_default_mounts() {
        for (auth, expected) in [
            (
                AuthMethod::AppRole,
                "https://vault.example.com:8200/v1/auth/approle/login",
            ),
            (
                AuthMethod::Jwt,
                "https://vault.example.com:8200/v1/auth/jwt/login",
            ),
        ] {
            let provider = KvProvider::new(
                KvConfig {
                    endpoint: "https://vault.example.com:8200".to_string(),
                    auth,
                    ..Default::default()
                },
                Product::Vault,
            );
            assert_eq!(provider.auth_login_url().as_str(), expected);
        }
    }

    #[test]
    fn invalid_auth_mounts_are_rejected_before_login() {
        for spec in [
            "vault://vault.example.com:8200/secret?auth_mount=approle",
            "vault://vault.example.com:8200/secret?auth=approle&auth_mount=",
            "vault://vault.example.com:8200/secret?auth=approle&auth_mount=team%2F%2Fapprole",
            "vault://vault.example.com:8200/secret?auth=approle&auth_mount=team%2F..%2Fapprole",
            "vault://vault.example.com:8200/secret?auth=approle&auth_mount=team%0Aapprole",
        ] {
            let error = KvConfig::parse(&provider_url(spec), Product::Vault).unwrap_err();
            assert!(error.to_string().contains("auth_mount"), "{spec}: {error}");
        }
    }

    #[test]
    fn storage_identity_unifies_compatible_products_and_authentication() {
        let vault = KvConfig::parse(
            &provider_url("vault://team-a@bao.example.com:8200/secret?tls=false&kv=1&auth=approle"),
            Product::Vault,
        )
        .unwrap();
        let openbao = KvConfig::parse(
            &provider_url(
                "openbao://team-a@bao.example.com:8200/secret?tls=false&auth=jwt&role=ci&audience=deploy",
            ),
            Product::OpenBao,
        )
        .unwrap();

        let expected = "vault-compatible://team-a@bao.example.com:8200/secret?tls=false";
        assert_eq!(
            KvProvider::new(vault, Product::Vault).storage_identity(),
            expected
        );
        assert_eq!(
            KvProvider::new(openbao, Product::OpenBao).storage_identity(),
            expected
        );
    }

    #[test]
    fn auth_mount_does_not_change_storage_identity() {
        let identity = |spec| {
            let config = KvConfig::parse(&provider_url(spec), Product::Vault).unwrap();
            KvProvider::new(config, Product::Vault).storage_identity()
        };

        assert_eq!(
            identity("vault://team-a@bao.example.com:8200/secret?auth=approle"),
            identity(
                "vault://team-a@bao.example.com:8200/secret?auth=approle&auth_mount=team-approle"
            )
        );
    }

    #[test]
    fn storage_identity_retains_the_physical_location() {
        let identity = |spec, product| {
            let config = KvConfig::parse(&provider_url(spec), product).unwrap();
            KvProvider::new(config, product).storage_identity()
        };
        let base = identity("vault://team-a@bao.example.com:8200/secret", Product::Vault);

        for different in [
            identity(
                "openbao://team-b@bao.example.com:8200/secret",
                Product::OpenBao,
            ),
            identity(
                "openbao://team-a@bao.example.com:8200/cache",
                Product::OpenBao,
            ),
            identity(
                "openbao://team-a@other.example.com:8200/secret",
                Product::OpenBao,
            ),
            identity(
                "openbao://team-a@bao.example.com:8200/secret?tls=false",
                Product::OpenBao,
            ),
        ] {
            assert_ne!(base, different);
        }
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
