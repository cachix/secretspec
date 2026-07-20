//! Infisical provider
//!
//! This provider integrates with [Infisical](https://infisical.com) to store and
//! retrieve secrets over its REST API, against both Infisical Cloud and
//! self-hosted instances.
//!
//! # Authentication
//!
//! A machine identity's `client_id` and `client_secret` are exchanged for a
//! short-lived access token via Universal Auth, cached for the life of the
//! process. A `token` minted elsewhere is used directly instead, which is what
//! CI usually has to hand. Credentials come from the provider alias or from
//! `INFISICAL_CLIENT_ID` / `INFISICAL_CLIENT_SECRET` / `INFISICAL_TOKEN`.
//!
//! Service tokens are not supported: Infisical deprecated them in favour of
//! machine identities.
//!
//! # URI Format
//!
//! `infisical://[host]/{project-id}[?env=slug&path=/prefix&layout=flat&tls=false]`
//!
//! The project is Infisical's own project UUID; its v4 API does not accept a
//! project slug. Query parameters:
//!
//! - `env` -- environment slug. When omitted, the SecretSpec profile names the
//!   environment, so a `production` profile reads Infisical's `production`
//!   environment. Set it to read every profile from one environment, e.g. an
//!   instance whose environments do not correspond to profiles.
//! - `path` -- folder prefix holding SecretSpec's secrets. Defaults to
//!   `/secretspec` under the nested layout and to the environment root (`/`)
//!   under the flat one.
//! - `layout` -- `nested` (default) or `flat`; see [Secret Naming](#secret-naming).
//! - `tls` -- enable TLS: `true` (default) or `false`, for self-hosted
//!   instances served over plain HTTP.
//!
//! When no host is given, falls back to `INFISICAL_DOMAIN`, then to Infisical's
//! legacy `INFISICAL_API_URL`, then to `app.infisical.com`.
//!
//! # Examples
//!
//! - `infisical://app.infisical.com/7e2f...` -- Infisical Cloud (US)
//! - `infisical://eu.infisical.com/7e2f...` -- Infisical Cloud (EU)
//! - `infisical://vault.example.com/7e2f...?env=prod` -- pin one environment
//! - `infisical://localhost:8080/7e2f...?tls=false` -- self-hosted, plain HTTP
//!
//! # Secret Naming
//!
//! Under the default **nested** layout a secret lives at the folder
//! `{path}/{project}/{profile}` in the environment named by the profile, under
//! the key itself:
//!
//! ```text
//! project "myapp", profile "prod", key "DATABASE_URL"
//!   -> environment prod
//!      secretPath  /secretspec/myapp/prod
//!      secretKey   DATABASE_URL
//! ```
//!
//! The profile names the folder as well as the environment, so that pinning
//! `?env=` moves every profile into one environment without two of them
//! landing on the same secret.
//!
//! The **flat** layout (`?layout=flat`) drops the `{project}/{profile}`
//! scaffolding, so a secret sits directly at the folder prefix -- the
//! environment root by default, or `{path}` when one is given:
//!
//! ```text
//! project "myapp", profile "prod", key "DATABASE_URL", layout flat
//!   -> environment prod
//!      secretPath  /
//!      secretKey   DATABASE_URL
//! ```
//!
//! This is the shape a single-project store already has -- a store migrated
//! from another manager, say -- where SecretSpec's namespace folders would only
//! be in the way. The profile still names the environment, so distinct profiles
//! stay apart. But pinning `?env=` under a flat layout collapses every profile
//! onto one environment root, so they share a key: that combination gives up
//! profile separation deliberately, and is only safe when a single profile is
//! ever resolved against the store.
//!
//! Keys are stored verbatim: Infisical imposes no charset of its own, so no
//! rewriting is needed and distinct keys cannot collide. Folder names are
//! narrower, so a project or profile Infisical cannot spell is refused rather
//! than rewritten.
//!
//! A folder that imports another resolves the imported keys too, with
//! Infisical's own precedence: a secret defined directly in the folder wins
//! over an imported one, and a later import wins over an earlier one.

use super::{Address, Layout, Provider, ProviderCredentials, ProviderUrl, credential_or_env};
use crate::config::NativeAddress;
use crate::{Result, SecretSpecError};
use reqwest::StatusCode;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;

/// Default folder prefix holding SecretSpec's secrets under the nested layout.
const DEFAULT_PATH: &str = "/secretspec";
/// The environment root, which is where the flat layout defaults its prefix.
const ROOT_PATH: &str = "/";
/// Infisical Cloud's US host, used when neither the URI nor the environment
/// names one.
const DEFAULT_HOST: &str = "app.infisical.com";

const CLIENT_ID: &str = "client_id";
const CLIENT_SECRET: &str = "client_secret";
const TOKEN: &str = "token";
const INFISICAL_CLIENT_ID_ENV: &str = "INFISICAL_CLIENT_ID";
const INFISICAL_CLIENT_SECRET_ENV: &str = "INFISICAL_CLIENT_SECRET";
const INFISICAL_TOKEN_ENV: &str = "INFISICAL_TOKEN";
/// The environment variables naming the instance, in the Infisical CLI's own
/// precedence order: `INFISICAL_DOMAIN` first, then the legacy
/// `INFISICAL_API_URL` it superseded but still honours (`util.GetEnvDomain`).
/// Reading only the current name would silently send an existing EU or
/// self-hosted setup, configured with the legacy one, to US Cloud.
const INFISICAL_DOMAIN_ENVS: [&str; 2] = ["INFISICAL_DOMAIN", "INFISICAL_API_URL"];

/// The folder prefix used when the URI names none: the `/secretspec` namespace
/// container under the nested [`Layout`], and the environment root under the
/// flat one. The layout is the shared, cross-provider setting; this is how
/// Infisical maps it onto its own default folder.
fn default_path(layout: Layout) -> &'static str {
    match layout {
        Layout::Nested => DEFAULT_PATH,
        Layout::Flat => ROOT_PATH,
    }
}

/// Joins an absolute folder prefix and a key into a secret path, without
/// doubling the separator when the prefix is the root.
fn join_prefix(path: &str, key: &str) -> String {
    if path == ROOT_PATH {
        format!("/{key}")
    } else {
        format!("{path}/{key}")
    }
}

/// Configuration for the Infisical provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfisicalConfig {
    /// The Infisical API endpoint (e.g. `https://app.infisical.com`).
    pub endpoint: String,
    /// The Infisical project UUID.
    pub project_id: String,
    /// Environment slug. When `None`, the profile names the environment.
    pub environment: Option<String>,
    /// Folder prefix holding SecretSpec's secrets.
    pub path: String,
    /// How a convention address maps onto Infisical's folders.
    #[serde(default)]
    pub layout: Layout,
}

impl Default for InfisicalConfig {
    fn default() -> Self {
        Self {
            endpoint: format!("https://{DEFAULT_HOST}"),
            project_id: String::new(),
            environment: None,
            path: DEFAULT_PATH.to_string(),
            layout: Layout::Nested,
        }
    }
}

impl InfisicalConfig {
    /// Reads `INFISICAL_DOMAIN` into an endpoint.
    ///
    /// The URI names a host, so the endpoint is a host too: a domain carrying
    /// a path is refused rather than accepted into a config that
    /// [`uri`](Provider::uri) could not render back.
    ///
    /// A trailing `/api` is the exception, and is dropped rather than refused.
    /// Infisical's own CLI appends `/api` to the domain unless it is already
    /// there, so the suffix is common in a working configuration -- one that
    /// SecretSpec should read the same way, since it appends `/api` too.
    fn endpoint_from_domain(var: &str, domain: &str, http_scheme: &str) -> Result<String> {
        let domain = domain.trim_end_matches('/');
        let domain = domain.strip_suffix("/api").unwrap_or(domain);
        let absolute = if domain.starts_with("http://") || domain.starts_with("https://") {
            domain.to_string()
        } else {
            format!("{http_scheme}://{domain}")
        };

        let parsed = url::Url::parse(&absolute).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!("Invalid {var} '{domain}': {e}"))
        })?;
        if !parsed.path().trim_matches('/').is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid {var} '{domain}': it names a path. Infisical's \
                 API is addressed at the host, e.g. https://vault.example.com."
            )));
        }
        Ok(absolute)
    }

    /// The instance named by the environment, with the variable that named it
    /// so an error can report the one the user actually set.
    fn env_domain() -> Option<(&'static str, String)> {
        Self::pick_domain(|var| std::env::var(var).ok())
    }

    /// The first variable in [`INFISICAL_DOMAIN_ENVS`] that names an instance.
    ///
    /// Trimmed and empty-filtered to match the CLI's `GetEnvDomain`, so a blank
    /// variable falls through to the next rather than being taken as a domain.
    /// Split from [`env_domain`](Self::env_domain) so the precedence is
    /// testable without mutating the process environment.
    fn pick_domain(lookup: impl Fn(&str) -> Option<String>) -> Option<(&'static str, String)> {
        INFISICAL_DOMAIN_ENVS.iter().find_map(|var| {
            let value = lookup(var)?;
            let value = value.trim().to_string();
            (!value.is_empty()).then_some((*var, value))
        })
    }
}

impl TryFrom<&ProviderUrl> for InfisicalConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        let scheme = url.scheme();
        if scheme != "infisical" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{scheme}' for infisical provider. Expected 'infisical'."
            )));
        }

        // An unreadable `tls` is refused rather than read as one of its two
        // meanings: the knob is explicit, so a typo in it should be too.
        let use_tls = url
            .query_pairs()
            .find(|(k, _)| k == "tls")
            .map(|(_, v)| match v.as_ref() {
                "true" | "1" => Ok(true),
                "false" | "0" => Ok(false),
                other => Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Unknown tls value '{other}'. Expected 'true' or 'false'."
                ))),
            })
            .transpose()?
            .unwrap_or(true);
        let http_scheme = if use_tls { "https" } else { "http" };

        // Host from the URI, else the environment, else Infisical Cloud.
        let endpoint = match url.host().filter(|s| !s.is_empty()) {
            Some(host) => match url.port() {
                Some(port) => format!("{http_scheme}://{host}:{port}"),
                None => format!("{http_scheme}://{host}"),
            },
            // The domain is a full URL in Infisical's own CLI.
            None => match Self::env_domain() {
                Some((var, domain)) => Self::endpoint_from_domain(var, &domain, http_scheme)?,
                None => format!("{http_scheme}://{DEFAULT_HOST}"),
            },
        };

        // The project UUID is the URI path; Infisical's v4 API has no slug form.
        let project_id = url.path().trim_matches('/').to_string();
        if project_id.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "No Infisical project given. Name the project UUID in the URI, e.g. \
                 infisical://app.infisical.com/7e2f1a4c-....  Infisical's API takes the \
                 project's UUID (Project Settings -> Project ID), not its slug."
                    .to_string(),
            ));
        }
        if project_id.contains('/') {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid Infisical project '{project_id}': expected a single project UUID. \
                 The folder holding the secrets is set with `?path=` instead."
            )));
        }

        let environment = url.query_value("env").filter(|s| !s.is_empty());

        // `layout` is the shared, cross-provider setting, parsed the same way
        // everywhere; an unreadable value is refused rather than guessed.
        let layout = url.layout()?;

        // The default prefix follows the layout: `/secretspec` namespaces the
        // nested layout, while the flat one sits at the environment root.
        let path = match url.query_value("path").filter(|s| !s.is_empty()) {
            Some(p) => {
                let trimmed = p.trim_end_matches('/');
                if trimmed.starts_with('/') {
                    trimmed.to_string()
                } else {
                    format!("/{trimmed}")
                }
            }
            None => default_path(layout).to_string(),
        };

        Ok(Self {
            endpoint,
            project_id,
            environment,
            path,
            layout,
        })
    }
}

/// One secret's location in Infisical's own terms.
struct Location {
    environment: String,
    secret_path: String,
    key: String,
}

/// Infisical provider.
pub struct InfisicalProvider {
    config: InfisicalConfig,
    /// Credentials supplied by the provider alias.
    credentials: ProviderCredentials,
    /// The Universal Auth access token, fetched once per process. Infisical's
    /// tokens are short-lived (7200s by default), which outlives any single
    /// SecretSpec invocation.
    ///
    /// Async, because the exchange itself must be serialized rather than merely
    /// its result: a batch read fetches distinct addresses concurrently, and a
    /// cell that only guards the completed token lets every caller log in and
    /// then discard all but one. Infisical supports client secrets with a
    /// one-use limit, for which the surplus exchanges are not just waste but a
    /// hard failure.
    token: tokio::sync::OnceCell<SecretString>,
    /// One HTTP client for every request, so a run of secrets reuses the
    /// connection rather than building a pool per call.
    http: OnceLock<reqwest::Client>,
}

crate::register_provider! {
    struct: InfisicalProvider,
    config: InfisicalConfig,
    name: "infisical",
    description: "Infisical secret management",
    schemes: ["infisical"],
    examples: ["infisical://app.infisical.com/{project-id}"],
    credential_names: [CLIENT_ID, CLIENT_SECRET, TOKEN],
}

impl InfisicalProvider {
    /// Creates a new InfisicalProvider with the given configuration.
    pub fn new(config: InfisicalConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
            token: tokio::sync::OnceCell::new(),
            http: OnceLock::new(),
        }
    }

    /// The shared HTTP client.
    fn http(&self) -> &reqwest::Client {
        self.http.get_or_init(reqwest::Client::new)
    }

    /// Resolves an address to one secret's Infisical location.
    ///
    /// `item` carries the folder and the key together, so convention and `ref`
    /// addresses share one spelling of the layout. The environment comes from
    /// the address itself, since the profile names it when `?env=` does not.
    fn locate(&self, addr: Address<'_>) -> Result<Location> {
        let coords = self.resolve_coords(addr)?;

        let environment = match (&self.config.environment, addr) {
            (Some(env), _) => env.clone(),
            (None, Address::Convention { profile, .. }) => profile.to_string(),
            (None, Address::Native(_)) => {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "No Infisical environment for this ref. Name one in the provider URI, \
                     e.g. infisical://app.infisical.com/{project-id}?env=prod."
                        .to_string(),
                ));
            }
        };

        // A leading slash distinguishes the two forms a ref can take: `/DB`
        // names the environment's root, while `DB` and `team/DB` alike are read
        // under the configured prefix. Trimming the slash first would move a
        // root secret under the prefix, where reading it finds nothing; reading
        // a relative folder from the root instead would put the prefix out of
        // reach of every ref that names a folder.
        let (secret_path, key) = match coords.item.rsplit_once('/') {
            Some((folder, key)) => {
                let folder = folder.trim_end_matches('/');
                let secret_path = match folder {
                    "" => "/".to_string(),
                    relative if !relative.starts_with('/') => {
                        // The prefix is `/` at the root, where a naive join
                        // would double the separator.
                        format!("{}/{relative}", self.config.path.trim_end_matches('/'))
                    }
                    absolute => absolute.to_string(),
                };
                (secret_path, key.to_string())
            }
            // A bare name sits at the folder prefix itself.
            None => (self.config.path.clone(), coords.item.clone()),
        };
        if key.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid Infisical ref '{}': it names a folder, not a secret.",
                coords.item
            )));
        }

        Ok(Location {
            environment,
            secret_path,
            key,
        })
    }

    /// Resolves the access token, logging in at most once.
    ///
    /// An already-minted token is used directly; otherwise a machine
    /// identity's credentials are exchanged for one. Infisical's tokens are
    /// short-lived (7200s by default), which outlives any single SecretSpec
    /// invocation, so the token is fetched once and never renewed.
    ///
    /// The login is awaited rather than blocked on: this runs inside the
    /// runtime that [`block_on`](super::block_on) already entered for the
    /// request, and blocking there would panic.
    async fn resolve_token(&self) -> Result<&SecretString> {
        // `get_or_try_init` runs one initializer at a time: a concurrent caller
        // waits for the in-flight exchange and takes its token rather than
        // starting a second one. On failure the cell stays empty, so a later
        // call retries instead of caching the error.
        self.token
            .get_or_try_init(|| async {
                // `credential_or_env` never yields an empty value, so a blank
                // INFISICAL_TOKEN reads as absent rather than as a broken token.
                match credential_or_env(&self.credentials, TOKEN, INFISICAL_TOKEN_ENV) {
                    Some(token) => Ok(SecretString::new(token.into())),
                    None => self.login().await,
                }
            })
            .await
    }

    /// Exchanges the machine identity's credentials for an access token.
    async fn login(&self) -> Result<SecretString> {
        let client_id = credential_or_env(&self.credentials, CLIENT_ID, INFISICAL_CLIENT_ID_ENV);
        let client_secret = credential_or_env(
            &self.credentials,
            CLIENT_SECRET,
            INFISICAL_CLIENT_SECRET_ENV,
        );

        // A half-specified identity is an error: falling back to an anonymous
        // request would fail later with an opaque 401 instead.
        let (client_id, client_secret) = match (client_id, client_secret) {
            (Some(id), Some(secret)) => (id, secret),
            (None, None) => {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "No Infisical credentials found. Configure the {CLIENT_ID} and \
                     {CLIENT_SECRET} provider credentials (or a ready-made {TOKEN}), or set \
                     {INFISICAL_CLIENT_ID_ENV} and {INFISICAL_CLIENT_SECRET_ENV} (or \
                     {INFISICAL_TOKEN_ENV})."
                )));
            }
            (Some(_), None) => {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Infisical {CLIENT_SECRET} is missing. Configure the {CLIENT_SECRET} \
                     provider credential, or set {INFISICAL_CLIENT_SECRET_ENV}."
                )));
            }
            (None, Some(_)) => {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Infisical {CLIENT_ID} is missing. Configure the {CLIENT_ID} provider \
                     credential, or set {INFISICAL_CLIENT_ID_ENV}."
                )));
            }
        };

        let url = format!("{}/api/v1/auth/universal-auth/login", self.config.endpoint);
        let body = serde_json::json!({
            "clientId": client_id,
            "clientSecret": client_secret,
        });

        let response = self
            .http()
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to connect to Infisical at {}: {e}",
                    self.config.endpoint
                ))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Infisical login returned HTTP {status}: {}",
                Self::error_message(&body)
            )));
        }

        let parsed: serde_json::Value = response.json().await.map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to parse Infisical login response: {e}"
            ))
        })?;

        let token = parsed["accessToken"].as_str().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "Infisical login response missing accessToken".to_string(),
            )
        })?;

        Ok(SecretString::new(token.to_string().into()))
    }

    /// Infisical's error envelope carries a human-readable `message`; the
    /// status code, not this text, decides control flow.
    fn error_message(body: &str) -> String {
        serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v["message"].as_str().map(str::to_string))
            .unwrap_or_else(|| body.to_string())
    }

    /// The query shared by every read: which project, environment and folder.
    ///
    /// `expandSecretReferences` follows Infisical's own default and CLI: a
    /// `${...}` reference is a feature its users configure deliberately, so the
    /// value SecretSpec hands over is the resolved one.
    ///
    /// `viewSecretValue` is set explicitly rather than left to its default,
    /// since Infisical can withhold a value from an identity that may only see
    /// that a secret exists. Requesting the value does not guarantee it, so
    /// every read is checked with [`secret_value`](Self::secret_value).
    fn read_query<'q>(
        &'q self,
        environment: &'q str,
        secret_path: &'q str,
    ) -> Vec<(&'static str, &'q str)> {
        vec![
            ("projectId", self.config.project_id.as_str()),
            ("environment", environment),
            ("secretPath", secret_path),
            ("expandSecretReferences", "true"),
            ("viewSecretValue", "true"),
        ]
    }

    /// Reads one secret's value from its JSON, rejecting a value Infisical
    /// withheld.
    ///
    /// An identity allowed to see that a secret exists, but not to read it,
    /// still gets HTTP 200: the value is replaced with a placeholder and
    /// `secretValueHidden` is set. Passing that placeholder on would export a
    /// literal `<hidden-by-infisical>` to the process SecretSpec runs, so it is
    /// reported as the refusal it is.
    fn secret_value(secret: &serde_json::Value, key: &str) -> Result<Option<SecretString>> {
        if secret["secretValueHidden"].as_bool() == Some(true) {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Infisical withheld the value of '{key}': this identity may see that the \
                 secret exists but not read it. Grant it permission to read secret values."
            )));
        }
        Ok(secret["secretValue"]
            .as_str()
            .map(|v| SecretString::new(v.to_string().into())))
    }

    /// The URL naming one secret.
    ///
    /// Infisical accepts any non-empty key -- spaces and non-ASCII included --
    /// so the key is escaped as a path segment rather than interpolated.
    fn secret_url(&self, key: &str) -> Result<String> {
        let mut url = url::Url::parse(&self.config.endpoint).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Invalid Infisical endpoint '{}': {e}",
                self.config.endpoint
            ))
        })?;
        url.path_segments_mut()
            .map_err(|_| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Invalid Infisical endpoint '{}': not a base URL",
                    self.config.endpoint
                ))
            })?
            .extend(["api", "v4", "secrets", key]);
        Ok(url.into())
    }

    /// Reads one secret, by version when the ref pins one.
    async fn get_async(
        &self,
        loc: &Location,
        version: Option<&str>,
    ) -> Result<Option<SecretString>> {
        let url = self.secret_url(&loc.key)?;
        let mut query = self.read_query(&loc.environment, &loc.secret_path);
        if let Some(version) = version {
            query.push(("version", version));
        }

        let response = self.send(reqwest::Method::GET, &url, &query, None).await?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        match status {
            StatusCode::OK => {
                let parsed: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to parse Infisical response: {e}"
                    ))
                })?;
                Self::secret_value(&parsed["secret"], &loc.key)
            }
            // A 404 covers a missing secret, folder, environment and project
            // alike, and only the message text tells them apart. Reading it
            // would make control flow turn on prose, so all four are taken as
            // "nothing stored here", which `check` and provider fallback read
            // as "not set". A misspelled `?env=` therefore looks like an unset
            // secret until a write reports it.
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(self.http_error(status, &body, "reading a secret")),
        }
    }

    /// Folds a list response's imported secrets into the keys read directly
    /// from the folder.
    ///
    /// A folder can import others, and the list endpoint answers with those in
    /// a separate `imports` array rather than merged into `secrets` (it sets
    /// `includeImports` by default, so they arrive whether or not they are
    /// asked for). Ignoring them would make a batch read disagree with a
    /// single read of the same key, which does resolve imports: `check` and
    /// `run` would call an imported secret missing while `get` returned it.
    ///
    /// The precedence mirrors the Infisical CLI's `InjectRawImportedSecret`, so
    /// a value resolves the same way here as it does through their own tool: a
    /// secret defined directly in the folder wins over any import, and among
    /// imports a later entry wins over an earlier one (the CLI walks the array
    /// in reverse, taking the first value it finds for a key).
    fn merge_imports(
        parsed: &serde_json::Value,
        listed: &mut HashMap<String, SecretString>,
    ) -> Result<()> {
        // Absent rather than empty on an instance that predates imports, or on
        // a folder that imports nothing.
        let Some(imports) = parsed["imports"].as_array() else {
            return Ok(());
        };

        for import in imports.iter().rev() {
            let Some(secrets) = import["secrets"].as_array() else {
                continue;
            };
            for secret in secrets {
                let Some(key) = secret["secretKey"].as_str() else {
                    continue;
                };
                // A direct secret, or a higher-precedence import, already
                // claimed this key.
                if listed.contains_key(key) {
                    continue;
                }
                // Withheld values are refused here exactly as for a direct
                // secret: an imported key the identity may not read must not
                // arrive as the literal placeholder.
                if let Some(value) = Self::secret_value(secret, key)? {
                    listed.insert(key.to_string(), value);
                }
            }
        }
        Ok(())
    }

    /// Lists every secret in one folder, indexed by key. Infisical has no
    /// fetch-these-N-names endpoint, so a batch read lists the folder once.
    async fn list_async(
        &self,
        environment: &str,
        secret_path: &str,
    ) -> Result<HashMap<String, SecretString>> {
        let url = format!("{}/api/v4/secrets", self.config.endpoint);
        let query = self.read_query(environment, secret_path);

        let response = self.send(reqwest::Method::GET, &url, &query, None).await?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        match status {
            StatusCode::OK => {
                let parsed: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to parse Infisical response: {e}"
                    ))
                })?;
                let secrets = parsed["secrets"].as_array().ok_or_else(|| {
                    SecretSpecError::ProviderOperationFailed(
                        "Infisical list response missing `secrets`".to_string(),
                    )
                })?;
                let mut listed = HashMap::new();
                for secret in secrets {
                    let Some(key) = secret["secretKey"].as_str() else {
                        continue;
                    };
                    // A withheld value is refused here rather than dropped:
                    // omitting it would read as a secret that is simply unset.
                    if let Some(value) = Self::secret_value(secret, key)? {
                        listed.insert(key.to_string(), value);
                    }
                }
                Self::merge_imports(&parsed, &mut listed)?;
                Ok(listed)
            }
            // An absent folder holds no secrets, exactly like an empty one.
            StatusCode::NOT_FOUND => Ok(HashMap::new()),
            _ => Err(self.http_error(status, &body, "listing secrets")),
        }
    }

    /// Writes a secret, creating its folder when Infisical requires one.
    ///
    /// Infisical separates creating a secret from updating one, and does not
    /// create a folder implicitly: writing into a folder that does not exist
    /// fails and stores nothing, not even part of the path. Each request is
    /// chosen from the status of the one before it, so updating an existing
    /// secret costs a single call, and only a new secret costs more.
    async fn set_async(&self, loc: &Location, value: &SecretString) -> Result<()> {
        // A secret that is merely absent, and a folder that is absent, both
        // answer 404 here.
        if self
            .write_secret(reqwest::Method::PATCH, loc, value)
            .await?
        {
            return Ok(());
        }
        if self.write_secret(reqwest::Method::POST, loc, value).await? {
            return Ok(());
        }

        // The folder is what is missing, unless the secret lives at the root,
        // which always exists -- then the 404 is the environment's.
        if loc.secret_path == "/" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Infisical has no environment '{}' in project {}. Environments are \
                 SecretSpec profiles here unless the provider URI pins one with `?env=`.",
                loc.environment, self.config.project_id
            )));
        }
        let refused = self.create_folder(loc).await?;

        if self.write_secret(reqwest::Method::POST, loc, value).await? {
            return Ok(());
        }
        Err(SecretSpecError::ProviderOperationFailed(format!(
            "Infisical could not find the folder '{}' in environment '{}' even after \
             creating it{}",
            loc.secret_path,
            loc.environment,
            match refused {
                Some(reason) => format!(", which reported: {reason}"),
                None => ".".to_string(),
            }
        )))
    }

    /// Creates or updates one secret. `Ok(false)` reports the 404 that means
    /// the secret, its folder or its environment is absent; the caller decides
    /// which, since Infisical answers all three alike.
    async fn write_secret(
        &self,
        method: reqwest::Method,
        loc: &Location,
        value: &SecretString,
    ) -> Result<bool> {
        let url = self.secret_url(&loc.key)?;
        let body = serde_json::json!({
            "projectId": self.config.project_id,
            "environment": loc.environment,
            "secretPath": loc.secret_path,
            "secretValue": value.expose_secret(),
        });

        let response = self.send(method, &url, &[], Some(body)).await?;
        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(false);
        }
        let body = response.text().await.unwrap_or_default();
        if status.is_success() {
            Self::written(&body, &loc.key)?;
            return Ok(true);
        }
        Err(self.http_error(status, &body, "writing a secret"))
    }

    /// Confirms a write that answered 200 actually stored the value.
    ///
    /// A project can carry an approval policy, under which a write is not a
    /// write but a change request: Infisical still answers 200, with an
    /// `approval` in place of the `secret`, and the value lands only once a
    /// human merges it. Reading that as success would have `set` report a
    /// secret stored that nobody can read back.
    fn written(body: &str, key: &str) -> Result<()> {
        let parsed: serde_json::Value = match serde_json::from_str(body) {
            Ok(parsed) => parsed,
            // A 200 whose body will not parse is left alone: the write is the
            // server's word, and the shape is only consulted to catch the
            // approval case.
            Err(_) => return Ok(()),
        };
        let Some(approval) = parsed.get("approval") else {
            return Ok(());
        };
        let status = approval["status"].as_str().unwrap_or("open");
        Err(SecretSpecError::ProviderOperationFailed(format!(
            "Infisical did not store '{key}': this project has an approval policy, so the \
             write opened a change request ({status}) instead. The value lands once the \
             request is approved in Infisical."
        )))
    }

    /// Creates the folder holding a secret, and any parent it still needs:
    /// Infisical creates the intermediate levels of a nested path in the one
    /// call.
    /// Returns whatever a refused creation said, for the caller to quote if
    /// the write that follows still fails.
    async fn create_folder(&self, loc: &Location) -> Result<Option<String>> {
        let (parent, name) = loc
            .secret_path
            .rsplit_once('/')
            .map(|(parent, name)| {
                let parent = if parent.is_empty() { "/" } else { parent };
                (parent.to_string(), name.to_string())
            })
            .ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Invalid Infisical folder '{}': paths are absolute, e.g. /secretspec.",
                    loc.secret_path
                ))
            })?;

        let url = format!("{}/api/v2/folders", self.config.endpoint);
        let body = serde_json::json!({
            "projectId": self.config.project_id,
            "environment": loc.environment,
            "path": parent,
            "name": name,
        });

        let response = self
            .send(reqwest::Method::POST, &url, &[], Some(body))
            .await?;
        let status = response.status();
        if status.is_success() {
            return Ok(None);
        }
        let body = response.text().await.unwrap_or_default();
        // A folder that already exists answers 400, and so does a folder a
        // concurrent SecretSpec run created. Telling those apart would mean
        // reading the message, so the write that follows decides instead: it
        // succeeds if the folder is present, whichever run created it. The
        // refusal's message is returned so a write that still fails can name
        // the reason rather than discard it.
        if status == StatusCode::BAD_REQUEST {
            return Ok(Some(Self::error_message(&body)));
        }
        Err(self.http_error(status, &body, "creating a folder"))
    }

    /// Sends an authenticated request.
    async fn send(
        &self,
        method: reqwest::Method,
        url: &str,
        query: &[(&str, &str)],
        body: Option<serde_json::Value>,
    ) -> Result<reqwest::Response> {
        let token = self.resolve_token().await?;
        let mut request = self
            .http()
            .request(method, url)
            .bearer_auth(token.expose_secret())
            .query(query);
        if let Some(body) = body {
            request = request.json(&body);
        }
        request.send().await.map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to connect to Infisical at {}: {e}",
                self.config.endpoint
            ))
        })
    }

    /// Renders a failed response, naming the likely cause for the statuses a
    /// user actually hits.
    fn http_error(&self, status: StatusCode, body: &str, action: &str) -> SecretSpecError {
        let message = Self::error_message(body);
        match status {
            StatusCode::UNAUTHORIZED => SecretSpecError::ProviderOperationFailed(format!(
                "Infisical authentication failed (401) while {action}: {message}. \
                 Check the machine identity's {CLIENT_ID}/{CLIENT_SECRET}."
            )),
            StatusCode::FORBIDDEN => SecretSpecError::ProviderOperationFailed(format!(
                "Infisical denied access (403) while {action}: {message}. Check the machine \
                 identity's permissions on project {}.",
                self.config.project_id
            )),
            StatusCode::TOO_MANY_REQUESTS => SecretSpecError::ProviderOperationFailed(format!(
                "Infisical rate limit exceeded (429) while {action}: {message}."
            )),
            _ => SecretSpecError::ProviderOperationFailed(format!(
                "Infisical returned HTTP {status} while {action}: {message}"
            )),
        }
    }
}

impl Provider for InfisicalProvider {
    /// A profile's secrets share one folder under the configured prefix, each
    /// under its own key. `item` carries the folder and the key together; the
    /// environment is resolved separately in [`locate`](Self::locate), since
    /// SecretSpec's `ref` table has no coordinate for it.
    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
        for (label, value) in [("project", project), ("profile", profile), ("key", key)] {
            if value.is_empty() {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "{label} cannot be empty"
                )));
            }
        }
        // Infisical addresses folders like a filesystem, so a key carrying a
        // separator would silently move the secret to another folder. The key
        // is otherwise unconstrained -- spaces and non-ASCII included -- so it
        // is stored exactly as written, and two distinct keys can never land
        // on one name.
        if key.contains('/') {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid key '{key}': Infisical addresses folders by path, so a '/' would \
                 move the secret to another folder."
            )));
        }

        // The flat layout drops the `{project}/{profile}` folders, so the
        // secret sits at the prefix itself and neither name reaches a folder --
        // the folder-spelling rule below has nothing to constrain.
        if self.config.layout == Layout::Flat {
            return Ok(NativeAddress {
                item: join_prefix(&self.config.path, key),
                ..Default::default()
            });
        }

        // The project and profile each name a folder, and Infisical spells
        // folder names in a narrower alphabet than keys. Rewriting a name to
        // fit would let two projects share a folder, so an unspellable one is
        // refused instead.
        for (label, value) in [("Project", project), ("Profile", profile)] {
            if !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "{label} '{value}' cannot name an Infisical folder: only letters, digits, \
                     dashes and underscores are allowed. Rename it in secretspec.toml, or \
                     address these secrets by their own coordinates with \
                     ref = {{ item = \"/folder/KEY\" }}."
                )));
            }
        }

        Ok(NativeAddress {
            item: format!("{}/{project}/{profile}/{key}", self.config.path),
            ..Default::default()
        })
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    /// The inverse of parsing: every knob the config holds is rendered, so the
    /// URI naming this store in an audit record or a warning is one that reads
    /// back as the same store. `tls` is the one that bites -- a plain-HTTP
    /// endpoint rendered without it comes back as HTTPS.
    fn uri(&self) -> String {
        let plain_http = self.config.endpoint.starts_with("http://");
        let host = self
            .config
            .endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let mut uri = format!("infisical://{host}/{}", self.config.project_id);
        let mut query = Vec::new();
        if let Some(env) = &self.config.environment {
            query.push(format!("env={}", ProviderUrl::encode_query(env)));
        }
        if self.config.layout == Layout::Flat {
            query.push("layout=flat".to_string());
        }
        // A prefix equal to the layout's own default reads back the same
        // without being spelled, so only a divergent one is rendered.
        if self.config.path != default_path(self.config.layout) {
            query.push(format!(
                "path={}",
                ProviderUrl::encode_query(&self.config.path)
            ));
        }
        if plain_http {
            query.push("tls=false".to_string());
        }
        if !query.is_empty() {
            uri.push('?');
            uri.push_str(&query.join("&"));
        }
        uri
    }

    /// Infisical versions its secrets, so a `ref` may pin one. Its values are
    /// single strings with no sub-components, so `field`, `section` and
    /// `vault` are rejected.
    fn supported_coords(&self) -> &'static [&'static str] {
        &["version"]
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let loc = self.locate(addr)?;
        let version = match addr {
            Address::Native(native) => native.version.as_deref(),
            Address::Convention { .. } => None,
        };
        super::block_on(self.get_async(&loc, version))
    }

    /// Secrets sharing a folder and environment are read with one list call
    /// each, rather than one round trip per secret: Infisical's cloud rate
    /// limits are per-minute, and a fan-out of single reads burns them.
    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        // A pinned version names one historical value, which the folder
        // listing (always latest) cannot answer.
        let (versioned, listable): (Vec<_>, Vec<_>) = requests.iter().partition(
            |(_, addr)| matches!(addr, Address::Native(native) if native.version.is_some()),
        );

        // Nothing about a versioned read is Infisical-specific, so it keeps the
        // shared fetch, which already fetches one address once however many
        // secrets name it, and fetches distinct ones concurrently.
        let versioned: Vec<(&str, Address<'_>)> = versioned.into_iter().copied().collect();
        let mut resolved = if versioned.is_empty() {
            HashMap::new()
        } else {
            super::get_each(self, &versioned)?
        };

        super::block_on(async {
            // One list call per distinct folder and environment.
            let mut folders: HashMap<(String, String), Vec<(&str, String)>> = HashMap::new();
            for (name, addr) in &listable {
                let loc = self.locate(*addr)?;
                folders
                    .entry((loc.environment, loc.secret_path))
                    .or_default()
                    .push((name, loc.key));
            }

            for ((environment, secret_path), wanted) in folders {
                let listed = self.list_async(&environment, &secret_path).await?;
                for (name, key) in wanted {
                    if let Some(value) = listed.get(&key) {
                        resolved.insert(name.to_string(), value.clone());
                    }
                }
            }

            Ok(resolved)
        })
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        self.check_writable(addr)?;
        let loc = self.locate(addr)?;
        super::block_on(self.set_async(&loc, value))
    }

    /// A pinned version names a value that already exists; writing one would
    /// mean rewriting history, which Infisical does not offer.
    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        match addr {
            Address::Native(native) if native.version.is_some() => {
                Err(SecretSpecError::ProviderOperationFailed(
                    "infisical refs pinning a `version` are read-only: a past version cannot \
                     be rewritten. Drop `version` to write the secret's latest value."
                        .to_string(),
                ))
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    const PROJECT: &str = "7e2f1a4c-0000-0000-0000-000000000000";

    fn config(s: &str) -> InfisicalConfig {
        InfisicalConfig::try_from(&ProviderUrl::new(Url::parse(s).unwrap())).unwrap()
    }

    fn provider(s: &str) -> InfisicalProvider {
        InfisicalProvider::new(config(s))
    }

    #[test]
    fn uri_defaults_to_infisical_cloud() {
        let c = config(&format!("infisical:///{PROJECT}"));
        assert_eq!(c.endpoint, "https://app.infisical.com");
        assert_eq!(c.project_id, PROJECT);
        assert_eq!(c.path, DEFAULT_PATH);
        assert_eq!(c.environment, None);
    }

    #[test]
    fn uri_carries_host_environment_and_path() {
        let c = config(&format!(
            "infisical://localhost:8080/{PROJECT}?env=prod&path=/team&tls=false"
        ));
        assert_eq!(c.endpoint, "http://localhost:8080");
        assert_eq!(c.environment.as_deref(), Some("prod"));
        assert_eq!(c.path, "/team");
    }

    /// A project is required, and its absence names the UUID that v4 wants:
    /// the slug the Infisical UI shows is not addressable.
    #[test]
    fn uri_without_a_project_is_rejected() {
        let err = InfisicalConfig::try_from(&ProviderUrl::new(
            Url::parse("infisical://app.infisical.com").unwrap(),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("UUID"), "{err}");
    }

    /// The profile names the folder as well as the environment, so pinning
    /// `?env=` cannot make two profiles share one secret.
    #[test]
    fn every_profile_gets_its_own_folder() {
        let p = provider(&format!("infisical://app.infisical.com/{PROJECT}?env=dev"));
        let dev = p.convention_address("myapp", "dev", "API_KEY").unwrap();
        let prod = p.convention_address("myapp", "prod", "API_KEY").unwrap();
        assert_eq!(dev.item, "/secretspec/myapp/dev/API_KEY");
        assert_ne!(dev.item, prod.item);
    }

    /// The profile names the environment when the URI pins none.
    #[test]
    fn profile_names_the_environment() {
        let p = provider(&format!("infisical://app.infisical.com/{PROJECT}"));
        let loc = p
            .locate(Address::convention("myapp", "prod", "API_KEY"))
            .unwrap();
        assert_eq!(loc.environment, "prod");
        assert_eq!(loc.secret_path, "/secretspec/myapp/prod");
        assert_eq!(loc.key, "API_KEY");

        let pinned = provider(&format!("infisical://app.infisical.com/{PROJECT}?env=dev"));
        let loc = pinned
            .locate(Address::convention("myapp", "prod", "API_KEY"))
            .unwrap();
        assert_eq!(loc.environment, "dev");
        // The folder still keeps the profile apart.
        assert_eq!(loc.secret_path, "/secretspec/myapp/prod");
    }

    /// Keys are stored exactly as written: Infisical constrains them no
    /// further than being non-empty, so nothing needs rewriting.
    #[test]
    fn keys_are_stored_verbatim() {
        let p = provider(&format!("infisical://app.infisical.com/{PROJECT}"));
        for key in ["lower_case", "SECTION__KEY", "with.dot", "with-dash"] {
            let addr = p.convention_address("myapp", "dev", key).unwrap();
            assert_eq!(addr.item, format!("/secretspec/myapp/dev/{key}"));
        }
    }

    /// A folder name Infisical cannot spell is refused, not rewritten: a
    /// rewrite could land two projects on one folder.
    #[test]
    fn unspellable_folder_names_are_refused() {
        let p = provider(&format!("infisical://app.infisical.com/{PROJECT}"));
        let err = p.convention_address("my.app", "dev", "KEY").unwrap_err();
        assert!(
            err.to_string().contains("cannot name an Infisical folder"),
            "{err}"
        );
        let err = p
            .convention_address("myapp", "my.profile", "KEY")
            .unwrap_err();
        assert!(
            err.to_string().contains("cannot name an Infisical folder"),
            "{err}"
        );
    }

    /// The flat layout defaults its prefix to the environment root, so a
    /// convention secret sits there with no `{project}/{profile}` folders.
    #[test]
    fn flat_layout_addresses_the_root() {
        let c = config(&format!(
            "infisical://app.infisical.com/{PROJECT}?layout=flat"
        ));
        assert_eq!(c.layout, Layout::Flat);
        assert_eq!(c.path, "/");

        let p = InfisicalProvider::new(c);
        assert_eq!(
            p.convention_address("myapp", "prod", "API_KEY")
                .unwrap()
                .item,
            "/API_KEY"
        );
        let loc = p
            .locate(Address::convention("myapp", "prod", "API_KEY"))
            .unwrap();
        assert_eq!(loc.secret_path, "/");
        assert_eq!(loc.environment, "prod");
        assert_eq!(loc.key, "API_KEY");
    }

    /// An explicit `?path=` under the flat layout is honored as the prefix,
    /// still with no `{project}/{profile}` scaffolding.
    #[test]
    fn flat_layout_honors_an_explicit_prefix() {
        let p = provider(&format!(
            "infisical://app.infisical.com/{PROJECT}?layout=flat&path=/team"
        ));
        assert_eq!(
            p.convention_address("myapp", "prod", "API_KEY")
                .unwrap()
                .item,
            "/team/API_KEY"
        );
        let loc = p
            .locate(Address::convention("myapp", "prod", "API_KEY"))
            .unwrap();
        assert_eq!(loc.secret_path, "/team");
        assert_eq!(loc.key, "API_KEY");
    }

    /// The flat layout puts neither project nor profile in a folder, so a name
    /// Infisical could not spell as a folder is no longer constrained.
    #[test]
    fn flat_layout_does_not_constrain_project_or_profile_names() {
        let p = provider(&format!(
            "infisical://app.infisical.com/{PROJECT}?layout=flat"
        ));
        assert_eq!(
            p.convention_address("my.app", "my.profile", "API_KEY")
                .unwrap()
                .item,
            "/API_KEY"
        );
    }

    /// A key carrying a separator is still refused under the flat layout: it
    /// would move the secret to another folder.
    #[test]
    fn flat_layout_still_rejects_a_key_with_a_slash() {
        let p = provider(&format!(
            "infisical://app.infisical.com/{PROJECT}?layout=flat"
        ));
        let err = p.convention_address("myapp", "prod", "a/b").unwrap_err();
        assert!(err.to_string().contains("move the secret"), "{err}");
    }

    /// Flat without `?env=` still lets the profile name the environment, so
    /// distinct profiles stay apart even sharing the root and key.
    #[test]
    fn flat_layout_separates_profiles_by_environment() {
        let p = provider(&format!(
            "infisical://app.infisical.com/{PROJECT}?layout=flat"
        ));
        let dev = p
            .locate(Address::convention("myapp", "dev", "API_KEY"))
            .unwrap();
        let prod = p
            .locate(Address::convention("myapp", "prod", "API_KEY"))
            .unwrap();
        assert_eq!(
            (dev.secret_path.as_str(), dev.key.as_str()),
            ("/", "API_KEY")
        );
        assert_eq!(
            (prod.secret_path.as_str(), prod.key.as_str()),
            ("/", "API_KEY")
        );
        // Same root and key, but different environments keep them apart.
        assert_eq!(dev.environment, "dev");
        assert_eq!(prod.environment, "prod");
    }

    /// Flat plus a pinned `?env=` collapses every profile onto one environment
    /// root and key -- the deliberate "no profile separation" mode.
    #[test]
    fn flat_layout_with_pinned_env_collapses_profiles() {
        let p = provider(&format!(
            "infisical://app.infisical.com/{PROJECT}?layout=flat&env=prod"
        ));
        let dev = p
            .locate(Address::convention("myapp", "dev", "API_KEY"))
            .unwrap();
        let prod = p
            .locate(Address::convention("myapp", "prod", "API_KEY"))
            .unwrap();
        assert_eq!(dev.environment, prod.environment);
        assert_eq!(dev.secret_path, prod.secret_path);
        assert_eq!(dev.key, prod.key);
    }

    /// The default and explicit nested layout are the same store, and neither
    /// touches the flat behavior.
    #[test]
    fn nested_layout_is_the_default() {
        let default = config(&format!("infisical://app.infisical.com/{PROJECT}"));
        let explicit = config(&format!(
            "infisical://app.infisical.com/{PROJECT}?layout=nested"
        ));
        assert_eq!(default.layout, Layout::Nested);
        assert_eq!(explicit.layout, Layout::Nested);
        assert_eq!(default.path, "/secretspec");
        assert_eq!(explicit.path, "/secretspec");
    }

    /// An unreadable `layout` is refused rather than silently meaning one of
    /// its two values, exactly like `tls`.
    #[test]
    fn unreadable_layout_is_rejected() {
        let err = InfisicalConfig::try_from(&ProviderUrl::new(
            Url::parse(&format!("infisical://host/{PROJECT}?layout=banana")).unwrap(),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("layout value 'banana'"), "{err}");
    }

    /// A ref names a folder and key; Infisical values have no components, so
    /// `field` has no meaning and is rejected rather than ignored.
    #[test]
    fn native_address_rejects_field() {
        let p = provider(&format!("infisical://app.infisical.com/{PROJECT}?env=dev"));
        let addr = NativeAddress {
            item: "/infra/DB_PASSWORD".into(),
            field: Some("password".into()),
            ..Default::default()
        };
        let err = p.get(Address::Native(&addr)).unwrap_err();
        assert!(err.to_string().contains("`field`"), "{err}");
    }

    /// A ref has no profile to name an environment with, so the URI must.
    #[test]
    fn native_address_needs_an_environment() {
        let p = provider(&format!("infisical://app.infisical.com/{PROJECT}"));
        let addr = NativeAddress {
            item: "/infra/DB_PASSWORD".into(),
            ..Default::default()
        };
        let err = p.get(Address::Native(&addr)).unwrap_err();
        assert!(err.to_string().contains("?env="), "{err}");
    }

    /// A ref splits into the folder holding it and the key itself.
    #[test]
    fn native_address_splits_folder_from_key() {
        let p = provider(&format!("infisical://app.infisical.com/{PROJECT}?env=dev"));
        let addr = NativeAddress {
            item: "/infra/shared/DB_PASSWORD".into(),
            ..Default::default()
        };
        let loc = p.locate(Address::Native(&addr)).unwrap();
        assert_eq!(loc.secret_path, "/infra/shared");
        assert_eq!(loc.key, "DB_PASSWORD");
    }

    /// A past version cannot be rewritten, so those refs refuse writes with
    /// the same reason the pre-check gives.
    #[test]
    fn versioned_refs_are_read_only() {
        let p = provider(&format!("infisical://app.infisical.com/{PROJECT}?env=dev"));
        let addr = NativeAddress {
            item: "/infra/DB_PASSWORD".into(),
            version: Some("3".into()),
            ..Default::default()
        };
        let refusal = p.check_writable(Address::Native(&addr)).unwrap_err();
        assert!(refusal.to_string().contains("read-only"), "{refusal}");
        let err = p
            .set(Address::Native(&addr), &SecretString::new("v".into()))
            .unwrap_err();
        assert_eq!(err.to_string(), refusal.to_string());
    }

    /// A value Infisical withheld is refused, not handed on.
    ///
    /// An identity that may see a secret exists but not read it still gets
    /// HTTP 200, with a placeholder where the value should be. Passing that on
    /// would export a literal `<hidden-by-infisical>` to the process
    /// SecretSpec runs, and reporting it as absent would read as an unset
    /// secret; both are worse than saying what happened.
    #[test]
    fn a_withheld_value_is_refused() {
        let hidden = serde_json::json!({
            "secretKey": "API_KEY",
            "secretValue": "<hidden-by-infisical>",
            "secretValueHidden": true,
        });
        let err = InfisicalProvider::secret_value(&hidden, "API_KEY").unwrap_err();
        assert!(err.to_string().contains("withheld"), "{err}");
        assert!(err.to_string().contains("API_KEY"), "{err}");
    }

    /// A readable value is returned unchanged.
    #[test]
    fn a_readable_value_is_returned() {
        let visible = serde_json::json!({
            "secretKey": "API_KEY",
            "secretValue": "s3cret",
            "secretValueHidden": false,
        });
        let value = InfisicalProvider::secret_value(&visible, "API_KEY")
            .unwrap()
            .expect("a readable value");
        assert_eq!(value.expose_secret(), "s3cret");
    }

    /// Builds a list-response import entry holding one key.
    fn import(path: &str, key: &str, value: &str) -> serde_json::Value {
        serde_json::json!({
            "secretPath": path,
            "environment": "prod",
            "secrets": [{
                "secretKey": key,
                "secretValue": value,
                "secretValueHidden": false,
            }],
        })
    }

    fn merged(parsed: &serde_json::Value, direct: &[(&str, &str)]) -> HashMap<String, String> {
        let mut listed: HashMap<String, SecretString> = direct
            .iter()
            .map(|(k, v)| (k.to_string(), SecretString::new((*v).into())))
            .collect();
        InfisicalProvider::merge_imports(parsed, &mut listed).expect("merge");
        listed
            .into_iter()
            .map(|(k, v)| (k, v.expose_secret().to_string()))
            .collect()
    }

    /// An imported secret is readable in a batch read.
    ///
    /// Infisical answers a folder's imports separately from its own secrets. A
    /// batch read that ignored them would call an imported secret missing while
    /// a single read of the same key returned it.
    #[test]
    fn imported_secrets_are_merged_into_a_listing() {
        let parsed = serde_json::json!({
            "secrets": [],
            "imports": [import("/shared", "DB_HOST", "db.internal")],
        });
        let merged = merged(&parsed, &[]);
        assert_eq!(
            merged.get("DB_HOST").map(String::as_str),
            Some("db.internal")
        );
    }

    /// A folder's own secret wins over an imported one, as in Infisical's CLI.
    #[test]
    fn a_direct_secret_beats_an_import() {
        let parsed = serde_json::json!({
            "secrets": [],
            "imports": [import("/shared", "DB_HOST", "imported")],
        });
        let merged = merged(&parsed, &[("DB_HOST", "direct")]);
        assert_eq!(merged.get("DB_HOST").map(String::as_str), Some("direct"));
    }

    /// Among imports the later entry wins: the CLI walks `imports` in reverse
    /// and keeps the first value it finds for a key.
    #[test]
    fn a_later_import_beats_an_earlier_one() {
        let parsed = serde_json::json!({
            "secrets": [],
            "imports": [
                import("/base", "DB_HOST", "from-base"),
                import("/override", "DB_HOST", "from-override"),
            ],
        });
        let merged = merged(&parsed, &[]);
        assert_eq!(
            merged.get("DB_HOST").map(String::as_str),
            Some("from-override"),
        );
    }

    /// A withheld imported value is refused, exactly as a direct one is.
    #[test]
    fn a_withheld_imported_value_is_refused() {
        let parsed = serde_json::json!({
            "secrets": [],
            "imports": [serde_json::json!({
                "secretPath": "/shared",
                "environment": "prod",
                "secrets": [{
                    "secretKey": "DB_HOST",
                    "secretValue": "<hidden-by-infisical>",
                    "secretValueHidden": true,
                }],
            })],
        });
        let mut listed = HashMap::new();
        let err = InfisicalProvider::merge_imports(&parsed, &mut listed)
            .expect_err("a withheld import must not pass through");
        assert!(err.to_string().contains("DB_HOST"), "{err}");
    }

    /// A response without `imports` is not an error: an instance predating
    /// imports, or a folder importing nothing, simply has none.
    #[test]
    fn a_listing_without_imports_is_unchanged() {
        let parsed = serde_json::json!({ "secrets": [] });
        let merged = merged(&parsed, &[("API_KEY", "kept")]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged.get("API_KEY").map(String::as_str), Some("kept"));
    }

    /// A write held for approval does not report success.
    ///
    /// A project under an approval policy answers a write with 200 and an
    /// `approval` where the `secret` would be, storing nothing until a human
    /// merges it. Reporting that as success would claim a secret was stored
    /// that cannot be read back.
    #[test]
    fn a_write_held_for_approval_is_not_a_write() {
        let held = serde_json::json!({
            "approval": { "id": "8f2c", "status": "open", "hasMerged": false },
        });
        let err = InfisicalProvider::written(&held.to_string(), "API_KEY").unwrap_err();
        assert!(err.to_string().contains("approval policy"), "{err}");
        assert!(err.to_string().contains("API_KEY"), "{err}");
    }

    /// An ordinary write answers with the secret it stored, and reports success.
    #[test]
    fn an_ordinary_write_reports_success() {
        let stored = serde_json::json!({
            "secret": { "id": "1a2b", "secretKey": "API_KEY", "version": 1 },
        });
        InfisicalProvider::written(&stored.to_string(), "API_KEY")
            .expect("a stored secret is not an approval");
        // A body that will not parse is the server's word, taken as given.
        InfisicalProvider::written("", "API_KEY").expect("an unparseable 200 stays a success");
    }

    /// The rendered URI round-trips through parsing.
    ///
    /// `uri()` names this store in audit records and warnings, so it has to
    /// read back as the same store -- including a self-hosted instance on
    /// plain HTTP, which without `tls` would come back as HTTPS.
    #[test]
    fn uri_round_trips() {
        for spec in [
            format!("infisical://app.infisical.com/{PROJECT}"),
            format!("infisical://app.infisical.com/{PROJECT}?env=prod"),
            format!("infisical://app.infisical.com/{PROJECT}?env=prod&path=/team"),
            // Flat at the root renders `layout=flat` but suppresses the default
            // `path=/`; an explicit prefix under flat renders both.
            format!("infisical://app.infisical.com/{PROJECT}?layout=flat"),
            format!("infisical://app.infisical.com/{PROJECT}?layout=flat&path=/team"),
            format!("infisical://app.infisical.com/{PROJECT}?env=prod&layout=flat"),
            format!("infisical://localhost:8080/{PROJECT}?tls=false"),
            format!("infisical://localhost:8080/{PROJECT}?env=dev&tls=false"),
        ] {
            let rendered = provider(&spec).uri();
            assert_eq!(rendered, spec, "uri() must render what parsing read");
            // ... and the rendering must parse back to the same endpoint.
            assert_eq!(
                config(&rendered).endpoint,
                config(&spec).endpoint,
                "re-reading uri() must reach the same instance"
            );
        }
    }

    /// An unreadable `tls` is refused rather than silently meaning one of its
    /// two values.
    #[test]
    fn unreadable_tls_is_rejected() {
        let err = InfisicalConfig::try_from(&ProviderUrl::new(
            Url::parse(&format!("infisical://host/{PROJECT}?tls=banana")).unwrap(),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("tls value 'banana'"), "{err}");
    }

    /// A ref names the environment's root with a leading slash, and the
    /// configured prefix without one. Trimming the slash away would move a
    /// root secret under the prefix, where it reads as unset.
    #[test]
    fn a_root_ref_stays_at_the_root() {
        let p = provider(&format!("infisical://app.infisical.com/{PROJECT}?env=dev"));

        let root = NativeAddress {
            item: "/DB_PASSWORD".into(),
            ..Default::default()
        };
        let loc = p.locate(Address::Native(&root)).unwrap();
        assert_eq!(loc.secret_path, "/");
        assert_eq!(loc.key, "DB_PASSWORD");

        // A bare name still means "in the configured prefix".
        let bare = NativeAddress {
            item: "DB_PASSWORD".into(),
            ..Default::default()
        };
        let loc = p.locate(Address::Native(&bare)).unwrap();
        assert_eq!(loc.secret_path, DEFAULT_PATH);
        assert_eq!(loc.key, "DB_PASSWORD");
    }

    /// A ref that names a folder without a leading slash is read under the
    /// prefix, exactly as a bare name is. Reading it from the root instead
    /// would put the prefix out of reach of every ref naming a folder, and
    /// make `team/DB` mean what `/team/DB` already means.
    #[test]
    fn a_relative_ref_is_read_under_the_prefix() {
        let p = provider(&format!(
            "infisical://app.infisical.com/{PROJECT}?env=dev&path=/myapp"
        ));
        let relative = NativeAddress {
            item: "team/DB_PASSWORD".into(),
            ..Default::default()
        };
        let loc = p.locate(Address::Native(&relative)).unwrap();
        assert_eq!(loc.secret_path, "/myapp/team");

        // ... while the absolute form still names the root, unprefixed.
        let absolute = NativeAddress {
            item: "/team/DB_PASSWORD".into(),
            ..Default::default()
        };
        let loc = p.locate(Address::Native(&absolute)).unwrap();
        assert_eq!(loc.secret_path, "/team");

        // A prefix of `/` joins without doubling the separator.
        let rooted = provider(&format!(
            "infisical://app.infisical.com/{PROJECT}?env=dev&path=/"
        ));
        let loc = rooted.locate(Address::Native(&relative)).unwrap();
        assert_eq!(loc.secret_path, "/team");
    }

    /// Infisical's own CLI appends `/api` to the domain unless it is already
    /// there, so a domain carrying it is a working configuration, not a
    /// mistake. A domain naming any other path still is one.
    #[test]
    fn a_domain_may_carry_the_api_suffix() {
        let var = INFISICAL_DOMAIN_ENVS[0];
        assert_eq!(
            InfisicalConfig::endpoint_from_domain(var, "https://vault.example.com/api", "https")
                .unwrap(),
            "https://vault.example.com"
        );
        assert_eq!(
            InfisicalConfig::endpoint_from_domain(var, "vault.example.com:8080", "https").unwrap(),
            "https://vault.example.com:8080"
        );
        let err =
            InfisicalConfig::endpoint_from_domain(var, "https://example.com/infisical", "https")
                .unwrap_err();
        assert!(err.to_string().contains("names a path"), "{err}");
    }

    /// An invalid domain is reported against the variable that actually set it,
    /// not against whichever name the provider happens to prefer.
    #[test]
    fn an_invalid_domain_names_the_variable_that_set_it() {
        let err =
            InfisicalConfig::endpoint_from_domain("INFISICAL_API_URL", "https://e.com/x", "https")
                .unwrap_err();
        assert!(err.to_string().contains("INFISICAL_API_URL"), "{err}");
    }

    /// The legacy variable still names an instance.
    ///
    /// Infisical superseded `INFISICAL_API_URL` with `INFISICAL_DOMAIN` but
    /// still honours it, so an existing EU or self-hosted setup configured with
    /// the old name must not be silently redirected to US Cloud.
    #[test]
    fn the_legacy_domain_variable_is_honoured() {
        let picked = InfisicalConfig::pick_domain(|var| {
            (var == "INFISICAL_API_URL").then(|| "https://eu.infisical.com".to_string())
        });
        assert_eq!(
            picked,
            Some(("INFISICAL_API_URL", "https://eu.infisical.com".to_string()))
        );
    }

    /// `INFISICAL_DOMAIN` wins when both are set, matching the CLI's
    /// `GetEnvDomain` precedence.
    #[test]
    fn the_current_domain_variable_supersedes_the_legacy_one() {
        let picked = InfisicalConfig::pick_domain(|var| {
            Some(
                match var {
                    "INFISICAL_DOMAIN" => "https://current.example.com",
                    _ => "https://legacy.example.com",
                }
                .to_string(),
            )
        });
        assert_eq!(
            picked,
            Some((
                "INFISICAL_DOMAIN",
                "https://current.example.com".to_string()
            ))
        );
    }

    /// A blank variable falls through rather than being taken as a domain, so
    /// `INFISICAL_DOMAIN=""` still lets the legacy name apply.
    #[test]
    fn a_blank_domain_variable_falls_through() {
        let picked = InfisicalConfig::pick_domain(|var| {
            Some(
                match var {
                    "INFISICAL_DOMAIN" => "   ",
                    _ => "https://legacy.example.com",
                }
                .to_string(),
            )
        });
        assert_eq!(
            picked,
            Some((
                "INFISICAL_API_URL",
                "https://legacy.example.com".to_string()
            ))
        );
    }

    /// Neither set means Infisical Cloud, not an error.
    #[test]
    fn no_domain_variable_is_not_an_error() {
        assert_eq!(InfisicalConfig::pick_domain(|_| None), None);
    }
}
