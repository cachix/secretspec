//! Infisical provider
//!
//! This provider integrates with [Infisical](https://infisical.com) to store and
//! retrieve secrets over its REST API, against both Infisical Cloud and
//! self-hosted instances.
//!
//! # Authentication
//!
//! The access token comes from the first source that is configured:
//!
//! 1. A `token` minted elsewhere, used directly; this is what CI usually has to
//!    hand. Provider credential `token`, else `INFISICAL_TOKEN`.
//! 2. A machine identity's `client_id` and `client_secret`, exchanged for a
//!    short-lived access token via Universal Auth. Provider credentials, else
//!    `INFISICAL_CLIENT_ID` / `INFISICAL_CLIENT_SECRET`. Naming only one of the
//!    pair is an error rather than a reason to fall through.
//! 3. The logged-in Infisical CLI user (0.22+), read with
//!    `infisical user get token --plain --silent --domain <endpoint>`. The
//!    binary is `infisical` on `PATH`, or `SECRETSPEC_INFISICAL_PATH`;
//!    `INFISICAL_PROFILE` / `INFISICAL_ORG` reach it through the environment.
//!    Infisical CLI 0.44.0 or newer is required, checked with
//!    `infisical --version`: older CLIs ignore `--domain` and would hand over
//!    a session issued by another instance. With stdin on a terminal the CLI
//!    inherits it and may take as long as a login needs; otherwise it gets no
//!    stdin and is stopped after 30 seconds.
//!
//! A token or machine identity is resolved once per provider instance and kept
//! for its life. A CLI session is shared by every instance in the process that
//! would run the same CLI for the same instance, profile and organization: at
//! most one run is in flight at a time, and its token is reused until it is
//! within a minute of its expiry.
//!
//! Service tokens are not supported: Infisical deprecated them in favour of
//! machine identities.
//!
//! # URI Format
//!
//! `infisical://[host]/{project-id}[?env=slug&path=/prefix&tls=false&personal=true]`
//!
//! The project is Infisical's own project UUID; its v4 API does not accept a
//! project slug. Query parameters:
//!
//! - `env` -- environment slug. When omitted, the SecretSpec profile names the
//!   environment, so a `production` profile reads Infisical's `production`
//!   environment. That holds for a `ref` too (0.20+), which names a folder and
//!   key but never an environment. Set it to read every profile from one
//!   environment, e.g. an instance whose environments do not correspond to
//!   profiles.
//! - `path` -- folder prefix holding SecretSpec's secrets (default:
//!   `/secretspec`).
//! - `tls` -- enable TLS: `true` (default) or `false`, for self-hosted
//!   instances served over plain HTTP.
//! - `personal` (0.22+) -- `true` reads the user's personal overrides, which
//!   win over the shared value, and makes `set` write a personal override
//!   instead of the shared secret. Default `false`. Infisical keeps personal
//!   overrides for users only, so this needs a user's token (the Infisical CLI
//!   login or a user's `INFISICAL_TOKEN`), and an override can only be written
//!   for a key whose shared secret already exists in the folder. A machine
//!   identity reads shared values and cannot write. A `ref` pinning a
//!   `version` reads the shared secret's history.
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
//! A secret lives at the folder `{path}/{project}/{profile}` in the
//! environment named by the profile, under the key itself:
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
//! Keys are stored verbatim: Infisical imposes no charset of its own, so no
//! rewriting is needed and distinct keys cannot collide. Folder names are
//! narrower, so a project or profile Infisical cannot spell is refused rather
//! than rewritten.
//!
//! A folder that imports another resolves the imported keys too, with
//! Infisical's own precedence: a secret defined directly in the folder wins
//! over an imported one, and a later import wins over an earlier one.
//!
//! Starting in 0.20, an all-missing read probes the environment root once to
//! distinguish an absent environment or project from ordinary absent secrets
//! and folders. The resulting error names the environment and whether the
//! profile or `?env=` selected it.

use super::{
    Address, Provider, ProviderCredentials, ProviderUrl, credential_or_env, join_slash_path,
};
use crate::SecretBytes;
use crate::config::NativeAddress;
use crate::{Result, SecretSpecError};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, PoisonError};
use std::time::{Duration, SystemTime};

/// Default folder prefix holding SecretSpec's secrets.
const DEFAULT_PATH: &str = "/secretspec";
/// Infisical Cloud's US host, used when neither the URI nor the environment
/// names one.
const DEFAULT_HOST: &str = "app.infisical.com";

const CLIENT_ID: &str = "client_id";
const CLIENT_SECRET: &str = "client_secret";
const TOKEN: &str = "token";
const INFISICAL_CLIENT_ID_ENV: &str = "INFISICAL_CLIENT_ID";
const INFISICAL_CLIENT_SECRET_ENV: &str = "INFISICAL_CLIENT_SECRET";
const INFISICAL_TOKEN_ENV: &str = "INFISICAL_TOKEN";
/// Overrides the Infisical CLI binary used for the login-session fallback.
const INFISICAL_CLI_PATH_ENV: &str = "SECRETSPEC_INFISICAL_PATH";
const DEFAULT_CLI_BINARY: &str = "infisical";
/// The environment variables naming the instance, in the Infisical CLI's own
/// precedence order: `INFISICAL_DOMAIN` first, then the legacy
/// `INFISICAL_API_URL` it superseded but still honours (`util.GetEnvDomain`).
/// Reading only the current name would silently send an existing EU or
/// self-hosted setup, configured with the legacy one, to US Cloud.
const INFISICAL_DOMAIN_ENVS: [&str; 2] = ["INFISICAL_DOMAIN", "INFISICAL_API_URL"];
/// The oldest Infisical CLI whose `--domain` refuses a session issued by
/// another instance. Older ones replace the requested instance with the
/// logged-in one, so their token would go to whichever instance SecretSpec
/// asked for. They also predate `INFISICAL_PROFILE` and `INFISICAL_ORG`.
const MIN_CLI_VERSION: (u64, u64, u64) = (0, 44, 0);
/// The environment variables through which the Infisical CLI selects a login
/// profile and organization. Each selects a different session, so each is
/// part of a cached session's identity.
const INFISICAL_CLI_SESSION_ENVS: [&str; 2] = ["INFISICAL_PROFILE", "INFISICAL_ORG"];
/// How long a CLI run without a terminal may take. With no stdin to answer a
/// login prompt, a CLI still running by then is waiting for a login nobody can
/// complete.
const CLI_DETACHED_TIMEOUT: Duration = Duration::from_secs(30);
/// How close to its expiry a CLI token stops being reused.
const CLI_TOKEN_EXPIRY_MARGIN: Duration = Duration::from_secs(60);

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
    /// Read the user's personal overrides, and write personal overrides
    /// instead of shared secrets.
    #[serde(default)]
    pub personal_overrides: bool,
}

impl Default for InfisicalConfig {
    fn default() -> Self {
        Self {
            endpoint: format!("https://{DEFAULT_HOST}"),
            project_id: String::new(),
            environment: None,
            path: DEFAULT_PATH.to_string(),
            personal_overrides: false,
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

        let path = match url.query_value("path").filter(|s| !s.is_empty()) {
            Some(p) => {
                let trimmed = p.trim_end_matches('/');
                if trimmed.starts_with('/') {
                    trimmed.to_string()
                } else {
                    format!("/{trimmed}")
                }
            }
            None => DEFAULT_PATH.to_string(),
        };

        // Strict like `tls`: a typo must not silently write the shared value.
        let personal_overrides = url
            .query_pairs()
            .find(|(k, _)| k == "personal")
            .map(|(_, v)| match v.as_ref() {
                "true" | "1" => Ok(true),
                "false" | "0" => Ok(false),
                other => Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Unknown personal value '{other}'. Expected 'true' or 'false'."
                ))),
            })
            .transpose()?
            .unwrap_or(false);

        Ok(Self {
            endpoint,
            project_id,
            environment,
            path,
            personal_overrides,
        })
    }
}

/// One secret's location in Infisical's own terms. Holds no secret value, so it
/// is safe to render in an error or a test failure.
#[derive(Debug)]
struct Location {
    environment: String,
    secret_path: String,
    key: String,
}

/// The distinction an environment diagnostic needs to retain after a secret
/// read. An HTTP 200 without a usable value is not Infisical's ambiguous 404.
enum SecretRead {
    Response(Option<SecretBytes>),
    NotFound,
}

/// Where a provider instance's access token comes from, decided on first use.
enum Auth {
    /// A configured token, or one exchanged for the machine identity's
    /// credentials, kept for the instance's life.
    Fixed(Arc<SecretBytes>),
    /// The Infisical CLI user's session, shared process-wide.
    Cli(Arc<CliSession>),
}

/// What makes two Infisical CLI runs interchangeable: the same binary, asked
/// for the same instance, under the same profile and organization selection
/// ([`INFISICAL_CLI_SESSION_ENVS`], in order).
type CliSessionKey = (String, String, [Option<std::ffi::OsString>; 2]);

/// The latest CLI run for one [`CliSessionKey`]: still in flight while its
/// cell is empty, then its outcome. A failure is kept as the message every
/// caller that waited on that run receives.
type CliFlight = tokio::sync::OnceCell<std::result::Result<CliToken, String>>;

/// One Infisical CLI session, shared by every provider instance in the process
/// with the same [`CliSessionKey`].
#[derive(Default)]
struct CliSession {
    /// Set once the binary's version is accepted, for the life of the process.
    version_accepted: tokio::sync::OnceCell<()>,
    /// The latest run; see [`CliFlight`].
    flight: Mutex<Arc<CliFlight>>,
}

impl CliSession {
    /// The session for `key`, created on first use.
    fn shared(key: CliSessionKey) -> Arc<Self> {
        static SESSIONS: LazyLock<Mutex<HashMap<CliSessionKey, Arc<CliSession>>>> =
            LazyLock::new(Default::default);
        let mut sessions = SESSIONS.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(sessions.entry(key).or_default())
    }

    /// The run a caller takes its token from: the one in flight, whatever its
    /// outcome, or a finished one whose token is still fresh. Otherwise a new
    /// run replaces it, so neither a failure nor an expiring token outlives
    /// the callers that waited on it.
    fn flight(&self) -> Arc<CliFlight> {
        let mut flight = self.flight.lock().unwrap_or_else(PoisonError::into_inner);
        let joinable = match flight.get() {
            None => true,
            Some(Ok(cli)) => cli.reusable_at(SystemTime::now()),
            Some(Err(_)) => false,
        };
        if !joinable {
            *flight = Arc::default();
        }
        Arc::clone(&flight)
    }
}

/// A token the Infisical CLI printed.
struct CliToken {
    token: Arc<SecretBytes>,
    /// The JWT's `exp`, when it carries a readable one.
    expires_at: Option<SystemTime>,
}

impl CliToken {
    /// Whether a later caller may reuse this token: its `exp` is readable and
    /// more than [`CLI_TOKEN_EXPIRY_MARGIN`] away.
    fn reusable_at(&self, now: SystemTime) -> bool {
        self.expires_at.is_some_and(|expires_at| {
            expires_at
                .duration_since(now)
                .is_ok_and(|left| left > CLI_TOKEN_EXPIRY_MARGIN)
        })
    }
}

/// Infisical provider.
pub struct InfisicalProvider {
    retry_policy: super::RetryPolicy,
    config: InfisicalConfig,
    /// Credentials supplied by the provider alias.
    credentials: ProviderCredentials,
    /// How this instance authenticates, decided once. A configured token, or
    /// the Universal Auth token, is kept for the instance's life: Infisical's
    /// tokens are short-lived (7200s by default), which outlives any single
    /// SecretSpec invocation. A CLI session is consulted on every call instead
    /// (see [`cli_token`](Self::cli_token)), since it renews on expiry.
    ///
    /// Async, because the exchange itself must be serialized rather than merely
    /// its result: a batch read fetches distinct addresses concurrently, and a
    /// cell that only guards the completed token lets every caller log in and
    /// then discard all but one. Infisical supports client secrets with a
    /// one-use limit, for which the surplus exchanges are not just waste but a
    /// hard failure.
    auth: tokio::sync::OnceCell<Auth>,
    /// One HTTP client for every request, so a run of secrets reuses the
    /// connection rather than building a pool per call.
    http: OnceLock<reqwest::Client>,
    /// The session's profile, set by [`Provider::set_profile`] before any I/O.
    ///
    /// A convention address names the profile itself, so this only answers for a
    /// `ref`, whose coordinates name a folder and key but never an environment.
    /// It is deliberately not part of [`InfisicalConfig`]: the environment a
    /// profile implies must not reach [`uri`](Provider::uri) or
    /// [`storage_identity`](Provider::storage_identity), or the same store would
    /// take one identity per profile.
    profile: Mutex<Option<String>>,
    /// The Infisical CLI consulted when no token or machine identity is
    /// configured.
    cli_binary_path: String,
    /// Whether stdin is a terminal the CLI may prompt on. A field so tests do
    /// not depend on the terminal `cargo test` was started from.
    cli_stdin_is_terminal: fn() -> bool,
    /// How long a CLI run without a terminal may take before it is stopped.
    cli_timeout: Duration,
}

crate::register_provider! {
    struct: InfisicalProvider,
    config: InfisicalConfig,
    metadata: &super::catalog::INFISICAL,
}

impl InfisicalProvider {
    /// Creates a new InfisicalProvider with the given configuration.
    pub fn new(config: InfisicalConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
            retry_policy: super::RetryPolicy::default(),
            auth: tokio::sync::OnceCell::new(),
            http: OnceLock::new(),
            profile: Mutex::new(None),
            cli_binary_path: std::env::var(INFISICAL_CLI_PATH_ENV)
                .unwrap_or_else(|_| DEFAULT_CLI_BINARY.to_string()),
            cli_stdin_is_terminal: || std::io::IsTerminal::is_terminal(&std::io::stdin()),
            cli_timeout: CLI_DETACHED_TIMEOUT,
        }
    }

    /// The shared HTTP client.
    fn http(&self) -> &reqwest::Client {
        self.http.get_or_init(super::http::default_client)
    }

    /// The profile this session resolves under, if [`Provider::set_profile`] has
    /// run.
    ///
    /// A blank profile is treated as absent: an empty environment slug would
    /// build a request Infisical answers with a 404 that reads as a missing
    /// secret, rather than as the missing configuration it is.
    fn session_profile(&self) -> Option<String> {
        self.profile
            .lock()
            .ok()?
            .as_deref()
            .map(str::trim)
            .filter(|profile| !profile.is_empty())
            .map(str::to_string)
    }

    /// Explains which SecretSpec setting selected an environment Infisical
    /// could not find.
    fn missing_environment_error(&self, environment: &str) -> SecretSpecError {
        let source = if self.config.environment.is_some() {
            "The provider URI selected it with `?env=`."
        } else {
            "The active SecretSpec profile selected it because the provider URI does not pin an \
             environment with `?env=`."
        };
        SecretSpecError::ProviderOperationFailed(format!(
            "Infisical could not find environment '{}' in project {} (or the project itself is \
             unavailable). {source}",
            environment, self.config.project_id
        ))
    }

    /// Renders the provider URI with the supplied entry-addressing defaults.
    ///
    /// The public URI passes the configured environment and path through. Entry
    /// comparison omits both from the underlying project container and resolves
    /// them alongside the address instead, so aliases with different defaults
    /// can still compare the physical entries they actually reach without
    /// changing either alias's cache identity.
    fn render_uri(&self, environment: Option<&str>, path: Option<&str>) -> String {
        let plain_http = self.config.endpoint.starts_with("http://");
        let host = self
            .config
            .endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let mut uri = format!("infisical://{host}/{}", self.config.project_id);
        let mut query = Vec::new();
        if let Some(env) = environment {
            query.push(format!("env={}", ProviderUrl::encode_query(env)));
        }
        if let Some(path) = path.filter(|path| *path != DEFAULT_PATH) {
            query.push(format!("path={}", ProviderUrl::encode_query(path)));
        }
        if self.config.personal_overrides {
            query.push("personal=true".to_string());
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

    /// Resolves an address to one secret's Infisical location.
    ///
    /// `item` carries the folder and the key together, so convention and `ref`
    /// addresses share one spelling of the layout. The environment comes from
    /// `?env=`, else the profile: a convention address names the profile, and a
    /// `ref` takes the one the session resolves under, so both spell the same
    /// environment for the same run.
    fn locate(&self, addr: Address<'_>) -> Result<Location> {
        let coords = self.resolve_coords(addr)?;

        let environment = match (&self.config.environment, addr) {
            (Some(env), _) => env.clone(),
            (None, Address::Convention { profile, .. }) => profile.to_string(),
            (None, Address::Native(_)) => self.session_profile().ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(
                    "No Infisical environment for this ref. Name one in the provider URI, \
                     e.g. infisical://app.infisical.com/{project-id}?env=prod. A provider \
                     credential is resolved without a profile, so its ref always needs one."
                        .to_string(),
                )
            })?,
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
                        join_slash_path(&self.config.path, relative)
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

    /// Resolves the access token, deciding how to authenticate at most once.
    ///
    /// An already-minted token is used directly; otherwise a machine
    /// identity's credentials are exchanged for one. Either is kept for the
    /// instance's life: Infisical's tokens are short-lived (7200s by default),
    /// which outlives any single SecretSpec invocation. Without either, every
    /// call reads the Infisical CLI user's session through
    /// [`cli_token`](Self::cli_token), which asks the CLI again only once its
    /// token nears expiry.
    ///
    /// The login is awaited rather than blocked on: this runs inside the
    /// runtime that [`block_on`](super::block_on) already entered for the
    /// request, and blocking there would panic.
    async fn resolve_token(&self) -> Result<Arc<SecretBytes>> {
        // `get_or_try_init` runs one initializer at a time: a concurrent caller
        // waits for the in-flight exchange and takes its token rather than
        // starting a second one. On failure the cell stays empty, so a later
        // call retries instead of caching the error.
        let auth = self
            .auth
            .get_or_try_init(|| async {
                // An absent credential permits login; an explicit value is
                // always used, with validation at the request boundary.
                match credential_or_env(&self.credentials, TOKEN, INFISICAL_TOKEN_ENV) {
                    Some(token) => Ok(Auth::Fixed(Arc::new(token))),
                    None => self.login().await,
                }
            })
            .await?;
        match auth {
            Auth::Fixed(token) => Ok(Arc::clone(token)),
            Auth::Cli(session) => self.cli_token(session).await,
        }
    }

    /// Exchanges the machine identity's credentials for an access token, or,
    /// when none are configured, selects the Infisical CLI user's session.
    async fn login(&self) -> Result<Auth> {
        let client_id = credential_or_env(&self.credentials, CLIENT_ID, INFISICAL_CLIENT_ID_ENV);
        let client_secret = credential_or_env(
            &self.credentials,
            CLIENT_SECRET,
            INFISICAL_CLIENT_SECRET_ENV,
        );

        // A half-specified identity is an error: falling back to an anonymous
        // request, or to a different identity, would fail later with an opaque
        // 401 or act as someone else.
        let (client_id, client_secret) = match (client_id, client_secret) {
            (Some(id), Some(secret)) => (id, secret),
            (None, None) => {
                return Ok(Auth::Cli(CliSession::shared((
                    self.cli_binary_path.clone(),
                    self.config.endpoint.clone(),
                    INFISICAL_CLI_SESSION_ENVS.map(std::env::var_os),
                ))));
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
            "clientId": client_id.try_as_utf8()?,
            "clientSecret": client_secret.try_as_utf8()?,
        });

        // Keep the authentication connection out of the pool used for secret reads.
        let auth_client = super::http::default_client();
        let response = super::http::send(
            self.retry_policy,
            "Infisical",
            auth_client.post(&url).json(&body),
            false,
        )
        .await
        .map_err(super::retry::terminal)?;

        if !response.status().is_success() {
            let status = response.status();
            let body = Self::response_body(response).await?;
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Infisical login returned HTTP {status}: {}",
                Self::error_message(&body)
            )));
        }

        let parsed: serde_json::Value = response
            .json()
            .await
            .map_err(|e| {
                super::http::body_error(
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to parse Infisical login response: {}",
                        crate::error::display_error_chain(&e)
                    )),
                    e,
                )
            })
            .map_err(super::retry::terminal)?;

        let token = parsed["accessToken"].as_str().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "Infisical login response missing accessToken".to_string(),
            )
        })?;

        Ok(Auth::Fixed(Arc::new(SecretBytes::from_utf8(token))))
    }

    /// Reads the logged-in Infisical CLI user's access token.
    ///
    /// Runs are shared process-wide through `session`: a caller arriving while
    /// a run is in flight waits for it and takes its outcome, success or
    /// failure, rather than starting a second CLI, which could open a second
    /// login. A token is then reused until its JWT `exp` is within
    /// [`CLI_TOKEN_EXPIRY_MARGIN`]; one without a readable `exp` is not reused
    /// past its own run. Nor is a failure, so a later call -- a long-running
    /// `serve` after the user logs in -- asks the CLI again.
    ///
    /// The binary's version is checked before its first run and remembered
    /// once accepted.
    async fn cli_token(&self, session: &CliSession) -> Result<Arc<SecretBytes>> {
        let flight = session.flight();
        let outcome = flight
            .get_or_init(|| async {
                session
                    .version_accepted
                    .get_or_try_init(|| self.check_cli_version())
                    .await?;
                self.run_cli().await
            })
            .await;
        match outcome {
            Ok(cli) => Ok(Arc::clone(&cli.token)),
            Err(message) => Err(SecretSpecError::ProviderOperationFailed(message.clone())),
        }
    }

    /// Refuses an Infisical CLI older than [`MIN_CLI_VERSION`], or one whose
    /// version cannot be read.
    async fn check_cli_version(&self) -> std::result::Result<(), String> {
        let path = &self.cli_binary_path;
        let mut command = tokio::process::Command::new(path);
        command
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        let output = match tokio::time::timeout(self.cli_timeout, command.output()).await {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => return Err(Self::cli_spawn_error(path, &error)),
            Err(_) => {
                return Err(format!(
                    "The Infisical CLI ('{path} --version') did not report its version within \
                     {} seconds.",
                    self.cli_timeout.as_secs_f64()
                ));
            }
        };
        if !output.status.success() {
            return Err(format!(
                "Failed to read the Infisical CLI version ('{path} --version' exited with {}).",
                output.status
            ));
        }

        let printed = String::from_utf8_lossy(&output.stdout);
        let reported = printed
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or_default();
        if Self::supported_cli_version(reported) {
            return Ok(());
        }
        let (major, minor, patch) = MIN_CLI_VERSION;
        Err(format!(
            "The Infisical CLI '{path}' reported '{reported}' for its version, but SecretSpec \
             needs Infisical CLI {major}.{minor}.{patch} or newer to use its login session: older \
             CLIs ignore `--domain` and would hand over a session issued by another Infisical \
             instance. Upgrade the Infisical CLI, or configure a token or machine identity \
             credentials."
        ))
    }

    /// Whether `infisical --version`'s output (`infisical version 0.44.0`)
    /// names [`MIN_CLI_VERSION`] or later. A pre-release of the minimum is
    /// older than the release, and output without a version is refused.
    fn supported_cli_version(reported: &str) -> bool {
        let version = reported.split_whitespace().find_map(|word| {
            let word = word.strip_prefix('v').unwrap_or(word);
            let (core, prerelease) = match word.split_once('-') {
                Some((core, _)) => (core, true),
                None => (word, false),
            };
            let core = core.split_once('+').map_or(core, |(core, _build)| core);
            let mut parts = core.split('.').map(|part| part.parse::<u64>().ok());
            match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some(Some(major)), Some(Some(minor)), Some(Some(patch)), None) => {
                    Some(((major, minor, patch), prerelease))
                }
                _ => None,
            }
        });
        version.is_some_and(|(version, prerelease)| {
            version > MIN_CLI_VERSION || (version == MIN_CLI_VERSION && !prerelease)
        })
    }

    /// Runs `infisical user get token` for the token it prints.
    ///
    /// `--domain` makes the CLI refuse a session issued by another instance
    /// (from 0.44.0, which [`check_cli_version`](Self::check_cli_version)
    /// enforces). Stderr is inherited so the CLI's own errors and login
    /// prompts show live. Stdout is never quoted in an error: it may hold a
    /// token.
    ///
    /// The CLI logs in on the way when its session is missing or expired. With
    /// stdin on a terminal it inherits stdin, for its paste-a-token prompt, and
    /// may take as long as the user does. Otherwise -- `secretspec serve`
    /// speaks over stdin, and CI or an agent has nobody to answer -- it gets no
    /// stdin, and a run still going after [`cli_timeout`](Self::cli_timeout)
    /// is waiting for a login nobody can complete, so it is stopped together
    /// with the `infisical login` it spawned.
    async fn run_cli(&self) -> std::result::Result<CliToken, String> {
        use tokio::io::AsyncReadExt;

        let path = &self.cli_binary_path;
        let endpoint = &self.config.endpoint;
        let interactive = (self.cli_stdin_is_terminal)();
        let mut command = tokio::process::Command::new(path);
        command
            .args([
                "user",
                "get",
                "token",
                "--plain",
                "--silent",
                "--domain",
                endpoint.as_str(),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);
        if interactive {
            command.stdin(std::process::Stdio::inherit());
        } else {
            command.stdin(std::process::Stdio::null());
            // Its own process group, so stopping it reaches the login it
            // spawns as well. Not with a terminal, where it has to stay in the
            // foreground group to read from it.
            #[cfg(unix)]
            command.process_group(0);
        }
        let mut child = command
            .spawn()
            .map_err(|error| Self::cli_spawn_error(path, &error))?;
        let pid = child.id();
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| format!("Failed to read the output of the Infisical CLI '{path}'."))?;

        let mut printed = Vec::new();
        let run = async {
            let (status, _) = tokio::try_join!(child.wait(), stdout.read_to_end(&mut printed))?;
            Ok::<_, std::io::Error>(status)
        };
        let finished = if interactive {
            Some(run.await)
        } else {
            tokio::time::timeout(self.cli_timeout, run).await.ok()
        };
        let Some(status) = finished else {
            Self::stop_cli(&mut child, pid).await;
            return Err(format!(
                "The Infisical CLI ('{path} user get token') was stopped after {} seconds without \
                 providing a login session: its session for {endpoint} is missing or expired, \
                 and with no terminal on stdin it cannot log you in. Run `infisical login \
                 --domain {endpoint}` interactively, or configure a token or machine identity \
                 credentials.",
                self.cli_timeout.as_secs_f64()
            ));
        };
        let status = status
            .map_err(|error| format!("Failed to execute the Infisical CLI '{path}': {error}"))?;

        if !status.success() {
            return Err(format!(
                "The Infisical CLI could not provide a login session ('{path} user get token' \
                 exited with {status}; its output is shown above). Run `infisical login --domain \
                 {endpoint}`, or configure a token or machine identity credentials."
            ));
        }

        // A login the CLI ran on the way can leave earlier lines on stdout;
        // the token is the last thing it prints.
        let stdout = String::from_utf8_lossy(&printed);
        match stdout.lines().map(str::trim).rfind(|line| !line.is_empty()) {
            Some(line) if Self::looks_like_jwt(line) => Ok(CliToken {
                expires_at: Self::jwt_expiry(line),
                token: Arc::new(SecretBytes::from_utf8(line)),
            }),
            _ => Err(format!(
                "The Infisical CLI ('{path} user get token --plain') did not print an access token."
            )),
        }
    }

    /// Stops a CLI run that outlived its timeout, along with any
    /// `infisical login` it spawned.
    async fn stop_cli(child: &mut tokio::process::Child, pid: Option<u32>) {
        #[cfg(unix)]
        {
            if let Some(group) = pid.and_then(|pid| libc::pid_t::try_from(pid).ok()) {
                // SAFETY: plain signal delivery to the group the child leads.
                // Its ID cannot have been reused: either the child is not yet
                // reaped, or a descendant still holds stdout open, which keeps
                // the group alive.
                unsafe { libc::kill(-group, libc::SIGKILL) };
            }
        }
        #[cfg(not(unix))]
        let _ = pid;
        // Reaps the child, killing it first wherever the group signal did not.
        let _ = child.kill().await;
    }

    /// Explains a CLI that could not be started; a missing one lists every way
    /// to authenticate.
    fn cli_spawn_error(path: &str, error: &std::io::Error) -> String {
        if error.kind() == std::io::ErrorKind::NotFound {
            format!(
                "No Infisical credentials found. Configure the {CLIENT_ID} and {CLIENT_SECRET} \
                 provider credentials (or a ready-made {TOKEN}), set {INFISICAL_CLIENT_ID_ENV} \
                 and {INFISICAL_CLIENT_SECRET_ENV} (or {INFISICAL_TOKEN_ENV}), or install the \
                 Infisical CLI and run `infisical login`. The Infisical CLI was looked up as \
                 '{path}'; set {INFISICAL_CLI_PATH_ENV} if it is installed elsewhere."
            )
        } else {
            format!("Failed to execute the Infisical CLI '{path}': {error}")
        }
    }

    /// A JWT's `exp` claim, read without verifying the token: it only decides
    /// when to ask the CLI again, and the server still checks the token.
    fn jwt_expiry(token: &str) -> Option<SystemTime> {
        let payload = token.split('.').nth(1)?;
        let payload = data_encoding::BASE64URL_NOPAD
            .decode(payload.as_bytes())
            .ok()?;
        let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
        let exp = Duration::try_from_secs_f64(claims["exp"].as_f64()?).ok()?;
        SystemTime::UNIX_EPOCH.checked_add(exp)
    }

    /// Three non-empty base64url segments separated by dots.
    fn looks_like_jwt(s: &str) -> bool {
        let segments: Vec<&str> = s.split('.').collect();
        segments.len() == 3
            && segments.iter().all(|segment| {
                !segment.is_empty()
                    && segment
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            })
    }

    /// Infisical's error envelope carries a human-readable `message`; the
    /// status code, not this text, decides control flow.
    fn error_message(body: &str) -> String {
        serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v["message"].as_str().map(str::to_string))
            .unwrap_or_else(|| body.to_string())
    }

    /// Reads a response body without hiding transport/decompression failures
    /// behind an empty string and a later, misleading JSON parse error.
    async fn response_body(response: reqwest::Response) -> Result<String> {
        let status = response.status();
        response.text().await.map_err(|e| {
            super::http::body_error(
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to read Infisical HTTP {status} response body: {}",
                    crate::error::display_error_chain(&e)
                )),
                e,
            )
        })
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

    /// A metadata-only root listing used solely to check whether an
    /// environment exists.
    ///
    /// Unlike a secret read, this must not retrieve or expand values: every
    /// secret at the root is unrelated to the missing entry being diagnosed.
    fn environment_probe_query<'q>(&'q self, environment: &'q str) -> Vec<(&'static str, &'q str)> {
        vec![
            ("projectId", self.config.project_id.as_str()),
            ("environment", environment),
            ("secretPath", "/"),
            ("expandSecretReferences", "false"),
            ("viewSecretValue", "false"),
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
    fn secret_value(secret: &serde_json::Value, key: &str) -> Result<Option<SecretBytes>> {
        if secret["secretValueHidden"].as_bool() == Some(true) {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Infisical withheld the value of '{key}': this identity may see that the \
                 secret exists but not read it. Grant it permission to read secret values."
            )));
        }
        Ok(secret["secretValue"]
            .as_str()
            .map(|v| SecretBytes::from_utf8(v.to_string())))
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
    async fn get_async(&self, loc: &Location, version: Option<&str>) -> Result<SecretRead> {
        let url = self.secret_url(&loc.key)?;
        let mut query = self.read_query(&loc.environment, &loc.secret_path);
        if let Some(version) = version {
            query.push(("version", version));
        }

        let response = self.send(reqwest::Method::GET, &url, &query, None).await?;
        let status = response.status();
        let body = Self::response_body(response).await?;

        match status {
            StatusCode::OK => {
                let parsed: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to parse Infisical response: {e}"
                    ))
                })?;
                Self::secret_value(&parsed["secret"], &loc.key).map(SecretRead::Response)
            }
            // A 404 covers a missing secret, folder, environment and project
            // alike. The caller decides when an all-missing operation warrants
            // an environment probe, so a batch can share one probe across all
            // of its version-pinned reads.
            StatusCode::NOT_FOUND => Ok(SecretRead::NotFound),
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
        listed: &mut HashMap<String, SecretBytes>,
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
    ) -> Result<Option<HashMap<String, SecretBytes>>> {
        let url = format!("{}/api/v4/secrets", self.config.endpoint);
        let mut query = self.read_query(environment, secret_path);
        // The server answers one entry per key, the user's override winning,
        // imports included. Not in `read_query`: the single-secret endpoint
        // gives `type` its own meaning and must not receive it.
        if self.config.personal_overrides {
            query.push(("includePersonalOverrides", "true"));
        }

        let response = self.send(reqwest::Method::GET, &url, &query, None).await?;
        let status = response.status();
        let body = Self::response_body(response).await?;

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
                Ok(Some(listed))
            }
            // The caller decides whether this is an absent folder or an absent
            // environment. Infisical uses the same 404 for both.
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(self.http_error(status, &body, "listing secrets")),
        }
    }

    /// Checks the environment's root to distinguish an ordinary missing
    /// secret/folder from an environment (or project) Infisical cannot find.
    ///
    /// The root folder always exists in a real environment. Inspecting only the
    /// HTTP status avoids parsing or exposing any unrelated root-level secrets.
    async fn ensure_environment_exists_async(&self, environment: &str) -> Result<()> {
        let url = format!("{}/api/v4/secrets", self.config.endpoint);
        let query = self.environment_probe_query(environment);
        let response = self
            .send_response(reqwest::Method::GET, &url, &query, None, false)
            .await?;
        let status = response.status();

        match status {
            StatusCode::OK => Ok(()),
            StatusCode::NOT_FOUND => Err(self.missing_environment_error(environment)),
            _ => {
                let body = Self::response_body(response).await?;
                Err(self.http_error(status, &body, "checking an environment"))
            }
        }
    }

    /// Writes a secret, creating its folder when Infisical requires one.
    ///
    /// Infisical separates creating a secret from updating one, and does not
    /// create a folder implicitly: writing into a folder that does not exist
    /// fails and stores nothing, not even part of the path. Each request is
    /// chosen from the status of the one before it, so updating an existing
    /// secret costs a single call, and only a new secret costs more.
    async fn set_async(&self, loc: &Location, value: &SecretBytes) -> Result<()> {
        // A personal override sits on an existing shared secret, so a missing
        // folder means there is nothing to override: no folder is created.
        if self.config.personal_overrides {
            if self
                .write_secret(reqwest::Method::PATCH, loc, value)
                .await?
            {
                return Ok(());
            }
            if self.write_secret(reqwest::Method::POST, loc, value).await? {
                return Ok(());
            }
            // A missing environment answers the same 404 as a missing shared
            // secret; report it as such rather than blame the shared secret.
            self.ensure_environment_exists_async(&loc.environment)
                .await?;
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Infisical has no shared secret '{}' in environment '{}', folder '{}' to \
                 override. Create the shared secret first (through an alias without \
                 `?personal=true`), then set the personal override.",
                loc.key, loc.environment, loc.secret_path
            )));
        }
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
            return Err(self.missing_environment_error(&loc.environment));
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
        value: &SecretBytes,
    ) -> Result<bool> {
        let value = super::require_utf8("infisical", value)?;
        let url = self.secret_url(&loc.key)?;
        let body = self.write_body(loc, value);

        let response = self.send(method, &url, &[], Some(body)).await?;
        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(false);
        }
        let body = Self::response_body(response).await?;
        if self.config.personal_overrides
            && status == StatusCode::BAD_REQUEST
            && let Some(refusal) = self.personal_refusal(loc, &Self::error_message(&body))
        {
            return Err(refusal);
        }
        if status.is_success() {
            Self::written(&body, &loc.key)?;
            return Ok(true);
        }
        Err(self.http_error(status, &body, "writing a secret"))
    }

    /// Explains a 400 from a personal write, but only when Infisical's message
    /// names one of the refusals particular to personal overrides: no shared
    /// secret to override, or a writer that is not a user. Any other 400 is
    /// reported by [`http_error`](Self::http_error) without a cause attached.
    fn personal_refusal(&self, loc: &Location, message: &str) -> Option<SecretSpecError> {
        let lowered = message.to_ascii_lowercase();
        let cause = if lowered.contains("shared secret") {
            "A personal override needs an existing shared secret with the same key in that \
             folder; create it first, through an alias without `?personal=true`."
                .to_string()
        } else if lowered.contains("must be user") {
            format!(
                "Infisical keeps personal overrides for users only, so this needs a user's token \
                 (the Infisical CLI login or a user's {INFISICAL_TOKEN_ENV}), not a machine \
                 identity."
            )
        } else {
            return None;
        };
        Some(SecretSpecError::ProviderOperationFailed(format!(
            "Infisical refused the personal override of '{}' in environment '{}', folder '{}': \
             {message}. {cause}",
            loc.key, loc.environment, loc.secret_path
        )))
    }

    /// The JSON body of a create or update. Shared writes omit `type`, which
    /// Infisical defaults to `shared`.
    fn write_body(&self, loc: &Location, value: &str) -> serde_json::Value {
        let mut body = serde_json::json!({
            "projectId": self.config.project_id,
            "environment": loc.environment,
            "secretPath": loc.secret_path,
            "secretValue": value,
        });
        if self.config.personal_overrides {
            body["type"] = serde_json::Value::from("personal");
        }
        body
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
        let body = Self::response_body(response).await?;
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
        self.send_response(method, url, query, body, true).await
    }

    async fn send_response(
        &self,
        method: reqwest::Method,
        url: &str,
        query: &[(&str, &str)],
        body: Option<serde_json::Value>,
        consume_success: bool,
    ) -> Result<reqwest::Response> {
        let token = self.resolve_token().await?;
        let mut request = self
            .http()
            .request(method, url)
            .header(
                reqwest::header::AUTHORIZATION,
                super::credentials::credential_bearer_header(token.expose_secret())?,
            )
            .query(query);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = super::http::send_checked(
            self.retry_policy,
            "Infisical",
            request,
            false,
            |response| async move {
                if consume_success {
                    super::http::checked_response("Infisical", response).await
                } else {
                    super::http::checked_status("Infisical", response).await
                }
            },
        )
        .await?;
        Ok(response)
    }

    /// Renders a failed response, naming the likely cause for the statuses a
    /// user actually hits.
    fn http_error(&self, status: StatusCode, body: &str, action: &str) -> SecretSpecError {
        let message = Self::error_message(body);
        match status {
            StatusCode::UNAUTHORIZED => SecretSpecError::ProviderOperationFailed(format!(
                "Infisical authentication failed (401) while {action}: {message}. \
                 Check the Infisical token, the machine identity's {CLIENT_ID}/{CLIENT_SECRET}, \
                 or the Infisical CLI login (`infisical login`)."
            )),
            StatusCode::FORBIDDEN => SecretSpecError::ProviderOperationFailed(format!(
                "Infisical denied access (403) while {action}: {message}. Check the identity's \
                 permissions on project {}.",
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
    fn retry_ownership(&self) -> super::RetryOwnership {
        super::RetryOwnership::Managed
    }

    fn set_retry_policy(&mut self, policy: super::RetryPolicy) {
        self.retry_policy = policy;
    }

    /// Keeps the session's profile as the environment a `ref` reads from when
    /// the URI names none. Last write wins, matching the other session hooks.
    fn set_profile(&self, profile: &str) {
        if let Ok(mut held) = self.profile.lock() {
            *held = Some(profile.to_string());
        }
    }

    /// Names the environment as well as the folder and key.
    ///
    /// The environment is half the destination and is not in the coordinates,
    /// which the default rendering shows; where the URI does not pin it, it is
    /// not in [`uri`](Provider::uri) either, so a preview built from those two
    /// would leave the profile-derived environment invisible on the one
    /// operation that overwrites a value.
    fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
        let loc = self.locate(addr)?;
        Ok(format!(
            "environment {}, {}/{}{}",
            loc.environment,
            loc.secret_path.trim_end_matches('/'),
            loc.key,
            if self.config.personal_overrides {
                " (personal override)"
            } else {
                ""
            }
        ))
    }

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

    /// Resolves every part of the entry identity that Infisical sends to the
    /// API. In particular, the environment may come from session profile
    /// context rather than the provider URI or native coordinates.
    fn configured_entry_coordinates<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<std::borrow::Cow<'a, NativeAddress>> {
        let loc = self.locate(addr)?;
        let version = match addr {
            Address::Native(native) => native.version.clone(),
            Address::Convention { .. } => None,
        };

        // NativeAddress has no environment coordinate. Encode the resolved
        // Infisical tuple into its canonical item identity; query encoding
        // keeps the component boundaries unambiguous. This value is used only
        // for comparisons and is never sent to Infisical.
        let item = format!(
            "environment={}&path={}&key={}",
            ProviderUrl::encode_query(&loc.environment),
            ProviderUrl::encode_query(&loc.secret_path),
            ProviderUrl::encode_query(&loc.key),
        );
        Ok(std::borrow::Cow::Owned(NativeAddress {
            item,
            version,
            ..Default::default()
        }))
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    fn name(&self) -> &str {
        Self::PROVIDER_NAME
    }

    /// The inverse of parsing: every knob the config holds is rendered, so the
    /// URI naming this store in an audit record or a warning is one that reads
    /// back as the same store. `tls` is the one that bites -- a plain-HTTP
    /// endpoint rendered without it comes back as HTTPS.
    fn uri(&self) -> String {
        self.render_uri(
            self.config.environment.as_deref(),
            Some(self.config.path.as_str()),
        )
    }

    /// The environment and path are part of the resolved entry coordinates,
    /// not the Infisical instance and project container. Omitting both here
    /// lets an unpinned provider under profile `prod` compare equal to
    /// `?env=prod`, and lets an absolute ref override different path defaults;
    /// [`storage_identity`](Provider::storage_identity) remains the public URI
    /// with its configured defaults and never absorbs session profile context.
    fn entry_container_identity(&self) -> String {
        self.render_uri(None, None)
    }

    /// Infisical versions its secrets, so a `ref` may pin one. Its values are
    /// single strings with no sub-components, so `field`, `section` and
    /// `vault` are rejected.
    fn supported_coords(&self) -> &'static [&'static str] {
        &["version"]
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
        let loc = self.locate(addr)?;
        let version = match addr {
            Address::Native(native) => native.version.as_deref(),
            Address::Convention { .. } => None,
        };
        // The single-secret endpoint neither falls back from a personal
        // override to the shared value nor resolves imports like the list
        // does, so a personal read goes through the batch path.
        if self.config.personal_overrides && version.is_none() {
            return Ok(self.get_many(&[(loc.key.as_str(), addr)])?.remove(&loc.key));
        }
        super::block_on(async {
            let read = self.get_async(&loc, version).await?;
            if matches!(&read, SecretRead::NotFound) {
                self.ensure_environment_exists_async(&loc.environment)
                    .await?;
            }
            Ok(match read {
                SecretRead::Response(value) => value,
                SecretRead::NotFound => None,
            })
        })
    }

    /// Secrets sharing a folder and environment are read with one list call
    /// each, rather than one round trip per secret: Infisical's cloud rate
    /// limits are per-minute, and a fan-out of single reads burns them.
    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretBytes>> {
        // A pinned version names one historical value, which the folder
        // listing (always latest) cannot answer.
        let (versioned, listable): (Vec<_>, Vec<_>) = requests.iter().partition(
            |(_, addr)| matches!(addr, Address::Native(native) if native.version.is_some()),
        );

        // Versioned reads still share the generic deduplicated, concurrent
        // fetch, but bypass `get`: its per-read diagnostic would issue one root
        // probe for every miss. Their environments are checked together below
        // only if the whole provider read is missing.
        let versioned: Vec<(&str, Address<'_>)> = versioned.into_iter().copied().collect();
        let versioned_misses = Mutex::new(HashSet::new());
        let mut resolved = if versioned.is_empty() {
            HashMap::new()
        } else {
            super::get_each_with(&versioned, |addr| {
                let loc = self.locate(addr)?;
                let version = match addr {
                    Address::Native(native) => native.version.as_deref(),
                    Address::Convention { .. } => None,
                };
                match super::block_on(self.get_async(&loc, version))? {
                    SecretRead::Response(value) => Ok(value),
                    SecretRead::NotFound => {
                        versioned_misses
                            .lock()
                            .map_err(|_| {
                                SecretSpecError::ProviderOperationFailed(
                                    "Infisical batch diagnostic state was poisoned".to_string(),
                                )
                            })?
                            .insert(loc.environment);
                        Ok(None)
                    }
                }
            })?
        };
        let versioned_environments = versioned_misses.into_inner().map_err(|_| {
            SecretSpecError::ProviderOperationFailed(
                "Infisical batch diagnostic state was poisoned".to_string(),
            )
        })?;

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

            // A successful listing proves the environment exists. A 404 on a
            // non-root folder is ambiguous, so defer its root probe until we
            // know the entire provider read missed; successful reads should not
            // pay for diagnostics on an unrelated optional secret.
            let mut known_environments = HashSet::new();
            let mut uncertain_environments = versioned_environments;

            for ((environment, secret_path), wanted) in folders {
                match self.list_async(&environment, &secret_path).await? {
                    Some(listed) => {
                        known_environments.insert(environment);
                        for (name, key) in wanted {
                            if let Some(value) = listed.get(&key) {
                                resolved.insert(name.to_string(), value.clone());
                            }
                        }
                    }
                    None if secret_path == "/" => {
                        // Listing the root itself removes the folder/secret
                        // ambiguity without another request.
                        return Err(self.missing_environment_error(&environment));
                    }
                    None => {
                        uncertain_environments.insert(environment);
                    }
                }
            }

            if resolved.is_empty() {
                let to_probe: Vec<String> = uncertain_environments
                    .difference(&known_environments)
                    .cloned()
                    .collect();
                for environment in to_probe {
                    self.ensure_environment_exists_async(&environment).await?;
                }
            }

            Ok(resolved)
        })
    }

    fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()> {
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
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    };
    use std::thread;
    use std::time::Duration;
    use url::Url;

    const PROJECT: &str = "7e2f1a4c-0000-0000-0000-000000000000";

    fn config(s: &str) -> InfisicalConfig {
        InfisicalConfig::try_from(&ProviderUrl::new(Url::parse(s).unwrap())).unwrap()
    }

    fn provider(s: &str) -> InfisicalProvider {
        InfisicalProvider::new(config(s))
    }

    fn read_request(reader: &mut BufReader<TcpStream>) -> Option<String> {
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).ok()? == 0 {
            return None;
        }

        let mut content_length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).ok()?;
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().ok()?;
                }
            }
        }

        if content_length > 0 {
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).ok()?;
        }

        Some(request_line.trim_end().to_string())
    }

    struct RecordingServer {
        endpoint: SocketAddr,
        stop: Arc<AtomicBool>,
        server: thread::JoinHandle<Vec<(usize, String)>>,
    }

    impl RecordingServer {
        /// Stops accepting, waits for the connection workers, and returns each
        /// recorded request with the connection that carried it.
        fn finish(self) -> Vec<(usize, String)> {
            self.stop.store(true, Ordering::Release);
            // The accept loop blocks; one more connection wakes it to see the flag.
            TcpStream::connect(self.endpoint).unwrap();
            self.server.join().unwrap()
        }
    }

    /// Keeps responses alive and records the accepted connection for each request.
    ///
    /// The accept loop blocks until `RecordingServer::finish`, so a missing
    /// request fails the caller's assertions instead of hanging the test.
    fn connection_recording_server() -> RecordingServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();
        let request_count = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let server = thread::spawn(move || {
            let mut workers = Vec::new();

            for (connection_id, stream) in listener.incoming().enumerate() {
                if stopped.load(Ordering::Acquire) {
                    break;
                }
                let stream = stream.unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let sender = sender.clone();
                let request_count = Arc::clone(&request_count);
                workers.push(thread::spawn(move || {
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut writer = stream;
                    while let Some(request) = read_request(&mut reader) {
                        let seen = request_count.fetch_add(1, Ordering::AcqRel) + 1;
                        sender.send((connection_id, request.clone())).unwrap();

                        let body = if request
                            .starts_with("POST /api/v1/auth/universal-auth/login ")
                        {
                            r#"{"accessToken":"test-token"}"#
                        } else if request.starts_with("GET /api/v4/secrets/DATABASE_HOST?") {
                            r#"{"secret":{"secretKey":"DATABASE_HOST","secretValue":"db.internal","secretValueHidden":false}}"#
                        } else {
                            r#"{"message":"unexpected request"}"#
                        };
                        write!(
                            writer,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
                            body.len()
                        )
                        .unwrap();
                        writer.flush().unwrap();
                        if seen >= 2 {
                            break;
                        }
                    }
                }));
            }

            for worker in workers {
                worker.join().unwrap();
            }
            drop(sender);
            receiver.into_iter().collect()
        });
        RecordingServer {
            endpoint,
            stop,
            server,
        }
    }

    #[test]
    fn universal_auth_and_secret_read_use_distinct_tcp_connections() {
        let server = connection_recording_server();
        let mut provider = provider(&format!(
            "infisical://{}/{PROJECT}?tls=false&env=development",
            server.endpoint
        ));
        provider.with_credentials(ProviderCredentials::from([
            (
                CLIENT_ID.to_string(),
                SecretBytes::from_utf8("test-client-id"),
            ),
            (
                CLIENT_SECRET.to_string(),
                SecretBytes::from_utf8("test-client-secret"),
            ),
        ]));
        let address = NativeAddress {
            item: "/DATABASE_HOST".into(),
            ..Default::default()
        };

        let value = provider
            .get(Address::Native(&address))
            .expect("the secret read must succeed")
            .expect("the fixture must return DATABASE_HOST");
        assert_eq!(value.expose_secret(), b"db.internal");

        let requests = server.finish();
        assert_eq!(requests.len(), 2, "{requests:#?}");
        assert!(
            requests[0]
                .1
                .starts_with("POST /api/v1/auth/universal-auth/login ")
        );
        assert!(
            requests[1]
                .1
                .starts_with("GET /api/v4/secrets/DATABASE_HOST?")
        );
        assert_ne!(
            requests[0].0, requests[1].0,
            "Universal Auth and secret reads must use different TCP connections"
        );
    }

    fn provider_with_token(endpoint: SocketAddr, environment: Option<&str>) -> InfisicalProvider {
        let environment =
            environment.map_or_else(String::new, |environment| format!("&env={environment}"));
        let mut provider = provider(&format!(
            "infisical://{endpoint}/{PROJECT}?tls=false{environment}"
        ));
        provider.with_credentials(ProviderCredentials::from([(
            TOKEN.to_string(),
            SecretBytes::from_utf8("test-token"),
        )]));
        provider
    }

    /// Serves a fixed sequence of Infisical-shaped responses and records the
    /// request lines. Closing every response keeps the tiny fixture independent
    /// of reqwest's connection-pool behavior.
    fn response_server(
        responses: Vec<(&'static str, &'static str)>,
    ) -> (SocketAddr, std::thread::JoinHandle<Vec<String>>) {
        response_server_with_lengths(
            responses
                .into_iter()
                .map(|(status, body)| (status, body, body.len()))
                .collect(),
        )
    }

    /// As [`response_server`], with an independently declared content length.
    /// A deliberately truncated body proves code only inspected the response
    /// status instead of buffering data it did not need.
    fn response_server_with_lengths(
        responses: Vec<(&'static str, &'static str, usize)>,
    ) -> (SocketAddr, std::thread::JoinHandle<Vec<String>>) {
        serve_responses(responses, |request_line, _request_body| request_line)
    }

    /// As [`response_server`], recording each request's body beside its
    /// request line.
    fn body_recording_server(
        responses: Vec<(&'static str, &'static str)>,
    ) -> (SocketAddr, std::thread::JoinHandle<Vec<(String, String)>>) {
        serve_responses(
            responses
                .into_iter()
                .map(|(status, body)| (status, body, body.len()))
                .collect(),
            |request_line, request_body| (request_line, request_body),
        )
    }

    /// Serves `responses` in order, one connection each, keeping what
    /// `record` makes of every request line and body.
    fn serve_responses<T: Send + 'static>(
        responses: Vec<(&'static str, &'static str, usize)>,
        record: fn(String, String) -> T,
    ) -> (SocketAddr, std::thread::JoinHandle<Vec<T>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, body, content_length) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                let mut request_length = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        request_length = value.trim().parse().unwrap();
                    }
                }
                let mut request_body = vec![0; request_length];
                reader.read_exact(&mut request_body).unwrap();
                requests.push(record(
                    request_line.trim_end().to_string(),
                    String::from_utf8(request_body).unwrap(),
                ));
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: \
                     {}\r\nConnection: close\r\n\r\n{body}",
                    content_length
                )
                .unwrap();
            }
            requests
        });
        (endpoint, server)
    }

    fn one_convention_request() -> [(&'static str, Address<'static>); 1] {
        [(
            "API_KEY",
            Address::convention("myapp", "development", "API_KEY"),
        )]
    }

    #[test]
    fn uri_defaults_to_infisical_cloud() {
        let c = config(&format!("infisical:///{PROJECT}"));
        assert_eq!(c.endpoint, "https://app.infisical.com");
        assert_eq!(c.project_id, PROJECT);
        assert_eq!(c.path, DEFAULT_PATH);
        assert_eq!(c.environment, None);
    }

    /// When the requested folder and the environment root both return 404,
    /// the provider names the missing environment instead of reducing the
    /// whole profile to a list of unset secrets.
    #[test]
    fn an_all_missing_batch_diagnoses_a_missing_profile_environment() {
        let (endpoint, server) = response_server(vec![
            ("404 Not Found", r#"{"message":"not found"}"#),
            ("404 Not Found", r#"{"message":"not found"}"#),
        ]);
        let provider = provider_with_token(endpoint, None);
        let error = provider
            .get_many(&one_convention_request())
            .expect_err("the absent environment must be reported")
            .to_string();

        assert!(error.contains("environment 'development'"), "{error}");
        assert!(error.contains(PROJECT), "{error}");
        assert!(error.contains("active SecretSpec profile"), "{error}");
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("environment=development"));
        assert!(requests[1].contains("secretPath=%2F"));
    }

    /// A missing non-root folder remains an ordinary miss when the root probe
    /// proves the environment exists, preserving provider fallback behavior.
    #[test]
    fn a_missing_folder_in_an_existing_environment_stays_unset() {
        let (endpoint, server) = response_server(vec![
            ("404 Not Found", r#"{"message":"not found"}"#),
            ("200 OK", r#"{"secrets":[]}"#),
        ]);
        let provider = provider_with_token(endpoint, None);

        assert!(
            provider
                .get_many(&one_convention_request())
                .expect("the environment exists")
                .is_empty()
        );
        assert_eq!(server.join().unwrap().len(), 2);
    }

    /// Distinct historical reads share one status-only, metadata-only root
    /// probe when the whole batch is missing.
    #[test]
    fn versioned_batch_misses_probe_the_environment_once_without_values() {
        let first_body = r#"{"message":"first version not found"}"#;
        let second_body = r#"{"message":"second version not found"}"#;
        let root_body = r#"{"secrets":[{"secretValue":"unrelated plaintext"}]}"#;
        let (endpoint, server) = response_server_with_lengths(vec![
            ("404 Not Found", first_body, first_body.len()),
            ("404 Not Found", second_body, second_body.len()),
            // Closing before the declared length makes consuming this body
            // fail. A status-only probe succeeds without touching it.
            ("200 OK", root_body, root_body.len() + 1024),
        ]);
        let provider = provider_with_token(endpoint, Some("development"));
        let first = NativeAddress {
            item: "/infra/FIRST".into(),
            version: Some("1".into()),
            ..Default::default()
        };
        let second = NativeAddress {
            item: "/infra/SECOND".into(),
            version: Some("2".into()),
            ..Default::default()
        };

        assert!(
            provider
                .get_many(&[
                    ("FIRST", Address::Native(&first)),
                    ("SECOND", Address::Native(&second)),
                ])
                .expect("the environment exists")
                .is_empty()
        );

        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 3);
        let probes: Vec<_> = requests
            .iter()
            .filter(|request| request.starts_with("GET /api/v4/secrets?"))
            .collect();
        assert_eq!(probes.len(), 1, "{requests:#?}");
        assert!(probes[0].contains("secretPath=%2F"), "{}", probes[0]);
        assert!(
            probes[0].contains("expandSecretReferences=false"),
            "{}",
            probes[0]
        );
        assert!(probes[0].contains("viewSecretValue=false"), "{}", probes[0]);
        assert!(!probes[0].contains("viewSecretValue=true"), "{}", probes[0]);
    }

    /// The diagnostic tells users whether to rename a profile or change the
    /// provider's explicit environment pin.
    #[test]
    fn a_missing_environment_names_how_it_was_selected() {
        let implicit = provider(&format!("infisical://app.infisical.com/{PROJECT}"));
        let implicit_error = implicit
            .missing_environment_error("development")
            .to_string();
        assert!(implicit_error.contains("active SecretSpec profile"));

        let pinned = provider(&format!(
            "infisical://app.infisical.com/{PROJECT}?env=shared"
        ));
        let pinned_error = pinned.missing_environment_error("shared").to_string();
        assert!(pinned_error.contains("provider URI selected it with `?env=`"));
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

    /// A ref names no environment, so one must come from `?env=` or the profile.
    /// With neither — a library caller that never set one — the error says so.
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
            .set(Address::Native(&addr), &SecretBytes::from_utf8("v"))
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
        assert_eq!(value.expose_secret(), b"s3cret");
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
        let mut listed: HashMap<String, SecretBytes> = direct
            .iter()
            .map(|(k, v)| (k.to_string(), SecretBytes::from_utf8(*v)))
            .collect();
        InfisicalProvider::merge_imports(parsed, &mut listed).expect("merge");
        listed
            .into_iter()
            .map(|(k, v)| (k, v.try_as_utf8().unwrap().to_string()))
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
            format!("infisical://app.infisical.com/{PROJECT}?env=prod&personal=true"),
            format!("infisical://app.infisical.com/{PROJECT}?env=prod&path=/team"),
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

    /// Without `?env=`, a ref reads the environment the session's profile names
    /// — the same one a convention address would reach in that run.
    #[test]
    fn a_ref_without_env_reads_the_profile_environment() {
        let p = provider(&format!("infisical://app.infisical.com/{PROJECT}"));
        p.set_profile("prod");

        let addr = NativeAddress {
            item: "/DB_PASSWORD".into(),
            ..Default::default()
        };
        let loc = p.locate(Address::Native(&addr)).unwrap();
        assert_eq!(loc.environment, "prod");
        assert_eq!(loc.secret_path, "/");
        assert_eq!(loc.key, "DB_PASSWORD");

        // A convention address in the same run names the same environment.
        let conv = p
            .locate(Address::convention("myapp", "prod", "DB_PASSWORD"))
            .unwrap();
        assert_eq!(conv.environment, loc.environment);
    }

    /// `?env=` is an explicit pin, so it outranks the profile for refs exactly as
    /// it already does for convention addresses.
    #[test]
    fn an_explicit_env_outranks_the_profile() {
        let p = provider(&format!(
            "infisical://app.infisical.com/{PROJECT}?env=shared"
        ));
        p.set_profile("prod");

        let addr = NativeAddress {
            item: "/DB_PASSWORD".into(),
            ..Default::default()
        };
        assert_eq!(
            p.locate(Address::Native(&addr)).unwrap().environment,
            "shared"
        );
        assert_eq!(
            p.locate(Address::convention("myapp", "prod", "DB_PASSWORD"))
                .unwrap()
                .environment,
            "shared"
        );
    }

    /// With neither `?env=` nor a profile, a ref still fails with the error that
    /// names the fix, rather than requesting an empty environment slug.
    #[test]
    fn a_ref_without_env_or_profile_still_explains_itself() {
        let addr = NativeAddress {
            item: "/DB_PASSWORD".into(),
            ..Default::default()
        };

        for profile in [None, Some(""), Some("   ")] {
            let p = provider(&format!("infisical://app.infisical.com/{PROJECT}"));
            if let Some(profile) = profile {
                p.set_profile(profile);
            }
            let err = p.locate(Address::Native(&addr)).unwrap_err().to_string();
            assert!(
                err.contains("No Infisical environment for this ref"),
                "{err}"
            );
        }
    }

    /// The profile is session context, not naming: an instance's URI must not
    /// change with it, or one store would take a different cache identity under
    /// every profile.
    #[test]
    fn the_profile_does_not_change_the_uri() {
        let p = provider(&format!("infisical://app.infisical.com/{PROJECT}"));
        let before = p.uri();
        p.set_profile("prod");
        assert_eq!(p.uri(), before);
        assert_eq!(p.storage_identity(), before);
    }

    /// Entry collision checks must see the environment that operations resolve,
    /// even when one alias derives it from the profile and another pins it in
    /// the URI. The profile remains absent from the cache storage identity.
    #[test]
    fn entry_identity_resolves_the_profile_environment() {
        let implicit = provider(&format!("infisical://app.infisical.com/{PROJECT}"));
        implicit.set_profile("prod");
        let pinned_prod = provider(&format!("infisical://app.infisical.com/{PROJECT}?env=prod"));
        let pinned_dev = provider(&format!("infisical://app.infisical.com/{PROJECT}?env=dev"));
        let addr = NativeAddress {
            item: "/DB_PASSWORD".into(),
            ..Default::default()
        };

        assert_ne!(implicit.storage_identity(), pinned_prod.storage_identity());
        assert!(
            implicit
                .same_entries(Address::Native(&addr), &pinned_prod, Address::Native(&addr),)
                .unwrap(),
            "profile prod and ?env=prod reach the same Infisical secret"
        );
        assert!(
            !implicit
                .same_entries(Address::Native(&addr), &pinned_dev, Address::Native(&addr),)
                .unwrap(),
            "different Infisical environments must remain distinct"
        );
    }

    /// An absolute ref supplies the complete Infisical folder, so configured
    /// path defaults do not distinguish two aliases that reach that same folder.
    #[test]
    fn entry_identity_uses_the_resolved_absolute_path() {
        let left = provider(&format!(
            "infisical://app.infisical.com/{PROJECT}?env=prod&path=/left"
        ));
        let right = provider(&format!(
            "infisical://app.infisical.com/{PROJECT}?env=prod&path=/right"
        ));
        let addr = NativeAddress {
            item: "/shared/DB_PASSWORD".into(),
            ..Default::default()
        };

        assert!(
            left.same_entries(Address::Native(&addr), &right, Address::Native(&addr),)
                .unwrap(),
            "absolute refs that resolve to the same API path are one entry"
        );
    }

    /// A relative ref is resolved under the configured path, so different path
    /// defaults still keep the resulting Infisical entries distinct.
    #[test]
    fn entry_identity_resolves_relative_refs_under_the_configured_path() {
        let left = provider(&format!(
            "infisical://app.infisical.com/{PROJECT}?env=prod&path=/left"
        ));
        let right = provider(&format!(
            "infisical://app.infisical.com/{PROJECT}?env=prod&path=/right"
        ));
        let addr = NativeAddress {
            item: "shared/DB_PASSWORD".into(),
            ..Default::default()
        };

        assert!(
            !left
                .same_entries(Address::Native(&addr), &right, Address::Native(&addr),)
                .unwrap(),
            "relative refs under different configured paths are distinct entries"
        );
    }

    /// `set_profile` is shared by every provider, and a preflight-enabled one is
    /// wrapped as `Box<Arc<P>>`, which a `&mut self` hook cannot reach through.
    /// Infisical registers no preflight today, so this guards the trait's
    /// contract rather than its own wrapping: it must stay a `&self` hook.
    #[test]
    fn set_profile_reaches_the_provider_through_arc() {
        let p = std::sync::Arc::new(provider(&format!(
            "infisical://app.infisical.com/{PROJECT}"
        )));
        Provider::set_profile(&p, "prod");

        let addr = NativeAddress {
            item: "/DB_PASSWORD".into(),
            ..Default::default()
        };
        assert_eq!(
            p.locate(Address::Native(&addr)).unwrap().environment,
            "prod"
        );
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

    /// A provider authenticated with a plain token, in personal mode.
    fn personal_provider_with_token(
        endpoint: SocketAddr,
        environment: Option<&str>,
    ) -> InfisicalProvider {
        let environment =
            environment.map_or_else(String::new, |environment| format!("&env={environment}"));
        let mut provider = provider(&format!(
            "infisical://{endpoint}/{PROJECT}?tls=false&personal=true{environment}"
        ));
        provider.with_credentials(ProviderCredentials::from([(
            TOKEN.to_string(),
            SecretBytes::from_utf8("test-token"),
        )]));
        provider
    }

    /// Clears every Infisical credential the environment could supply. The
    /// returned guards must outlive the test body; the caller holds the lock.
    fn without_infisical_env() -> [crate::tests::EnvVarGuard; 3] {
        [
            crate::tests::EnvVarGuard::remove(INFISICAL_TOKEN_ENV),
            crate::tests::EnvVarGuard::remove(INFISICAL_CLIENT_ID_ENV),
            crate::tests::EnvVarGuard::remove(INFISICAL_CLIENT_SECRET_ENV),
        ]
    }

    /// A provider whose CLI fallback is `script`, installed in `directory`. It
    /// runs as it would without a terminal, so these tests do not depend on
    /// how `cargo test` was started.
    #[cfg(unix)]
    fn provider_with_cli_script(directory: &std::path::Path, script: &str) -> InfisicalProvider {
        let binary = directory.join("infisical");
        crate::fake_executable::install(&binary, script);
        let mut provider = provider(&format!("infisical://localhost:8080/{PROJECT}?tls=false"));
        provider.cli_binary_path = binary.to_string_lossy().into_owned();
        provider.cli_stdin_is_terminal = || false;
        provider
    }

    /// A provider whose CLI fallback is an Infisical CLI 0.44.0 running `body`
    /// for `user get token`, with `$dir` naming its directory. Each version
    /// check appends a line to `versions` there, and each token run to `runs`.
    #[cfg(unix)]
    fn provider_with_cli(directory: &std::path::Path, body: &str) -> InfisicalProvider {
        provider_with_cli_script(
            directory,
            &format!(
                "#!/bin/sh\ndir=\"$(dirname \"$0\")\"\nif [ \"$1\" = --version ]; then\n  echo \
                 version >> \"$dir/versions\"\n  echo 'infisical version 0.44.0'\n  exit 0\nfi\n\
                 echo run >> \"$dir/runs\"\n{body}"
            ),
        )
    }

    /// Another provider instance running the same CLI against the same
    /// Infisical instance as `original`, so the two share a CLI session.
    #[cfg(unix)]
    fn same_cli(original: &InfisicalProvider) -> InfisicalProvider {
        let mut other = provider(&format!("infisical://localhost:8080/{PROJECT}?tls=false"));
        other.cli_binary_path = original.cli_binary_path.clone();
        other.cli_stdin_is_terminal = original.cli_stdin_is_terminal;
        other
    }

    /// How many lines the fake CLI in `directory` appended to `log`.
    #[cfg(unix)]
    fn cli_calls(directory: &std::path::Path, log: &str) -> usize {
        std::fs::read_to_string(directory.join(log)).map_or(0, |calls| calls.lines().count())
    }

    /// An unsigned JWT whose `exp` claim is `exp`.
    fn jwt_expiring_at(exp: u64) -> String {
        let claims = format!(r#"{{"exp":{exp}}}"#);
        let claims = data_encoding::BASE64URL_NOPAD.encode(claims.as_bytes());
        format!("eyJhbGciOiJIUzI1NiJ9.{claims}.c2lnbmF0dXJl")
    }

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn token_error(provider: &InfisicalProvider) -> String {
        super::super::block_on(provider.resolve_token())
            .map(|_| ())
            .expect_err("authentication must fail")
            .to_string()
    }

    #[cfg(unix)]
    #[test]
    fn the_cli_session_is_the_fallback_without_credentials() {
        let _lock = crate::tests::scrub_resolution_env();
        let _env = without_infisical_env();
        let directory = tempfile::tempdir().unwrap();
        let provider = provider_with_cli(
            directory.path(),
            "printf '%s' \"$*\" > \"$dir/args\"\nprintf 'notice\\naaa.bbb.ccc\\n'\n",
        );

        let token = super::super::block_on(provider.resolve_token()).unwrap();
        assert_eq!(token.expose_secret(), b"aaa.bbb.ccc");
        assert_eq!(
            std::fs::read_to_string(directory.path().join("args")).unwrap(),
            "user get token --plain --silent --domain http://localhost:8080"
        );
    }

    #[test]
    fn an_explicit_token_never_runs_the_cli() {
        let _lock = crate::tests::scrub_resolution_env();
        let _env = without_infisical_env();
        let _token = crate::tests::EnvVarGuard::set(INFISICAL_TOKEN_ENV, "env-token");
        let mut provider = provider(&format!("infisical://localhost:8080/{PROJECT}?tls=false"));
        provider.cli_binary_path = "/must-not-run-infisical".into();

        let token = super::super::block_on(provider.resolve_token()).unwrap();
        assert_eq!(token.expose_secret(), b"env-token");
    }

    #[test]
    fn a_half_specified_identity_never_runs_the_cli() {
        let _lock = crate::tests::scrub_resolution_env();
        let _env = without_infisical_env();
        let _id = crate::tests::EnvVarGuard::set(INFISICAL_CLIENT_ID_ENV, "client");
        let mut provider = provider(&format!("infisical://localhost:8080/{PROJECT}?tls=false"));
        provider.cli_binary_path = "/must-not-run-infisical".into();

        let error = token_error(&provider);
        assert!(error.contains("client_secret is missing"), "{error}");
    }

    #[test]
    fn a_lone_client_secret_never_runs_the_cli() {
        let _lock = crate::tests::scrub_resolution_env();
        let _env = without_infisical_env();
        let _secret = crate::tests::EnvVarGuard::set(INFISICAL_CLIENT_SECRET_ENV, "secret");
        let mut provider = provider(&format!("infisical://localhost:8080/{PROJECT}?tls=false"));
        provider.cli_binary_path = "/must-not-run-infisical".into();

        let error = token_error(&provider);
        assert!(error.contains("client_id is missing"), "{error}");
    }

    #[test]
    fn a_half_specified_credential_identity_never_runs_the_cli() {
        let _lock = crate::tests::scrub_resolution_env();
        let _env = without_infisical_env();
        let mut provider = provider(&format!("infisical://localhost:8080/{PROJECT}?tls=false"));
        provider.with_credentials(ProviderCredentials::from([(
            CLIENT_ID.to_string(),
            SecretBytes::from_utf8("client"),
        )]));
        provider.cli_binary_path = "/must-not-run-infisical".into();

        let error = token_error(&provider);
        assert!(error.contains("client_secret is missing"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_cli_names_infisical_login() {
        let _lock = crate::tests::scrub_resolution_env();
        let _env = without_infisical_env();
        let directory = tempfile::tempdir().unwrap();
        let provider =
            provider_with_cli(directory.path(), "printf 'secret-ish.out.put\\n'\nexit 1\n");

        let error = token_error(&provider);
        assert!(error.contains("infisical login --domain"), "{error}");
        assert!(!error.contains("secret-ish"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn cli_output_without_a_token_is_refused() {
        let _lock = crate::tests::scrub_resolution_env();
        let _env = without_infisical_env();
        let directory = tempfile::tempdir().unwrap();
        let provider = provider_with_cli(directory.path(), "printf 'not a token\\n'\n");

        let error = token_error(&provider);
        assert!(error.contains("did not print an access token"), "{error}");
        assert!(!error.contains("not a token"), "{error}");
    }

    #[test]
    fn a_missing_cli_lists_every_auth_option() {
        let _lock = crate::tests::scrub_resolution_env();
        let _env = without_infisical_env();
        let directory = tempfile::tempdir().unwrap();
        let mut provider = provider(&format!("infisical://localhost:8080/{PROJECT}?tls=false"));
        provider.cli_binary_path = directory
            .path()
            .join("no-such-infisical")
            .to_string_lossy()
            .into_owned();

        let error = token_error(&provider);
        assert!(error.contains("INFISICAL_TOKEN"), "{error}");
        assert!(error.contains("infisical login"), "{error}");
        assert!(error.contains("SECRETSPEC_INFISICAL_PATH"), "{error}");
    }

    /// Before 0.44.0 the CLI ignores `--domain`, so asking it for a token could
    /// hand over another instance's session: it is never asked.
    #[cfg(unix)]
    #[test]
    fn an_old_cli_is_refused_before_it_is_asked_for_a_token() {
        let _lock = crate::tests::scrub_resolution_env();
        let _env = without_infisical_env();
        let directory = tempfile::tempdir().unwrap();
        let provider = provider_with_cli_script(
            directory.path(),
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'infisical version 0.43.99'; exit 0; \
             fi\necho run >> \"$(dirname \"$0\")/runs\"\nprintf 'aaa.bbb.ccc\\n'\n",
        );

        let error = token_error(&provider);
        assert!(error.contains("0.43.99"), "{error}");
        assert!(error.contains("0.44.0 or newer"), "{error}");
        assert!(error.contains("--domain"), "{error}");
        assert_eq!(cli_calls(directory.path(), "runs"), 0);
    }

    #[test]
    fn cli_versions_are_compared_as_versions() {
        for supported in [
            "infisical version 0.44.0",
            "infisical version 0.44.12",
            "infisical version 0.45.0-rc.1",
            "infisical version 1.0.0",
            "infisical version 0.44.0+build.5",
            "v0.44.0",
        ] {
            assert!(
                InfisicalProvider::supported_cli_version(supported),
                "{supported}"
            );
        }
        for unsupported in [
            "infisical version 0.43.99",
            "infisical version 0.9.100",
            "infisical version 0.44.0-rc.1",
            "infisical version 0.44",
            "infisical version devel",
            "",
        ] {
            assert!(
                !InfisicalProvider::supported_cli_version(unsupported),
                "{unsupported}"
            );
        }
    }

    /// Two instances asking at once share one CLI run, which could otherwise
    /// open two logins. The token has no `exp`, so it is not reused past its
    /// run: one run proves the callers shared it.
    #[cfg(unix)]
    #[test]
    fn concurrent_instances_share_one_cli_run() {
        let _lock = crate::tests::scrub_resolution_env();
        let _env = without_infisical_env();
        let directory = tempfile::tempdir().unwrap();
        let first = provider_with_cli(directory.path(), "sleep 1\nprintf 'aaa.bbb.ccc\\n'\n");
        let second = same_cli(&first);

        let (first_token, second_token) = super::super::block_on(async {
            tokio::join!(first.resolve_token(), second.resolve_token())
        });
        assert_eq!(first_token.unwrap().expose_secret(), b"aaa.bbb.ccc");
        assert_eq!(second_token.unwrap().expose_secret(), b"aaa.bbb.ccc");
        assert_eq!(cli_calls(directory.path(), "runs"), 1);
    }

    /// Callers waiting on a failed run share its failure rather than each
    /// running the CLI again, but the failure is not remembered: a later call,
    /// once the user has logged in, asks the CLI again.
    #[cfg(unix)]
    #[test]
    fn a_failed_cli_run_is_shared_but_not_remembered() {
        let _lock = crate::tests::scrub_resolution_env();
        let _env = without_infisical_env();
        let directory = tempfile::tempdir().unwrap();
        let first = provider_with_cli(
            directory.path(),
            "sleep 1\nif [ -f \"$dir/logged-in\" ]; then printf 'aaa.bbb.ccc\\n'; else exit 1; fi\n",
        );
        let second = same_cli(&first);

        let (first_token, second_token) = super::super::block_on(async {
            tokio::join!(first.resolve_token(), second.resolve_token())
        });
        for token in [first_token, second_token] {
            let error = token.map(|_| ()).unwrap_err().to_string();
            assert!(error.contains("infisical login --domain"), "{error}");
        }
        assert_eq!(cli_calls(directory.path(), "runs"), 1);

        std::fs::write(directory.path().join("logged-in"), "").unwrap();
        let token = super::super::block_on(second.resolve_token()).unwrap();
        assert_eq!(token.expose_secret(), b"aaa.bbb.ccc");
        assert_eq!(cli_calls(directory.path(), "runs"), 2);
    }

    /// A token well before its `exp` is reused, by other instances too, and
    /// the version check is not repeated.
    #[cfg(unix)]
    #[test]
    fn a_fresh_cli_token_is_reused() {
        let _lock = crate::tests::scrub_resolution_env();
        let _env = without_infisical_env();
        let directory = tempfile::tempdir().unwrap();
        let token = jwt_expiring_at(unix_now() + 3600);
        let first = provider_with_cli(directory.path(), &format!("printf '%s\\n' '{token}'\n"));
        let second = same_cli(&first);

        for provider in [&first, &second, &first] {
            let resolved = super::super::block_on(provider.resolve_token()).unwrap();
            assert_eq!(resolved.expose_secret(), token.as_bytes());
        }
        assert_eq!(cli_calls(directory.path(), "runs"), 1);
        assert_eq!(cli_calls(directory.path(), "versions"), 1);
    }

    /// An expired token, or one within a minute of its `exp`, is fetched again
    /// on the next call; the accepted version is remembered across runs.
    #[cfg(unix)]
    #[test]
    fn an_expiring_cli_token_is_fetched_again() {
        let _lock = crate::tests::scrub_resolution_env();
        let _env = without_infisical_env();
        for exp in [1, unix_now() + 30] {
            let directory = tempfile::tempdir().unwrap();
            let token = jwt_expiring_at(exp);
            let provider =
                provider_with_cli(directory.path(), &format!("printf '%s\\n' '{token}'\n"));

            for _ in 0..2 {
                let resolved = super::super::block_on(provider.resolve_token()).unwrap();
                assert_eq!(resolved.expose_secret(), token.as_bytes());
            }
            assert_eq!(cli_calls(directory.path(), "runs"), 2, "exp {exp}");
            assert_eq!(cli_calls(directory.path(), "versions"), 1, "exp {exp}");
        }
    }

    #[test]
    fn a_cli_token_is_reused_only_with_a_distant_exp() {
        let now = SystemTime::now();
        let token = |raw: &str| CliToken {
            token: Arc::new(SecretBytes::from_utf8(raw)),
            expires_at: InfisicalProvider::jwt_expiry(raw),
        };

        assert_eq!(
            InfisicalProvider::jwt_expiry(&jwt_expiring_at(1)),
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        );
        assert!(token(&jwt_expiring_at(unix_now() + 3600)).reusable_at(now));
        assert!(!token(&jwt_expiring_at(unix_now() + 30)).reusable_at(now));
        assert!(!token(&jwt_expiring_at(1)).reusable_at(now));
        assert!(!token("aaa.bbb.ccc").reusable_at(now));
    }

    /// Without a terminal nobody can answer a login, so a CLI still running
    /// at the timeout is stopped, together with what it spawned (here a
    /// stand-in for `infisical login`).
    #[cfg(unix)]
    #[test]
    fn a_cli_without_a_terminal_is_stopped_at_the_timeout() {
        let _lock = crate::tests::scrub_resolution_env();
        let _env = without_infisical_env();
        let directory = tempfile::tempdir().unwrap();
        let mut provider = provider_with_cli(
            directory.path(),
            "sleep 60 &\necho $! > \"$dir/descendant\"\nwait\n",
        );
        provider.cli_timeout = Duration::from_secs(1);

        let started = std::time::Instant::now();
        let error = token_error(&provider);
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(error.contains("missing or expired"), "{error}");
        assert!(
            error.contains("infisical login --domain http://localhost:8080"),
            "{error}"
        );

        let pid: libc::pid_t = std::fs::read_to_string(directory.path().join("descendant"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            // SAFETY: signal 0 only probes a PID recorded by the test child.
            if unsafe { libc::kill(pid, 0) } == -1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // SAFETY: same non-mutating existence probe as above.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    }

    #[test]
    fn personal_is_parsed_strictly() {
        assert!(
            config(&format!(
                "infisical://app.infisical.com/{PROJECT}?personal=true"
            ))
            .personal_overrides
        );
        assert!(!config(&format!("infisical://app.infisical.com/{PROJECT}")).personal_overrides);
        let error = InfisicalConfig::try_from(&ProviderUrl::new(
            Url::parse(&format!(
                "infisical://app.infisical.com/{PROJECT}?personal=banana"
            ))
            .unwrap(),
        ))
        .unwrap_err()
        .to_string();
        assert!(error.contains("Unknown personal value"), "{error}");
    }

    #[test]
    fn personal_reads_list_with_overrides() {
        let (endpoint, server) = response_server(vec![(
            "200 OK",
            r#"{"secrets":[{"secretKey":"API_KEY","secretValue":"mine"}]}"#,
        )]);
        let provider = personal_provider_with_token(endpoint, Some("development"));

        let value = provider
            .get(Address::convention("myapp", "development", "API_KEY"))
            .unwrap()
            .expect("the override must be read");
        assert_eq!(value.expose_secret(), b"mine");

        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1, "{requests:#?}");
        assert!(
            requests[0].starts_with("GET /api/v4/secrets?"),
            "{}",
            requests[0]
        );
        assert!(
            requests[0].contains("includePersonalOverrides=true"),
            "{}",
            requests[0]
        );
    }

    #[test]
    fn shared_reads_never_request_overrides() {
        let (endpoint, server) = response_server(vec![(
            "200 OK",
            r#"{"secrets":[{"secretKey":"API_KEY","secretValue":"shared"}]}"#,
        )]);
        let provider = provider_with_token(endpoint, Some("development"));
        provider.get_many(&one_convention_request()).unwrap();

        let requests = server.join().unwrap();
        assert!(
            !requests[0].contains("includePersonalOverrides"),
            "{}",
            requests[0]
        );
    }

    #[test]
    fn a_personal_override_without_a_shared_secret_is_refused() {
        let (endpoint, server) = response_server(vec![
            (
                "404 Not Found",
                r#"{"message":"Personal secret with name API_KEY not found"}"#,
            ),
            (
                "400 Bad Request",
                r#"{"message":"Failed to create personal secret override for no corresponding shared secret"}"#,
            ),
        ]);
        let provider = personal_provider_with_token(endpoint, Some("development"));

        let error = provider
            .set(
                Address::convention("myapp", "development", "API_KEY"),
                &SecretBytes::from_utf8("local"),
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("no corresponding shared secret"), "{error}");
        assert!(error.contains("existing shared secret"), "{error}");
        assert!(!error.contains("machine identity"), "{error}");

        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2, "{requests:#?}");
        assert!(requests[0].starts_with("PATCH /api/v4/secrets/API_KEY"));
        assert!(requests[1].starts_with("POST /api/v4/secrets/API_KEY"));
    }

    #[test]
    fn a_personal_override_never_creates_folders() {
        let (endpoint, server) = response_server(vec![
            ("404 Not Found", r#"{"message":"not found"}"#),
            ("404 Not Found", r#"{"message":"not found"}"#),
            // The environment probe: it exists, so the shared secret is missing.
            ("200 OK", r#"{"secrets":[]}"#),
        ]);
        let provider = personal_provider_with_token(endpoint, Some("development"));

        let error = provider
            .set(
                Address::convention("myapp", "development", "API_KEY"),
                &SecretBytes::from_utf8("local"),
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("has no shared secret"), "{error}");

        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 3, "{requests:#?}");
        assert!(requests[2].contains("secretPath=%2F"), "{}", requests[2]);
        assert!(
            requests
                .iter()
                .all(|request| !request.contains("/api/v2/folders")),
            "{requests:#?}"
        );
    }

    /// Infisical answers a missing environment with the same 404 as a missing
    /// shared secret; the root probe tells them apart.
    #[test]
    fn a_personal_override_in_a_missing_environment_names_the_environment() {
        let (endpoint, server) = response_server(vec![
            ("404 Not Found", r#"{"message":"not found"}"#),
            ("404 Not Found", r#"{"message":"not found"}"#),
            ("404 Not Found", r#"{"message":"not found"}"#),
        ]);
        let provider = personal_provider_with_token(endpoint, None);

        let error = provider
            .set(
                Address::convention("myapp", "development", "API_KEY"),
                &SecretBytes::from_utf8("local"),
            )
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("could not find environment 'development'"),
            "{error}"
        );
        assert!(error.contains("active SecretSpec profile"), "{error}");
        assert!(!error.contains("shared secret"), "{error}");

        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 3, "{requests:#?}");
        assert!(
            requests[2].starts_with("GET /api/v4/secrets?"),
            "{}",
            requests[2]
        );
        assert!(requests[2].contains("secretPath=%2F"), "{}", requests[2]);
    }

    /// A 400 is put down to a missing shared secret or a non-user writer only
    /// when Infisical says so.
    #[test]
    fn an_unrelated_personal_400_is_reported_plainly() {
        let (endpoint, server) = response_server(vec![(
            "400 Bad Request",
            r#"{"message":"secretValue: Expected string, received number"}"#,
        )]);
        let provider = personal_provider_with_token(endpoint, Some("development"));

        let error = provider
            .set(
                Address::convention("myapp", "development", "API_KEY"),
                &SecretBytes::from_utf8("local"),
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("HTTP 400"), "{error}");
        assert!(error.contains("Expected string"), "{error}");
        assert!(!error.contains("shared secret"), "{error}");
        assert!(!error.contains("machine identity"), "{error}");
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[test]
    fn a_personal_write_by_a_non_user_names_the_cause() {
        let (endpoint, server) = response_server(vec![(
            "400 Bad Request",
            r#"{"message":"Must be user to create personal secret"}"#,
        )]);
        let provider = personal_provider_with_token(endpoint, Some("development"));

        let error = provider
            .set(
                Address::convention("myapp", "development", "API_KEY"),
                &SecretBytes::from_utf8("local"),
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("Must be user"), "{error}");
        assert!(error.contains("users only"), "{error}");
        assert!(!error.contains("shared secret"), "{error}");
        assert_eq!(server.join().unwrap().len(), 1);
    }

    /// Both requests of a personal write -- the update, then the create it
    /// falls back to -- carry `type: personal` on the wire.
    #[test]
    fn personal_writes_send_the_personal_type() {
        let (endpoint, server) = body_recording_server(vec![
            (
                "404 Not Found",
                r#"{"message":"Personal secret with name API_KEY not found"}"#,
            ),
            (
                "200 OK",
                r#"{"secret":{"secretKey":"API_KEY","version":1}}"#,
            ),
        ]);
        let provider = personal_provider_with_token(endpoint, Some("development"));

        provider
            .set(
                Address::convention("myapp", "development", "API_KEY"),
                &SecretBytes::from_utf8("local"),
            )
            .unwrap();

        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2, "{requests:#?}");
        for ((line, body), method) in requests.iter().zip(["PATCH", "POST"]) {
            assert!(
                line.starts_with(&format!("{method} /api/v4/secrets/API_KEY")),
                "{line}"
            );
            let body: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(body["type"], "personal", "{line}: {body}");
            assert_eq!(body["secretValue"], "local", "{line}: {body}");
        }
    }

    #[test]
    fn shared_writes_send_no_type() {
        let (endpoint, server) = body_recording_server(vec![(
            "200 OK",
            r#"{"secret":{"secretKey":"API_KEY","version":2}}"#,
        )]);
        let provider = provider_with_token(endpoint, Some("development"));

        provider
            .set(
                Address::convention("myapp", "development", "API_KEY"),
                &SecretBytes::from_utf8("local"),
            )
            .unwrap();

        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1, "{requests:#?}");
        let (line, body) = &requests[0];
        assert!(line.starts_with("PATCH /api/v4/secrets/API_KEY"), "{line}");
        let body: serde_json::Value = serde_json::from_str(body).unwrap();
        assert!(body.get("type").is_none(), "{body}");
    }
}
