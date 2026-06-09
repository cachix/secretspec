//! Core secrets management functionality

use crate::audit::{AuditAction, AuditContext, AuditLogger, AuditOutcome};
use crate::config::{Config, GlobalConfig, Profile, RequireReason, Resolved};
use crate::error::{Result, SecretSpecError};
use crate::provider::Provider as ProviderTrait;
use crate::report::{ResolutionStatus, SecretResolution};
use crate::resolve::{RESOLVE_SCHEMA_VERSION, ResolveResponse, ResolvedSecret, ResolvedSource};
use crate::validation::{ValidatedSecrets, ValidationErrors};
use colored::Colorize;
use secrecy::{ExposeSecret, SecretString};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::TryFrom;
use std::env;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Emits a warning when a provider in a fallback chain fails so the user
/// can see why a particular link was skipped, without aborting the chain.
///
/// `display_uri` must already be credential-free: pass the provider's
/// reconstructed [`uri()`](ProviderTrait::uri) when a provider was built, or
/// [`redact_uri_strict`] of the raw alias when construction itself failed. This
/// function does not redact, so it never strips legitimate attribution (e.g. an
/// `awssm://…?prefix=…`) from a provider's own `uri()`.
///
/// [`redact_uri_strict`]: crate::audit::redact_uri_strict
fn warn_provider_failure(display_uri: &str, secret_name: &str, err: &SecretSpecError) {
    eprintln!(
        "{} provider {} failed for {}: {}; trying next provider in chain",
        "warning:".yellow(),
        display_uri.bold(),
        secret_name.bold(),
        err
    );
}

/// Emits a warning when the primary provider for a batch fetch fails (either
/// during construction or during `get_batch`); affected secrets will still be
/// retried via their per-secret fallback chain below.
///
/// Like [`warn_provider_failure`], `display_uri` must already be credential-free
/// (a provider's reconstructed `uri()`, or [`redact_uri_strict`] of a raw alias).
/// `None` renders as `<default>` (no per-secret provider was configured).
///
/// [`redact_uri_strict`]: crate::audit::redact_uri_strict
fn warn_primary_provider_failure(display_uri: Option<&str>, err: &SecretSpecError) {
    eprintln!(
        "{} primary provider {} failed: {}; will try fallback chain for affected secrets",
        "warning:".yellow(),
        display_uri.unwrap_or("<default>").bold(),
        err
    );
}

/// Walks up from the current directory looking for `secretspec.toml`.
fn find_config_file() -> Result<PathBuf> {
    let mut dir = std::env::current_dir()?;
    loop {
        let candidate = dir.join("secretspec.toml");
        if candidate.exists() {
            return Ok(candidate);
        }
        if !dir.pop() {
            return Err(SecretSpecError::NoManifest);
        }
    }
}

/// The main entry point for the secretspec library
///
/// `Secrets` manages the loading, validation, and retrieval of secrets
/// based on the project and global configuration files.
///
/// # Example
///
/// ```no_run
/// use secretspec::Secrets;
///
/// // Load configuration and validate secrets
/// let mut spec = Secrets::load().unwrap();
/// spec.check(false).unwrap();
/// ```
pub struct Secrets {
    /// The project-specific configuration
    config: Config,
    /// Optional global user configuration
    global_config: Option<GlobalConfig>,
    /// The provider to use (if set via builder)
    provider: Option<String>,
    /// The profile to use (if set via builder)
    profile: Option<String>,
    /// Reason for this session's secret access, forwarded to providers that
    /// support audit logging (set via [`Secrets::with_reason`]).
    reason: Option<String>,
    /// Project policy (`[project].require_reason` in secretspec.toml) controlling
    /// when secret access requires an explicit reason.
    require_reason: RequireReason,
    /// Audit logger, if auditing is enabled (user-global `[audit]` config). `None`
    /// disables auditing. Built once per `Secrets` so all events share a session id.
    audit: Option<AuditLogger>,
}

/// secretspec's own opt-in for marking the current process as an agent. Lets any
/// harness that the `detect-coding-agent` crate does not recognize identify itself.
const AGENT_OPT_IN_ENV: &str = "SECRETSPEC_AGENT";

/// A UTF-8 snapshot of the process environment, dropping any non-UTF-8 entries.
///
/// `detect-coding-agent`'s `detect()`/`is_agent()` capture the environment with
/// `std::env::vars()`, which **panics** on any non-UTF-8 variable — and env vars
/// are arbitrary byte strings on Unix. Building the map ourselves with `vars_os`
/// and silently skipping non-UTF-8 entries lets detection run safely: the
/// agent-signal variables the crate looks for are always plain ASCII, so a stray
/// non-UTF-8 var cannot abort an otherwise-fine secretspec command. Feeds the
/// crate's `*_with_env` variants, which take the map instead of reading the
/// environment directly.
fn utf8_env() -> std::collections::HashMap<String, String> {
    utf8_env_from(std::env::vars_os())
}

/// [`utf8_env`] over an explicit iterator, so the non-UTF-8 filtering can be tested
/// without mutating the process environment (which is global and racy under `cargo
/// test`).
fn utf8_env_from<I>(vars: I) -> std::collections::HashMap<String, String>
where
    I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
{
    vars.into_iter()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect()
}

/// The id of the detected coding agent (e.g. `"claude-code"`), or `None`.
///
/// Routes through [`detect_with_env`](detect_coding_agent::detect_with_env) with a
/// [`utf8_env`] snapshot so a non-UTF-8 environment cannot panic the process.
pub(crate) fn detect_agent_id() -> Option<&'static str> {
    detect_coding_agent::detect_with_env(utf8_env()).map(|a| a.id)
}

/// Whether secretspec is currently running as an AI coding agent.
///
/// Detection of the known agents (Claude Code, Cursor, Codex, Gemini CLI, Copilot,
/// ...) is delegated to the [`detect-coding-agent`] crate, which maintains the
/// per-tool signal list. This covers autonomous and hybrid environments (not
/// human-driven interactive editors), mirroring the crate's own `is_agent()`.
/// `SECRETSPEC_AGENT` is an additional explicit opt-in for harnesses the crate does
/// not yet recognize. Detection goes through [`utf8_env`] so a non-UTF-8
/// environment variable cannot panic the process.
///
/// [`detect-coding-agent`]: https://crates.io/crates/detect-coding-agent
pub(crate) fn running_as_agent() -> bool {
    std::env::var_os(AGENT_OPT_IN_ENV).is_some_and(|v| !v.is_empty())
        || detect_coding_agent::detect_with_env(utf8_env())
            .is_some_and(|a| a.is_agent() || a.is_hybrid())
}

/// Pure policy decision: does `mode` require a reason given whether the caller is
/// an agent? Kept separate from [`running_as_agent`] so it is deterministically testable.
fn policy_requires_reason(mode: RequireReason, is_agent: bool) -> bool {
    match mode {
        RequireReason::Never => false,
        RequireReason::Always => true,
        RequireReason::Agents => is_agent,
    }
}

/// Environment variable holding the session reason for SDK/library callers. This is
/// the counterpart to the CLI `--reason` flag: it lets any caller — including code
/// generated by `secretspec-derive`, which never calls [`Secrets::with_reason`] —
/// satisfy the `require_reason` policy and supply an audit reason without code
/// changes, mirroring how `SECRETSPEC_PROVIDER`/`SECRETSPEC_PROFILE` are honored.
const REASON_ENV: &str = "SECRETSPEC_REASON";

/// Normalizes a session reason: trims surrounding whitespace and treats a blank
/// result as "no reason given". Applied to every reason source so the policy gate
/// and the audit log agree on what counts as a real reason (a blank `--reason ""`
/// or `SECRETSPEC_REASON=` must not satisfy the policy). Kept pure for testability.
///
/// Shared with providers (e.g. Proton Pass) so the gate and the audit reason agree
/// on what counts as a real reason.
pub(crate) fn normalize_reason(reason: &str) -> Option<String> {
    let trimmed = reason.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Resolves the session reason from the `SECRETSPEC_REASON` environment variable,
/// normalized via [`normalize_reason`]. An explicit [`Secrets::with_reason`] takes
/// precedence over this.
fn env_reason() -> Option<String> {
    std::env::var(REASON_ENV)
        .ok()
        .as_deref()
        .and_then(normalize_reason)
}

/// The variable, per-call fields of an audit event. Session-constant fields
/// (project, session reason, whether auditing is enabled) are filled by
/// [`Secrets::record`], so call sites specify only what differs and default the
/// rest with `..Default::default()`.
#[derive(Default)]
struct AuditFields<'a> {
    /// The single secret involved (`get`/`set`); `None` for bulk actions.
    key: Option<&'a str>,
    /// The secrets involved in a bulk action (`check`/`run`/`import`).
    keys: &'a [String],
    /// For `run`, the executed program (argv[0] only).
    command: Option<&'a str>,
    /// Redacted provider URI the access is attributed to.
    provider_uri: Option<String>,
    /// Stable error-variant token when the outcome is an error.
    error_kind: Option<&'a str>,
}

impl Secrets {
    /// Creates a new `Secrets` instance with the given configurations
    ///
    /// # Arguments
    ///
    /// * `config` - The project configuration
    /// * `global_config` - Optional global user configuration
    /// * `provider` - Optional provider to use
    /// * `profile` - Optional profile to use
    ///
    /// # Returns
    ///
    /// A new `Secrets` instance
    #[cfg(test)]
    pub(crate) fn new(
        config: Config,
        global_config: Option<GlobalConfig>,
        provider: Option<String>,
        profile: Option<String>,
    ) -> Self {
        Self {
            config,
            global_config,
            provider,
            profile,
            reason: None,
            require_reason: RequireReason::Never,
            audit: None,
        }
    }

    /// Loads a `Secrets` by walking up from the current directory to find `secretspec.toml`
    ///
    /// This method searches the current directory and all parent directories for
    /// a `secretspec.toml` file, similar to how `cargo` and `git` find their configs.
    ///
    /// # Returns
    ///
    /// A loaded `Secrets` instance
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No `secretspec.toml` file is found in the current or any parent directory
    /// - Configuration files are invalid
    /// - The project revision is unsupported
    ///
    /// # Example
    ///
    /// ```no_run
    /// use secretspec::Secrets;
    ///
    /// let mut spec = Secrets::load().unwrap();
    /// spec.set_provider("keyring");
    /// spec.check(false).unwrap();
    /// ```
    pub fn load() -> Result<Self> {
        let config_path = find_config_file()?;
        Self::load_from(&config_path)
    }

    /// Loads a `Secrets` from an explicit config file path
    ///
    /// Use this when the path to `secretspec.toml` is known, e.g. via the `--file` flag.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the `secretspec.toml` file
    pub fn load_from(path: &Path) -> Result<Self> {
        let project_config = Config::try_from(path)?;
        let global_config = GlobalConfig::load()?;
        // Auditing is a per-machine concern configured in the user-global config
        // (`[audit]` in ~/.config/secretspec/config.toml), not the project. It is
        // on by default when unconfigured.
        let audit = AuditLogger::from_config(
            &global_config
                .as_ref()
                .and_then(|g| g.audit.clone())
                .unwrap_or_default(),
        );
        Ok(Self {
            require_reason: project_config.project.require_reason.unwrap_or_default(),
            config: project_config,
            global_config,
            provider: None,
            profile: None,
            reason: env_reason(),
            audit,
        })
    }

    /// Sets the provider to use for secret operations
    ///
    /// This overrides the provider from global configuration.
    ///
    /// # Arguments
    ///
    /// * `provider` - The provider name or URI (e.g., "keyring", "dotenv:/path/to/.env")
    ///
    /// # Example
    ///
    /// ```no_run
    /// use secretspec::Secrets;
    ///
    /// let mut spec = Secrets::load().unwrap();
    /// spec.set_provider("dotenv:.env.production");
    /// spec.check(false).unwrap();
    /// ```
    pub fn set_provider(&mut self, provider: impl Into<String>) {
        self.provider = Some(provider.into());
    }

    /// Sets the profile to use for secret operations
    ///
    /// This overrides the profile from global configuration.
    ///
    /// # Arguments
    ///
    /// * `profile` - The profile name (e.g., "development", "staging", "production")
    ///
    /// # Example
    ///
    /// ```no_run
    /// use secretspec::Secrets;
    ///
    /// let mut spec = Secrets::load().unwrap();
    /// spec.set_profile("production");
    /// spec.check(false).unwrap();
    /// ```
    pub fn set_profile(&mut self, profile: impl Into<String>) {
        self.profile = Some(profile.into());
    }

    /// Sets a human-readable reason for this session's secret access.
    ///
    /// The reason is forwarded to providers that support audit logging. For
    /// example, the Proton Pass provider passes it to `pass-cli` agent sessions,
    /// which require a reason for every audited item operation; providers that do
    /// not support auditing ignore it.
    ///
    /// Takes precedence over the `SECRETSPEC_REASON` environment variable, which
    /// [`Secrets::load`]/[`Secrets::load_from`] already resolve. A blank or
    /// whitespace-only reason is ignored (it neither satisfies the `require_reason`
    /// policy nor overrides a reason already resolved from the environment).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use secretspec::Secrets;
    ///
    /// let spec = Secrets::load().unwrap().with_reason("deploy web frontend");
    /// spec.check(false).unwrap();
    /// ```
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        if let Some(reason) = normalize_reason(&reason.into()) {
            self.reason = Some(reason);
        }
        self
    }

    /// Enforces the project's `require_reason` policy.
    ///
    /// Depending on `[project].require_reason` in `secretspec.toml` (`"agents"` by
    /// default, or a boolean), secret access may require an explicit reason
    /// (`--reason`, `SECRETSPEC_REASON`, or [`Secrets::with_reason`]). Because this
    /// is enforced by the tool itself, the policy applies uniformly to every
    /// caller — humans, CI, and any AI agent — and none can bypass it. Called at
    /// the start of each public secret-accessing operation.
    fn ensure_reason(&self) -> Result<()> {
        // A supplied reason satisfies every policy, so short-circuit before any agent
        // detection (this also makes the redundant call cheap when check()/get()
        // delegate to validate()).
        if self.reason.is_some() {
            return Ok(());
        }
        // running_as_agent() probes the environment/process; only the Agents policy
        // consults it, so skip that work for the Never/Always policies.
        let is_agent = self.require_reason == RequireReason::Agents && running_as_agent();
        if policy_requires_reason(self.require_reason, is_agent) {
            return Err(SecretSpecError::ReasonRequired);
        }
        Ok(())
    }

    /// Builds a provider from a spec (name or URI) and applies the session reason.
    ///
    /// All provider construction in this module goes through here so that the
    /// reason set via [`Secrets::with_reason`] reaches every provider instance.
    fn build_provider(&self, spec: String) -> Result<Box<dyn ProviderTrait>> {
        let provider = Box::<dyn ProviderTrait>::try_from(spec)?;
        provider.set_reason(self.reason.clone());
        Ok(provider)
    }

    /// Records one audit event with the given variable fields, if auditing is
    /// enabled (a no-op otherwise). Session-constant fields — project, the session
    /// reason, and whether auditing is on — are filled here so call sites specify
    /// only what varies. Single-secret (`get`/`set`) and bulk
    /// (`check`/`run`/`import`) events go through this one method.
    fn record(
        &self,
        action: AuditAction,
        profile: &str,
        outcome: AuditOutcome,
        fields: AuditFields<'_>,
    ) {
        if let Some(logger) = &self.audit {
            logger.record(
                action,
                AuditContext {
                    project: &self.config.project.name,
                    profile,
                    key: fields.key,
                    keys: fields.keys,
                    command: fields.command,
                    provider_uri: fields.provider_uri,
                    outcome,
                    error_kind: fields.error_kind,
                    reason: self.reason.as_deref(),
                },
            );
        }
    }

    /// Audits the result of a single secret write (`set`/generate/prompt): a
    /// `Written` event on success, an `Error` event (tagged with the error kind)
    /// on failure. Centralizes the write-audit so every write path records the
    /// same way and a new one cannot accidentally diverge or skip auditing.
    fn audit_write_result(
        &self,
        result: &Result<()>,
        key: &str,
        profile: &str,
        provider_uri: Option<String>,
    ) {
        let (outcome, error_kind) = match result {
            Ok(()) => (AuditOutcome::Written, None),
            Err(e) => (AuditOutcome::Error, Some(e.kind())),
        };
        self.record(
            AuditAction::Set,
            profile,
            outcome,
            AuditFields {
                key: Some(key),
                provider_uri,
                error_kind,
                ..Default::default()
            },
        );
    }

    /// Enforces the `require_reason` policy and, when it denies access, records the
    /// blocked attempt as an `Error` event before returning, so a policy denial
    /// still leaves an audit trace. `action`/`key` describe the attempted
    /// operation. Used at every public secret-accessing entry point.
    fn ensure_reason_for(&self, action: AuditAction, key: Option<&str>) -> Result<()> {
        if let Err(e) = self.ensure_reason() {
            let profile = self.resolve_profile_name(None);
            self.record(
                action,
                &profile,
                AuditOutcome::Error,
                AuditFields {
                    key,
                    error_kind: Some(e.kind()),
                    ..Default::default()
                },
            );
            return Err(e);
        }
        Ok(())
    }

    /// Inserts a resolved secret into the working set, transparently materializing
    /// an `as_path` secret to an owner-only temp file whose lifetime is tied to
    /// `temp_files`. Shared by every resolution branch so the temp-file handling
    /// cannot drift between them.
    fn insert_resolved(
        &self,
        secrets: &mut HashMap<String, SecretString>,
        temp_files: &mut Vec<tempfile::NamedTempFile>,
        name: String,
        value: SecretString,
        as_path: bool,
    ) -> Result<()> {
        if as_path {
            let (temp_file, path_str) = self.write_secret_to_temp_file(&value)?;
            temp_files.push(temp_file);
            secrets.insert(name, SecretString::new(path_str.into()));
        } else {
            secrets.insert(name, value);
        }
        Ok(())
    }

    /// Get a reference to the project configuration. Used by `secretspec
    /// codegen` (which needs the manifest, not a provider) and by tests.
    pub(crate) fn config(&self) -> &Config {
        &self.config
    }

    /// Get a reference to the global configuration (for testing)
    #[cfg(test)]
    pub(crate) fn global_config(&self) -> &Option<GlobalConfig> {
        &self.global_config
    }

    /// Attach an audit logger (for testing which events an operation emits).
    #[cfg(test)]
    pub(crate) fn set_audit_for_test(&mut self, logger: crate::audit::AuditLogger) {
        self.audit = Some(logger);
    }

    /// Override the `require_reason` policy (for testing the gate without going
    /// through `load`/`load_from`, which would build a real audit logger and write
    /// to the user's real audit log).
    #[cfg(test)]
    pub(crate) fn set_require_reason(&mut self, policy: RequireReason) {
        self.require_reason = policy;
    }

    /// Resolves the profile to use based on the provided value and configuration
    ///
    /// Profile resolution order:
    /// 1. Provided profile argument
    /// 2. Profile set via set_profile()
    /// 3. SECRETSPEC_PROFILE environment variable
    /// 4. Global configuration default profile
    /// 5. "default" profile
    ///
    /// # Arguments
    ///
    /// * `profile` - Optional profile name to use
    ///
    /// # Returns
    ///
    /// The resolved profile name
    pub(crate) fn resolve_profile_name(&self, profile: Option<&str>) -> String {
        profile
            .map(|p| p.to_string())
            .or_else(|| self.profile.clone())
            .or_else(|| env::var("SECRETSPEC_PROFILE").ok())
            .or_else(|| {
                self.global_config
                    .as_ref()
                    .and_then(|gc| gc.defaults.profile.clone())
            })
            .unwrap_or_else(|| "default".to_string())
    }

    /// Returns the named profile or an `InvalidProfile` error listing the profiles
    /// defined in `secretspec.toml`.
    fn require_profile(&self, profile_name: &str) -> Result<&Profile> {
        self.config.profiles.get(profile_name).ok_or_else(|| {
            let mut available: Vec<&str> =
                self.config.profiles.keys().map(String::as_str).collect();
            available.sort();
            SecretSpecError::InvalidProfile(format!(
                "'{}' is not defined in secretspec.toml. Available profiles: {}",
                profile_name,
                available.join(", ")
            ))
        })
    }

    /// Resolves the full profile configuration, merging with default profile if needed
    ///
    /// # Arguments
    ///
    /// * `profile` - Optional profile name to resolve (if None, uses resolved profile name)
    ///
    /// # Returns
    ///
    /// The resolved profile configuration
    pub(crate) fn resolve_profile(&self, profile: Option<&str>) -> Result<Profile> {
        let profile_name = profile
            .map(str::to_string)
            .unwrap_or_else(|| self.resolve_profile_name(None));
        let mut profile_config = self.require_profile(&profile_name)?.clone();

        // If not the default profile, also add secrets from default profile
        if profile_name != "default"
            && let Some(default_profile) = self.config.profiles.get("default").cloned()
        {
            profile_config.merge_with(default_profile);
        }

        Ok(profile_config)
    }

    /// Resolves the configuration for a specific secret
    ///
    /// This method looks for the secret in the specified profile, falling back
    /// to the default profile if not found. If the secret exists in both profiles,
    /// fields are merged with the current profile taking precedence.
    /// Profile defaults are also applied with lower precedence than explicit secret config.
    ///
    /// Precedence order (highest to lowest):
    /// 1. Secret config in current profile
    /// 2. Secret config in default profile
    /// 3. Profile defaults from current profile
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the secret
    /// * `profile` - Optional profile to search in (if None, uses resolved profile)
    ///
    /// # Returns
    ///
    /// The secret configuration if found (may be merged from multiple profiles)
    pub(crate) fn resolve_secret_config(
        &self,
        name: &str,
        profile: Option<&str>,
    ) -> Option<crate::config::Secret> {
        let profile_name = self.resolve_profile_name(profile);

        let current_profile = self.config.profiles.get(&profile_name);
        let current_secret =
            current_profile.and_then(|profile_config| profile_config.secrets.get(name));
        let current_defaults =
            current_profile.and_then(|profile_config| profile_config.defaults.as_ref());

        let default_secret = if profile_name != "default" {
            self.config
                .profiles
                .get("default")
                .and_then(|default_profile| default_profile.secrets.get(name))
        } else {
            None
        };

        match (current_secret, default_secret) {
            (Some(current), Some(default)) => {
                // Merge: current profile takes precedence, then default profile, then profile defaults
                Some(crate::config::Secret {
                    description: current
                        .description
                        .clone()
                        .or_else(|| default.description.clone()),
                    required: current
                        .required
                        .or(default.required)
                        .or(current_defaults.and_then(|d| d.required)),
                    default: current
                        .default
                        .clone()
                        .or_else(|| default.default.clone())
                        .or_else(|| current_defaults.and_then(|d| d.default.clone())),
                    providers: current
                        .providers
                        .clone()
                        .or_else(|| default.providers.clone())
                        .or_else(|| current_defaults.and_then(|d| d.providers.clone())),
                    as_path: current.as_path.or(default.as_path),
                    secret_type: current
                        .secret_type
                        .clone()
                        .or_else(|| default.secret_type.clone()),
                    generate: current
                        .generate
                        .clone()
                        .or_else(|| default.generate.clone()),
                })
            }
            (Some(secret), None) | (None, Some(secret)) => {
                // Apply profile defaults to the found secret
                Some(crate::config::Secret {
                    description: secret.description.clone(),
                    required: secret
                        .required
                        .or(current_defaults.and_then(|d| d.required)),
                    default: secret
                        .default
                        .clone()
                        .or_else(|| current_defaults.and_then(|d| d.default.clone())),
                    providers: secret
                        .providers
                        .clone()
                        .or_else(|| current_defaults.and_then(|d| d.providers.clone())),
                    as_path: secret.as_path,
                    secret_type: secret.secret_type.clone(),
                    generate: secret.generate.clone(),
                })
            }
            (None, None) => None,
        }
    }

    /// Provider-alias maps in lookup order: project `secretspec.toml` first,
    /// then user-global config. Project entries win on conflict so teams can
    /// pin shareable mappings in version control while still allowing per-user
    /// overrides via the global config.
    fn provider_alias_sources(&self) -> impl Iterator<Item = &HashMap<String, String>> {
        self.config.providers.iter().chain(
            self.global_config
                .as_ref()
                .and_then(|gc| gc.defaults.providers.as_ref()),
        )
    }

    /// Resolves a single provider alias to its URI, walking
    /// [`Self::provider_alias_sources`] in order.
    fn lookup_provider_alias(&self, alias: &str) -> Option<String> {
        self.provider_alias_sources()
            .find_map(|m| m.get(alias))
            .cloned()
    }

    /// Returns the union of alias names known across all sources, sorted.
    fn known_provider_aliases(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .provider_alias_sources()
            .flat_map(|m| m.keys().cloned())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        names.sort();
        names
    }

    /// Resolves a list of provider aliases to their URIs, preserving order.
    /// Used for fallback chain resolution; each alias is looked up via
    /// [`Self::lookup_provider_alias`].
    ///
    /// # Errors
    ///
    /// Returns an error if any alias is not defined in either the project or global config.
    pub(crate) fn resolve_provider_aliases(
        &self,
        provider_aliases: Option<&[String]>,
    ) -> Result<Option<Vec<String>>> {
        let Some(aliases) = provider_aliases else {
            return Ok(None);
        };

        let mut uris = Vec::with_capacity(aliases.len());
        for alias in aliases {
            match self.lookup_provider_alias(alias) {
                Some(uri) => uris.push(uri),
                None => {
                    let known = self.known_provider_aliases();
                    let msg = if known.is_empty() {
                        format!(
                            "Provider alias '{}' is not defined. Declare it in [providers] in secretspec.toml or in the global config.",
                            alias
                        )
                    } else {
                        format!(
                            "Provider alias '{}' is not defined. Available aliases: {}",
                            alias,
                            known.join(", ")
                        )
                    };
                    return Err(SecretSpecError::ProviderNotFound(msg));
                }
            }
        }
        Ok(Some(uris))
    }

    /// Returns the explicit provider spec from caller arg, builder, or env, in
    /// that priority order.
    ///
    /// Used as the shared head of provider resolution so the precedence between
    /// the `--provider` flag (forwarded via `set_provider`) and the
    /// `SECRETSPEC_PROVIDER` env var stays consistent across resolvers.
    fn explicit_provider_spec(&self, override_arg: Option<String>) -> Option<String> {
        override_arg
            .or_else(|| self.provider.clone())
            .or_else(|| env::var("SECRETSPEC_PROVIDER").ok())
    }

    /// Returns the explicit provider override resolved to a URI, if one is set.
    ///
    /// Resolves the explicit spec via [`Self::explicit_provider_spec`], then
    /// expands any matching alias via [`Self::lookup_provider_alias`].
    pub(crate) fn resolve_provider_override(&self, override_arg: Option<&str>) -> Option<String> {
        let spec = self.explicit_provider_spec(override_arg.map(|s| s.to_string()))?;
        Some(self.lookup_provider_alias(&spec).unwrap_or(spec))
    }

    /// Resolves the write target for a secret.
    ///
    /// Resolution order:
    /// 1. Explicit override (`--provider` flag, `SECRETSPEC_PROVIDER`, or builder)
    /// 2. First entry of the secret's `providers` chain
    /// 3. Default provider from global config
    pub(crate) fn resolve_write_provider(
        &self,
        secret_config: &crate::config::Secret,
        override_arg: Option<&str>,
    ) -> Result<Box<dyn ProviderTrait>> {
        if let Some(uri) = self.resolve_provider_override(override_arg) {
            return self.build_provider(uri);
        }
        if let Some(alias) = secret_config.providers.as_ref().and_then(|p| p.first()) {
            let provider_uris = self.resolve_provider_aliases(Some(std::slice::from_ref(alias)))?;
            let uri = provider_uris
                .and_then(|uris| uris.into_iter().next())
                .ok_or_else(|| {
                    SecretSpecError::ProviderNotFound(format!(
                        "Provider alias '{}' could not be resolved",
                        alias
                    ))
                })?;
            return self.build_provider(uri);
        }
        self.get_provider(None)
    }

    /// Resolves the read provider chain for a secret.
    ///
    /// If an explicit override is set, returns just that single URI (no chain fallback).
    /// Otherwise, resolves the secret's `providers` chain to URIs, or returns `None`
    /// to indicate the default provider should be used.
    pub(crate) fn resolve_read_provider_uris(
        &self,
        secret_config: &crate::config::Secret,
        override_arg: Option<&str>,
    ) -> Result<Option<Vec<String>>> {
        if let Some(uri) = self.resolve_provider_override(override_arg) {
            return Ok(Some(vec![uri]));
        }
        self.resolve_provider_aliases(secret_config.providers.as_deref())
    }

    /// Gets the provider instance to use for secret operations
    ///
    /// Provider resolution order:
    /// 1. Provided provider argument
    /// 2. Provider set via builder (used by the CLI to forward `--provider`)
    /// 3. Environment variable (SECRETSPEC_PROVIDER)
    /// 4. Global configuration default provider
    /// 5. Error if no provider is configured
    ///
    /// # Arguments
    ///
    /// * `provider_arg` - Optional provider specification (name or URI)
    ///
    /// # Returns
    ///
    /// A boxed provider instance
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No provider is configured
    /// - The specified provider is not found
    pub(crate) fn get_provider(
        &self,
        provider_arg: Option<String>,
    ) -> Result<Box<dyn ProviderTrait>> {
        let provider_spec = self
            .explicit_provider_spec(provider_arg)
            .or_else(|| {
                self.global_config
                    .as_ref()
                    .and_then(|gc| gc.defaults.provider.clone())
            })
            .map(|spec| self.lookup_provider_alias(&spec).unwrap_or(spec))
            .ok_or(SecretSpecError::NoProviderConfigured)?;

        let provider = self.build_provider(provider_spec)?;

        Ok(provider)
    }

    /// Returns a provider URI for validation result metadata without forcing a
    /// user-global default when every secret used an explicit or per-secret provider.
    fn validation_report_provider_uri(
        &self,
        override_uri: Option<&str>,
        secret_primary_uris: &HashMap<String, Option<String>>,
    ) -> Result<String> {
        if let Some(uri) = override_uri {
            return Ok(uri.to_string());
        }

        if secret_primary_uris.values().any(Option::is_none) {
            return self.get_provider(None).map(|provider| provider.uri());
        }

        let mut provider_uris: Vec<&String> = secret_primary_uris
            .values()
            .filter_map(Option::as_ref)
            .collect();
        provider_uris.sort();

        if let Some(uri) = provider_uris.first() {
            return Ok((*uri).clone());
        }

        self.get_provider(None).map(|provider| provider.uri())
    }

    /// Gets a secret from a list of providers with fallback.
    ///
    /// Tries each provider in order until one has the secret. Errors from a
    /// provider (e.g. authentication failure, network error) are treated like
    /// "not found" so the chain continues; a warning is emitted and the next
    /// provider is tried. If every provider errored without any reporting a
    /// healthy "not found", the last error is returned so the user sees why
    /// the secret could not be retrieved.
    ///
    /// If no provider URIs are specified, falls back to the global provider.
    ///
    /// # Arguments
    ///
    /// * `project_name` - The project name
    /// * `secret_name` - The secret name
    /// * `profile_name` - The profile name
    /// * `provider_uris` - Optional list of provider URIs to try in order
    /// * `default_provider_arg` - Optional default provider if no URIs provided
    ///
    /// # Returns
    ///
    /// A tuple of the secret value (or `None` if not found in any provider) and
    /// the URI of the provider to attribute the access to: on a hit, the serving
    /// provider; on a chain miss/error, the last provider tried. The URI lets
    /// callers (e.g. the audit log) record which provider actually answered.
    fn get_secret_from_providers(
        &self,
        project_name: &str,
        secret_name: &str,
        profile_name: &str,
        provider_uris: Option<&[String]>,
        default_provider_arg: Option<String>,
    ) -> Result<(Option<SecretString>, Option<String>)> {
        // If provider URIs are specified, try them in order
        if let Some(uris) = provider_uris {
            let mut last_error: Option<SecretSpecError> = None;
            let mut any_healthy = false;
            let mut last_uri: Option<String> = None;
            for uri in uris {
                let provider = match self.build_provider(uri.clone()) {
                    Ok(p) => p,
                    Err(e) => {
                        // Construction failed, so only the raw alias exists; redact it.
                        warn_provider_failure(
                            &crate::audit::redact_uri_strict(uri),
                            secret_name,
                            &e,
                        );
                        last_error = Some(e);
                        continue;
                    }
                };
                // Attribute the access to the provider's own redacted `uri()`, never
                // the raw configured alias: a per-secret alias may embed credentials
                // (e.g. `vault+token:s3cr3t@host`) that the provider strips from
                // `uri()` but that `redact_uri` cannot remove from an opaque URI.
                let provider_uri = provider.uri();
                last_uri = Some(provider_uri.clone());
                match provider.get(project_name, secret_name, profile_name) {
                    Ok(Some(value)) => return Ok((Some(value), Some(provider_uri))),
                    Ok(None) => {
                        any_healthy = true;
                        continue;
                    }
                    Err(e) => {
                        // A provider was built, so attribute the warning to its own
                        // credential-free `uri()` rather than the raw alias.
                        warn_provider_failure(&provider_uri, secret_name, &e);
                        last_error = Some(e);
                        continue;
                    }
                }
            }
            // Surface the last error only if no provider in the chain returned
            // a healthy "not found" — otherwise the secret is genuinely missing.
            match last_error {
                Some(e) if !any_healthy => Err(e),
                _ => Ok((None, last_uri)),
            }
        } else {
            // No per-secret providers, use default provider
            let backend = self.get_provider(default_provider_arg)?;
            let uri = backend.uri();
            backend
                .get(project_name, secret_name, profile_name)
                .map(|opt| (opt, Some(uri)))
        }
    }

    /// Sets a secret value in the provider
    ///
    /// If no value is provided, the user will be prompted to enter it securely.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the secret to set
    /// * `value` - Optional value to set (prompts if None)
    /// * `provider_arg` - Optional provider to use
    /// * `profile` - Optional profile to use
    ///
    /// # Returns
    ///
    /// `Ok(())` if the secret was successfully set
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The secret is not defined in the specification
    /// - The provider doesn't support setting values
    /// - The storage operation fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use secretspec::Secrets;
    ///
    /// let mut spec = Secrets::load().unwrap();
    /// spec.set("DATABASE_URL", Some("postgres://localhost".to_string())).unwrap();
    /// ```
    pub fn set(&self, name: &str, value: Option<String>) -> Result<()> {
        self.ensure_reason_for(AuditAction::Set, Some(name))?;
        // Check if the secret exists in the spec
        let profile_name = self.resolve_profile_name(None);
        self.require_profile(&profile_name)?;

        // Check if the secret exists in the profile or is inherited from default
        let secret_config = match self.resolve_secret_config(name, None) {
            Some(sc) => sc,
            None => {
                let profile = self.resolve_profile(Some(&profile_name))?;
                let mut available_secrets = profile
                    .into_iter()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>();
                available_secrets.sort();

                let err = SecretSpecError::SecretNotFound(format!(
                    "Secret '{}' is not defined in profile '{}'. Available secrets: {}",
                    name,
                    profile_name,
                    available_secrets.join(", ")
                ));
                // Provider is unknown for an undefined secret, so attribute to None.
                self.record(
                    AuditAction::Set,
                    &profile_name,
                    AuditOutcome::Error,
                    AuditFields {
                        key: Some(name),
                        error_kind: Some(err.kind()),
                        ..Default::default()
                    },
                );
                return Err(err);
            }
        };

        let backend = self.resolve_write_provider(&secret_config, None)?;

        if !backend.allows_set() {
            let err = SecretSpecError::ProviderOperationFailed(format!(
                "Provider '{}' is read-only and does not support setting values",
                backend.name()
            ));
            self.record(
                AuditAction::Set,
                &profile_name,
                AuditOutcome::Error,
                AuditFields {
                    key: Some(name),
                    provider_uri: Some(backend.uri()),
                    error_kind: Some(err.kind()),
                    ..Default::default()
                },
            );
            return Err(err);
        }

        let value = if let Some(v) = value {
            SecretString::new(v.into())
        } else if io::stdin().is_terminal() {
            let secret = inquire::Password::new(&format!(
                "Enter value for {name} (profile: {profile_name}):"
            ))
            .without_confirmation()
            .prompt()?;
            SecretString::new(secret.into())
        } else {
            // Read from stdin when input is piped
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;
            SecretString::new(buffer.trim().to_string().into())
        };

        if value.expose_secret().is_empty() {
            let err = SecretSpecError::ProviderOperationFailed(
                "Secret value cannot be empty".to_string(),
            );
            self.record(
                AuditAction::Set,
                &profile_name,
                AuditOutcome::Error,
                AuditFields {
                    key: Some(name),
                    provider_uri: Some(backend.uri()),
                    error_kind: Some(err.kind()),
                    ..Default::default()
                },
            );
            return Err(err);
        }

        let result = backend.set(&self.config.project.name, name, &value, &profile_name);
        self.audit_write_result(&result, name, &profile_name, Some(backend.uri()));
        result?;

        eprintln!(
            "{} Secret '{}' saved to {} (profile: {})",
            "✓".green(),
            name,
            backend.name(),
            profile_name
        );

        Ok(())
    }

    /// Retrieves and prints a secret value
    ///
    /// This method retrieves a secret from the storage backend and prints it
    /// to stdout. If the secret is not found but has a default value, the
    /// default is printed.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the secret to retrieve
    /// * `provider_arg` - Optional provider to use
    /// * `profile` - Optional profile to use
    ///
    /// # Returns
    ///
    /// `Ok(())` if the secret was found and printed
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The secret is not defined in the specification
    /// - The secret is not found and has no default value
    pub fn get(&self, name: &str) -> Result<()> {
        self.ensure_reason_for(AuditAction::Get, Some(name))?;
        let profile_name = self.resolve_profile_name(None);
        let secret_config = match self.resolve_secret_config(name, None) {
            Some(config) => config,
            None => {
                // The secret is not defined, so no provider can be attributed.
                // Audit the failed read for parity with `set`'s undefined path.
                let err = SecretSpecError::SecretNotFound(name.to_string());
                self.record(
                    AuditAction::Get,
                    &profile_name,
                    AuditOutcome::Error,
                    AuditFields {
                        key: Some(name),
                        error_kind: Some(err.kind()),
                        ..Default::default()
                    },
                );
                return Err(err);
            }
        };
        let default = secret_config.default.clone();
        let as_path = secret_config.as_path.unwrap_or(false);

        let provider_uris = self.resolve_read_provider_uris(&secret_config, None)?;

        let result = self.get_secret_from_providers(
            &self.config.project.name,
            name,
            &profile_name,
            provider_uris.as_deref(),
            None,
        );

        // Audit the access at the provider boundary, before defaults are applied.
        // The provider URI consulted is reported back so the chain miss/error
        // attributes to the last provider tried rather than guessing.
        match &result {
            Ok((Some(_), uri)) => self.record(
                AuditAction::Get,
                &profile_name,
                AuditOutcome::Found,
                AuditFields {
                    key: Some(name),
                    provider_uri: uri.clone(),
                    ..Default::default()
                },
            ),
            Ok((None, uri)) if default.is_some() => self.record(
                AuditAction::Get,
                &profile_name,
                AuditOutcome::Default,
                AuditFields {
                    key: Some(name),
                    provider_uri: uri.clone(),
                    ..Default::default()
                },
            ),
            Ok((None, uri)) => self.record(
                AuditAction::Get,
                &profile_name,
                AuditOutcome::Missing,
                AuditFields {
                    key: Some(name),
                    provider_uri: uri.clone(),
                    ..Default::default()
                },
            ),
            Err(e) => self.record(
                AuditAction::Get,
                &profile_name,
                AuditOutcome::Error,
                AuditFields {
                    key: Some(name),
                    error_kind: Some(e.kind()),
                    ..Default::default()
                },
            ),
        }

        match result?.0 {
            Some(value) => {
                if as_path {
                    // Write to temp file and persist it (don't auto-delete)
                    let (temp_file, _path_str) = self.write_secret_to_temp_file(&value)?;
                    let temp_path = temp_file.into_temp_path();
                    let persisted_path = temp_path.keep().map_err(|e| {
                        SecretSpecError::Io(io::Error::other(format!(
                            "Failed to persist temporary file: {}",
                            e
                        )))
                    })?;
                    println!("{}", persisted_path.display());
                } else {
                    // Use expose_secret() to access the actual value for printing
                    println!("{}", value.expose_secret());
                }
                Ok(())
            }
            None => {
                if let Some(default_value) = default {
                    if as_path {
                        // Write default value to temp file and persist it
                        let (temp_file, _) = self
                            .write_secret_to_temp_file(&SecretString::new(default_value.into()))?;
                        let temp_path = temp_file.into_temp_path();
                        let persisted_path = temp_path.keep().map_err(|e| {
                            SecretSpecError::Io(io::Error::other(format!(
                                "Failed to persist temporary file: {}",
                                e
                            )))
                        })?;
                        println!("{}", persisted_path.display());
                    } else {
                        println!("{}", default_value);
                    }
                    Ok(())
                } else {
                    Err(SecretSpecError::SecretNotFound(name.to_string()))
                }
            }
        }
    }

    /// Ensures all required secrets are present, optionally prompting for missing ones
    ///
    /// This method validates all secrets and, in interactive mode, prompts the
    /// user to provide values for any missing required secrets.
    ///
    /// # Arguments
    ///
    /// * `provider_arg` - Optional provider to use
    /// * `profile` - Optional profile to use
    /// * `interactive` - Whether to prompt for missing secrets
    ///
    /// # Returns
    ///
    /// A `ValidatedSecrets` with the final state of all secrets
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Required secrets are missing and interactive mode is disabled
    /// - Storage operations fail
    pub fn ensure_secrets(
        &self,
        provider_arg: Option<String>,
        profile: Option<String>,
        interactive: bool,
    ) -> Result<ValidatedSecrets> {
        let profile_display = self.resolve_profile_name(profile.as_deref());

        // First validate to see what's missing. Use the non-auditing variant:
        // the caller that owns this operation (`check`, `run`) records its own
        // audit event, so re-validating here must not emit another `Check`.
        let validation_result = self.validate_audited(false)?;

        match validation_result {
            Ok(valid_secrets) => Ok(valid_secrets),
            Err(validation_errors) => {
                // If we're in interactive mode and have missing required secrets, prompt for them
                if interactive && !validation_errors.missing_required.is_empty() {
                    if !io::stdin().is_terminal() {
                        return Err(SecretSpecError::RequiredSecretMissing(
                            validation_errors.missing_required.join(", "),
                        ));
                    }

                    let missing = &validation_errors.missing_required;
                    let total = missing.len();
                    let default_backend = self.get_provider(provider_arg.clone())?;

                    // List all missing secrets upfront
                    eprintln!(
                        "\n{} required {} missing in profile {} with provider {}:\n",
                        total,
                        if total == 1 {
                            "secret is"
                        } else {
                            "secrets are"
                        },
                        profile_display.bold(),
                        default_backend.name().bold(),
                    );
                    for secret_name in missing {
                        let description = self
                            .resolve_secret_config(secret_name, Some(&profile_display))
                            .and_then(|c| c.description)
                            .unwrap_or_default();
                        if description.is_empty() {
                            eprintln!("  {} {}", "-".dimmed(), secret_name.bold());
                        } else {
                            eprintln!(
                                "  {} {} - {}",
                                "-".dimmed(),
                                secret_name.bold(),
                                description
                            );
                        }
                    }
                    eprintln!();

                    // Prompt for each missing secret
                    for (i, secret_name) in missing.iter().enumerate() {
                        if let Some(secret_config) =
                            self.resolve_secret_config(secret_name, Some(&profile_display))
                        {
                            let prompt_msg =
                                format!("[{}/{}] Enter value for {}:", i + 1, total, secret_name,);
                            let prompt = inquire::Password::new(&prompt_msg).without_confirmation();

                            let value = prompt.prompt()?;

                            let backend = self
                                .resolve_write_provider(&secret_config, provider_arg.as_deref())?;
                            let set_result = backend.set(
                                &self.config.project.name,
                                secret_name,
                                &SecretString::new(value.into()),
                                &profile_display,
                            );
                            self.audit_write_result(
                                &set_result,
                                secret_name,
                                &profile_display,
                                Some(backend.uri()),
                            );
                            set_result?;
                            eprintln!(
                                "{} Secret '{}' saved to {} (profile: {})",
                                "✓".green(),
                                secret_name,
                                backend.name(),
                                profile_display
                            );
                        }
                    }

                    eprintln!("\nAll required secrets have been set.");

                    // Re-validate to get the updated results
                    // Re-validate after prompting; still part of the same
                    // operation, so do not emit another `Check` event.
                    match self.validate_audited(false)? {
                        Ok(valid_secrets) => Ok(valid_secrets),
                        Err(still_errors) => Err(SecretSpecError::RequiredSecretMissing(
                            still_errors.missing_required.join(", "),
                        )),
                    }
                } else {
                    // Not interactive or no missing required secrets
                    Err(SecretSpecError::RequiredSecretMissing(
                        validation_errors.missing_required.join(", "),
                    ))
                }
            }
        }
    }

    /// Checks the status of all secrets and optionally prompts for missing required ones
    ///
    /// This method displays the status of all secrets defined in the specification,
    /// showing which are present, missing, or using defaults. Unless `no_prompt` is set,
    /// it then prompts the user to provide values for any missing required secrets.
    ///
    /// # Arguments
    ///
    /// * `no_prompt` - If true, don't prompt for missing secrets and return an error instead
    ///
    /// # Returns
    ///
    /// A `ValidatedSecrets` if all required secrets are present
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The provider cannot be initialized
    /// - Storage operations fail
    /// - Required secrets are missing (when `no_prompt` is true)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use secretspec::Secrets;
    ///
    /// let mut spec = Secrets::load().unwrap();
    /// let validated = spec.check(false).unwrap();
    /// ```
    pub fn check(&self, no_prompt: bool) -> Result<ValidatedSecrets> {
        self.ensure_reason_for(AuditAction::Check, None)?;
        let profile_display = self.resolve_profile_name(None);

        eprintln!(
            "Checking secrets in {} (profile: {})...\n",
            self.config.project.name.bold(),
            profile_display.cyan()
        );

        // Validate and display results
        // The read is audited inside `validate()`, so no bulk event here.
        match self.validate()? {
            Ok(valid) => {
                self.display_validation_success(&valid)?;
                // All secrets present - return early without re-validating
                Ok(valid)
            }
            Err(errors) => {
                self.display_validation_errors(&errors)?;
                // Missing secrets - prompt if interactive (and not no_prompt) and re-validate
                self.ensure_secrets(None, None, !no_prompt)
            }
        }
    }

    /// Display validation success results
    fn display_validation_success(&self, valid: &ValidatedSecrets) -> Result<()> {
        let profile = self.resolve_profile(Some(&valid.resolved.profile))?;
        let mut found_count = 0;
        let mut optional_count = 0;
        let default_names = valid
            .with_defaults
            .iter()
            .map(|(name, _)| name)
            .collect::<HashSet<_>>();
        let missing_optional: HashSet<&String> = valid.missing_optional.iter().collect();

        for (name, config) in profile.iter() {
            if missing_optional.contains(&name) {
                optional_count += 1;
                eprintln!(
                    "{} {} - {} {}",
                    "○".blue(),
                    name,
                    config.description.as_deref().unwrap_or("No description"),
                    "(optional)".blue()
                );
            } else if config.default.is_some() && default_names.contains(&name) {
                found_count += 1;
                eprintln!(
                    "{} {} - {} {}",
                    "○".yellow(),
                    name,
                    config.description.as_deref().unwrap_or("No description"),
                    "(has default)".yellow()
                );
            } else {
                found_count += 1;
                eprintln!(
                    "{} {} - {}",
                    "✓".green(),
                    name,
                    config.description.as_deref().unwrap_or("No description")
                );
            }
        }

        eprintln!("\n{}", Self::format_summary(found_count, 0, optional_count));

        Ok(())
    }

    /// Display validation error results
    fn display_validation_errors(&self, errors: &ValidationErrors) -> Result<()> {
        let profile = self.resolve_profile(Some(&errors.profile))?;
        let mut found_count = 0;
        let mut missing_count = 0;
        let mut optional_count = 0;
        let default_names = errors
            .with_defaults
            .iter()
            .map(|(name, _)| name)
            .collect::<HashSet<_>>();

        for (name, config) in &profile {
            if errors.missing_required.contains(name) {
                missing_count += 1;
                eprintln!(
                    "{} {} - {} {}",
                    "✗".red(),
                    name,
                    config.description.as_deref().unwrap_or("No description"),
                    "(required)".red()
                );
            } else if errors.missing_optional.contains(name) {
                optional_count += 1;
                eprintln!(
                    "{} {} - {} {}",
                    "○".blue(),
                    name,
                    config.description.as_deref().unwrap_or("No description"),
                    "(optional)".blue()
                );
            } else {
                found_count += 1;
                if default_names.contains(name) {
                    eprintln!(
                        "{} {} - {} {}",
                        "○".yellow(),
                        name,
                        config.description.as_deref().unwrap_or("No description"),
                        "(has default)".yellow()
                    );
                } else {
                    eprintln!(
                        "{} {} - {}",
                        "✓".green(),
                        name,
                        config.description.as_deref().unwrap_or("No description")
                    );
                }
            }
        }

        eprintln!(
            "\n{}",
            Self::format_summary(found_count, missing_count, optional_count)
        );

        Ok(())
    }

    /// Build the trailing "Summary: X found, Y missing[, Z optional]" line.
    /// The `optional` segment is appended only when at least one optional
    /// secret is unset, so the all-set output keeps its previous two-segment
    /// form.
    pub(crate) fn format_summary(found: usize, missing: usize, optional: usize) -> String {
        if optional > 0 {
            format!(
                "Summary: {} found, {} missing, {} optional",
                found.to_string().green(),
                missing.to_string().red(),
                optional.to_string().blue()
            )
        } else {
            format!(
                "Summary: {} found, {} missing",
                found.to_string().green(),
                missing.to_string().red()
            )
        }
    }

    /// Imports secrets from one provider to another
    ///
    /// This method copies all secrets defined in the specification from the
    /// source provider to the default provider configured in the global settings.
    ///
    /// # Arguments
    ///
    /// * `from_provider` - The provider specification to import from
    ///
    /// # Returns
    ///
    /// `Ok(())` if the import completes (even if some secrets were not found)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The source provider cannot be initialized
    /// - The target provider cannot be initialized
    /// - Storage operations fail
    ///
    /// # Example
    ///
    /// ```no_run
    /// use secretspec::Secrets;
    ///
    /// let spec = Secrets::load().unwrap();
    /// spec.import("dotenv://.env.production").unwrap();
    /// ```
    pub fn import(&self, from_provider: &str) -> Result<()> {
        self.ensure_reason_for(AuditAction::Import, None)?;
        // Resolve profile (checks env var, then global config, then defaults to "default")
        let profile_display = self.resolve_profile_name(None);

        let mut imported = 0;
        let mut already_exists = 0;
        let mut not_found = 0;
        // Every secret the import reads from the source/target, in iteration
        // order. An import is one bulk action over this whole set, so it is the
        // `keys` recorded in the audit log — independent of how many were copied,
        // so a no-op import (nothing to copy) is still recorded as a read.
        let mut read_names: Vec<String> = Vec::new();

        // Run the copy in an inner closure so that any early error (provider
        // build, profile resolution, a per-secret get/set) can be audited with
        // the secrets read so far before the error propagates. `source_uri`
        // is filled in once the source provider is built.
        let mut source_uri: Option<String> = None;
        let copy_result = (|| -> Result<()> {
            // Create the "from" provider and check availability
            let from_provider_instance = self.build_provider(from_provider.to_string())?;
            source_uri = Some(from_provider_instance.uri());

            eprintln!(
                "Importing secrets from {} (profile: {})...\n",
                from_provider.blue(),
                profile_display.cyan()
            );

            // Collect all secrets to import - from current profile and default profile
            // This ensures we can import secrets defined in default profile when using other profiles
            let profile = self.resolve_profile(Some(&profile_display))?;

            // Process each secret using proper profile resolution
            for (name, config) in profile.into_iter() {
                read_names.push(name.clone());
                let secret_config = self
                    .resolve_secret_config(&name, Some(&profile_display))
                    .expect("Secret should exist since we're iterating over it");

                let to_provider = self.resolve_write_provider(&secret_config, None)?;

                // First check if the secret exists in the "from" provider
                match from_provider_instance.get(
                    &self.config.project.name,
                    &name,
                    &profile_display,
                )? {
                    Some(value) => {
                        // Secret exists in "from" provider, check if it exists in "to" provider
                        match to_provider.get(&self.config.project.name, &name, &profile_display)? {
                            Some(_) => {
                                eprintln!(
                                    "{} {} - {} {} (→ {})",
                                    "○".yellow(),
                                    name,
                                    config.description.as_deref().unwrap_or("No description"),
                                    "(already exists in target)".yellow(),
                                    to_provider.name().blue()
                                );
                                already_exists += 1;
                            }
                            None => {
                                // Secret doesn't exist in "to" provider, import it.
                                let set_result = to_provider.set(
                                    &self.config.project.name,
                                    &name,
                                    &value,
                                    &profile_display,
                                );
                                // Audit each copied secret as a write attributed to the
                                // target provider, so import writes are recorded like
                                // `set`/generate/prompt. The bulk Import event below only
                                // captures the source read, not where secrets were copied.
                                self.audit_write_result(
                                    &set_result,
                                    &name,
                                    &profile_display,
                                    Some(to_provider.uri()),
                                );
                                set_result?;
                                eprintln!(
                                    "{} {} - {} (→ {})",
                                    "✓".green(),
                                    name,
                                    config.description.as_deref().unwrap_or("No description"),
                                    to_provider.name().blue()
                                );
                                imported += 1;
                            }
                        }
                    }
                    None => {
                        // Secret doesn't exist in "from" provider
                        // Check if it exists in the "to" provider
                        match to_provider.get(&self.config.project.name, &name, &profile_display)? {
                            Some(_) => {
                                eprintln!(
                                    "{} {} - {} {} (→ {})",
                                    "○".blue(),
                                    name,
                                    config.description.as_deref().unwrap_or("No description"),
                                    "(already in target, not in source)".blue(),
                                    to_provider.name().blue()
                                );
                                already_exists += 1;
                            }
                            None => {
                                eprintln!(
                                    "{} {} - {} {}",
                                    "✗".red(),
                                    name,
                                    config.description.as_deref().unwrap_or("No description"),
                                    "(not found in source)".red()
                                );
                                not_found += 1;
                            }
                        }
                    }
                }
            }
            Ok(())
        })();

        if let Err(e) = copy_result {
            // Record a failed/partial import with the secrets read before the error.
            read_names.sort();
            self.record(
                AuditAction::Import,
                &profile_display,
                AuditOutcome::Error,
                AuditFields {
                    keys: &read_names,
                    provider_uri: source_uri,
                    error_kind: Some(e.kind()),
                    ..Default::default()
                },
            );
            return Err(e);
        }

        eprintln!(
            "\nSummary: {} imported, {} already exists, {} not found in source",
            imported.to_string().green(),
            already_exists.to_string().yellow(),
            not_found.to_string().red()
        );

        if imported > 0 {
            eprintln!(
                "\n{} Successfully imported {} secrets from {}",
                "✓".green(),
                imported,
                from_provider,
            );
        }

        // Always record the import: it read every declared secret from the
        // source (and target), so the access is logged even when nothing was
        // copied. Outcome reflects what the read found: `Written` when at least
        // one secret was copied, `Found` when nothing was copied but secrets were
        // already present (in source or target), and `Missing` when nothing was
        // copied and nothing was found anywhere — so a "found nothing" import is
        // not mislabeled as a successful retrieval. Per-secret copies are also
        // recorded individually as `Set`/`Written` events above.
        read_names.sort();
        let outcome = if imported > 0 {
            AuditOutcome::Written
        } else if already_exists > 0 {
            AuditOutcome::Found
        } else {
            AuditOutcome::Missing
        };
        self.record(
            AuditAction::Import,
            &profile_display,
            outcome,
            AuditFields {
                keys: &read_names,
                provider_uri: source_uri,
                ..Default::default()
            },
        );

        Ok(())
    }

    /// Resolves a writable provider for a secret.
    ///
    /// Uses the first provider from the secret's provider list if specified,
    /// otherwise falls back to the default provider.
    fn get_writable_provider_for_secret(
        &self,
        secret_config: &crate::config::Secret,
    ) -> Result<Box<dyn ProviderTrait>> {
        let backend = self.resolve_write_provider(secret_config, None)?;

        if !backend.allows_set() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Provider '{}' is read-only and cannot store generated secrets",
                backend.name()
            )));
        }

        Ok(backend)
    }

    /// Attempts to generate a secret if it has generation config.
    ///
    /// Returns `Ok(Some(value))` if generation succeeded,
    /// `Ok(None)` if generation is not configured,
    /// or `Err` if generation was configured but failed.
    fn try_generate_secret(
        &self,
        name: &str,
        secret_config: &crate::config::Secret,
        profile_name: &str,
    ) -> Result<Option<SecretString>> {
        let gen_config = match &secret_config.generate {
            Some(config) if config.is_enabled() => config,
            _ => return Ok(None),
        };

        let secret_type = match &secret_config.secret_type {
            Some(t) => t.as_str(),
            None => {
                return Err(SecretSpecError::GenerationFailed(format!(
                    "Secret '{}' has generate config but no type",
                    name
                )));
            }
        };

        let value = crate::generator::generate(secret_type, gen_config)?;

        // Store the generated value
        let backend = self.get_writable_provider_for_secret(secret_config)?;
        let set_result = backend.set(&self.config.project.name, name, &value, profile_name);
        // Generating a secret writes a brand-new value to the provider; record it
        // like any other write so the audit log captures every stored secret.
        self.audit_write_result(&set_result, name, profile_name, Some(backend.uri()));
        set_result?;

        eprintln!(
            "{} {} - generated and saved to {} (profile: {})",
            "✓".green(),
            name,
            backend.name(),
            profile_name
        );

        Ok(Some(value))
    }

    /// Writes a secret value to a temporary file and returns the file handle and path
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret value to write
    ///
    /// # Returns
    ///
    /// A tuple containing the temporary file handle and the path as a string
    ///
    /// # Errors
    ///
    /// Returns an error if the temporary file cannot be created or written to
    fn write_secret_to_temp_file(
        &self,
        secret: &SecretString,
    ) -> Result<(tempfile::NamedTempFile, String)> {
        use std::io::Write;

        let mut temp_file = tempfile::NamedTempFile::new().map_err(SecretSpecError::Io)?;

        temp_file
            .write_all(secret.expose_secret().as_bytes())
            .map_err(SecretSpecError::Io)?;

        // Flush to ensure the data is written
        temp_file.flush().map_err(SecretSpecError::Io)?;

        // Set restrictive permissions (0o400) so only the owner can read
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = temp_file
                .as_file()
                .metadata()
                .map_err(SecretSpecError::Io)?
                .permissions();
            perms.set_mode(0o400);
            temp_file
                .as_file()
                .set_permissions(perms)
                .map_err(SecretSpecError::Io)?;
        }

        // Get the path as a string
        let path_str = temp_file
            .path()
            .to_str()
            .ok_or_else(|| {
                SecretSpecError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Temporary file path is not valid UTF-8",
                ))
            })?
            .to_string();

        Ok((temp_file, path_str))
    }

    /// Validates all secrets in the specification
    ///
    /// This method checks all secrets defined in the current profile (and default
    /// profile if different) and returns detailed information about their status.
    ///
    /// Uses batch fetching when possible to improve performance with providers
    /// that have high latency (like 1Password).
    ///
    /// # Returns
    ///
    /// A `ValidatedSecrets` containing the status of all secrets
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The provider cannot be initialized
    /// - The specified profile doesn't exist
    /// - Storage operations fail
    ///
    /// # Example
    ///
    /// ```no_run
    /// use secretspec::Secrets;
    ///
    /// let mut spec = Secrets::load().unwrap();
    /// let result = spec.validate().unwrap();
    /// if let Ok(validated) = result {
    ///     println!("All required secrets are present!");
    /// }
    /// ```
    ///
    /// This is the public read/resolution entry point — used directly by the SDK
    /// and by `secretspec-derive`-generated code — so it records exactly one
    /// `Check` audit event per call.
    pub fn validate(&self) -> Result<std::result::Result<ValidatedSecrets, ValidationErrors>> {
        self.validate_audited(true)
    }

    /// Resolve every declared secret into a value-carrying [`ResolveResponse`],
    /// the authoritative output other-language SDKs consume (over the C ABI or
    /// `secretspec resolve --json`).
    ///
    /// Unlike [`Self::validate`], the returned payload **carries secret
    /// values** (or, for `as_path` secrets, the path to a persisted temp file).
    /// Treat its bytes as sensitive. When a required secret is missing the
    /// resolution failed: `secrets` is empty and `missing_required` is
    /// populated, mirroring the derive crate's `load()`.
    ///
    /// `as_path` temp files are persisted so the returned paths stay valid for
    /// the caller; this is a one-shot boundary and the caller owns their
    /// lifetime thereafter.
    pub fn resolve(&self) -> Result<ResolveResponse> {
        match self.validate()? {
            Ok(mut validated) => {
                // Persist as_path temp files so returned paths outlive this call.
                validated.keep_temp_files()?;

                let mut secrets = BTreeMap::new();
                for entry in &validated.resolution {
                    if entry.status != ResolutionStatus::Resolved {
                        continue;
                    }
                    let raw = validated
                        .resolved
                        .secrets
                        .get(&entry.name)
                        .expect("a Resolved entry always has a value")
                        .expose_secret()
                        .to_string();
                    let source = if entry.generated {
                        ResolvedSource::Generated
                    } else if entry.default_applied {
                        ResolvedSource::Default
                    } else {
                        ResolvedSource::Provider
                    };
                    let (value, path) = if entry.as_path {
                        (None, Some(raw))
                    } else {
                        (Some(raw), None)
                    };
                    secrets.insert(
                        entry.name.clone(),
                        ResolvedSecret {
                            value,
                            path,
                            as_path: entry.as_path,
                            source,
                            source_provider: entry.source_provider.clone(),
                        },
                    );
                }

                let mut missing_optional = validated.missing_optional.clone();
                missing_optional.sort();

                Ok(ResolveResponse {
                    schema_version: RESOLVE_SCHEMA_VERSION,
                    provider: validated.resolved.provider.clone(),
                    profile: validated.resolved.profile.clone(),
                    secrets,
                    missing_required: Vec::new(),
                    missing_optional,
                })
            }
            Err(errors) => {
                let mut missing_required = errors.missing_required.clone();
                missing_required.sort();
                let mut missing_optional = errors.missing_optional.clone();
                missing_optional.sort();
                Ok(ResolveResponse {
                    schema_version: RESOLVE_SCHEMA_VERSION,
                    provider: errors.provider.clone(),
                    profile: errors.profile.clone(),
                    secrets: BTreeMap::new(),
                    missing_required,
                    missing_optional,
                })
            }
        }
    }

    /// Resolves all secrets. `emit_check` controls whether this pass records a
    /// `Check` audit event.
    ///
    /// Top-level reads ([`Self::validate`], `check`) pass `true`. Internal
    /// re-validations inside [`Self::ensure_secrets`] pass `false`, so a single
    /// user action emits one `Check` (not several), and `secretspec run` — which
    /// resolves via `ensure_secrets` and then records its own `Run` event — is
    /// not also recorded as a `Check`. The trade-off: a direct
    /// `ensure_secrets` call (rare; not the path `secretspec-derive` uses) does
    /// not emit a `Check` read event, though any writes it performs are audited.
    fn validate_audited(
        &self,
        emit_check: bool,
    ) -> Result<std::result::Result<ValidatedSecrets, ValidationErrors>> {
        // Enforce the reason policy. For the top-level read (`emit_check`) a denial
        // is itself audited; internal re-validations (emit_check=false) re-check the
        // gate silently, since the reason is already present by the time they run.
        if emit_check {
            self.ensure_reason_for(AuditAction::Check, None)?;
        } else {
            self.ensure_reason()?;
        }

        let profile_name = self.resolve_profile_name(None);
        // Keys for the single read-audit event. Filled inside the closure once the
        // profile resolves; stays empty if resolution fails before that point.
        let mut audit_keys: Vec<String> = Vec::new();

        // Resolve every secret inside one fallible block so that *any* error — not
        // just the inline primary-provider failure — is captured and recorded as a
        // single `Check` event below before it propagates. Previously only one error
        // arm audited, so a failed alias resolution or fallback-chain error left no
        // trace despite being an attempted read.
        let result: Result<std::result::Result<ValidatedSecrets, ValidationErrors>> =
            (|| -> Result<std::result::Result<ValidatedSecrets, ValidationErrors>> {
                let mut secrets: HashMap<String, SecretString> = HashMap::new();
                let mut missing_required = Vec::new();
                let mut missing_optional = Vec::new();
                let mut with_defaults = Vec::new();
                let mut temp_files = Vec::new();
                // Per-secret provenance for the value-free resolution report.
                let mut resolution: Vec<SecretResolution> = Vec::new();
                // Credential-free `uri()` of each successfully built primary
                // provider group, keyed by the configured group URI, so a
                // primary hit can be attributed to the provider that answered.
                let mut group_uris: HashMap<Option<String>, String> = HashMap::new();

                let profile = self.resolve_profile(Some(&profile_name))?;
                let all_secrets: Vec<(String, crate::config::Secret)> =
                    profile.into_iter().collect();

                audit_keys = {
                    let mut keys: Vec<String> =
                        all_secrets.iter().map(|(name, _)| name.clone()).collect();
                    keys.sort();
                    keys
                };

                let override_uri = self.resolve_provider_override(None);

                let mut provider_groups: HashMap<Option<String>, Vec<String>> = HashMap::new();
                let mut secret_primary_uris: HashMap<String, Option<String>> = HashMap::new();

                for (name, _) in &all_secrets {
                    let secret_config = self
                        .resolve_secret_config(name, Some(&profile_name))
                        .expect("Secret should exist in config since we're iterating over it");

                    let provider_uri = match (&override_uri, secret_config.providers.as_deref()) {
                        (Some(uri), _) => Some(uri.clone()),
                        (None, Some([first_alias, ..])) => self
                            .resolve_provider_aliases(Some(std::slice::from_ref(first_alias)))?
                            .and_then(|uris| uris.into_iter().next()),
                        _ => None,
                    };

                    secret_primary_uris.insert(name.clone(), provider_uri.clone());
                    provider_groups
                        .entry(provider_uri)
                        .or_default()
                        .push(name.clone());
                }

                // Batch fetch from each provider group. A failure here (e.g. an
                // unauthenticated vault) does not abort validation: secrets that
                // declare a fallback chain are retried per-secret below. Secrets in
                // the failed group with no fallback to try will surface the original
                // error instead of being silently reported as missing.
                let mut fetched_values: HashMap<String, SecretString> = HashMap::new();
                let mut failed_primary_uris: HashMap<Option<String>, SecretSpecError> =
                    HashMap::new();

                for (provider_uri, secret_names) in provider_groups {
                    let provider_result = if let Some(uri) = provider_uri.clone() {
                        self.build_provider(uri)
                    } else {
                        self.get_provider(None)
                    };

                    let provider = match provider_result {
                        Ok(p) => p,
                        Err(e) => {
                            // Construction failed: only the raw alias exists, so redact it.
                            let shown =
                                provider_uri.as_deref().map(crate::audit::redact_uri_strict);
                            warn_primary_provider_failure(shown.as_deref(), &e);
                            failed_primary_uris.insert(provider_uri, e);
                            continue;
                        }
                    };

                    // Attribute primary hits to the provider's own credential-free
                    // `uri()`, never the raw configured alias (which may embed a
                    // token). Recorded before the fetch so attribution survives a
                    // partial batch.
                    group_uris.insert(provider_uri.clone(), provider.uri());

                    let keys: Vec<&str> = secret_names.iter().map(|s| s.as_str()).collect();
                    match provider.get_batch(&self.config.project.name, &keys, &profile_name) {
                        Ok(batch_results) => fetched_values.extend(batch_results),
                        Err(e) => {
                            // A provider was built; attribute to its credential-free `uri()`.
                            warn_primary_provider_failure(Some(&provider.uri()), &e);
                            failed_primary_uris.insert(provider_uri, e);
                        }
                    }
                }

                // Process results - apply defaults, handle as_path, track missing.
                // Each secret also records a value-free provenance entry for the
                // resolution report (status, which provider answered, generated,
                // defaulted).
                for (name, _) in all_secrets {
                    let secret_config = self
                        .resolve_secret_config(&name, Some(&profile_name))
                        .expect("Secret should exist in config since we're iterating over it");
                    let required = secret_config.required.unwrap_or(true);
                    let default = secret_config.default.clone();
                    let as_path = secret_config.as_path.unwrap_or(false);

                    // `name` is consumed by whichever arm resolves/records it;
                    // keep a copy for the provenance entry pushed at the end.
                    let report_name = name.clone();
                    let status;
                    let mut source_provider = None;
                    let mut default_applied = false;
                    let mut generated = false;

                    match fetched_values.remove(&name) {
                        Some(value) => {
                            source_provider = group_uris.get(&secret_primary_uris[&name]).cloned();
                            self.insert_resolved(
                                &mut secrets,
                                &mut temp_files,
                                name,
                                value,
                                as_path,
                            )?;
                            status = ResolutionStatus::Resolved;
                        }
                        None => {
                            let primary_uri = &secret_primary_uris[&name];
                            let primary_failed = failed_primary_uris.contains_key(primary_uri);

                            // An explicit override collapses the chain to one provider, no fallback.
                            let (fallback_value, fallback_uri) =
                                match (override_uri.as_ref(), secret_config.providers.as_deref()) {
                                    (None, Some(providers)) if providers.len() > 1 => {
                                        let fallback_uris =
                                            self.resolve_provider_aliases(Some(&providers[1..]))?;
                                        self.get_secret_from_providers(
                                            &self.config.project.name,
                                            &name,
                                            &profile_name,
                                            fallback_uris.as_deref(),
                                            None,
                                        )?
                                    }
                                    // No alternative chain to try and the primary failed: surface the
                                    // original error rather than reporting the secret as merely
                                    // missing. The single `Check` event is recorded by the caller
                                    // below, so this arm just propagates.
                                    _ if primary_failed => {
                                        let err = failed_primary_uris
                                            .remove(primary_uri)
                                            .expect("primary_failed implies entry present");
                                        return Err(err);
                                    }
                                    _ => (None, None),
                                };

                            if let Some(value) = fallback_value {
                                source_provider = fallback_uri;
                                self.insert_resolved(
                                    &mut secrets,
                                    &mut temp_files,
                                    name,
                                    value,
                                    as_path,
                                )?;
                                status = ResolutionStatus::Resolved;
                            } else if let Some(generated_value) =
                                self.try_generate_secret(&name, &secret_config, &profile_name)?
                            {
                                generated = true;
                                self.insert_resolved(
                                    &mut secrets,
                                    &mut temp_files,
                                    name,
                                    generated_value,
                                    as_path,
                                )?;
                                status = ResolutionStatus::Resolved;
                            } else if let Some(default_value) = default {
                                default_applied = true;
                                self.insert_resolved(
                                    &mut secrets,
                                    &mut temp_files,
                                    name.clone(),
                                    SecretString::new(default_value.clone().into()),
                                    as_path,
                                )?;
                                with_defaults.push((name, default_value));
                                status = ResolutionStatus::Resolved;
                            } else if required {
                                missing_required.push(name);
                                status = ResolutionStatus::MissingRequired;
                            } else {
                                missing_optional.push(name);
                                status = ResolutionStatus::MissingOptional;
                            }
                        }
                    }

                    resolution.push(SecretResolution {
                        name: report_name,
                        status,
                        required,
                        source_provider,
                        default_applied,
                        generated,
                        as_path,
                    });
                }

                let report_provider_uri = self.validation_report_provider_uri(
                    override_uri.as_deref(),
                    &secret_primary_uris,
                )?;

                if !missing_required.is_empty() {
                    let mut errors = ValidationErrors::new(
                        missing_required,
                        missing_optional,
                        with_defaults,
                        report_provider_uri,
                        profile_name.to_string(),
                    );
                    errors.resolution = resolution;
                    Ok(Err(errors))
                } else {
                    Ok(Ok(ValidatedSecrets {
                        resolved: Resolved::new(
                            secrets,
                            report_provider_uri,
                            profile_name.to_string(),
                        ),
                        missing_optional,
                        with_defaults,
                        resolution,
                        temp_files,
                    }))
                }
            })();

        // Record exactly one `Check` event for the whole batch when this is a
        // top-level read, regardless of how the resolution exited — so a failed
        // attempt (bad alias, fallback-chain error, report-URI failure) is audited
        // too, not only success/missing. `record` is a no-op when auditing is off.
        if emit_check {
            let (outcome, error_kind) = match &result {
                Ok(Ok(_)) => (AuditOutcome::Found, None),
                Ok(Err(_)) => (AuditOutcome::Missing, None),
                Err(e) => (AuditOutcome::Error, Some(e.kind())),
            };
            self.record(
                AuditAction::Check,
                &profile_name,
                outcome,
                AuditFields {
                    keys: &audit_keys,
                    error_kind,
                    ..Default::default()
                },
            );
        }

        result
    }

    /// Runs a command with secrets injected as environment variables
    ///
    /// This method validates that all required secrets are present, then runs
    /// the specified command with all secrets injected as environment variables.
    ///
    /// # Arguments
    ///
    /// * `command` - The command and arguments to run
    /// * `provider_arg` - Optional provider to use
    /// * `profile` - Optional profile to use
    ///
    /// # Returns
    ///
    /// This method executes the command and exits with the command's exit code.
    /// It only returns an error if validation fails or the command cannot be started.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No command is specified
    /// - Required secrets are missing
    /// - The command cannot be executed
    ///
    /// # Example
    ///
    /// ```no_run
    /// use secretspec::Secrets;
    ///
    /// let mut spec = Secrets::load().unwrap();
    /// spec.run(vec!["npm".to_string(), "start".to_string()]).unwrap();
    /// ```
    pub fn run(&self, command: Vec<String>) -> Result<()> {
        self.ensure_reason_for(AuditAction::Run, None)?;
        let exit_code = self.run_command(command)?;
        std::process::exit(exit_code);
    }

    /// Runs a command with secrets injected and returns its exit code.
    ///
    /// Splitting this out from [`Self::run`] ensures that any temporary files
    /// backing `as_path` secrets are dropped (and removed from disk) before
    /// `std::process::exit` is called — `exit` does not run destructors.
    pub(crate) fn run_command(&self, command: Vec<String>) -> Result<i32> {
        if command.is_empty() {
            return Err(SecretSpecError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No command specified. Usage: secretspec run -- <command> [args...]",
            )));
        }

        // Ensure all secrets are available (will error out if missing).
        // `validation_result` owns the temp files for `as_path` secrets and
        // must stay alive until the child process has terminated.
        let validation_result = match self.ensure_secrets(None, None, false) {
            Ok(v) => v,
            Err(e) => {
                // Record the attempt even when validation fails and the command
                // never runs, so a failed/blocked run is still auditable.
                self.record(
                    AuditAction::Run,
                    &self.resolve_profile_name(None),
                    AuditOutcome::Error,
                    AuditFields {
                        command: Some(&command[0]),
                        error_kind: Some(e.kind()),
                        ..Default::default()
                    },
                );
                return Err(e);
            }
        };

        let mut env_vars = env::vars().collect::<HashMap<_, _>>();
        for (key, secret) in &validation_result.resolved.secrets {
            env_vars.insert(key.clone(), secret.expose_secret().to_string());
        }

        // Record which secrets were injected into which command (argv[0] only —
        // arguments may contain secrets). Keys are computed before the spawn but
        // the event is emitted after it so the outcome reflects whether the
        // command actually started.
        let keys: Vec<String> = if self.audit.is_some() {
            let mut keys: Vec<String> =
                validation_result.resolved.secrets.keys().cloned().collect();
            keys.sort();
            keys
        } else {
            Vec::new()
        };

        let mut cmd = Command::new(&command[0]);
        cmd.args(&command[1..]);
        cmd.envs(&env_vars);

        // Spawn (rather than `status`) so the Run event is recorded the moment the
        // child starts, before the potentially long-running wait. A long-lived
        // command (e.g. a dev server) would otherwise not be logged until it exits,
        // and would be lost entirely if secretspec were killed first. A failure to
        // start is recorded as an error. `Child::wait` closes stdin and inherits
        // stdio just like `Command::status`, so behavior is otherwise unchanged.
        let child = cmd.spawn();
        let (outcome, error_kind) = match &child {
            Ok(_) => (AuditOutcome::Started, None),
            Err(_) => (AuditOutcome::Error, Some("io")),
        };
        // `record` is a no-op when auditing is off, so no `self.audit.is_some()`
        // guard is needed here (the `keys` collection above is still guarded to
        // skip the sort).
        self.record(
            AuditAction::Run,
            &validation_result.resolved.profile,
            outcome,
            AuditFields {
                keys: &keys,
                command: Some(&command[0]),
                error_kind,
                ..Default::default()
            },
        );

        let status = child?.wait()?;
        Ok(status.code().unwrap_or(1))
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn policy_decision_matrix() {
        use RequireReason::*;
        assert!(!policy_requires_reason(Never, true));
        assert!(!policy_requires_reason(Never, false));
        assert!(policy_requires_reason(Always, false));
        assert!(policy_requires_reason(Always, true));
        assert!(policy_requires_reason(Agents, true));
        assert!(!policy_requires_reason(Agents, false));
    }

    #[test]
    fn normalize_reason_trims_and_blanks_to_none() {
        assert_eq!(
            normalize_reason("  deploy web  "),
            Some("deploy web".to_string())
        );
        assert_eq!(normalize_reason("deploy"), Some("deploy".to_string()));
        assert_eq!(normalize_reason(""), None);
        assert_eq!(normalize_reason("   "), None);
        assert_eq!(normalize_reason("\t\n"), None);
    }

    /// A non-UTF-8 environment variable must not crash detection: the offending
    /// entry is dropped and the UTF-8 entries survive. This guards against the
    /// `std::env::vars()` panic in `detect-coding-agent`, which auditing (on by
    /// default) would otherwise trigger on every command.
    #[cfg(unix)]
    #[test]
    fn utf8_env_drops_non_utf8_entries_without_panicking() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let bad_key = OsString::from_vec(vec![0x66, 0x6f, 0xff]); // "fo\xff"
        let bad_val = OsString::from_vec(vec![0xfe, 0xfe]);
        let vars = vec![
            (OsString::from("CLEAN_KEY"), OsString::from("clean_value")),
            (bad_key, OsString::from("value_for_bad_key")),
            (OsString::from("KEY_WITH_BAD_VALUE"), bad_val),
        ];

        let env = utf8_env_from(vars);

        // Only the fully-UTF-8 entry survives; the two non-UTF-8 entries are skipped.
        assert_eq!(
            env.get("CLEAN_KEY").map(String::as_str),
            Some("clean_value")
        );
        assert_eq!(env.len(), 1);
    }
}
