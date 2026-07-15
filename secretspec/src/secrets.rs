//! Core secrets management functionality

use crate::audit::{AuditAction, AuditContext, AuditLogger, AuditOutcome};
use crate::config::{Config, GlobalConfig, NativeAddress, Profile, RequireReason, Resolved};
use crate::error::{Result, SecretSpecError};
use crate::plan::{PlannedSecret, ResolutionPlan, Route};
use crate::provider::{Address, Provider as ProviderTrait};
use crate::report::{ResolutionReport, ResolutionStatus, SecretResolution};
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
/// during construction or during `get_many`); affected secrets will still be
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

/// Whether a resolution pass may produce side effects and persist secrets.
///
/// A resolution pass always queries providers to learn what is present, but the
/// two value-free entry points ([`Secrets::report`], [`Secrets::resolve_without_values`])
/// must not change anything as a side effect of reading. This flag gates the two
/// mutating steps of a pass so those entry points can share the exact same
/// resolution logic without inheriting its side effects.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Materialize {
    /// Full pass: mint-and-store a missing generatable secret and write each
    /// `as_path` secret to a temp file. Backs `validate()`/`resolve()`/`check`.
    Values,
    /// Value-free pass: never write a generated secret back to a provider and
    /// never persist a secret to disk. A generatable-but-absent secret is still
    /// reported as it *would* resolve, without minting it. Backs `report()` and
    /// `resolve_without_values()`.
    None,
}

/// Walks up from the current directory looking for `secretspec.toml`.
fn find_config_file() -> Result<PathBuf> {
    find_config_file_from(std::env::current_dir()?)
}

/// Walks up from `start` looking for `secretspec.toml`, returning the path to the
/// nearest one. Factored out of [`find_config_file`] so the walk can be tested
/// against an explicit starting directory without mutating the process-global
/// current directory (which is racy under `cargo test`).
fn find_config_file_from(start: PathBuf) -> Result<PathBuf> {
    let mut dir = start;
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
    /// Directory containing the loaded `secretspec.toml`. Relative filesystem
    /// paths held by file-backed providers (e.g. `dotenv`) are resolved against
    /// this rather than the process's current working directory, so running
    /// from a subdirectory with `--file ../secretspec.toml` still finds the
    /// `.env` files next to the config.
    config_dir: PathBuf,
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

/// The child-process environment for `run`: the parent environment plus the
/// resolved secrets.
///
/// Kept as `OsString` end to end and captured with `vars_os` (never `vars`,
/// whose iterator panics on non-UTF-8 entries — env vars are arbitrary bytes on
/// Unix). Unlike agent detection ([`utf8_env`]), which may safely *drop*
/// non-UTF-8 entries, `run` must stay transparent: the child inherits every
/// parent variable untouched, UTF-8 or not. Secrets overwrite same-named vars.
fn child_env_from<I, S>(
    vars: I,
    secrets: S,
) -> std::collections::HashMap<std::ffi::OsString, std::ffi::OsString>
where
    I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    S: IntoIterator<Item = (String, String)>,
{
    let mut env: std::collections::HashMap<std::ffi::OsString, std::ffi::OsString> =
        vars.into_iter().collect();
    env.extend(secrets.into_iter().map(|(k, v)| (k.into(), v.into())));
    env
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
    /// The secret's native `ref` coordinates, when the access resolved them;
    /// rendered for the log by [`Secrets::record`].
    reference: Option<&'a NativeAddress>,
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
            config_dir: PathBuf::from("."),
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
        // Semantic validation (required vs default, ref coordinate rules,
        // generate consistency) runs here so every CLI and SDK entry point
        // enforces the same rules the config documents.
        project_config.validate()?;
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
        // Directory the config lives in, used to resolve relative provider
        // paths (e.g. `dotenv:.config/.env`) against the project root instead
        // of the current working directory. Kept logical (not canonicalized) so
        // a relative `--file` stays relative to the CWD and Windows extended
        // (`\\?\`) prefixes are never introduced.
        let config_dir = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));

        Ok(Self {
            require_reason: project_config.project.require_reason.unwrap_or_default(),
            config: project_config,
            config_dir,
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
        // Resolve provider aliases here, at the single construction chokepoint, so
        // every caller that hands us a user-supplied spec gets alias expansion for
        // free and no new entry point can forget it. Resolution is a no-op on an
        // already-resolved URI (a `scheme://...` string is never an alias key), so
        // callers that pass pre-resolved URIs (the per-secret chain) are unaffected.
        let resolved = self.resolve_provider_spec(spec);
        let mut provider = Box::<dyn ProviderTrait>::try_from(resolved.as_str())
            .map_err(|err| self.explain_unknown_provider(err, &resolved))?;
        provider.with_base_dir(&self.config_dir);
        provider.set_reason(self.reason.clone());
        Ok(provider)
    }

    /// Enriches a provider-construction failure: when a bare token (no scheme
    /// separator) matched neither a built-in provider nor a known alias, the
    /// raw "provider not found" error is unhelpful. List the defined aliases so a
    /// mistyped alias points the user at the right names, matching the guidance
    /// [`Self::resolve_one_provider`] gives for per-secret provider chains.
    fn explain_unknown_provider(&self, err: SecretSpecError, spec: &str) -> SecretSpecError {
        match err {
            SecretSpecError::ProviderNotFound(_) if !spec.contains(':') => {
                let known = self.known_provider_aliases();
                if known.is_empty() {
                    return err;
                }
                SecretSpecError::ProviderNotFound(format!(
                    "{} (not a known provider or alias; available aliases: {})",
                    spec,
                    known.join(", ")
                ))
            }
            _ => err,
        }
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
                    reference: fields.reference.map(NativeAddress::render),
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
        reference: Option<&NativeAddress>,
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
                reference,
                error_kind,
                ..Default::default()
            },
        );
    }

    /// Records a failed single-secret operation (`get`/`set`) as an `Error`
    /// event attributed to `key` — and to a provider and native `ref`
    /// coordinates, when they were determined before the failure. The one shape
    /// every `get`/`set` failure path records, so the paths cannot drift on
    /// which fields a failure carries.
    fn record_key_error(
        &self,
        action: AuditAction,
        profile: &str,
        key: &str,
        provider_uri: Option<String>,
        reference: Option<&NativeAddress>,
        err: &SecretSpecError,
    ) {
        self.record(
            action,
            profile,
            AuditOutcome::Error,
            AuditFields {
                key: Some(key),
                provider_uri,
                reference,
                error_kind: Some(err.kind()),
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
                    reference: current
                        .reference
                        .clone()
                        .or_else(|| default.reference.clone()),
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
                    reference: secret.reference.clone(),
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

    fn resolve_provider_spec(&self, spec: String) -> String {
        self.lookup_provider_alias(&spec).unwrap_or(spec)
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

    /// Resolves a single provider spec to its URI. A defined alias is expanded
    /// via [`Self::lookup_provider_alias`]. A spec that is already a URI
    /// (contains `://`) passes through unchanged, so a chain can point at a
    /// store inline — `providers = ["onepassword://Production"]` — without
    /// declaring an alias for it; a `scheme://` string is never an alias key,
    /// so the two forms cannot collide. A non-alias spec that names a
    /// registered provider (a bare name like `keyring`, or `scheme:path`
    /// shorthand like `dotenv:.env.production`) also passes through, so the
    /// chain and the resolved override accept exactly the specs `--provider`
    /// and the default provider accept; `build_provider` constructs it later.
    /// Only a token that names neither an alias nor a provider errors — with
    /// the corrective "use `onepassword` instead" message when it is the
    /// common `1password` misspelling.
    ///
    /// Used both to resolve a chain's primary up front and to resolve each
    /// fallback entry lazily, in order, as a read actually reaches it.
    pub(crate) fn resolve_one_provider(&self, spec: &str) -> Result<String> {
        if spec.contains("://") {
            return Ok(spec.to_string());
        }
        if let Some(uri) = self.lookup_provider_alias(spec) {
            return Ok(uri);
        }
        if crate::provider::spec_names_known_provider(spec)? {
            return Ok(spec.to_string());
        }
        let known = self.known_provider_aliases();
        let msg = if known.is_empty() {
            format!(
                "Provider alias '{}' is not defined. Declare it in [providers] in secretspec.toml or in the global config.",
                spec
            )
        } else {
            format!(
                "Provider alias '{}' is not defined. Available aliases: {}",
                spec,
                known.join(", ")
            )
        };
        Err(SecretSpecError::ProviderNotFound(msg))
    }

    /// Returns the explicit provider spec from caller arg, builder, or env, in
    /// that priority order.
    ///
    /// Used as the shared head of provider resolution so the precedence between
    /// the `--provider` flag (forwarded via `set_provider`) and the
    /// `SECRETSPEC_PROVIDER` env var stays consistent across resolvers.
    fn explicit_provider_spec(&self, override_arg: Option<&str>) -> Option<String> {
        override_arg
            .map(|spec| spec.to_string())
            .or_else(|| self.provider.clone())
            .or_else(|| env::var("SECRETSPEC_PROVIDER").ok())
    }

    /// Returns the explicit provider override resolved to a URI, if one is set.
    ///
    /// Resolves the explicit spec via [`Self::explicit_provider_spec`], then
    /// expands any matching alias via [`Self::lookup_provider_alias`].
    pub(crate) fn resolve_provider_override(&self, override_arg: Option<&str>) -> Option<String> {
        let spec = self.explicit_provider_spec(override_arg)?;
        Some(self.resolve_provider_spec(spec))
    }

    /// Fetches one provider group's secrets through the provider's batch
    /// surface: every planned secret's [`Address`] (native `ref` coordinates or
    /// convention naming) is handed to `get_many`, which dedupes identical
    /// coordinates and batches or parallelizes as the store allows. The address
    /// is the one the plan already derived, so naming lives in exactly one place.
    fn fetch_group(
        provider: &dyn ProviderTrait,
        group: &[&PlannedSecret],
        project: &str,
        profile: &str,
    ) -> Result<HashMap<String, SecretString>> {
        let requests: Vec<(&str, Address<'_>)> = group
            .iter()
            .map(|planned| (planned.name.as_str(), planned.as_address(project, profile)))
            .collect();
        provider.get_many(&requests)
    }

    /// Builds the provider a write goes to for a resolved [`Route`]: the primary
    /// store, or the default provider when the route sets none. A write never
    /// consults the fallback, so an undefined alias further down the chain does
    /// not affect it.
    fn write_provider_for_route(&self, route: &Route) -> Result<Box<dyn ProviderTrait>> {
        self.get_provider(route.primary())
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
        provider_arg: Option<&str>,
    ) -> Result<Box<dyn ProviderTrait>> {
        let provider_spec = self
            .explicit_provider_spec(provider_arg)
            .or_else(|| {
                self.global_config
                    .as_ref()
                    .and_then(|gc| gc.defaults.provider.clone())
            })
            .ok_or(SecretSpecError::NoProviderConfigured)?;

        // Alias resolution happens inside `build_provider`.
        let provider = self.build_provider(provider_spec)?;

        Ok(provider)
    }

    /// Returns a provider URI for validation result metadata without forcing a
    /// user-global default when every secret used an explicit or per-secret provider.
    ///
    /// The returned URI lands in the `provider` field of the resolution report and
    /// the resolve response, which `check --explain` prints, `--json` emits, and the
    /// other-language SDKs read over the FFI boundary. A user-authored alias or
    /// override may embed a credential (`vault+token:s3cr3t@host`,
    /// `vault://host?token=...`), so raw URIs are run through `redact_uri_strict`
    /// first. The `provider.uri()` paths below are already credential-free.
    fn validation_report_provider_uri<'a>(
        &self,
        override_uri: Option<&str>,
        primary_uris: impl Iterator<Item = Option<&'a str>>,
    ) -> Result<String> {
        if let Some(uri) = override_uri {
            return Ok(crate::audit::redact_uri_strict(uri));
        }

        // Collecting into `Option` yields `None` as soon as any secret sits on
        // the default provider, which then names the report.
        let provider_uris: Option<Vec<&str>> = primary_uris.collect();
        match provider_uris.and_then(|uris| uris.into_iter().min()) {
            Some(uri) => Ok(crate::audit::redact_uri_strict(uri)),
            // A secret on the default provider, or no secrets at all.
            None => self.get_provider(None).map(|provider| provider.uri()),
        }
    }

    /// Gets a secret from a chain of provider specs with fallback.
    ///
    /// Tries each provider in order until one has the secret. Each spec is
    /// resolved to a URI **only when the chain reaches it** — every earlier
    /// provider having missed. A spec that fails to resolve (an undefined
    /// alias) is a broken link, not a reason to abandon the chain: like a
    /// provider that fails to construct or read (authentication failure,
    /// network error), it is warned about and the next link is tried. If every
    /// provider errored without any reporting a healthy "not found", the last
    /// error is returned so the user sees why the secret could not be
    /// retrieved.
    ///
    /// If no provider specs are supplied, falls back to the default provider.
    ///
    /// # Arguments
    ///
    /// * `secret_name` - The secret name, for warning messages
    /// * `addr` - The secret's [`Address`] (see [`PlannedSecret::as_address`]);
    ///   the same address is asked of every provider in the chain
    /// * `provider_specs` - Optional chain of provider specs (aliases or inline
    ///   URIs) to try in order, resolved lazily per entry
    ///
    /// # Returns
    ///
    /// A tuple of the secret value (or `None` if not found in any provider) and
    /// the URI of the provider to attribute the access to: on a hit, the serving
    /// provider; on a chain miss/error, the last provider tried. The URI lets
    /// callers (e.g. the audit log) record which provider actually answered.
    fn get_secret_from_providers(
        &self,
        secret_name: &str,
        addr: Address<'_>,
        provider_specs: Option<&[String]>,
    ) -> Result<(Option<SecretString>, Option<String>)> {
        // If a provider chain is supplied, try it in order.
        if let Some(specs) = provider_specs {
            let mut last_error: Option<SecretSpecError> = None;
            let mut any_healthy = false;
            let mut last_uri: Option<String> = None;
            for spec in specs {
                // Resolve this link only now, as the chain reaches it. An
                // undefined alias is one broken link, treated exactly like a
                // provider that fails to construct or read: warn and try the
                // next, so a working provider later in the chain still answers.
                let uri = match self.resolve_one_provider(spec) {
                    Ok(uri) => uri,
                    Err(e) => {
                        // Resolution failed, so only the raw spec exists; redact it.
                        warn_provider_failure(
                            &crate::audit::redact_uri_strict(spec),
                            secret_name,
                            &e,
                        );
                        last_error = Some(e);
                        continue;
                    }
                };
                let provider = match self.build_provider(uri.clone()) {
                    Ok(p) => p,
                    Err(e) => {
                        // Construction failed after resolution, so redact the
                        // resolved URI (it may carry an inline credential).
                        warn_provider_failure(
                            &crate::audit::redact_uri_strict(&uri),
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
                match provider.get(addr) {
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
            let backend = self.get_provider(None)?;
            let uri = backend.uri();
            backend.get(addr).map(|opt| (opt, Some(uri)))
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

        // Plan the secret exactly as batch resolution would, so the write
        // target, address, and effective config are the same decisions
        // `check`/`run` make. `None` means it is not declared in this profile.
        let planned = match self.plan_secret(name, &profile_name, None) {
            Ok(Some(planned)) => planned,
            // Planning failed (e.g. an undefined provider alias). Still an
            // attempted write, so audit it like the batch path audits every
            // planning failure; no provider can be attributed yet.
            Err(err) => {
                self.record_key_error(AuditAction::Set, &profile_name, name, None, None, &err);
                return Err(err);
            }
            Ok(None) => {
                let profile = self.resolve_profile(Some(&profile_name))?;
                let available_secrets = profile.sorted_secret_names();

                let err = SecretSpecError::SecretNotFound(format!(
                    "Secret '{}' is not defined in profile '{}'. Available secrets: {}",
                    name,
                    profile_name,
                    available_secrets.join(", ")
                ));
                // Provider is unknown for an undefined secret, so attribute to None.
                self.record_key_error(AuditAction::Set, &profile_name, name, None, None, &err);
                return Err(err);
            }
        };

        let backend = match self.write_provider_for_route(&planned.route) {
            Ok(backend) => backend,
            Err(err) => {
                self.record_key_error(AuditAction::Set, &profile_name, name, None, None, &err);
                return Err(err);
            }
        };

        let addr = planned.as_address(&self.config.project.name, &profile_name);
        // Refuse before prompting for a value. The provider states the reason:
        // a store may be writable through the convention layout yet reject the
        // `ref` this secret names.
        if let Err(err) = backend.check_writable(addr) {
            self.record_key_error(
                AuditAction::Set,
                &profile_name,
                name,
                Some(backend.uri()),
                None,
                &err,
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
            self.record_key_error(
                AuditAction::Set,
                &profile_name,
                name,
                Some(backend.uri()),
                None,
                &err,
            );
            return Err(err);
        }

        let result = backend.set(addr, &value);
        self.audit_write_result(
            &result,
            name,
            &profile_name,
            Some(backend.uri()),
            planned.reference(),
        );
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
        // Plan the secret exactly as batch resolution would, so the read route,
        // address, and effective config are the same decisions `check`/`run`
        // make. `None` means it is not declared in this profile.
        let planned = match self.plan_secret(name, &profile_name, None) {
            Ok(Some(planned)) => planned,
            // Planning failed (e.g. an undefined provider alias). Still an
            // attempted read, so audit it like the batch path audits every
            // planning failure; no provider can be attributed yet.
            Err(err) => {
                self.record_key_error(AuditAction::Get, &profile_name, name, None, None, &err);
                return Err(err);
            }
            Ok(None) => {
                // The secret is not defined, so no provider can be attributed.
                // Audit the failed read for parity with `set`'s undefined path.
                let err = SecretSpecError::SecretNotFound(name.to_string());
                self.record_key_error(AuditAction::Get, &profile_name, name, None, None, &err);
                return Err(err);
            }
        };
        let default = planned.config.default.clone();
        let as_path = planned.as_path();

        // Walk the route's chain in order; each entry is resolved lazily and a
        // broken link is skipped with a warning, so an undefined alias never
        // blocks a provider elsewhere in the chain from answering.
        let read_specs = planned.route.specs();
        let result = self.get_secret_from_providers(
            name,
            planned.as_address(&self.config.project.name, &profile_name),
            read_specs.as_deref(),
        );

        // Audit the access at the provider boundary, before defaults are applied.
        // The provider URI consulted is reported back so the chain miss/error
        // attributes to the last provider tried rather than guessing. The native
        // coordinates (if any) are recorded alongside, since the provider URI
        // names only the store.
        let reference = planned.reference();
        match &result {
            Ok((Some(_), uri)) => self.record(
                AuditAction::Get,
                &profile_name,
                AuditOutcome::Found,
                AuditFields {
                    key: Some(name),
                    provider_uri: uri.clone(),
                    reference,
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
                    reference,
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
                    reference,
                    ..Default::default()
                },
            ),
            Err(e) => {
                self.record_key_error(AuditAction::Get, &profile_name, name, None, reference, e)
            }
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
        // audit event, so re-validating here must not emit another `Check`. This
        // is the value-injecting path (`run`), so it materializes fully.
        let validation_result = self.validate_audited(false, Materialize::Values)?;

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
                    let default_backend = self.get_provider(provider_arg.as_deref())?;

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

                    // Prompt for each missing secret. Each write goes through the
                    // plan's route and address, the same decisions `set` executes.
                    for (i, secret_name) in missing.iter().enumerate() {
                        if let Some(planned) = self.plan_secret(
                            secret_name,
                            &profile_display,
                            provider_arg.as_deref(),
                        )? {
                            let prompt_msg =
                                format!("[{}/{}] Enter value for {}:", i + 1, total, secret_name,);
                            let prompt = inquire::Password::new(&prompt_msg).without_confirmation();

                            let value = prompt.prompt()?;

                            let backend = self.write_provider_for_route(&planned.route)?;
                            let set_result = backend.set(
                                planned.as_address(&self.config.project.name, &profile_display),
                                &SecretString::new(value.into()),
                            );
                            self.audit_write_result(
                                &set_result,
                                secret_name,
                                &profile_display,
                                Some(backend.uri()),
                                planned.reference(),
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
                    match self.validate_audited(false, Materialize::Values)? {
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
            // Create the "from" provider and check availability. `build_provider`
            // expands a provider alias used as the import source.
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

            // Process each secret using proper profile resolution: the plan
            // supplies the same write route and address `set` executes. Sorted
            // names keep the per-secret summary lines in a stable order.
            for name in profile.sorted_secret_names() {
                read_names.push(name.clone());
                let planned = self
                    .plan_secret(&name, &profile_display, None)?
                    .expect("Secret should exist since we're iterating over it");
                let description = planned.config.description.as_deref();

                let to_provider = self.write_provider_for_route(&planned.route)?;

                // The secret's address (native `ref` coordinates or convention
                // naming) applies to both stores: naming is orthogonal to
                // which store holds the value.
                let addr = planned.as_address(&self.config.project.name, &profile_display);
                // First check if the secret exists in the "from" provider
                match from_provider_instance.get(addr)? {
                    Some(value) => {
                        // Secret exists in "from" provider, check if it exists in "to" provider
                        match to_provider.get(addr)? {
                            Some(_) => {
                                eprintln!(
                                    "{} {} - {} {} (→ {})",
                                    "○".yellow(),
                                    name,
                                    description.unwrap_or("No description"),
                                    "(already exists in target)".yellow(),
                                    to_provider.name().blue()
                                );
                                already_exists += 1;
                            }
                            None => {
                                // Secret doesn't exist in "to" provider, import it.
                                let set_result = to_provider.set(addr, &value);
                                // Audit each copied secret as a write attributed to the
                                // target provider, so import writes are recorded like
                                // `set`/generate/prompt. The bulk Import event below only
                                // captures the source read, not where secrets were copied.
                                self.audit_write_result(
                                    &set_result,
                                    &name,
                                    &profile_display,
                                    Some(to_provider.uri()),
                                    planned.reference(),
                                );
                                set_result?;
                                eprintln!(
                                    "{} {} - {} (→ {})",
                                    "✓".green(),
                                    name,
                                    description.unwrap_or("No description"),
                                    to_provider.name().blue()
                                );
                                imported += 1;
                            }
                        }
                    }
                    None => {
                        // Secret doesn't exist in "from" provider
                        // Check if it exists in the "to" provider
                        match to_provider.get(addr)? {
                            Some(_) => {
                                eprintln!(
                                    "{} {} - {} {} (→ {})",
                                    "○".blue(),
                                    name,
                                    description.unwrap_or("No description"),
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
                                    description.unwrap_or("No description"),
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
            // Record a failed/partial import with the secrets read before the
            // error (already in sorted order, from the import loop).
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

    /// Whether an absent secret would be auto-generated on a full resolve: it
    /// declares an enabled `generate` config. Lets the value-free pass report
    /// that a missing secret *would* resolve via generation without minting and
    /// storing it (the side effect [`Self::try_generate_secret`] performs). A
    /// `generate`-enabled secret with no declared type still counts here; the
    /// resulting "no type" error is raised only on the full pass that actually
    /// generates, keeping the value-free preflight failure-free.
    fn would_generate(secret_config: &crate::config::Secret) -> bool {
        matches!(&secret_config.generate, Some(g) if g.is_enabled())
    }

    /// Attempts to generate a secret if it has generation config.
    ///
    /// Returns `Ok(Some(value))` if generation succeeded,
    /// `Ok(None)` if generation is not configured,
    /// or `Err` if generation was configured but failed.
    fn try_generate_secret(
        &self,
        planned: &PlannedSecret,
        profile_name: &str,
    ) -> Result<Option<SecretString>> {
        let name = planned.name.as_str();
        let gen_config = match &planned.config.generate {
            Some(config) if config.is_enabled() => config,
            _ => return Ok(None),
        };

        let secret_type = match &planned.config.secret_type {
            Some(t) => t.as_str(),
            None => {
                return Err(SecretSpecError::GenerationFailed(format!(
                    "Secret '{}' has generate config but no type",
                    name
                )));
            }
        };

        let value = crate::generator::generate(secret_type, gen_config)?;

        // Store the generated value at the plan's address, through the plan's
        // write route: the same decisions every other write path executes.
        let addr = planned.as_address(&self.config.project.name, profile_name);
        let backend = self.write_provider_for_route(&planned.route)?;
        // The provider states why a write is refused; wrapping it here would
        // only nest a second "Provider operation failed" prefix.
        backend.check_writable(addr)?;
        let set_result = backend.set(addr, &value);
        // Generating a secret writes a brand-new value to the provider; record it
        // like any other write so the audit log captures every stored secret.
        self.audit_write_result(
            &set_result,
            name,
            profile_name,
            Some(backend.uri()),
            planned.reference(),
        );
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
        self.validate_audited(true, Materialize::Values)
    }

    /// Resolve every declared secret into a value-carrying [`ResolveResponse`],
    /// the authoritative output other-language SDKs consume over the C ABI.
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
        self.resolve_impl(true)
    }

    /// Like [`Self::resolve`], but value-free and side-effect-free: every
    /// `value`/`path` in the response is `None`, no `as_path` temp file is ever
    /// written, and no missing generatable secret is minted or stored. Structure
    /// and provenance (`as_path`, `source`, `source_provider`,
    /// `missing_optional`) are still populated. This backs the `no_values`
    /// request path, so a policy/preflight consumer gets the resolve shape
    /// without persisting a secret to disk or mutating a provider. Resolution
    /// still queries providers so provenance can be reported — a value may
    /// transit memory transiently to learn whether it is present — but nothing
    /// is materialized; a missing required secret still fails the same way as
    /// [`Self::resolve`]. For a value-free view that tolerates missing required
    /// secrets, use [`Self::report`].
    pub fn resolve_without_values(&self) -> Result<ResolveResponse> {
        self.resolve_impl(false)
    }

    /// Shared core of [`Self::resolve`]/[`Self::resolve_without_values`].
    /// `include_values` gates whether resolved secret values are copied into the
    /// response and, in turn, whether the underlying pass mints generated
    /// secrets and writes `as_path` temp files at all.
    fn resolve_impl(&self, include_values: bool) -> Result<ResolveResponse> {
        let materialize = if include_values {
            Materialize::Values
        } else {
            Materialize::None
        };
        match self.validate_audited(true, materialize)? {
            Ok(mut validated) => {
                // Persist as_path temp files so returned paths outlive this call.
                // Only the full pass writes any: under `Materialize::None` no
                // temp file is ever created, so there is nothing to persist and
                // nothing is left on disk.
                if include_values {
                    validated.keep_temp_files()?;
                }

                let mut secrets = BTreeMap::new();
                for entry in &validated.resolution {
                    if entry.status != ResolutionStatus::Resolved {
                        continue;
                    }
                    let source = if entry.generated {
                        ResolvedSource::Generated
                    } else if entry.default_applied {
                        ResolvedSource::Default
                    } else {
                        ResolvedSource::Provider
                    };
                    // Only copy the secret value out when the caller wants it;
                    // otherwise the bytes never enter the response.
                    let (value, path) = if !include_values {
                        (None, None)
                    } else {
                        let raw = validated
                            .resolved
                            .secrets
                            .get(&entry.name)
                            .expect("a Resolved entry always has a value")
                            .expose_secret()
                            .to_string();
                        if entry.as_path {
                            (None, Some(raw))
                        } else {
                            (Some(raw), None)
                        }
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

    /// Resolve every declared secret into a value-free [`ResolutionReport`]:
    /// per-secret status (resolved / missing-required / missing-optional) plus
    /// provenance, never a value. Unlike [`Self::resolve`], a missing required
    /// secret is reported as a `MissingRequired` status rather than failing the
    /// call, so this is the inventory/preflight view: it answers "what is
    /// declared and how would each secret resolve" even for a profile whose
    /// secrets the caller cannot fully provide. It is the same report the CLI
    /// surfaces as `check --json` / `check --explain`, exposed to the SDKs.
    ///
    /// This pass is value-free and side-effect-free: it never mints or stores a
    /// generatable secret and never writes an `as_path` temp file. A secret that
    /// *would* be generated on a real resolve is reported as resolved
    /// (`generated`), so the report still answers "would this resolve" without
    /// mutating any provider or touching disk.
    pub fn report(&self) -> Result<ResolutionReport> {
        Ok(match self.validate_audited(true, Materialize::None)? {
            Ok(validated) => validated.report(),
            Err(errors) => errors.report(),
        })
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
    ///
    /// `materialize` gates the pass's two side effects (minting+storing a
    /// generated secret, and writing `as_path` temp files). [`Materialize::None`]
    /// runs the identical resolution but skips both, so the value-free entry
    /// points reach the same per-secret status without mutating a provider or
    /// touching disk; see [`Materialize`].
    fn validate_audited(
        &self,
        emit_check: bool,
        materialize: Materialize,
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
        // The profile is resolved once; its sorted names serve both as the
        // audit keys and as the plan's input, so nothing is merged or sorted
        // twice.
        let profile_result = self.resolve_profile(Some(&profile_name));
        // Keys for the single read-audit event, computed before any planning
        // can fail (e.g. on an undefined alias) so a failed read is still
        // attributed to every secret it attempted; they stay empty only if the
        // profile itself fails to resolve.
        let audit_keys: Vec<String> = profile_result
            .as_ref()
            .map(|profile| profile.sorted_secret_names())
            .unwrap_or_default();

        // Decide the whole profile up front (pure, no I/O), then execute the
        // plan. Each step returns `Result`, so *any* error — an undefined
        // alias, an unsupported `ref` coordinate, a fallback-chain outage, a
        // report-URI failure — is captured in `result` and recorded as the
        // single `Check` event below rather than escaping unaudited. `record`
        // is a no-op when auditing is off.
        let result: Result<std::result::Result<ValidatedSecrets, ValidationErrors>> =
            profile_result
                .and_then(|_| self.build_plan_from_names(profile_name.clone(), audit_keys.clone()))
                .and_then(|plan| self.execute_plan(&plan, materialize));

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

    /// Rejects a `ref` routed at exactly one store that cannot honor its
    /// coordinates. Run per primary-store group right after the provider is
    /// built and before any fetch is spawned, so the definite error surfaces up
    /// front (and, in the value-free report, without a fetch at all).
    ///
    /// A single store is consulted when the route has no fallback — an
    /// override, a single-provider chain, or the default provider — so no other
    /// store could answer instead. A `ref` on a multi-store chain is
    /// deliberately skipped: its coordinates are validated per store as the
    /// chain is walked at read time, so a coordinate a later store cannot
    /// express never blocks a primary that can.
    ///
    /// [`Provider::resolve_coords`](crate::provider::Provider::resolve_coords)
    /// reads the provider's declared supported coordinates and does no I/O for
    /// a native address.
    fn check_single_store_ref_coords(
        group: &[&PlannedSecret],
        provider: &dyn ProviderTrait,
    ) -> Result<()> {
        for planned in group {
            // Only the routes that consult exactly one store; a chain with a
            // fallback defers coordinate checking to per-store read time.
            if planned.route.fallback_specs().is_some() {
                continue;
            }
            if let Some(native) = planned.reference() {
                provider.resolve_coords(Address::Native(native))?;
            }
        }
        Ok(())
    }

    /// Executes a [`ResolutionPlan`]: the I/O half of resolution.
    ///
    /// Consumes the plan's already-decided groups, routes, and addresses — it
    /// derives nothing itself. It builds a provider per primary-store group,
    /// fetches the groups concurrently, then walks each secret: a primary hit is
    /// recorded; a miss falls through the secret's resolved fallback chain, then
    /// generation, then the committed default, before being reported missing. A
    /// primary that *errored* (rather than merely lacked the secret) with no
    /// fallback to try surfaces that error instead of a spurious "missing", so a
    /// machine consumer can tell an outage from an unprovisioned secret.
    ///
    /// `materialize` gates the two side effects (minting+storing a generated
    /// secret and writing `as_path` temp files); [`Materialize::None`] runs the
    /// identical resolution but skips both, reaching the same per-secret status
    /// without mutating a provider or touching disk.
    fn execute_plan(
        &self,
        plan: &ResolutionPlan,
        materialize: Materialize,
    ) -> Result<std::result::Result<ValidatedSecrets, ValidationErrors>> {
        let project = self.config.project.name.as_str();
        let profile = plan.profile.as_str();

        let mut secrets: HashMap<String, SecretString> = HashMap::new();
        let mut missing_required = Vec::new();
        let mut missing_optional = Vec::new();
        let mut with_defaults = Vec::new();
        let mut temp_files = Vec::new();
        // Per-secret provenance for the value-free resolution report.
        let mut resolution: Vec<SecretResolution> = Vec::new();
        // Credential-free `uri()` of each successfully built primary provider
        // group, keyed by the group's primary URI, so a primary hit can be
        // attributed to the provider that answered.
        let mut group_uris: HashMap<Option<&str>, String> = HashMap::new();

        // Batch fetch from each provider group. A failure here (e.g. an
        // unauthenticated vault) does not abort resolution: secrets that declare
        // a fallback chain are retried per-secret below, and secrets in the
        // failed group with no fallback surface the original error rather than
        // being reported as missing.
        let mut fetched_values: HashMap<String, SecretString> = HashMap::new();
        let mut failed_primary_uris: HashMap<Option<&str>, SecretSpecError> = HashMap::new();

        // Construction is cheap and stays on this thread; only the fetches run
        // concurrently below.
        let mut group_fetches: Vec<(Option<&str>, Vec<&PlannedSecret>, Box<dyn ProviderTrait>)> =
            Vec::new();
        for (provider_uri, group) in plan.groups() {
            match self.get_provider(provider_uri) {
                Ok(provider) => {
                    // Attribute primary hits to the provider's own credential-free
                    // `uri()`, never the raw configured alias (which may embed a
                    // token). Recorded before the fetch so attribution survives a
                    // partial batch.
                    group_uris.insert(provider_uri, provider.uri());
                    group_fetches.push((provider_uri, group, provider));
                }
                Err(e) => {
                    // Construction failed: only the raw alias exists, so redact it.
                    let shown = provider_uri.map(crate::audit::redact_uri_strict);
                    warn_primary_provider_failure(shown.as_deref(), &e);
                    failed_primary_uris.insert(provider_uri, e);
                }
            }
        }

        // Reject up front, before any store is contacted, a `ref` routed at
        // exactly one store that cannot honor its coordinates: with no fallback
        // to answer instead, the failure is definite and better surfaced now
        // than mid-fetch.
        for (_, group, provider) in &group_fetches {
            Self::check_single_store_ref_coords(group, provider.as_ref())?;
        }

        // Fetch the groups concurrently: each group is at least one provider
        // round-trip. One thread per group mirrors the per-item threading
        // providers already do inside `get_many`. A single group (the common
        // case) stays on this thread.
        let fetch_group =
            |(provider_uri, group, provider): (_, Vec<&PlannedSecret>, Box<dyn ProviderTrait>)| {
                let result = Self::fetch_group(&*provider, &group, project, profile);
                (provider_uri, result)
            };
        let fetch_results: Vec<(Option<&str>, Result<_>)> = if group_fetches.len() <= 1 {
            group_fetches.into_iter().map(fetch_group).collect()
        } else {
            std::thread::scope(|scope| {
                let handles: Vec<_> = group_fetches
                    .into_iter()
                    .map(|group| scope.spawn(|| fetch_group(group)))
                    .collect();
                handles
                    .into_iter()
                    .map(|handle| handle.join().expect("group fetch thread panicked"))
                    .collect()
            })
        };

        for (provider_uri, result) in fetch_results {
            match result {
                Ok(batch_results) => fetched_values.extend(batch_results),
                Err(e) => {
                    // A provider was built; attribute to its credential-free
                    // `uri()`, already recorded in `group_uris` above.
                    let display_uri = group_uris.get(&provider_uri).map(String::as_str);
                    warn_primary_provider_failure(display_uri, &e);
                    failed_primary_uris.insert(provider_uri, e);
                }
            }
        }

        // Process each planned secret: apply the fetched value, its fallback
        // chain, generation, or default, and record a value-free provenance entry
        // for the resolution report.
        for planned in &plan.secrets {
            let name = &planned.name;
            let required = planned.required();
            let as_path = planned.as_path();
            let primary_uri = planned.route.primary();

            let status;
            let mut source_provider = None;
            let mut default_applied = false;
            let mut generated = false;

            match fetched_values.remove(name.as_str()) {
                Some(value) => {
                    source_provider = group_uris.get(&primary_uri).cloned();
                    // Copy the value into the response only on a full pass; a
                    // value-free pass has the status it needs and never
                    // materializes a value or writes a temp file.
                    if materialize == Materialize::Values {
                        self.insert_resolved(
                            &mut secrets,
                            &mut temp_files,
                            name.clone(),
                            value,
                            as_path,
                        )?;
                    }
                    status = ResolutionStatus::Resolved;
                }
                None => {
                    let primary_failed = failed_primary_uris.contains_key(&primary_uri);

                    // The primary missed, so now walk the fallback — tried in
                    // order, each entry resolved lazily inside the chain walk; an
                    // undefined alias is skipped with a warning so a working
                    // provider after it still answers. An override or the
                    // default store has no fallback.
                    let (fallback_value, fallback_uri) = match planned.route.fallback_specs() {
                        Some(fallback) => {
                            let resolved = self.get_secret_from_providers(
                                name,
                                planned.as_address(project, profile),
                                Some(fallback),
                            )?;
                            // A primary that errored plus an exhausted fallback
                            // chain is not "missing": the authoritative provider
                            // is unreachable and might hold the value. Surface the
                            // primary error, exactly as the no-fallback arm below.
                            if resolved.0.is_none() && primary_failed {
                                let err = failed_primary_uris
                                    .remove(&primary_uri)
                                    .expect("primary_failed implies entry present");
                                return Err(err);
                            }
                            resolved
                        }
                        // No alternative chain and the primary failed: surface the
                        // original error rather than reporting a spurious missing.
                        None if primary_failed => {
                            let err = failed_primary_uris
                                .remove(&primary_uri)
                                .expect("primary_failed implies entry present");
                            return Err(err);
                        }
                        None => (None, None),
                    };

                    if let Some(value) = fallback_value {
                        source_provider = fallback_uri;
                        if materialize == Materialize::Values {
                            self.insert_resolved(
                                &mut secrets,
                                &mut temp_files,
                                name.clone(),
                                value,
                                as_path,
                            )?;
                        }
                        status = ResolutionStatus::Resolved;
                    } else if Self::would_generate(&planned.config) {
                        // The secret would be auto-generated. A full pass mints and
                        // stores it (writing a temp file when `as_path`); a
                        // value-free pass reports that it would resolve without
                        // minting or storing anything.
                        generated = true;
                        if materialize == Materialize::Values {
                            let generated_value = self
                                .try_generate_secret(planned, profile)?
                                .expect("would_generate implies a generated value");
                            self.insert_resolved(
                                &mut secrets,
                                &mut temp_files,
                                name.clone(),
                                generated_value,
                                as_path,
                            )?;
                        }
                        status = ResolutionStatus::Resolved;
                    } else if let Some(default_value) = &planned.config.default {
                        default_applied = true;
                        if materialize == Materialize::Values {
                            self.insert_resolved(
                                &mut secrets,
                                &mut temp_files,
                                name.clone(),
                                SecretString::new(default_value.clone().into()),
                                as_path,
                            )?;
                            with_defaults.push((name.clone(), default_value.clone()));
                        }
                        status = ResolutionStatus::Resolved;
                    } else if required {
                        missing_required.push(name.clone());
                        status = ResolutionStatus::MissingRequired;
                    } else {
                        missing_optional.push(name.clone());
                        status = ResolutionStatus::MissingOptional;
                    }
                }
            }

            resolution.push(SecretResolution {
                name: name.clone(),
                status,
                required,
                source_provider,
                default_applied,
                generated,
                as_path,
            });
        }

        let report_provider_uri = self.validation_report_provider_uri(
            plan.override_uri.as_deref(),
            plan.secrets.iter().map(|s| s.route.primary()),
        )?;

        if !missing_required.is_empty() {
            let mut errors = ValidationErrors::new(
                missing_required,
                missing_optional,
                with_defaults,
                report_provider_uri,
                profile.to_string(),
            );
            errors.resolution = resolution;
            Ok(Err(errors))
        } else {
            Ok(Ok(ValidatedSecrets {
                resolved: Resolved::new(secrets, report_provider_uri, profile.to_string()),
                missing_optional,
                with_defaults,
                resolution,
                temp_files,
            }))
        }
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

        let env_vars = child_env_from(
            env::vars_os(),
            validation_result
                .resolved
                .secrets
                .iter()
                .map(|(key, secret)| (key.clone(), secret.expose_secret().to_string())),
        );

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

    /// The `run` child environment must tolerate non-UTF-8 parent variables
    /// (`env::vars()` would panic on them — see #140) AND pass them through to
    /// the child untouched, unlike agent detection which drops them. Resolved
    /// secrets are added on top and overwrite same-named parent variables.
    #[cfg(unix)]
    #[test]
    fn child_env_passes_through_non_utf8_and_overlays_secrets() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let bad_val = OsString::from_vec(vec![0x64, 0x61, 0x63, 0xa3]); // "dac\xa3"
        let vars = vec![
            (OsString::from("CLEAN_KEY"), OsString::from("clean_value")),
            (OsString::from("BAD"), bad_val.clone()),
            (OsString::from("OVERRIDDEN"), OsString::from("parent_value")),
        ];
        let secrets = vec![
            ("SECRET_KEY".to_string(), "secret_value".to_string()),
            ("OVERRIDDEN".to_string(), "secret_wins".to_string()),
        ];

        let env = child_env_from(vars, secrets);

        // Non-UTF-8 parent entry survives byte-for-byte instead of panicking.
        assert_eq!(env.get(&OsString::from("BAD")), Some(&bad_val));
        assert_eq!(
            env.get(&OsString::from("CLEAN_KEY")),
            Some(&OsString::from("clean_value"))
        );
        // Secrets are injected and win over same-named parent variables.
        assert_eq!(
            env.get(&OsString::from("SECRET_KEY")),
            Some(&OsString::from("secret_value"))
        );
        assert_eq!(
            env.get(&OsString::from("OVERRIDDEN")),
            Some(&OsString::from("secret_wins"))
        );
        assert_eq!(env.len(), 4);
    }
}

/// Serializes tests that mutate the process-global current directory. The current
/// directory is shared across all threads, so two `set_current_dir` tests running
/// concurrently (the default under `cargo test`) would corrupt each other. Any test
/// that calls `set_current_dir` must hold this guard for its whole body. Poisoning
/// is recovered from (a panicking test leaves the lock poisoned but the data — unit
/// — is meaningless), so one failing test does not cascade into the others.
#[cfg(test)]
pub(crate) static CWD_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Locks [`CWD_GUARD`], recovering from a previous test's poison.
#[cfg(test)]
pub(crate) fn lock_cwd() -> std::sync::MutexGuard<'static, ()> {
    CWD_GUARD.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod config_discovery_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Walking up from a nested subdirectory finds the nearest ancestor
    /// `secretspec.toml`. This is the library half of "run secretspec from a
    /// subdirectory" (issue #59). It exercises `find_config_file_from` directly so
    /// no current-directory mutation is needed — the walk is fully deterministic.
    #[test]
    fn find_config_file_walks_up_to_nearest_ancestor() {
        let root = TempDir::new().unwrap();
        let manifest = root.path().join("secretspec.toml");
        fs::write(&manifest, "[project]\nname=\"x\"\nrevision=\"1.0\"\n").unwrap();

        let nested = root.path().join("a").join("b").join("c");
        fs::create_dir_all(&nested).unwrap();

        let found = find_config_file_from(nested).unwrap();
        // Compare canonicalized paths: on macOS the temp dir lives under a
        // `/var -> /private/var` symlink, so the raw paths differ.
        assert_eq!(
            found.canonicalize().unwrap(),
            manifest.canonicalize().unwrap()
        );
    }

    /// With no `secretspec.toml` anywhere up the tree, the walk reports a missing
    /// manifest rather than looping or panicking. (Assumes the temp dir's ancestors
    /// contain no `secretspec.toml`, which holds for the OS temp directory.)
    #[test]
    fn find_config_file_reports_missing_manifest() {
        let empty = TempDir::new().unwrap();
        assert!(matches!(
            find_config_file_from(empty.path().to_path_buf()),
            Err(SecretSpecError::NoManifest)
        ));
    }

    /// Loading via an explicit **relative** path resolves against the current
    /// directory — both a bare filename and a `../`-relative parent path. This is
    /// the `-f ../secretspec.toml` form from issue #59, and it is the case that
    /// regressed on Windows: `Config::try_from` calls `Path::canonicalize`, whose
    /// behavior on relative paths differs from Unix. Mutates the current directory,
    /// so it holds [`CWD_GUARD`].
    #[test]
    fn try_from_resolves_relative_paths_against_cwd() {
        let _cwd = lock_cwd();

        let root = TempDir::new().unwrap();
        fs::write(
            root.path().join("secretspec.toml"),
            "[project]\nname=\"x\"\nrevision=\"1.0\"\n\n[profiles.default]\n",
        )
        .unwrap();
        let sub = root.path().join("sub");
        fs::create_dir_all(&sub).unwrap();

        let original = env::current_dir().unwrap();

        // Bare filename from the manifest's own directory (the working case).
        env::set_current_dir(root.path()).unwrap();
        let from_cwd = Config::try_from(Path::new("secretspec.toml"));

        // `../`-relative path from a subdirectory (the case that failed on Windows).
        env::set_current_dir(&sub).unwrap();
        let from_parent = Config::try_from(Path::new("../secretspec.toml"));

        // Restore the current directory before any assertion (and before the
        // TempDir is dropped) so a failure cannot leave the process — or TempDir
        // cleanup, which cannot remove the current directory on Windows — wedged.
        env::set_current_dir(&original).unwrap();

        assert!(from_cwd.is_ok(), "bare filename: {:?}", from_cwd.err());
        assert!(
            from_parent.is_ok(),
            "../ relative path: {:?}",
            from_parent.err()
        );
    }
}

#[cfg(test)]
mod report_provider_tests {
    use super::*;

    /// The `provider` field of the resolution report / resolve response must not
    /// echo a credential embedded in a user-authored override or alias URI. That
    /// field is shown by `check --explain`, emitted by `--json`, and crosses the
    /// SDK boundary, so `validation_report_provider_uri` runs raw URIs through
    /// `redact_uri_strict` (the `provider.uri()` paths are already credential-free).
    #[test]
    fn report_provider_uri_redacts_credentials() {
        let spec = Secrets::new(
            Config {
                project: crate::config::Project {
                    name: "redact-test".to_string(),
                    ..Default::default()
                },
                profiles: HashMap::new(),
                providers: None,
            },
            None,
            None,
            None,
        );

        // Override branch: userinfo and query token are stripped.
        let got = spec
            .validation_report_provider_uri(
                Some("vault+token:s3cr3t@host/db?token=abc"),
                std::iter::empty(),
            )
            .unwrap();
        assert_eq!(got, "vault+token:host/db");
        assert!(!got.contains("s3cr3t") && !got.contains("abc"));

        // Per-secret alias branch: the first sorted primary URI is redacted too.
        let got = spec
            .validation_report_provider_uri(None, [Some("vault://host?token=zzz")].into_iter())
            .unwrap();
        assert_eq!(got, "vault://host");
        assert!(!got.contains("zzz"));
    }
}

#[cfg(test)]
mod reference_routing_tests {
    use super::*;
    use crate::config::Secret;

    fn spec_with_provider(provider: Option<&str>) -> Secrets {
        Secrets::new(
            Config {
                project: crate::config::Project {
                    name: "ref-test".to_string(),
                    ..Default::default()
                },
                profiles: HashMap::new(),
                providers: None,
            },
            None,
            provider.map(String::from),
            None,
        )
    }

    fn ref_secret(providers: Option<Vec<&str>>) -> Secret {
        Secret {
            description: Some("Sentry DSN".to_string()),
            reference: Some(crate::config::NativeAddress {
                item: "shared".to_string(),
                field: Some("SENTRY_DSN".to_string()),
                ..Default::default()
            }),
            providers: providers.map(|p| p.into_iter().map(String::from).collect()),
            ..Default::default()
        }
    }

    /// The read chain the shared router resolves for a secret, in the shape the
    /// read path consumes (`None` = default provider). Exercises the same
    /// `route_for` that the plan, `get`, and `set` route through.
    fn read_uris(
        spec: &Secrets,
        config: &Secret,
        override_arg: Option<&str>,
    ) -> Option<Vec<String>> {
        let override_uri = spec.resolve_provider_override(override_arg);
        spec.route_for(config, &override_uri).unwrap().specs()
    }

    /// A `ref` supplies naming only: it never contributes to the read chain,
    /// which stays whatever routing (here: nothing, so the default provider)
    /// resolves.
    #[test]
    fn reference_does_not_affect_read_routing() {
        let _env = crate::tests::scrub_resolution_env();
        let spec = spec_with_provider(None);
        let uris = read_uris(&spec, &ref_secret(None), None);
        assert_eq!(uris, None, "no routing configured, default store applies");
    }

    /// Uniform precedence: an explicit `--provider` override redirects ref
    /// secrets exactly like convention secrets, e.g. at a fixtures store
    /// during tests.
    #[test]
    fn override_redirects_reference() {
        let _env = crate::tests::scrub_resolution_env();
        let spec = spec_with_provider(Some("keyring"));
        let uris = read_uris(&spec, &ref_secret(None), Some("dotenv://.env.mock"));
        assert_eq!(uris, Some(vec!["dotenv://.env.mock".to_string()]));
    }

    /// Routing for a ref secret follows its `providers` chain; inline
    /// `scheme://` entries pass through without an alias declaration.
    #[test]
    fn reference_routes_through_providers_chain() {
        let _env = crate::tests::scrub_resolution_env();
        let spec = spec_with_provider(None);
        let uris = read_uris(
            &spec,
            &ref_secret(Some(vec!["onepassword://Production", "keyring://"])),
            None,
        );
        assert_eq!(
            uris,
            Some(vec![
                "onepassword://Production".to_string(),
                "keyring://".to_string()
            ])
        );
    }

    /// The write path follows the same routing: first chain entry without an
    /// override, the override when present.
    #[test]
    fn write_provider_follows_routing() {
        let _env = crate::tests::scrub_resolution_env();
        let spec = spec_with_provider(None);
        let write_provider = |override_arg: Option<&str>| {
            let override_uri = spec.resolve_provider_override(override_arg);
            let route = spec
                .route_for(
                    &ref_secret(Some(vec!["onepassword://Production"])),
                    &override_uri,
                )
                .unwrap();
            spec.write_provider_for_route(&route).unwrap()
        };

        assert_eq!(write_provider(None).name(), "onepassword");
        assert_eq!(write_provider(Some("dotenv://.env.mock")).name(), "dotenv");
    }

    /// Run the executor's pre-fetch coordinate check over a plan holding a
    /// single `default`-profile secret, exactly as `execute_plan` runs it: one
    /// built provider per primary-store group.
    fn check_ref_coords_of(secret: Secret) -> Result<()> {
        let mut secrets = HashMap::new();
        secrets.insert("SECRET".to_string(), secret);
        let spec = Secrets::new(crate::tests::resolve_test_config(secrets), None, None, None);
        let plan = spec.build_plan(None).unwrap();
        for (primary, group) in plan.groups() {
            let provider = spec.get_provider(primary).unwrap();
            Secrets::check_single_store_ref_coords(&group, provider.as_ref())?;
        }
        Ok(())
    }

    /// A `ref` routed at a single store that cannot honor its coordinates is
    /// rejected up front: dotenv keys have no `field`, so a `field` ref fails.
    #[test]
    fn single_store_ref_with_unsupported_coord_is_rejected() {
        let _env = crate::tests::scrub_resolution_env();
        assert!(
            check_ref_coords_of(ref_secret(Some(vec!["dotenv:///tmp/x"]))).is_err(),
            "a single-store ref with an unsupported coordinate must be rejected"
        );
    }

    /// The same unsupported `ref` on a multi-store chain is NOT rejected up
    /// front: coordinate checking defers to per-store read-time, so a later
    /// store that cannot express the coordinate never blocks a primary that can.
    #[test]
    fn multi_store_ref_defers_coord_validation() {
        let _env = crate::tests::scrub_resolution_env();
        assert!(
            check_ref_coords_of(ref_secret(Some(vec!["dotenv:///tmp/a", "dotenv:///tmp/b"])))
                .is_ok(),
            "a multi-store ref must defer coordinate checking to read time"
        );
    }
}
