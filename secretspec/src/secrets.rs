//! Core secrets management functionality

use crate::CallerContext;
use crate::audit::{AuditAction, AuditContext, AuditLogger, AuditOutcome};
use crate::cache::{self, CacheEntryStatus, CacheOwnership};
use crate::config::{
    Config, CredentialSource, ExtractFormat, GlobalConfig, NativeAddress, Profile, ProviderAlias,
    RequireReason, Resolved, SecretEncoding, SecretExtract,
};
use crate::error::{Result, SecretSpecError};
use crate::manifest::{CompiledManifest, MissingPolicy};
use crate::plan::{PlannedSecret, ResolutionPlan, ResolvedCache, Route};
use crate::provider::{
    Address, OwnedAddress, ProducedValuePersistence, Provider as ProviderTrait,
    ProviderCredentials, same_storage_container,
};
use crate::report::{ResolutionReport, ResolutionStatus, SecretResolution};
use crate::resolve::{
    NamedResolution, RESOLVE_SCHEMA_VERSION, ResolveResponse, ResolvedSecret, ResolvedSource,
};
use crate::validation::{ConstraintKind, ConstraintViolation, ValidatedSecrets, ValidationErrors};
use colored::Colorize;
use data_encoding::{
    BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD, Encoding, HEXLOWER, HEXLOWER_PERMISSIVE,
};
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::TryFrom;
use std::env;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Format the human-facing name and optional description used by status output.
///
/// The name carries the visual emphasis while the description is secondary.
/// When no description is available, omit it entirely instead of printing a
/// repetitive placeholder (and avoid leaving a dangling separator).
fn format_secret_label(name: &str, description: Option<&str>) -> String {
    match description {
        Some(description) => format!(
            "{} {} {}",
            name.cyan().bold(),
            "-".dimmed(),
            description.dimmed()
        ),
        None => name.cyan().bold().to_string(),
    }
}

/// Preserve the established missing-secret error for ordinary required fields,
/// while retaining structured group diagnostics for cross-secret constraints.
fn validation_failure(errors: ValidationErrors) -> SecretSpecError {
    if errors.constraint_violations.is_empty() {
        SecretSpecError::RequiredSecretMissing(errors.missing_required.join(", "))
    } else {
        SecretSpecError::ValidationFailed(Box::new(errors))
    }
}

/// Which declared secrets a single-secret resolution can see.
///
/// A scope narrows what a session resolves, but it is a `check`/`run`/`export`
/// concept: `secretspec get NAME` names one secret and has no `--scope`, so it
/// reads the whole profile. The SDK's [`Secrets::resolve_named`] resolves the
/// session's surface instead, scope included.
#[derive(Clone, Copy)]
enum Surface {
    /// The scope intersection, or the whole profile when no scope is active.
    Scoped,
    /// Every secret the profile declares, whatever the active scope.
    WholeProfile,
}

impl Surface {
    fn names(self, secrets: &Secrets, profile: &str) -> Result<Vec<String>> {
        match self {
            Self::Scoped => secrets.resolve_profile_secret_names(Some(profile)),
            Self::WholeProfile => secrets.profile_secret_names_unscoped(Some(profile)),
        }
    }
}

/// Translates a resolution entry's provenance flags into the value-carrying
/// response's [`ResolvedSource`]. Shared so a batch resolve and a named one
/// cannot disagree about where a value came from.
fn resolved_source(entry: &SecretResolution) -> ResolvedSource {
    if entry.generated {
        ResolvedSource::Generated
    } else if entry.default_applied {
        ResolvedSource::Default
    } else if entry.composed {
        ResolvedSource::Composed
    } else {
        ResolvedSource::Provider
    }
}

/// Stands in for a secret's name in diagnostics when the active scope hides it.
///
/// Every accessed-but-not-visible secret is by construction a dependency of a
/// visible composed secret, so this describes what it is without disclosing
/// which secret it is.
pub(crate) const HIDDEN_SECRET_LABEL: &str = "a hidden composition input";

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

/// The error for a declared provider credential that could not be found in its
/// source provider. Names the credential, the provider needing it, the exact
/// location searched, and how to fix it.
fn credential_missing_error(name: &str, alias_spec: &str, location: &str) -> SecretSpecError {
    SecretSpecError::ProviderOperationFailed(format!(
        "credential '{name}' for provider '{alias_spec}' was not found in {location}; \
         store it there with `secretspec config provider login {alias_spec}`"
    ))
}

/// An alias's credential entries sorted by semantic name. The one
/// ordering rule, so fetch order, validation-error order, and the login prompt
/// order all agree.
fn sorted_credential_entries(
    credentials: &HashMap<String, CredentialSource>,
) -> Vec<(&String, &CredentialSource)> {
    let mut entries: Vec<(&String, &CredentialSource)> = credentials.iter().collect();
    entries.sort_by_key(|(name, _)| name.as_str());
    entries
}

/// Warn that a cache operation failed. A cache only accelerates a route, so its
/// failures are reported and never turn a successful operation into an error.
fn cache_warning(secret_name: &str, message: impl std::fmt::Display) {
    eprintln!(
        "{} cache failed for {}: {}",
        "warning:".yellow(),
        secret_name.bold(),
        message
    );
}

/// As [`cache_warning`], for a failure on the read path, where the authoritative
/// route still gets its turn.
fn cache_read_warning(secret_name: &str, message: impl std::fmt::Display) {
    cache_warning(
        secret_name,
        format!("{message}; consulting authoritative providers"),
    );
}

/// The secrets of one cache group, for a warning that covers all of them: a
/// cache store that cannot be built or read fails every secret it holds, and
/// naming them once is more useful than one warning per secret.
fn group_names(group: &[&PlannedSecret]) -> String {
    group
        .iter()
        .map(|planned| planned.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// What a stored cache entry can do for the read that found it.
enum CachedEntry {
    /// Fresh, and written for this route: serve it.
    Fresh(SecretString),
    /// A SecretSpec entry no read will serve: expired regardless of owner, or
    /// ours but unreadable or written for another route or freshness policy.
    /// Safe to drop.
    Stale,
    /// Not ours to serve *or* to drop: another project's entry, or a value
    /// SecretSpec never wrote.
    Foreign,
}

/// Decide what a stored entry is worth to this read.
///
/// Most cache stores cannot expire a value on their own, so this check *is* the
/// expiry: the envelope records its absolute expiration time. An entry that
/// merely no longer applies (route change, expiry) is a silent miss; one that
/// belongs to someone else is warned about, since it means this route is
/// addressing a store something else writes to.
fn cached_entry(
    planned: &PlannedSecret,
    cache: &ResolvedCache,
    stored: &SecretString,
    project: &str,
    profile: &str,
) -> CachedEntry {
    let route_fingerprint = planned.cache_fingerprint(cache, project, profile);
    match cache::inspect_entry(
        stored,
        project,
        profile,
        &route_fingerprint,
        cache.max_age_secs,
    ) {
        Ok(CacheEntryStatus::Fresh(value)) => CachedEntry::Fresh(value),
        Ok(CacheEntryStatus::Stale) => CachedEntry::Stale,
        Ok(CacheEntryStatus::OursUnreadable) => {
            cache_read_warning(&planned.name, "the cache entry could not be read");
            CachedEntry::Stale
        }
        Ok(CacheEntryStatus::Foreign { project, profile }) => {
            cache_read_warning(
                &planned.name,
                format!("the cache holds {project}/{profile}'s entry at this address"),
            );
            CachedEntry::Foreign
        }
        Ok(CacheEntryStatus::Unrecognized) => {
            cache_read_warning(
                &planned.name,
                "the cache holds a value SecretSpec did not write",
            );
            CachedEntry::Foreign
        }
        Err(error) => {
            cache_read_warning(&planned.name, error);
            CachedEntry::Stale
        }
    }
}

/// Convention-path profile segment for provider credentials. A provider's
/// authentication (an access token, an AppRole id) is a property of the alias,
/// not of any one profile, so a convention-path credential is stored under one
/// fixed segment rather than the active profile. Scoping it by profile would
/// make a credential stored via `config provider login` (which runs under the
/// session profile) invisible when the provider is later used under a different
/// profile, hard-erroring with "credential not found".
const PROVIDER_CREDENTIAL_SCOPE: &str = "_provider";

impl CredentialSource {
    /// Credential-free provider text for prompts and diagnostics.
    pub(crate) fn display_provider(&self) -> String {
        crate::audit::redact_uri_strict(&self.provider)
    }

    /// The store location this source reads and writes: the pinned `ref`, or
    /// the profile-independent convention path for the active project. The
    /// single derivation both [`Secrets::resolve_provider_credentials`] (read)
    /// and [`Secrets::store_provider_credential`] (write) use, so
    /// login-then-resolve round-trips regardless of the profile either runs
    /// under.
    fn address<'a>(&'a self, project: &'a str, name: &'a str) -> Address<'a> {
        match &self.reference {
            Some(reference) => Address::Native(reference),
            None => Address::convention(project, PROVIDER_CREDENTIAL_SCOPE, name),
        }
    }

    /// Human-readable `<provider> at <location>` for prompts and errors,
    /// describing exactly what [`Self::address`] resolves to. The source spec
    /// is redacted: a URI-form source may embed an inline credential
    /// (`onepassword+token://tok@Vault`), and this string reaches stderr and
    /// the `config provider login` output.
    fn location(&self, project: &str, name: &str) -> String {
        let provider = self.display_provider();
        match &self.reference {
            Some(reference) => format!("{provider} at {}", reference.render()),
            None => format!("{provider} at {project}/{PROVIDER_CREDENTIAL_SCOPE}/{name}"),
        }
    }
}

type ProviderCredentialsKey = (String, String);
type ProviderCredentialsSlot = Arc<Mutex<Option<ProviderCredentials>>>;
type ProviderKey = (String, String);
type ProviderSlot = Arc<Mutex<Option<Arc<dyn ProviderTrait>>>>;
type GroupFetch<'a> = (
    Option<&'a str>,
    Vec<&'a PlannedSecret>,
    Box<dyn ProviderTrait>,
);
type FallbackReadResult = Result<(Option<SecretString>, Option<String>, Option<NativeAddress>)>;

struct PreparedImport {
    planned: PlannedSecret,
    target_provider: Box<dyn ProviderTrait>,
    source_address: OwnedAddress,
    target_address: OwnedAddress,
    source_value: Option<SecretString>,
    target_value: Option<SecretString>,
    copied: bool,
    source_deleted: bool,
}

/// One selectable alias whose address mapping diverges from a literal import
/// source even though both providers address the same storage container.
struct ImportAliasDivergence {
    alias: String,
    affected_secrets: Vec<String>,
}

/// Memoized provider credentials with single-flight population per key.
///
/// The outer mutex protects only the key-to-slot map. Resolution runs while
/// holding the selected slot, so callers for the same alias/profile wait for
/// its first fetch while unrelated keys can populate concurrently.
#[derive(Default)]
struct ProviderCredentialsCache {
    entries: Mutex<HashMap<ProviderCredentialsKey, ProviderCredentialsSlot>>,
}

impl ProviderCredentialsCache {
    fn get_or_try_init<F>(
        &self,
        key: ProviderCredentialsKey,
        resolve: F,
    ) -> Result<ProviderCredentials>
    where
        F: FnOnce() -> Result<ProviderCredentials>,
    {
        let slot = {
            let mut entries = self.entries.lock().unwrap();
            Arc::clone(
                entries
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(Mutex::new(None))),
            )
        };

        let mut cached = slot.lock().unwrap();
        if let Some(credentials) = cached.as_ref() {
            return Ok(credentials.clone());
        }

        match resolve() {
            Ok(credentials) => {
                *cached = Some(credentials.clone());
                Ok(credentials)
            }
            Err(err) => {
                // Do not memoize failures: a later operation may succeed after
                // credentials or provider availability change.
                drop(cached);
                let mut entries = self.entries.lock().unwrap();
                if entries
                    .get(&key)
                    .is_some_and(|current| Arc::ptr_eq(current, &slot))
                {
                    entries.remove(&key);
                }
                Err(err)
            }
        }
    }

    #[cfg(any(feature = "cli", test))]
    fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

/// Operation-scoped built providers with single-flight construction per key.
///
/// A provider memoizes connection state to serve a batch, but a fallback chain
/// is walked per secret, so rebuilding there discards it every time: with
/// `akv?auth=cli` each rebuild re-spawns the Azure CLI. Locking mirrors
/// [`ProviderCredentialsCache`]: the outer mutex guards only the key-to-slot
/// map, so callers for one spec wait on its first construction while unrelated
/// specs build concurrently. A fresh cache is created for every resolution so
/// provider-local snapshots cannot leak into a later operation.
#[derive(Default)]
struct ProviderCache {
    entries: Mutex<HashMap<ProviderKey, ProviderSlot>>,
}

impl ProviderCache {
    fn get_or_try_init<F>(&self, key: ProviderKey, build: F) -> Result<Arc<dyn ProviderTrait>>
    where
        F: FnOnce() -> Result<Box<dyn ProviderTrait>>,
    {
        let slot = {
            let mut entries = self.entries.lock().unwrap();
            Arc::clone(
                entries
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(Mutex::new(None))),
            )
        };

        let mut cached = slot.lock().unwrap();
        if let Some(provider) = cached.as_ref() {
            return Ok(Arc::clone(provider));
        }

        match build() {
            Ok(provider) => {
                let provider: Arc<dyn ProviderTrait> = Arc::from(provider);
                *cached = Some(Arc::clone(&provider));
                Ok(provider)
            }
            Err(err) => {
                // Do not memoize failures, for the same reason the credentials
                // cache does not: a later operation may succeed once provider
                // availability or credentials change.
                drop(cached);
                let mut entries = self.entries.lock().unwrap();
                if entries
                    .get(&key)
                    .is_some_and(|current| Arc::ptr_eq(current, &slot))
                {
                    entries.remove(&key);
                }
                Err(err)
            }
        }
    }
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
    /// Full pass for `run`: the same materialization as `Values`, plus secure
    /// controlling-terminal input for declarations with `prompt = true`.
    Run,
    /// Value-free pass: never write a generated secret back to a provider and
    /// never persist a secret to disk. A generatable-but-absent secret is still
    /// reported as it *would* resolve, without minting it. Backs `report()` and
    /// `resolve_without_values()`.
    None,
}

impl Materialize {
    fn values(self) -> bool {
        self != Self::None
    }

    fn prompts(self) -> bool {
        self == Self::Run
    }
}

/// A logical value in the shape exposed to callers. Inline values remain
/// secret strings; file-shaped values carry their owner so the caller decides
/// whether cleanup follows the resolved-value lifetime or the path is kept.
enum PreparedSecret {
    Inline(SecretString),
    File {
        owner: tempfile::NamedTempFile,
        path: String,
    },
}

/// Whether a resolved string came from a storage boundary and is eligible for
/// decoding, or is already the logical value produced inside SecretSpec.
#[derive(Clone, Copy)]
enum ResolvedRepresentation {
    Stored,
    Logical,
}

/// Walks up from the current directory looking for `secretspec.toml`.
pub(crate) fn find_config_file() -> Result<PathBuf> {
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
    /// Effective profile semantics compiled once from `config` and shared by
    /// planning, runtime resolution, and inventory surfaces.
    pub(crate) manifest: CompiledManifest,
    /// Directory containing the loaded `secretspec.toml`. Relative filesystem
    /// paths held by file-backed providers (e.g. `dotenv`) are resolved against
    /// this rather than the process's current working directory, so running
    /// from a subdirectory with `--file ../secretspec.toml` still finds the
    /// `.env` files next to the config.
    pub(crate) config_dir: PathBuf,
    /// Optional global user configuration
    global_config: Option<GlobalConfig>,
    /// The provider to use (if set via builder)
    provider: Option<String>,
    /// The profile to use (if set via builder)
    profile: Option<String>,
    /// The active secret scope (if set via builder/`--scope`/`SECRETSPEC_SCOPE`).
    /// `None` resolves the complete profile; a scope narrows resolution to the
    /// intersection of the merged profile and the scope's secret list.
    scope: Option<String>,
    /// When `true`, [`Self::resolve_scope_name`] does not fall back to the
    /// ambient `SECRETSPEC_SCOPE` environment variable. Set by the typed loaders
    /// that `secretspec-derive` generates: they expect the full generated shape,
    /// so an environment scope narrowing the resolved set below that shape would
    /// surface as a spurious `RequiredSecretMissing`. An explicitly set scope
    /// (builder/`set_scope`) is still honored — only the ambient fallback is cut.
    ignore_ambient_scope: bool,
    /// Reason for this session's secret access, forwarded to providers that
    /// support audit logging (set via [`Secrets::with_reason`]).
    reason: Option<String>,
    /// Software integration that invoked SecretSpec. This is audit context, not
    /// a user-supplied reason, and never satisfies `require_reason`.
    caller: Option<CallerContext>,
    /// Project policy (`[project].require_reason` in secretspec.toml) controlling
    /// when secret access requires an explicit reason.
    require_reason: RequireReason,
    /// Audit logger, if auditing is enabled (user-global `[audit]` config). `None`
    /// disables auditing. Built once per `Secrets` so all events share a session id.
    audit: Option<AuditLogger>,
    /// Provider credentials memoized per (profile, raw provider spec), so N
    /// secrets routed at one alias fetch its credentials from the source provider
    /// once per session, not once per provider build. The stored *values* are
    /// profile-independent (see `PROVIDER_CREDENTIAL_SCOPE`); the profile is kept
    /// in the key only so each profile's operations audit their own credential
    /// read. Cleared by [`Secrets::store_provider_credential`] so a freshly
    /// stored credential is re-read.
    provider_credentials_cache: ProviderCredentialsCache,
    /// Optional CLI-owned observer for writes that are about to prompt for or
    /// consume a value. Library and SDK instances leave this unset, so planning
    /// a write never produces unsolicited output outside the CLI.
    write_target_reporter: Option<WriteTargetReporter>,
    /// Test seam for deterministic run-prompt coverage. Production CLI
    /// instances leave this unset and use the controlling terminal.
    prompt_reader: Option<PromptReader>,
}

/// Credential-free description of one provider write, computed after routing
/// and writability checks but before the value is read or prompted for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WriteTarget {
    pub name: String,
    pub provider_uri: String,
    pub profile: String,
    pub target: String,
}

type WriteTargetReporter = Arc<dyn Fn(&WriteTarget) + Send + Sync>;
type PromptReader = Arc<dyn Fn(&str, &str) -> Result<SecretString> + Send + Sync>;

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

/// Trims `value` and returns it owned when non-empty, or `None` when the input
/// is blank (empty or whitespace-only). The single choke point for the "blank
/// means unset" rule: a stray empty `--provider`/`--profile`, a whitespace-only
/// override, or a padded env var (a trailing newline from `$(cat file)` is the
/// common CI case) neither shadows the configured fallback chain nor is stored
/// verbatim — the value that survives is always trimmed.
pub(crate) fn non_blank(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Normalizes a session reason: trims surrounding whitespace and treats a blank
/// result as "no reason given". Applied to every reason source so the policy gate
/// and the audit log agree on what counts as a real reason (a blank `--reason ""`
/// or `SECRETSPEC_REASON=` must not satisfy the policy). Kept pure for testability.
///
/// Shared with providers (e.g. Proton Pass) so the gate and the audit reason agree
/// on what counts as a real reason.
pub(crate) fn normalize_reason(reason: &str) -> Option<String> {
    non_blank(reason)
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
        let manifest = CompiledManifest::compile(&config);
        Self {
            config,
            manifest,
            config_dir: PathBuf::from("."),
            global_config,
            provider,
            profile,
            scope: None,
            ignore_ambient_scope: false,
            reason: None,
            caller: None,
            require_reason: RequireReason::Never,
            audit: None,
            provider_credentials_cache: ProviderCredentialsCache::default(),
            write_target_reporter: None,
            prompt_reader: None,
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
        // enforces the same rules the config documents. The compiled manifest it
        // produces is the one stored below, so the effective view is compiled
        // exactly once per load.
        let manifest = project_config.validate_and_compile()?;
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
            manifest,
            config_dir,
            global_config,
            provider: None,
            profile: None,
            scope: None,
            ignore_ambient_scope: false,
            reason: env_reason(),
            caller: None,
            audit,
            provider_credentials_cache: ProviderCredentialsCache::default(),
            write_target_reporter: None,
            prompt_reader: None,
        })
    }

    /// Installs the CLI's write-target observer. The provider and core library
    /// only compute credential-free target metadata; presentation stays with
    /// the caller that explicitly opts in.
    #[cfg(any(feature = "cli", test))]
    pub(crate) fn set_write_target_reporter(
        &mut self,
        reporter: impl Fn(&WriteTarget) + Send + Sync + 'static,
    ) {
        self.write_target_reporter = Some(Arc::new(reporter));
    }

    #[cfg(test)]
    pub(crate) fn set_prompt_reader(
        &mut self,
        reader: impl Fn(&str, &str) -> Result<SecretString> + Send + Sync + 'static,
    ) {
        self.prompt_reader = Some(Arc::new(reader));
    }

    /// Sets the provider to use for secret operations
    ///
    /// This overrides the provider from global configuration.
    /// Blank input (empty or whitespace-only) is ignored, so a blank
    /// `--provider` or `SECRETSPEC_PROVIDER` cannot shadow the configured
    /// fallback chain. CI templates and workflow `env:` maps routinely
    /// materialize unset values as empty strings. A padded-but-nonblank value
    /// is trimmed before it is stored, so a trailing newline from `$(cat file)`
    /// does not select a nonexistent provider (see [`non_blank`]).
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
        if let Some(provider) = non_blank(&provider.into()) {
            self.provider = Some(provider);
        }
    }

    /// Sets the profile to use for secret operations
    ///
    /// This overrides the profile from global configuration.
    /// Blank input is ignored, matching [`Secrets::set_provider`].
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
        if let Some(profile) = non_blank(&profile.into()) {
            self.profile = Some(profile);
        }
    }

    /// Sets the active secret scope for resolution.
    ///
    /// A scope narrows every subsequent resolution (`check`, `run`, `export`, and
    /// the SDK resolve paths) to the intersection of the selected profile and the
    /// scope's declared secrets, so a single service loads only what it needs.
    /// Leaving the scope unset resolves the complete profile, exactly as before
    /// scopes existed.
    ///
    /// Blank input is ignored, matching [`Secrets::set_provider`]/[`Secrets::set_profile`].
    /// Note that ignoring it is *not* on its own enough to stop a blank
    /// `--scope` from narrowing: with no scope stored, resolution falls back to
    /// an ambient `SECRETSPEC_SCOPE`. A caller that means "resolve the whole
    /// profile" must also call [`Self::set_ignore_ambient_scope`], as the CLI
    /// does for a blank flag.
    ///
    /// # Arguments
    ///
    /// * `scope` - The scope name as declared under `[scopes]` in `secretspec.toml`
    pub fn set_scope(&mut self, scope: impl Into<String>) {
        if let Some(scope) = non_blank(&scope.into()) {
            self.scope = Some(scope);
        }
    }

    /// Suppresses the ambient `SECRETSPEC_SCOPE` fallback in scope resolution.
    ///
    /// This says "the scope has been decided by this caller; do not consult the
    /// environment". Two callers mean it: the typed loaders generated by
    /// `secretspec-derive`, so an environment scope cannot narrow a typed load
    /// below the full generated struct shape it expects, and the CLI on a blank
    /// `--scope`, so an explicit opt-out clears an inherited scope instead of
    /// deferring to it. An explicitly set scope ([`Self::set_scope`]) is still
    /// honored — only the environment fallback is cut. Untyped SDK and FFI
    /// resolution that sets no scope keeps honoring `SECRETSPEC_SCOPE`.
    pub fn set_ignore_ambient_scope(&mut self, ignore: bool) {
        self.ignore_ambient_scope = ignore;
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

    /// Records the software integration that invoked SecretSpec.
    ///
    /// Caller context describes *what* is requesting secrets, while
    /// [`Secrets::with_reason`] records the user-supplied explanation of *why*.
    /// It is included in audit events and forwarded to providers, but it never
    /// satisfies the project's `require_reason` policy.
    ///
    /// Blank names are ignored. Optional fields are trimmed and blank values are
    /// dropped. The context is caller-asserted metadata rather than an
    /// authenticated identity; it must not contain credentials or secret values.
    ///
    /// Available since SecretSpec 0.20.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use secretspec::{CallerContext, Secrets};
    ///
    /// let spec = Secrets::load().unwrap().with_caller(
    ///     CallerContext::new("git")
    ///         .with_operation("credential_get")
    ///         .with_resource("github.com"),
    /// );
    /// spec.check(false).unwrap();
    /// ```
    pub fn with_caller(mut self, caller: CallerContext) -> Self {
        if let Some(caller) = caller.normalized() {
            self.caller = Some(caller);
        }
        self
    }

    /// Sets a session reason only when none is already in effect.
    ///
    /// This is the "supply a fallback" form of [`Secrets::with_reason`]: an
    /// embedding application can describe *itself* ("nightly export job") without
    /// overwriting the more specific reason its own caller passed through
    /// `SECRETSPEC_REASON`. Calling `with_reason` for that purpose would silently
    /// discard the user's reason and put the wrapper's boilerplate in every audit
    /// log entry instead.
    ///
    /// The reason is normalized like every other source, so a blank or
    /// whitespace-only argument still leaves the session without a reason rather
    /// than storing an empty one. Precedence is therefore: an explicit
    /// [`Secrets::with_reason`], then `SECRETSPEC_REASON`, then this default.
    /// A default reason still counts as a reason for policy purposes. An
    /// integration that only wants to identify itself should use
    /// [`Secrets::with_caller`] instead.
    ///
    /// Available since SecretSpec 0.19.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use secretspec::Secrets;
    ///
    /// // Uses SECRETSPEC_REASON when the caller set one, "nightly export" otherwise.
    /// let spec = Secrets::load().unwrap().with_default_reason("nightly export");
    /// spec.check(false).unwrap();
    /// ```
    pub fn with_default_reason(mut self, reason: impl Into<String>) -> Self {
        if self.reason.is_none() {
            self.reason = normalize_reason(&reason.into());
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

    /// Builds a provider from a generic leaf spec (name or URI).
    ///
    /// Provider construction converges in [`Self::build_provider_with_credentials`]
    /// so the reason set via [`Secrets::with_reason`] reaches every instance.
    ///
    /// `profile` is the profile the caller resolved for the surrounding
    /// operation (`None` falls back to the session profile): an alias's
    /// convention-path credentials live at `{project}/{profile}/{credential}`,
    /// so the provider must be built for the same profile its secrets are
    /// addressed under.
    pub(crate) fn build_provider(
        &self,
        spec: String,
        profile: Option<&str>,
    ) -> Result<Box<dyn ProviderTrait>> {
        self.build_provider_for_use(spec, profile, false)
    }

    /// Builds the authoritative leaf selected by a planned route.
    ///
    /// The 0.19+ inline cache form is both a complete route and the alias for
    /// its one authoritative URI. Only planned route execution may unwrap that
    /// alias into the leaf; generic provider inputs (for example an import
    /// source) must still reject cached aliases as routes rather than silently
    /// bypassing their cache policy.
    fn build_route_provider(
        &self,
        spec: String,
        profile: Option<&str>,
    ) -> Result<Box<dyn ProviderTrait>> {
        self.build_provider_for_use(spec, profile, true)
    }

    fn build_provider_for_use(
        &self,
        spec: String,
        profile: Option<&str>,
        allow_inline_cached: bool,
    ) -> Result<Box<dyn ProviderTrait>> {
        // Reject a route where a leaf is required before resolving any of the
        // alias's credentials. Besides producing the route-specific error
        // consistently, this keeps an invalid import/source use from touching
        // credential stores merely to discover that it cannot build the alias.
        self.ensure_provider_use_allowed(&spec, allow_inline_cached)?;

        // When `spec` names an alias with a `credentials` map, resolve those
        // values from their source providers and hand them to the built provider.
        // Memoized per (profile, spec) so rebuilding a provider (per-secret chain walks,
        // interactive prompting) does not refetch the same credentials from
        // the source store, while a profile switch on this instance does not
        // reuse the other profile's credentials.
        let profile = self.resolve_profile_name(profile);
        let key = (profile.clone(), spec.clone());
        let credentials = self
            .provider_credentials_cache
            .get_or_try_init(key, || self.resolve_provider_credentials(&spec, &profile))?;
        self.build_provider_with_credentials(
            &spec,
            credentials,
            allow_inline_cached,
            Some(&profile),
        )
    }

    /// [`Self::build_provider`], memoized within one resolution so repeated
    /// builds of one spec share one provider and the connection state it holds.
    /// The caller owns the cache to prevent provider-local snapshots and session
    /// metadata from surviving into a later operation.
    fn shared_provider(
        &self,
        cache: &ProviderCache,
        spec: &str,
        profile: Option<&str>,
        allow_inline_cached: bool,
    ) -> Result<Arc<dyn ProviderTrait>> {
        let key = (self.resolve_profile_name(profile), spec.to_string());
        cache.get_or_try_init(key, || {
            self.build_provider_for_use(spec.to_string(), profile, allow_inline_cached)
        })
    }
    /// Rejects cached routes in construction contexts that require one leaf.
    /// Planned execution may unwrap only the inline form into its authoritative
    /// URI; a fallback-based cached alias remains a complete multi-store route.
    fn ensure_provider_use_allowed(&self, spec: &str, allow_inline_cached: bool) -> Result<()> {
        if self
            .cached_alias(spec)
            .is_some_and(|alias| !allow_inline_cached || alias.authoritative_uri().is_none())
        {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "cached provider alias '{spec}' is a complete route; select it through a \
                 secret's providers list, the default provider, or --provider"
            )));
        }
        Ok(())
    }

    /// Builds a leaf provider without resolving its declared credentials: for a
    /// credential source, so credential-source chains are at most one hop and
    /// cannot recurse, and for cache remediation, where the credential source
    /// itself may be what failed.
    ///
    /// Deliberately hands the provider no profile: a credential belongs to the
    /// alias rather than to any one profile ([`PROVIDER_CREDENTIAL_SCOPE`]), and
    /// [`CredentialSource::address`] must round-trip whichever profile stores and
    /// reads it. A `ref`-addressed credential would otherwise resolve in the
    /// storing profile's Infisical environment and read from the reading
    /// profile's, so a credential stored under `prod` would be missing under
    /// `dev`. Such a ref keeps needing an explicit `?env=`, which is
    /// profile-independent by construction.
    ///
    /// Cache remediation is the other caller and needs no profile either: it
    /// addresses through [`Self::cache_address`], which is a convention address
    /// carrying its own.
    pub(crate) fn build_source_provider(&self, spec: &str) -> Result<Box<dyn ProviderTrait>> {
        self.build_provider_with_credentials(spec, ProviderCredentials::new(), false, None)
    }

    /// The shared construction body behind generic, routed, and credential
    /// source providers: alias expansion, error enrichment, and the
    /// base-dir/reason/caller hooks live only here, so those paths cannot drift.
    fn build_provider_with_credentials(
        &self,
        spec: &str,
        credentials: ProviderCredentials,
        allow_inline_cached: bool,
        profile: Option<&str>,
    ) -> Result<Box<dyn ProviderTrait>> {
        // `build_source_provider` calls this body directly, so retain the guard
        // here as well as before credential initialization in the generic path.
        self.ensure_provider_use_allowed(spec, allow_inline_cached)?;
        // Resolve provider aliases here, at the single construction chokepoint, so
        // every caller that hands us a user-supplied spec gets alias expansion for
        // free and no new entry point can forget it. Resolution is a no-op on an
        // already-resolved URI (a `scheme://...` string is never an alias key), so
        // callers that pass pre-resolved URIs (the per-secret chain) are unaffected.
        let resolved = self.resolve_provider_spec(spec.to_string());
        let mut provider = crate::provider::provider_from_spec(resolved.as_str(), credentials)
            .map_err(|err| self.explain_unknown_provider(err, &resolved))?;
        provider.with_base_dir(&self.config_dir);
        provider.set_reason(self.reason.clone());
        provider.set_caller(self.caller.clone());
        // Context a native address cannot carry: a `ref` names coordinates only,
        // so a provider whose store is partitioned by something outside them
        // (Infisical's environment) reads the operation's profile here. It is
        // the profile the caller already resolved, so a provider and the
        // addresses handed to it never disagree about which profile is running.
        // `None` is for a credential source, which is profile-independent by
        // contract. Naming stays with the address; this never reaches
        // `uri`/`storage_identity`.
        if let Some(profile) = profile {
            provider.set_profile(profile);
        }
        Ok(provider)
    }

    /// Resolves the credentials declared by a provider alias, fetching each
    /// semantic `(name, source)` entry from its source provider.
    ///
    /// `profile` scopes the convention path a bare-string source reads from.
    /// Returns an empty map for a spec that is not an alias, or an alias with
    /// no credentials. A declared credential that cannot be found is a
    /// hard error naming exactly how to fix it. Sources pass
    /// [`Self::validate_credential_sources`] and are built without credentials, so a
    /// chain is at most one hop and cannot recurse. Each source read is audited
    /// with a `credential` marker, so the audit trail explains why the source
    /// store was touched during an operation on the target provider.
    pub(crate) fn resolve_provider_credentials(
        &self,
        spec: &str,
        profile: &str,
    ) -> Result<ProviderCredentials> {
        let mut credentials = ProviderCredentials::new();
        let Some(declared) = self
            .lookup_provider_alias_entry(spec)
            .and_then(ProviderAlias::credentials)
            .filter(|credentials| !credentials.is_empty())
        else {
            return Ok(credentials);
        };
        self.validate_credential_sources(spec)?;

        let project = self.config.project.name.clone();

        // One provider per distinct source spec, so credentials sharing a source
        // (e.g. AppRole role and secret ids from one vault) reuse the instance
        // and whatever it caches, instead of authenticating once per variable.
        let mut sources: HashMap<String, Box<dyn ProviderTrait>> = HashMap::new();

        for (name, source) in sorted_credential_entries(declared) {
            let source_provider = match sources.entry(source.provider.clone()) {
                std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(self.build_source_provider(&source.provider)?)
                }
            };
            let fetched = source_provider.get(source.address(&project, name));
            // Audit the source read (design: every secret access is recorded).
            // The key is the semantic credential name and the event carries a
            // `credential` marker plus the source provider's credential-free
            // `uri()`, so the trail explains why this store was touched.
            let (outcome, error_kind) = match &fetched {
                Ok(Some(_)) => (AuditOutcome::Found, None),
                Ok(None) => (AuditOutcome::Missing, None),
                Err(e) => (AuditOutcome::Error, Some(e.kind())),
            };
            self.record(
                AuditAction::Get,
                profile,
                outcome,
                AuditFields {
                    key: Some(name),
                    command: Some("credential"),
                    provider_uri: Some(source_provider.uri()),
                    reference: source.reference.as_ref(),
                    error_kind,
                    ..Default::default()
                },
            );
            match fetched? {
                Some(value) => {
                    credentials.insert(name.clone(), value);
                }
                None => {
                    return Err(credential_missing_error(
                        name,
                        spec,
                        &source.location(&project, name),
                    ));
                }
            }
        }

        Ok(credentials)
    }

    /// The credentials a provider alias declares, sorted by semantic name
    /// name, for the `config provider login` flow. Validates every source before
    /// returning any credentials. Errors if the alias is not defined; returns
    /// an empty list for an alias with no `credentials`.
    #[cfg(any(feature = "cli", test))]
    pub(crate) fn declared_provider_credentials(
        &self,
        alias: &str,
    ) -> Result<Vec<(String, CredentialSource)>> {
        // Validate the complete map before returning any entry. The login CLI
        // prompts and writes only after this method succeeds, so a later-sorted
        // invalid source cannot leave earlier credentials partially stored.
        self.validate_credential_sources(alias)?;
        let entry = self
            .lookup_provider_alias_entry(alias)
            .ok_or_else(|| SecretSpecError::ProviderNotFound(alias.to_string()))?;
        Ok(entry
            .credentials()
            .map(sorted_credential_entries)
            .unwrap_or_default()
            .into_iter()
            .map(|(name, source)| (name.clone(), source.clone()))
            .collect())
    }

    /// Stores one provider credential at its source provider — the exact
    /// location [`Self::resolve_provider_credentials`] later reads it from (a `ref`
    /// or the profile-independent convention path for the active project). Errors
    /// if the source provider is read-only. Returns a human-readable description
    /// of where it was stored.
    ///
    /// Like every other write path, the write is gated by the `require_reason`
    /// policy and audited (with a `credential` marker). A successful store also
    /// clears the credential memo, so a credential rotated through this instance
    /// is re-read instead of resolving to the stale cached value.
    #[cfg(any(feature = "cli", test))]
    pub(crate) fn store_provider_credential(
        &self,
        source: &CredentialSource,
        name: &str,
        value: &SecretString,
    ) -> Result<String> {
        self.ensure_reason_for(AuditAction::Set, Some(name))?;
        // The store location is profile-independent (see `PROVIDER_CREDENTIAL_SCOPE`);
        // the session profile attributes the audit event, and is the session
        // context handed to the provider.
        let profile = self.resolve_profile_name(None);
        let provider = self.build_source_provider(&source.provider)?;
        let project = self.config.project.name.clone();
        let address = source.address(&project, name);
        let result = provider
            .check_writable(address)
            .and_then(|()| provider.set(address, value));
        self.audit_write_result(
            &result,
            name,
            &profile,
            Some(provider.uri()),
            source.reference.as_ref(),
            Some("credential"),
        );
        result?;
        // The stored credential replaces whatever an earlier resolution
        // memoized; drop the memo so the next build re-reads it.
        self.provider_credentials_cache.clear();
        Ok(source.location(&project, name))
    }

    /// Validates a spec's `credentials` (pure map lookups, no I/O): every name
    /// must be accepted by the target provider, every source must resolve to a
    /// known provider, and no source may itself declare credentials. Credential
    /// chains are limited to one hop, which also makes cycles impossible.
    /// Run at plan time to fail fast on a routed primary or override, and again
    /// by [`Self::resolve_provider_credentials`], so every construction path —
    /// fallback links and the default provider included — enforces the same
    /// invariants instead of silently dropping a chained source's credentials.
    pub(crate) fn validate_credential_sources(&self, spec: &str) -> Result<()> {
        let Some(alias) = self.lookup_provider_alias_entry(spec) else {
            return Ok(());
        };
        let Some(credentials) = alias.credentials() else {
            return Ok(());
        };
        let resolved_target = self.resolve_provider_spec(spec.to_string());
        let supported = crate::provider::credential_names_for_spec(&resolved_target);
        let provider_name = crate::provider::provider_display_name_for_spec(&resolved_target);
        for (name, source) in sorted_credential_entries(credentials) {
            if !supported.contains(&name.as_str()) {
                let supported_display = if supported.is_empty() {
                    "none".to_string()
                } else {
                    supported.join(", ")
                };
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "credential '{name}' is not supported by provider '{provider_name}' \
                     for alias '{spec}' (supported credentials: {supported_display})"
                )));
            }
            // Compose the underlying error into the message instead of
            // replacing it: it carries the corrective guidance (the
            // `1password` -> `onepassword` hint, the defined-aliases listing)
            // that the other resolution paths give for the same mistakes.
            let context = |err: SecretSpecError| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "credential source for '{name}' in provider alias '{spec}': {err}"
                ))
            };
            let resolved = self
                .resolve_one_provider(&source.provider)
                .map_err(context)?;
            // `resolve_one_provider` passes URI-form specs through untouched,
            // so gate the resolved spec's scheme against the registry here:
            // a typo'd scheme should fail at plan time, not surface later as
            // a construction failure a fallback chain downgrades to a warning.
            let known = crate::provider::spec_names_known_provider(&resolved).map_err(context)?;
            if !known {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "credential source for '{name}' in provider alias '{spec}' names an unknown \
                     provider '{}'",
                    crate::audit::redact_uri_strict(&source.provider)
                )));
            }
            if let Some(source_alias) = self.lookup_provider_alias_entry(&source.provider)
                && source_alias
                    .credentials()
                    .is_some_and(|credentials| !credentials.is_empty())
            {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "provider alias '{}' cannot be a credential source for '{spec}' because it \
                     declares its own credentials; credential chains are limited to one hop",
                    source.provider
                )));
            }
        }
        Ok(())
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
    /// enabled (a no-op otherwise). Session-constant fields — project, caller,
    /// session reason, and whether auditing is on — are filled here so call sites
    /// specify only what varies. Single-secret (`get`/`set`/`delete`) and bulk
    /// (`check`/`run`/`import`) events go through this one method.
    fn record(
        &self,
        action: AuditAction,
        profile: &str,
        outcome: AuditOutcome,
        fields: AuditFields<'_>,
    ) {
        if let Some(logger) = &self.audit {
            // Scopes affect only these bulk resolution surfaces. `get`, `set`,
            // and `import` deliberately ignore an ambient scope, so attaching it
            // to those events would falsely imply that it constrained the action.
            let scope = match action {
                AuditAction::Check | AuditAction::Run | AuditAction::Export => {
                    self.resolve_scope_name(None)
                }
                AuditAction::Get
                | AuditAction::Set
                | AuditAction::Delete
                | AuditAction::Import
                | AuditAction::CacheClear
                | AuditAction::CacheRefresh => None,
            };
            logger.record(
                action,
                AuditContext {
                    project: &self.config.project.name,
                    profile,
                    scope: scope.as_deref(),
                    key: fields.key,
                    keys: fields.keys,
                    command: fields.command,
                    provider_uri: fields.provider_uri,
                    reference: fields.reference.map(NativeAddress::render),
                    outcome,
                    error_kind: fields.error_kind,
                    reason: self.reason.as_deref(),
                    caller: self.caller.as_ref(),
                },
            );
        }
    }

    /// Audits the result of a single secret or provider-credential write: a
    /// `Written` event on success, an `Error` event (tagged with
    /// the error kind) on failure. Centralizes the write-audit so every write
    /// path records the same way and a new one cannot accidentally diverge or
    /// skip auditing. `command` marks a special-purpose credential store;
    /// `None` denotes a plain secret write.
    fn audit_write_result(
        &self,
        result: &Result<()>,
        key: &str,
        profile: &str,
        provider_uri: Option<String>,
        reference: Option<&NativeAddress>,
        command: Option<&str>,
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
                command,
                provider_uri,
                reference,
                error_kind,
                ..Default::default()
            },
        );
    }

    /// Audits one durable provider deletion. `Ok(false)` is a successful,
    /// idempotent no-op and is recorded as `Missing`; cache invalidation has its
    /// own `CacheClear` events and is never conflated with this operation.
    fn audit_delete_result(
        &self,
        result: &Result<bool>,
        key: &str,
        profile: &str,
        provider_uri: Option<String>,
        reference: Option<&NativeAddress>,
    ) {
        let (outcome, error_kind) = match result {
            Ok(true) => (AuditOutcome::Deleted, None),
            Ok(false) => (AuditOutcome::Missing, None),
            Err(error) => (AuditOutcome::Error, Some(error.kind())),
        };
        self.record(
            AuditAction::Delete,
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

    /// Records a failed single-secret operation (`get`/`set`/`delete`) as an `Error`
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

    /// Decode a stored textual representation. Exactly one trailing LF or CRLF
    /// is ignored to accommodate a value captured from command output; every
    /// other non-alphabet character remains a hard error.
    fn decode_stored_value(
        encoding: SecretEncoding,
        diagnostic_name: &str,
        value: &SecretString,
    ) -> Result<SecretSlice<u8>> {
        let encoded = value
            .expose_secret()
            .strip_suffix("\r\n")
            .or_else(|| value.expose_secret().strip_suffix('\n'))
            .unwrap_or_else(|| value.expose_secret());

        fn decode_base(
            encoded: &[u8],
            padded: &Encoding,
            unpadded: &Encoding,
        ) -> std::result::Result<Vec<u8>, String> {
            if encoded.contains(&b'=') {
                padded.decode(encoded).map_err(|error| error.to_string())
            } else {
                padded
                    .decode(encoded)
                    .or_else(|_| unpadded.decode(encoded))
                    .map_err(|error| error.to_string())
            }
        }

        let decoded = match encoding {
            SecretEncoding::Base64 => decode_base(encoded.as_bytes(), &BASE64, &BASE64_NOPAD),
            SecretEncoding::Base64Url => {
                decode_base(encoded.as_bytes(), &BASE64URL, &BASE64URL_NOPAD)
            }
            SecretEncoding::Hex => HEXLOWER_PERMISSIVE
                .decode(encoded.as_bytes())
                .map_err(|error| error.to_string()),
        }
        .map_err(|reason| SecretSpecError::DecodeFailed {
            name: diagnostic_name.to_string(),
            encoding: encoding.as_str(),
            reason,
        })?;

        Ok(decoded.into())
    }

    /// Encode a logical UTF-8 value into the canonical stored representation
    /// for its declared encoding.
    fn encode_logical_value(encoding: SecretEncoding, value: &SecretString) -> SecretString {
        let bytes = value.expose_secret().as_bytes();
        let encoded = match encoding {
            SecretEncoding::Base64 => BASE64.encode(bytes),
            SecretEncoding::Base64Url => BASE64URL_NOPAD.encode(bytes),
            SecretEncoding::Hex => HEXLOWER.encode(bytes),
        };
        SecretString::new(encoded.into())
    }

    /// Return an encoded copy only when this secret declares an encoding. The
    /// caller can otherwise pass the original value through without cloning it.
    fn encoded_for_storage(planned: &PlannedSecret, value: &SecretString) -> Option<SecretString> {
        planned
            .encoding()
            .map(|encoding| Self::encode_logical_value(encoding, value))
    }

    /// Validate a stored value before import copies it into another provider.
    /// Import moves the stored representation verbatim, so an invalid encoded
    /// source must fail before any target write (and especially before source
    /// cleanup) instead of creating an unreadable destination.
    fn validate_import_value(
        planned: &PlannedSecret,
        diagnostic_name: &str,
        value: &SecretString,
    ) -> Result<()> {
        let Some(encoding) = planned.encoding() else {
            return Ok(());
        };
        let decoded = Self::decode_stored_value(encoding, diagnostic_name, value)?;
        if !planned.as_path() {
            std::str::from_utf8(decoded.expose_secret()).map_err(|error| {
                SecretSpecError::DecodeFailed {
                    name: diagnostic_name.to_string(),
                    encoding: encoding.as_str(),
                    reason: format!(
                        "decoded bytes are not valid UTF-8 ({error}); set `as_path = true` to expose binary data"
                    ),
                }
            })?;
        }
        Ok(())
    }

    /// Select one logical value from a structured stored representation.
    /// Diagnostics deliberately include only the secret name, format, pointer,
    /// and parser location — never the stored document or selected value.
    pub(crate) fn extract_stored_value(
        extract: &SecretExtract,
        diagnostic_name: &str,
        value: &str,
    ) -> Result<SecretString> {
        match extract.format {
            ExtractFormat::Json => {
                let document: serde_json::Value =
                    serde_json::from_str(value).map_err(|error| SecretSpecError::DecodeFailed {
                        name: diagnostic_name.to_string(),
                        encoding: extract.format.as_str(),
                        reason: format!("stored value is not valid JSON: {error}"),
                    })?;
                let selected = document.pointer(&extract.pointer).ok_or_else(|| {
                    SecretSpecError::DecodeFailed {
                        name: diagnostic_name.to_string(),
                        encoding: extract.format.as_str(),
                        reason: format!(
                            "JSON Pointer '{}' did not match the stored document",
                            extract.pointer
                        ),
                    }
                })?;
                let selected = match selected {
                    serde_json::Value::String(value) => value.clone(),
                    value => {
                        serde_json::to_string(value).expect("serializing JSON value cannot fail")
                    }
                };
                Ok(SecretString::new(selected.into()))
            }
        }
    }

    /// Decode and extract a stored representation independently of its exposure
    /// shape, then either return UTF-8 text or materialize the bytes to an
    /// owner-only file. Extraction follows decoding and applies only across a
    /// storage boundary; defaults and generated values are already logical.
    fn prepare_resolved(
        &self,
        planned: &PlannedSecret,
        diagnostic_name: &str,
        value: SecretString,
        representation: ResolvedRepresentation,
    ) -> Result<PreparedSecret> {
        let decoded = match (representation, planned.encoding()) {
            (ResolvedRepresentation::Stored, Some(encoding)) => {
                let value = Self::decode_stored_value(encoding, diagnostic_name, &value)?;
                Some((encoding, value))
            }
            _ => None,
        };

        let extracted = match (representation, planned.extract()) {
            (ResolvedRepresentation::Stored, Some(extract)) => {
                let text = match &decoded {
                    Some((encoding, decoded)) => {
                        std::str::from_utf8(decoded.expose_secret()).map_err(|error| {
                            SecretSpecError::DecodeFailed {
                                name: diagnostic_name.to_string(),
                                encoding: encoding.as_str(),
                                reason: format!(
                                    "decoded bytes are not valid UTF-8 and cannot be extracted as {} ({error})",
                                    extract.format.as_str()
                                ),
                            }
                        })?
                    }
                    None => value.expose_secret(),
                };
                Some(Self::extract_stored_value(extract, diagnostic_name, text)?)
            }
            _ => None,
        };

        if planned.as_path() {
            let bytes = extracted
                .as_ref()
                .map(|value| value.expose_secret().as_bytes())
                .or_else(|| decoded.as_ref().map(|(_, decoded)| decoded.expose_secret()))
                .unwrap_or_else(|| value.expose_secret().as_bytes());
            let (owner, path) = self.write_secret_to_temp_file(bytes)?;
            Ok(PreparedSecret::File { owner, path })
        } else if let Some(extracted) = extracted {
            Ok(PreparedSecret::Inline(extracted))
        } else if let Some((encoding, decoded)) = decoded {
            let text = std::str::from_utf8(decoded.expose_secret()).map_err(|error| {
                SecretSpecError::DecodeFailed {
                    name: diagnostic_name.to_string(),
                    encoding: encoding.as_str(),
                    reason: format!(
                        "decoded bytes are not valid UTF-8 ({error}); set `as_path = true` to expose binary data"
                    ),
                }
            })?;
            Ok(PreparedSecret::Inline(SecretString::new(
                text.to_owned().into(),
            )))
        } else {
            Ok(PreparedSecret::Inline(value))
        }
    }

    /// Inserts a resolved secret into the working set, applying its optional
    /// storage decoding and extraction when the value crossed a storage
    /// boundary, then transparently materializing an `as_path` value to an
    /// owner-only temp file whose lifetime is tied to `temp_files`. Shared by
    /// every resolution branch so stored-value transforms cannot drift.
    fn insert_resolved(
        &self,
        secrets: &mut HashMap<String, SecretString>,
        temp_files: &mut Vec<tempfile::NamedTempFile>,
        planned: &PlannedSecret,
        diagnostic_name: &str,
        value: SecretString,
        representation: ResolvedRepresentation,
    ) -> Result<()> {
        match self.prepare_resolved(planned, diagnostic_name, value, representation)? {
            PreparedSecret::Inline(value) => {
                secrets.insert(planned.name.clone(), value);
            }
            PreparedSecret::File { owner, path } => {
                temp_files.push(owner);
                secrets.insert(planned.name.clone(), SecretString::new(path.into()));
            }
        }
        Ok(())
    }

    /// Get a reference to the project configuration. Used by `secretspec
    /// codegen` (which needs the manifest, not a provider) and by tests.
    #[cfg(any(feature = "cli", test))]
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
            .or_else(|| {
                env::var("SECRETSPEC_PROFILE")
                    .ok()
                    .as_deref()
                    .and_then(non_blank)
            })
            .or_else(|| {
                self.global_config
                    .as_ref()
                    .and_then(|gc| gc.defaults.profile.clone())
            })
            .unwrap_or_else(|| "default".to_string())
    }

    /// Resolves the active scope name, or `None` when resolution should cover the
    /// complete profile.
    ///
    /// Precedence mirrors [`Self::resolve_profile_name`] minus the global default:
    /// an explicit argument, then the builder value ([`Self::set_scope`]), then
    /// `SECRETSPEC_SCOPE`. There is deliberately **no** user-global default — an
    /// unset scope always means "the whole profile", so a machine-level default
    /// can never silently drop secrets a project expects to resolve.
    pub(crate) fn resolve_scope_name(&self, scope: Option<&str>) -> Option<String> {
        scope
            .map(str::to_string)
            .or_else(|| self.scope.clone())
            .or_else(|| {
                // Typed loaders opt out of the ambient fallback (see
                // `ignore_ambient_scope`); an explicit scope above still applies.
                if self.ignore_ambient_scope {
                    return None;
                }
                env::var("SECRETSPEC_SCOPE")
                    .ok()
                    .as_deref()
                    .and_then(non_blank)
            })
    }

    /// The set of secret names the active scope admits, or `None` when no scope
    /// is active (meaning "no filtering — the whole profile participates").
    ///
    /// A scope's membership is profile-independent; the *effective* set is the
    /// intersection of this membership with the selected profile, which callers
    /// obtain by filtering the profile's names through the returned set.
    ///
    /// # Errors
    ///
    /// Returns [`SecretSpecError::InvalidScope`] when a scope is selected but not
    /// declared under `[scopes]` in `secretspec.toml`, listing the available
    /// scopes.
    fn active_scope_members(&self) -> Result<Option<HashSet<&str>>> {
        let Some(scope_name) = self.resolve_scope_name(None) else {
            return Ok(None);
        };
        let scope = self
            .config
            .scopes
            .as_ref()
            .and_then(|scopes| scopes.get(&scope_name))
            .ok_or_else(|| {
                let mut available: Vec<&str> = self
                    .config
                    .scopes
                    .iter()
                    .flat_map(|scopes| scopes.keys())
                    .map(String::as_str)
                    .collect();
                available.sort();
                let available = if available.is_empty() {
                    "none defined".to_string()
                } else {
                    available.join(", ")
                };
                SecretSpecError::InvalidScope(format!(
                    "'{}' is not defined in secretspec.toml. Available scopes: {}",
                    scope_name, available
                ))
            })?;
        Ok(Some(scope.secrets.iter().map(String::as_str).collect()))
    }

    /// The manifest-declared names an active scope does **not** admit. Empty
    /// when no scope is active.
    ///
    /// `run --scope` must actively remove these from the child's inherited
    /// environment. Injecting only the scoped subset is not enough on its own: a
    /// shell that already loaded the full profile (a devenv `secretspec run`, a
    /// prior `eval "$(secretspec export)"`) would otherwise pass the excluded
    /// values straight through to the child. This is secret minimization, not an
    /// authorization boundary — a child still holding provider credentials could
    /// resolve another scope itself.
    ///
    /// Membership, not the visible set (scope ∩ profile), decides this. A secret
    /// the scope lists is admitted even when the *selected* profile does not
    /// declare it: the scope said this consumer may hold it, and scopes are
    /// reusable across profiles that declare different subsets, so narrowing by
    /// profile here would unset a name the operator explicitly allowed. The
    /// same rule already governs an admitted secret that fails to resolve.
    /// Composed-secret dependencies the scope leaves out are not admitted, so
    /// they stay scrubbed: they are resolved to build a value, never exposed.
    fn scope_excluded_names(&self) -> Result<Vec<String>> {
        let Some(admitted) = self.active_scope_members()? else {
            return Ok(Vec::new());
        };
        // Scrub across *all* profiles, not only the selected one: a secret
        // declared under another profile can reach the child through the
        // inherited parent environment (a devenv shell, a prior `eval
        // "$(secretspec export)"`), and filtering only the selected profile
        // would let it leak.
        let mut excluded: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for profile in self.manifest.profiles.values() {
            for name in profile.secrets.keys() {
                if !admitted.contains(name.as_str()) {
                    excluded.insert(name.clone());
                }
            }
        }
        Ok(excluded.into_iter().collect())
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

    /// Validates that the profile exists and returns its effective secret names
    /// in sorted order — the union of the profile's own and the `default`
    /// profile's secrets, as the compiled manifest records them.
    ///
    /// # Arguments
    ///
    /// * `profile` - Optional profile name to resolve (if None, uses resolved profile name)
    ///
    /// # Errors
    ///
    /// Returns `InvalidProfile` when the named profile is not defined.
    pub(crate) fn resolve_profile_secret_names(
        &self,
        profile: Option<&str>,
    ) -> Result<Vec<String>> {
        let all = self.profile_secret_names_unscoped(profile)?;
        // An active scope narrows the profile to its membership intersection —
        // the single worklist that scopes every consumer at once, failing on an
        // unknown scope before any provider is touched.
        match self.active_scope_members()? {
            None => Ok(all),
            Some(members) => Ok(all
                .into_iter()
                .filter(|name| members.contains(name.as_str()))
                .collect()),
        }
    }

    /// Every secret name in `profile` (∪ `default`), sorted, with no scope
    /// filtering. `import` uses this directly so an ambient `SECRETSPEC_SCOPE`
    /// can't narrow a command that has no `--scope`.
    pub(crate) fn profile_secret_names_unscoped(
        &self,
        profile: Option<&str>,
    ) -> Result<Vec<String>> {
        let profile_name = profile
            .map(str::to_string)
            .unwrap_or_else(|| self.resolve_profile_name(None));
        self.require_profile(&profile_name)?;
        let compiled = self
            .manifest
            .profile(&profile_name)
            .expect("raw and compiled profile sets stay identical");
        // `CompiledProfile.secrets` is a sorted `BTreeMap`.
        Ok(compiled.secrets.keys().cloned().collect())
    }

    /// Expands the *visible* set (the scope ∩ profile output) to the set
    /// resolution must **access**: `visible` plus the transitive composed-secret
    /// dependency closure. An in-scope composed secret (e.g. `DATABASE_URL`) may
    /// reference secrets the scope leaves out (`DB_USER`, `DB_PASSWORD`); those
    /// must be fetched to render the composition, but they are dropped from the
    /// output afterwards so the scope never exposes them. Names not reachable
    /// from `visible` are never planned, so no provider is contacted for them.
    ///
    /// Sorted for a deterministic plan. Used only when a scope is active; with no
    /// scope the closure equals the whole profile and this is not called.
    fn accessed_names(&self, profile_name: &str, visible: &[String]) -> Vec<String> {
        fn visit(
            name: &str,
            profile: &crate::manifest::CompiledProfile,
            acc: &mut HashSet<String>,
        ) {
            if !acc.insert(name.to_string()) {
                return;
            }
            if let Some(secret) = profile.secrets.get(name)
                && let Some(template) = &secret.composition
            {
                for dependency in template.dependencies() {
                    visit(dependency, profile, acc);
                }
            }
        }

        let Some(profile) = self.manifest.profile(profile_name) else {
            return visible.to_vec();
        };
        let mut acc = HashSet::new();
        for name in visible {
            visit(name, profile, &mut acc);
        }
        let mut names: Vec<String> = acc.into_iter().collect();
        names.sort();
        names
    }

    /// Returns the effective configuration for a specific secret, or `None` if
    /// the profile does not carry it. The field-level merge with the `default`
    /// profile and `[defaults]` already happened once during manifest
    /// compilation ([`crate::config::Secret::resolved`]); this only reads it.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the secret
    /// * `profile` - Optional profile to search in (if None, uses resolved profile)
    pub(crate) fn resolve_secret_config(
        &self,
        name: &str,
        profile: Option<&str>,
    ) -> Option<crate::config::Secret> {
        let profile_name = self.resolve_profile_name(profile);
        self.manifest
            .profile(&profile_name)
            .and_then(|profile| profile.secrets.get(name))
            .map(|secret| secret.config.clone())
    }

    /// The effective (field-level merged) secrets of `profile_name` in
    /// name-sorted order, read directly off the compiled manifest. This is the
    /// view `check`/`run` list, matching what resolution acts on.
    ///
    /// Backs the `check` display, which runs only after resolution has already
    /// validated the active scope, so an unknown scope cannot reach here in
    /// practice. The error is propagated rather than discarded anyway: swallowing
    /// it would silently display the *whole* profile under a scope, which is the
    /// one thing this filter exists to prevent. The displayed set stays identical
    /// to the resolved set.
    fn effective_secrets(
        &self,
        profile_name: &str,
    ) -> Result<Vec<(String, crate::config::Secret)>> {
        let members = self.active_scope_members()?;
        Ok(self
            .manifest
            .profile(profile_name)
            .into_iter()
            .flat_map(|profile| &profile.secrets)
            .filter(|(name, _)| members.as_ref().is_none_or(|m| m.contains(name.as_str())))
            .map(|(name, secret)| (name.clone(), secret.config.clone()))
            .collect())
    }

    /// Provider-alias maps in lookup order: project `secretspec.toml` first,
    /// then user-global config. Project entries win on conflict so teams can
    /// pin shareable mappings in version control while still allowing per-user
    /// overrides via the global config.
    fn provider_alias_sources(&self) -> impl Iterator<Item = &HashMap<String, ProviderAlias>> {
        self.config.providers.iter().chain(
            self.global_config
                .as_ref()
                .and_then(|gc| gc.defaults.providers.as_ref()),
        )
    }

    /// Resolves a provider alias to its full entry (URI plus any provider
    /// credentials), walking [`Self::provider_alias_sources`] in order. Project
    /// entries win over user-global ones.
    pub(crate) fn lookup_provider_alias_entry(&self, alias: &str) -> Option<&ProviderAlias> {
        self.provider_alias_sources().find_map(|m| m.get(alias))
    }

    /// Resolves a single provider alias to its URI, walking
    /// [`Self::provider_alias_sources`] in order.
    fn lookup_provider_alias(&self, alias: &str) -> Option<String> {
        self.lookup_provider_alias_entry(alias)
            // An inline cached alias still names one leaf URI. Route planning
            // sees its cache policy first; provider construction resolves the
            // same alias to this URI so its credentials remain available.
            .and_then(|alias| alias.authoritative_uri())
            .map(str::to_string)
    }

    /// The cached route `spec` names, if it names one at all.
    ///
    /// A cached alias is a complete route rather than a store, so the paths that
    /// build or display a single provider all have to recognize one; asking here
    /// keeps that one question in one place.
    pub(crate) fn cached_alias(&self, spec: &str) -> Option<&ProviderAlias> {
        self.lookup_provider_alias_entry(spec)
            .filter(|alias| alias.is_cached())
    }

    pub(crate) fn resolve_provider_spec(&self, spec: String) -> String {
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
        if self.cached_alias(spec).is_some() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "cached provider alias '{spec}' is a complete route and cannot be used where a \
                 leaf provider is required"
            )));
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
    pub(crate) fn explicit_provider_spec(&self, override_arg: Option<&str>) -> Option<String> {
        override_arg
            .map(|spec| spec.to_string())
            .or_else(|| self.provider.clone())
            .or_else(|| {
                env::var("SECRETSPEC_PROVIDER")
                    .ok()
                    .as_deref()
                    .and_then(non_blank)
            })
    }

    /// Fetches one provider group's secrets through the provider's batch
    /// surface: every planned secret's [`Address`] (native `ref` coordinates or
    /// convention naming) is handed to `get_many`, which dedupes identical
    /// coordinates and batches or parallelizes as the store allows. The address
    /// is the one the plan already derived, so naming lives in exactly one place.
    fn fetch_group(
        &self,
        provider: &dyn ProviderTrait,
        provider_spec: Option<&str>,
        group: &[&PlannedSecret],
        project: &str,
        profile: &str,
    ) -> Result<HashMap<String, SecretString>> {
        let addresses = group
            .iter()
            .map(|planned| self.address_for_spec(planned, provider_spec, project, profile))
            .collect::<Result<Vec<_>>>()?;
        let requests: Vec<(&str, Address<'_>)> = group
            .iter()
            .zip(&addresses)
            .map(|(planned, address)| (planned.name.as_str(), address.as_address()))
            .collect();
        provider.get_many(&requests)
    }

    /// Cache-first read for a whole plan: one provider per distinct cache store,
    /// one batched read each.
    ///
    /// The per-secret path would build a provider and make a round trip for every
    /// cached secret before the authoritative route is even consulted — for a
    /// dotenv cache, re-reading and re-parsing the same file once per secret.
    /// Batching mirrors what [`Self::fetch_group`] already does for authoritative
    /// stores. Returns the fresh values by secret name, with the serving store's
    /// URI for provenance.
    fn read_cached_group(
        &self,
        plan: &ResolutionPlan,
        profile: &str,
    ) -> HashMap<String, (SecretString, String)> {
        // Grouped by cache spec (not URI) so an alias's `credentials` stays
        // reachable at build time, and sorted so warnings come out in a stable
        // order.
        let mut groups: BTreeMap<&str, Vec<&PlannedSecret>> = BTreeMap::new();
        for planned in &plan.secrets {
            if let Some(cache) = planned.route.as_ref().and_then(Route::cache) {
                groups.entry(cache.spec.as_str()).or_default().push(planned);
            }
        }

        let mut cached = HashMap::new();
        for (spec, group) in groups {
            let provider = match self.build_provider(spec.to_string(), Some(profile)) {
                Ok(provider) => provider,
                Err(error) => {
                    // One warning per unusable cache store, not per secret.
                    cache_read_warning(&group_names(&group), error);
                    continue;
                }
            };
            let requests: Vec<(&str, Address<'_>)> = group
                .iter()
                .map(|planned| {
                    (
                        planned.name.as_str(),
                        self.cache_address(profile, &planned.name),
                    )
                })
                .collect();
            let stored = match provider.get_many(&requests) {
                Ok(stored) => stored,
                Err(error) => {
                    cache_read_warning(&group_names(&group), error);
                    continue;
                }
            };
            let uri = provider.uri();
            for planned in group {
                let Some(stored) = stored.get(&planned.name) else {
                    continue;
                };
                let cache = planned
                    .route
                    .as_ref()
                    .and_then(Route::cache)
                    .expect("the group was built from secrets with a cached route");
                match cached_entry(planned, cache, stored, &self.config.project.name, profile) {
                    CachedEntry::Fresh(value) => {
                        cached.insert(planned.name.clone(), (value, uri.clone()));
                    }
                    CachedEntry::Stale => {
                        self.evict_cache_entry(provider.as_ref(), &planned.name, profile)
                    }
                    CachedEntry::Foreign => {}
                }
            }
        }
        cached
    }

    /// The address a cached entry lives at: SecretSpec's logical
    /// `{project}/{profile}/{secret}` naming, even when the authoritative
    /// provider addresses the secret through a native `ref`. One place, so the
    /// read, refresh, and invalidation paths cannot address different entries.
    fn cache_address<'a>(&'a self, profile: &'a str, name: &'a str) -> Address<'a> {
        Address::convention(&self.config.project.name, profile, name)
    }

    /// Refresh a cached route after its authoritative provider returns or
    /// accepts a value. Cache writes are best-effort: losing the acceleration
    /// layer must never turn a successful authoritative operation into failure.
    ///
    /// A refresh that fails drops the entry instead of leaving it: the value it
    /// holds has been superseded, so serving it until it expired would be worse
    /// than a cache miss.
    fn write_cached_secret(
        &self,
        planned: &PlannedSecret,
        route: &Route,
        profile: &str,
        value: &SecretString,
    ) {
        let Some(cache) = route.cache() else {
            return;
        };
        let provider = match self.build_provider(cache.spec.clone(), Some(profile)) {
            Ok(provider) => provider,
            Err(error) => {
                self.remediate_failed_cache_refresh(planned, cache, profile, error, None);
                return;
            }
        };
        // Refusing here rather than through the remediation path: what is at that
        // address is not ours, so it must be neither overwritten nor removed.
        if let Err(error) =
            self.check_cache_address_is_ours(provider.as_ref(), &planned.name, profile)
        {
            cache_warning(&planned.name, format!("not caching: {error}"));
            return;
        }
        let serialized = match cache::encode_entry(
            &self.config.project.name,
            profile,
            cache.max_age_secs,
            planned.cache_fingerprint(cache, &self.config.project.name, profile),
            value,
        ) {
            Ok(serialized) => serialized,
            Err(error) => {
                self.remediate_failed_cache_refresh(
                    planned,
                    cache,
                    profile,
                    error,
                    Some(provider.as_ref()),
                );
                return;
            }
        };
        let address = self.cache_address(profile, &planned.name);
        // Ask the store to expire the entry at the same age the envelope does.
        // Providers that cannot expire a value write it plainly; the envelope's
        // own `expires_at` is the freshness authority either way. A store that
        // *can* expire but fails to arrange it refuses the write, which lands
        // here as a warning and drops the entry — no unexpiring copy is left.
        let result = provider.check_writable(address).and_then(|()| {
            provider.set_expiring(
                address,
                &serialized,
                Duration::from_secs(cache.max_age_secs),
            )
        });
        let (outcome, error_kind) = match &result {
            Ok(()) => (AuditOutcome::Written, None),
            Err(error) => (AuditOutcome::Error, Some(error.kind())),
        };
        self.record(
            AuditAction::CacheRefresh,
            profile,
            outcome,
            AuditFields {
                key: Some(&planned.name),
                provider_uri: Some(provider.uri()),
                error_kind,
                ..Default::default()
            },
        );
        if let Err(error) = result {
            self.remediate_failed_cache_refresh(
                planned,
                cache,
                profile,
                error,
                Some(provider.as_ref()),
            );
        }
    }

    /// Report a failed refresh and make the superseded entry unusable.
    ///
    /// When normal cache construction failed (most commonly because a declared
    /// credential source is temporarily unavailable), retry construction
    /// without those declared credentials for remediation only. Providers may
    /// still authenticate from their standard environment or agent, allowing
    /// the old entry to be removed even though the configured credential source
    /// could not be read. If a provider was already built, reuse it.
    fn remediate_failed_cache_refresh(
        &self,
        planned: &PlannedSecret,
        cache: &ResolvedCache,
        profile: &str,
        failure: impl std::fmt::Display,
        provider: Option<&dyn ProviderTrait>,
    ) {
        cache_warning(&planned.name, failure);
        let result = match provider {
            Some(provider) => self.delete_cache_entry(provider, &planned.name, profile),
            None => self
                .build_source_provider(&cache.spec)
                .and_then(|provider| {
                    self.delete_cache_entry(provider.as_ref(), &planned.name, profile)
                }),
        };
        if let Err(error) = result {
            cache_warning(
                &planned.name,
                format!(
                    "could not drop the superseded entry either: {error}. Run \
                     `secretspec cache clear {}` — until then a read may serve the old value",
                    planned.name
                ),
            );
        }
    }

    /// Drop an entry a read found unusable.
    ///
    /// Most cache stores cannot expire a value themselves, so without this an
    /// entry the route can no longer serve would sit there — plaintext, past its
    /// `max_age` — until something happened to overwrite it. A refresh only
    /// overwrites it when the authoritative read succeeds *and* the pass
    /// materializes values, so neither an offline resolve nor a value-free
    /// `check` would ever clear it.
    ///
    /// Best effort: the read has already decided not to serve this entry, so a
    /// failure to remove it cannot change the outcome of the operation.
    fn evict_cache_entry(&self, provider: &dyn ProviderTrait, name: &str, profile: &str) {
        if let Err(error) = self.delete_cache_entry(provider, name, profile) {
            cache_warning(
                name,
                format!("could not drop an unusable cache entry: {error}"),
            );
        }
    }

    /// Whether this project and profile may write to or remove what sits at a
    /// cache address, naming the reason when they may not.
    ///
    /// A cache store can be shared: a flat dotenv file gives every project the
    /// same key for a given secret name, and a store may hold values SecretSpec
    /// never wrote. Overwriting is as destructive as deleting, so both go through
    /// here, and both refuse only on *positive* evidence that the value belongs
    /// to someone else. Silence is not evidence — an address that cannot be read
    /// is still ours to write and clear, which is what keeps an
    /// expired-but-recoverable KV v2 version destroyable.
    fn check_cache_address_is_ours(
        &self,
        provider: &dyn ProviderTrait,
        name: &str,
        profile: &str,
    ) -> Result<()> {
        let Ok(Some(stored)) = provider.get(self.cache_address(profile, name)) else {
            return Ok(());
        };
        match cache::ownership(&stored, &self.config.project.name, profile) {
            CacheOwnership::Ours | CacheOwnership::Expired | CacheOwnership::OursUnreadable => {
                Ok(())
            }
            CacheOwnership::Foreign { project, profile } => {
                Err(SecretSpecError::ProviderOperationFailed(format!(
                    "the cache holds {project}/{profile}'s entry for '{name}' at this address, so \
                     it is not ours to change. Give this project's cache a store or path of its own."
                )))
            }
            CacheOwnership::Unrecognized => Err(SecretSpecError::ProviderOperationFailed(format!(
                "the value stored for '{name}' is not a SecretSpec cache entry, so it is not ours \
                 to change. Check that the cache provider addresses a store only SecretSpec writes \
                 to."
            ))),
        }
    }

    /// Drop the cached entry for `name`, reporting whether one existed.
    ///
    /// A delete that removed nothing is not audited: no secret was touched, and
    /// recording it would make an empty cache indistinguishable from a real
    /// invalidation in the audit log.
    fn delete_cache_entry(
        &self,
        provider: &dyn ProviderTrait,
        name: &str,
        profile: &str,
    ) -> Result<bool> {
        self.check_cache_address_is_ours(provider, name, profile)?;
        let result = provider.delete(self.cache_address(profile, name));
        match &result {
            Ok(true) => self.record(
                AuditAction::CacheClear,
                profile,
                AuditOutcome::Deleted,
                AuditFields {
                    key: Some(name),
                    provider_uri: Some(provider.uri()),
                    ..Default::default()
                },
            ),
            Ok(false) => {}
            Err(error) => self.record_key_error(
                AuditAction::CacheClear,
                profile,
                name,
                Some(provider.uri()),
                None,
                error,
            ),
        }
        result
    }

    /// Drop the cached entry a route holds, reporting whether one existed.
    /// `Ok(false)` for a route with no cache: there is nothing to invalidate.
    fn invalidate_cached_secret(
        &self,
        planned: &PlannedSecret,
        route: &Route,
        profile: &str,
    ) -> Result<bool> {
        let Some(cache) = route.cache() else {
            return Ok(false);
        };
        let provider = self.build_provider(cache.spec.clone(), Some(profile))?;
        self.delete_cache_entry(provider.as_ref(), &planned.name, profile)
    }

    /// Keep the cache consistent with a successful authoritative write.
    ///
    /// A write through the cached route refreshes the entry. A write that
    /// *bypassed* the cache — the documented `--provider <leaf>` escape hatch,
    /// `SECRETSPEC_PROVIDER`, the builder — has to drop the entry it superseded
    /// instead, or every later read would serve the old value until it expired.
    fn sync_cache_after_write(
        &self,
        planned: &PlannedSecret,
        route: &Route,
        profile: &str,
        value: &SecretString,
    ) {
        if route.cache().is_some() {
            self.write_cached_secret(planned, route, profile, value);
            return;
        }
        // Only re-plan when the declared routing could name a cached route at
        // all: re-planning unconditionally would report an unrelated routing
        // problem (an undefined alias the override sidestepped) as a cache
        // warning on a write that succeeded.
        let default_spec = self.configured_default_provider_spec();
        let names_cache = planned
            .config()
            .providers
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(String::as_str)
            .chain(default_spec.as_deref())
            .any(|spec| self.cached_alias(spec).is_some());
        if !names_cache {
            return;
        }
        // An override collapses the route and drops its cache, so ask what the
        // manifest declares to find the entry this write just superseded.
        let declared = match self.route_for(planned.config(), &None) {
            Ok(declared) => declared,
            Err(error) => {
                cache_warning(&planned.name, error);
                return;
            }
        };
        if let Err(error) = self.invalidate_cached_secret(planned, &declared, profile) {
            cache_warning(
                &planned.name,
                format!(
                    "could not drop the cache entry this write superseded: {error}. Run \
                     `secretspec cache clear {}` — until then a read may serve the old value",
                    planned.name
                ),
            );
        }
    }

    /// Drop any cache entry that could otherwise keep serving a value after its
    /// authoritative copy was deleted. As with direct writes, a provider
    /// override hides the manifest's cached route, so re-plan only when the
    /// declaration could actually name a cache.
    fn sync_cache_after_delete(&self, planned: &PlannedSecret, route: &Route, profile: &str) {
        if route.cache().is_some() {
            if let Err(error) = self.invalidate_cached_secret(planned, route, profile) {
                cache_warning(
                    &planned.name,
                    format!(
                        "could not drop the cache entry for the deleted secret: {error}. Run \
                         `secretspec cache clear {}` — until then a read may serve the deleted value",
                        planned.name
                    ),
                );
            }
            return;
        }

        let default_spec = self.configured_default_provider_spec();
        let names_cache = planned
            .config()
            .providers
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(String::as_str)
            .chain(default_spec.as_deref())
            .any(|spec| self.cached_alias(spec).is_some());
        if !names_cache {
            return;
        }
        let declared = match self.route_for(planned.config(), &None) {
            Ok(declared) => declared,
            Err(error) => {
                cache_warning(&planned.name, error);
                return;
            }
        };
        if let Err(error) = self.invalidate_cached_secret(planned, &declared, profile) {
            cache_warning(
                &planned.name,
                format!(
                    "could not drop the cache entry for the deleted secret: {error}. Run \
                     `secretspec cache clear {}` — until then a read may serve the deleted value",
                    planned.name
                ),
            );
        }
    }

    /// Builds the provider a write goes to for a resolved [`Route`]: the primary
    /// store, or the default provider when the route sets none. A write never
    /// consults the fallback, so an undefined alias further down the chain does
    /// not affect it. `profile` is the profile the write is addressed under.
    fn write_provider_for_route(
        &self,
        route: &Route,
        profile: Option<&str>,
    ) -> Result<Box<dyn ProviderTrait>> {
        // Build from the primary spec (not the resolved URI) so an alias's
        // `credentials` is applied to the write target too.
        self.get_route_provider(route.group_key(), profile)
    }

    /// Refuses an invalid write before the value is requested, then reports
    /// its credential-free destination when the caller installed a reporter.
    /// Both `set` and interactive `check` use this one pre-write path so their
    /// target preview and refusal behavior cannot drift apart.
    fn preflight_write(
        &self,
        planned: &PlannedSecret,
        profile: &str,
        backend: &dyn ProviderTrait,
    ) -> Result<()> {
        let address = self.address_for_spec(
            planned,
            planned.route.as_ref().and_then(Route::group_key),
            &self.config.project.name,
            profile,
        )?;
        let addr = address.as_address();
        backend.check_writable(addr)?;

        let Some(reporter) = &self.write_target_reporter else {
            return Ok(());
        };
        reporter(&WriteTarget {
            name: planned.name.clone(),
            provider_uri: backend.uri(),
            profile: profile.to_string(),
            target: backend.describe_write_target(addr)?,
        });
        Ok(())
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
    /// * `profile` - The profile the operation is addressed under (`None`
    ///   falls back to the session profile); scopes any provider credentials
    ///   fetched during construction
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
        profile: Option<&str>,
    ) -> Result<Box<dyn ProviderTrait>> {
        let provider_spec = self.default_provider_spec(provider_arg)?;

        // Alias resolution happens inside `build_provider`.
        let provider = self.build_provider(provider_spec, profile)?;

        Ok(provider)
    }

    /// The routed sibling of [`Self::get_provider`]: resolves `provider_arg`
    /// against the default provider, then builds it as a planned route's
    /// primary, so an inline cached alias (0.19+) unwraps to its authoritative
    /// leaf instead of being rejected as a route.
    fn get_route_provider(
        &self,
        provider_arg: Option<&str>,
        profile: Option<&str>,
    ) -> Result<Box<dyn ProviderTrait>> {
        let provider_spec = self.default_provider_spec(provider_arg)?;
        self.build_route_provider(provider_spec, profile)
    }

    /// The raw provider spec [`Self::get_provider`] would build for
    /// `provider_arg`: the explicit override, else the user-global default.
    /// Split out so display paths can name the provider without constructing
    /// it (construction fetches provider credentials, so a display-only build
    /// could fail or do I/O).
    fn default_provider_spec(&self, provider_arg: Option<&str>) -> Result<String> {
        self.explicit_provider_spec(provider_arg)
            .or_else(|| self.configured_default_provider_spec())
            .ok_or(SecretSpecError::NoProviderConfigured)
    }

    /// User-global default provider spec, without applying explicit overrides.
    /// Planning uses this only when it names a cached alias; ordinary defaults
    /// retain the existing lazy `Route { primary: None }` representation.
    pub(crate) fn configured_default_provider_spec(&self) -> Option<String> {
        self.global_config
            .as_ref()
            .and_then(|config| config.defaults.provider.clone())
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
        profile: Option<&str>,
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
            None => {
                let spec = self.default_provider_spec(None)?;
                // A cached default alias cannot be constructed — it is a route,
                // not a store — so name the store it reads first instead of
                // failing a report that needed no provider at all.
                if self.cached_alias(&spec).is_some() {
                    return Ok(crate::audit::redact_uri_strict(
                        &self.override_display_uri(&spec)?,
                    ));
                }
                self.get_provider(Some(&spec), profile)
                    .map(|provider| provider.uri())
            }
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
    /// * `secret_name` - What a warning may call this secret. Diagnostics only —
    ///   the read is addressed from `planned` and each selected provider spec —
    ///   so a caller resolving a secret the
    ///   active scope hides passes [`HIDDEN_SECRET_LABEL`] instead of the real
    ///   name (see [`Secrets::diagnostic_secret_name`])
    /// * `planned` - The logical secret and provider-scoped refs used to derive
    ///   each endpoint's address
    /// * `provider_specs` - Optional chain of provider specs (aliases or inline
    ///   URIs) to try in order, resolved lazily per entry
    /// * `planned_primary_uri` - The already-resolved URI of the first entry
    ///   when it is a planned route primary. Its presence selects route-aware
    ///   construction for that entry; fallback-only walks pass `None`.
    /// * `profile` - The profile the read is addressed under; scopes any
    ///   provider credentials fetched when a chain link is built
    ///
    /// # Returns
    ///
    /// A tuple of the secret value (or `None` if not found in any provider), the
    /// URI of the provider to attribute the access to, and that endpoint's
    /// expanded native ref (if any). On a hit, attribution names the serving
    /// provider; on a chain miss/error, the last provider tried.
    fn get_secret_from_providers(
        &self,
        provider_cache: &ProviderCache,
        planned: &PlannedSecret,
        secret_name: &str,
        provider_specs: Option<&[String]>,
        project: &str,
        profile: &str,
        planned_primary_uri: Option<&str>,
    ) -> Result<(Option<SecretString>, Option<String>, Option<NativeAddress>)> {
        // If a provider chain is supplied, try it in order.
        if let Some(specs) = provider_specs {
            let mut last_error: Option<SecretSpecError> = None;
            let mut any_healthy = false;
            let mut last_uri: Option<String> = None;
            let mut last_reference: Option<NativeAddress> = None;
            for (index, spec) in specs.iter().enumerate() {
                let is_planned_primary = index == 0 && planned_primary_uri.is_some();
                // Resolve this link only now, as the chain reaches it. An
                // undefined alias is one broken link, treated exactly like a
                // provider that fails to construct or read: warn and try the
                // next, so a working provider later in the chain still answers.
                // A planned primary was already resolved and validated while
                // building the route. Reuse that URI: an inline cached alias is
                // deliberately rejected by the generic leaf-only resolver.
                let resolved = match planned_primary_uri.filter(|_| is_planned_primary) {
                    Some(uri) => Ok(uri.to_string()),
                    None => self.resolve_one_provider(spec),
                };
                let uri = match resolved {
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
                // Build from the raw spec (not the resolved URI) so an alias's
                // `credentials` is applied to this chain link too. A planned
                // primary uses the same route-aware construction as batch
                // execution, allowing an inline cached alias to unwrap to its
                // authoritative leaf while keeping generic uses leaf-only. The
                // provider is shared across this operation's per-secret walks.
                let provider = match self.shared_provider(
                    provider_cache,
                    spec,
                    Some(profile),
                    is_planned_primary,
                ) {
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
                let address = self.address_for_spec(planned, Some(spec), project, profile)?;
                last_reference = address.native().cloned();
                match provider.get(address.as_address()) {
                    Ok(Some(value)) => {
                        return Ok((Some(value), Some(provider_uri), last_reference));
                    }
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
                _ => Ok((None, last_uri, last_reference)),
            }
        } else {
            // No per-secret providers, use default provider
            let backend = self.get_provider(None, Some(profile))?;
            let uri = backend.uri();
            let address = self.address_for_spec(planned, None, project, profile)?;
            backend
                .get(address.as_address())
                .map(|opt| (opt, Some(uri), address.native().cloned()))
        }
    }

    /// Delete cached values for the active profile. Available since SecretSpec
    /// 0.17.
    ///
    /// When `name` is `None`, every declared secret using a cached route is
    /// cleared. A named secret must exist and use a cached route.
    ///
    /// The count is the number of entries actually removed, not the number of
    /// cached secrets declared, so an empty cache reports `0` and a real
    /// invalidation is distinguishable from a no-op.
    ///
    /// Provider overrides are ignored: this maintains the cache the manifest
    /// declares, and an override would collapse the route and hide the very
    /// entry that needs clearing.
    pub fn clear_cache(&self, name: Option<&str>) -> Result<usize> {
        self.ensure_reason_for(AuditAction::CacheClear, name)?;
        let profile = self.resolve_profile_name(None);
        let named = name.is_some();
        let names = match name {
            Some(name) => {
                // `resolve_profile_secret_names` validates the profile for the
                // sweep; a named secret needs the same check explicitly, or an
                // unknown profile would be reported as an unknown secret.
                self.require_profile(&profile)?;
                vec![name.to_string()]
            }
            None => self.resolve_profile_secret_names(Some(&profile))?,
        };
        let mut cleared = 0;
        let mut failures: Vec<(String, SecretSpecError)> = Vec::new();

        for name in names {
            let planned = match self.plan_declared_secret(&name, &profile)? {
                Some(planned) => planned,
                None => {
                    return Err(SecretSpecError::SecretNotFound(format!(
                        "Secret '{name}' is not defined in profile '{profile}'"
                    )));
                }
            };
            let Some(route) = &planned.route else {
                if named {
                    return Err(SecretSpecError::ProviderOperationFailed(format!(
                        "secret '{name}' is composed and has no provider cache"
                    )));
                }
                continue;
            };
            if route.cache().is_none() {
                if named {
                    return Err(SecretSpecError::ProviderOperationFailed(format!(
                        "secret '{name}' does not use a cached provider route"
                    )));
                }
                continue;
            }
            match self.invalidate_cached_secret(&planned, route, &profile) {
                Ok(deleted) => cleared += usize::from(deleted),
                // One unreachable cache store must not leave the rest of the
                // profile's entries in place: clear what can be cleared, then
                // report what could not, with the count that did succeed.
                Err(error) if named => return Err(error),
                Err(error) => failures.push((name, error)),
            }
        }

        if let Some((name, error)) = failures.first() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "cleared {cleared} cache {entries}, but {count} could not be cleared \
                 ('{name}': {error})",
                entries = if cleared == 1 { "entry" } else { "entries" },
                count = failures.len(),
            )));
        }
        Ok(cleared)
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
                // Unscoped, like `import`: `set` has no `--scope`, so an ambient
                // `SECRETSPEC_SCOPE` must not hide names from the listing (it
                // does not restrict what `set` may write) nor turn an undefined
                // scope into an early return that skips the audit record below.
                let available_secrets = self.profile_secret_names_unscoped(Some(&profile_name))?;

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

        // A composed secret plans no route: its value is derived, so a write
        // has nowhere to go.
        let Some(route) = &planned.route else {
            let err = SecretSpecError::ComposedSecretReadOnly(name.to_string());
            self.record_key_error(AuditAction::Set, &profile_name, name, None, None, &err);
            return Err(err);
        };

        if planned.extract().is_some() {
            let err = SecretSpecError::ExtractedSecretReadOnly(name.to_string());
            self.record_key_error(
                AuditAction::Set,
                &profile_name,
                name,
                route.primary().map(str::to_string),
                planned.reference(),
                &err,
            );
            return Err(err);
        }

        let backend = match self.write_provider_for_route(route, Some(&profile_name)) {
            Ok(backend) => backend,
            Err(err) => {
                self.record_key_error(AuditAction::Set, &profile_name, name, None, None, &err);
                return Err(err);
            }
        };

        let address = self.address_for_spec(
            &planned,
            route.group_key(),
            &self.config.project.name,
            &profile_name,
        )?;
        let addr = address.as_address();
        // Refuse before prompting for a value. The provider states the reason:
        // a store may be writable through the convention layout yet reject the
        // `ref` this secret names. A CLI-owned reporter also previews the
        // resolved destination here; SDK/library callers install none.
        if let Err(err) = self.preflight_write(&planned, &profile_name, backend.as_ref()) {
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

        let encoded_value = Self::encoded_for_storage(&planned, &value);
        let stored_value = encoded_value.as_ref().unwrap_or(&value);
        let result = backend.set(addr, stored_value);
        self.audit_write_result(
            &result,
            name,
            &profile_name,
            Some(backend.uri()),
            address.native(),
            None,
        );
        result?;
        self.sync_cache_after_write(&planned, route, &profile_name, stored_value);

        eprintln!(
            "{} Secret '{}' saved to {} (profile: {})",
            "✓".green(),
            name,
            backend.name(),
            profile_name
        );

        Ok(())
    }

    /// Deletes one secret value from its authoritative provider. Available
    /// since SecretSpec 0.18.
    ///
    /// The provider route and address are resolved exactly as for [`Self::set`]:
    /// without an override, only the primary write provider is changed; fallback
    /// copies are never traversed and deleted implicitly. A successful deletion
    /// also invalidates the manifest's cache so a later read cannot return the
    /// removed value. Missing values are an idempotent `Ok(false)`.
    pub fn delete(&self, name: &str) -> Result<bool> {
        self.ensure_reason_for(AuditAction::Delete, Some(name))?;
        let profile_name = self.resolve_profile_name(None);
        self.require_profile(&profile_name)?;

        let planned = match self.plan_secret(name, &profile_name, None) {
            Ok(Some(planned)) => planned,
            Err(error) => {
                self.record_key_error(AuditAction::Delete, &profile_name, name, None, None, &error);
                return Err(error);
            }
            Ok(None) => {
                let available = self.profile_secret_names_unscoped(Some(&profile_name))?;
                let error = SecretSpecError::SecretNotFound(format!(
                    "Secret '{name}' is not defined in profile '{profile_name}'. Available secrets: {}",
                    available.join(", ")
                ));
                self.record_key_error(AuditAction::Delete, &profile_name, name, None, None, &error);
                return Err(error);
            }
        };

        let Some(route) = &planned.route else {
            let error = SecretSpecError::ComposedSecretReadOnly(name.to_string());
            self.record_key_error(AuditAction::Delete, &profile_name, name, None, None, &error);
            return Err(error);
        };
        if planned.extract().is_some() {
            let error = SecretSpecError::ExtractedSecretReadOnly(name.to_string());
            self.record_key_error(
                AuditAction::Delete,
                &profile_name,
                name,
                route.primary().map(str::to_string),
                planned.reference(),
                &error,
            );
            return Err(error);
        }
        let backend = match self.write_provider_for_route(route, Some(&profile_name)) {
            Ok(backend) => backend,
            Err(error) => {
                self.record_key_error(
                    AuditAction::Delete,
                    &profile_name,
                    name,
                    None,
                    planned.reference(),
                    &error,
                );
                return Err(error);
            }
        };

        let address = self.address_for_spec(
            &planned,
            route.group_key(),
            &self.config.project.name,
            &profile_name,
        )?;
        let result = backend.delete(address.as_address());
        self.audit_delete_result(
            &result,
            name,
            &profile_name,
            Some(backend.uri()),
            address.native(),
        );
        let deleted = result?;
        // Even a no-op authoritative delete must invalidate the cache: the
        // cache may still contain the only surviving copy of the value.
        self.sync_cache_after_delete(&planned, route, &profile_name);
        Ok(deleted)
    }

    /// Resolves one secret and prints it to stdout: the CLI's `secretspec get`.
    ///
    /// A secret declared `as_path` prints the path to its materialized file,
    /// which outlives this process; every other secret prints its value. A
    /// value from the manifest's `default`, a `generate` config, or a
    /// composition prints like any other.
    ///
    /// Library callers want [`Self::resolve_named`], which returns the value
    /// instead of printing it and distinguishes an undeclared name from a
    /// declared secret with no value.
    ///
    /// # Errors
    ///
    /// [`SecretSpecError::SecretNotFound`] when the name is not declared on the
    /// active profile and scope, or is declared but produced no value. Provider
    /// and configuration failures surface as their own errors.
    pub fn get(&self, name: &str) -> Result<()> {
        // A printer over the library API, so the CLI's single-secret read makes
        // exactly the resolution decisions `resolve_named` makes (and audits
        // them once, there) rather than maintaining a second single-secret path.
        match self.resolve_named_within(name, Surface::WholeProfile)? {
            NamedResolution::Resolved(secret) => {
                // `as_path` secrets are materialized and their temp file
                // persisted during resolution, so a printed path is still valid
                // after this process exits.
                let rendered = secret
                    .value
                    .or(secret.path)
                    .expect("a resolved secret carries either a value or a path");
                println!("{rendered}");
                Ok(())
            }
            // Undeclared and missing are one error for the CLI: either way there
            // is nothing to print. Both are already audited by `resolve_named`.
            NamedResolution::Missing { .. } | NamedResolution::Undeclared => {
                Err(SecretSpecError::SecretNotFound(name.to_string()))
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
                        return Err(validation_failure(validation_errors));
                    }

                    let missing =
                        self.scoped_promptable_missing(&validation_errors, &profile_display)?;
                    if missing.is_empty() {
                        return Err(validation_failure(validation_errors));
                    }
                    // Extraction cannot be inverted into a containing document.
                    // Reject the whole interactive write pass before prompting
                    // for (and possibly storing) any earlier secret.
                    if let Some(name) = missing.iter().find(|name| {
                        self.resolve_secret_config(name, Some(&profile_display))
                            .is_some_and(|secret| secret.extract.is_some())
                    }) {
                        return Err(SecretSpecError::ExtractedSecretReadOnly(name.clone()));
                    }
                    let total = missing.len();
                    // Name the provider without constructing it: this value is
                    // display-only (each prompted write builds its own route's
                    // provider below), and construction now fetches provider
                    // credentials, so a display-only build could hard-error on
                    // a credential-backed default alias no missing secret routes to.
                    let default_backend_name = crate::provider::provider_display_name_for_spec(
                        &self.resolve_provider_spec(
                            self.default_provider_spec(provider_arg.as_deref())?,
                        ),
                    );

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
                        default_backend_name.bold(),
                    );
                    for secret_name in &missing {
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
                            let route = planned
                                .route
                                .as_ref()
                                .expect("prompted names are provider-backed leaves");
                            let backend =
                                self.write_provider_for_route(route, Some(&profile_display))?;
                            if let Err(error) =
                                self.preflight_write(&planned, &profile_display, backend.as_ref())
                            {
                                self.record_key_error(
                                    AuditAction::Set,
                                    &profile_display,
                                    secret_name,
                                    Some(backend.uri()),
                                    planned.reference(),
                                    &error,
                                );
                                return Err(error);
                            }

                            let prompt_msg =
                                format!("[{}/{}] Enter value for {}:", i + 1, total, secret_name,);
                            let prompt = inquire::Password::new(&prompt_msg).without_confirmation();

                            let value = SecretString::new(prompt.prompt()?.into());

                            let encoded_value = Self::encoded_for_storage(&planned, &value);
                            let stored_value = encoded_value.as_ref().unwrap_or(&value);
                            let address = self.address_for_spec(
                                &planned,
                                route.group_key(),
                                &self.config.project.name,
                                &profile_display,
                            )?;
                            let set_result = backend.set(address.as_address(), stored_value);
                            self.audit_write_result(
                                &set_result,
                                secret_name,
                                &profile_display,
                                Some(backend.uri()),
                                address.native(),
                                None,
                            );
                            set_result?;
                            self.sync_cache_after_write(
                                &planned,
                                route,
                                &profile_display,
                                stored_value,
                            );
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
                        Err(still_errors) => Err(validation_failure(still_errors)),
                    }
                } else {
                    // Not interactive or no missing required secrets
                    Err(validation_failure(validation_errors))
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
        let mut found_count = 0;
        let mut optional_count = 0;
        let default_names = valid
            .with_defaults
            .iter()
            .map(|(name, _)| name)
            .collect::<HashSet<_>>();
        let missing_optional: HashSet<&String> = valid.missing_optional.iter().collect();

        for (name, config) in &self.effective_secrets(&valid.resolved.profile)? {
            let label = format_secret_label(name, config.description.as_deref());
            if missing_optional.contains(&name) {
                optional_count += 1;
                eprintln!("{} {} {}", "○".blue(), label, "(optional)".blue());
            } else if config.default.is_some() && default_names.contains(&name) {
                found_count += 1;
                eprintln!("{} {} {}", "○".yellow(), label, "(has default)".yellow());
            } else {
                found_count += 1;
                eprintln!("{} {}", "✓".green(), label);
            }
        }

        eprintln!("\n{}", Self::format_summary(found_count, 0, optional_count));

        Ok(())
    }

    /// Display validation error results
    fn display_validation_errors(&self, errors: &ValidationErrors) -> Result<()> {
        let mut found_count = 0;
        let mut missing_count = 0;
        let mut optional_count = 0;
        let default_names = errors
            .with_defaults
            .iter()
            .map(|(name, _)| name)
            .collect::<HashSet<_>>();

        for (name, config) in &self.effective_secrets(&errors.profile)? {
            let label = format_secret_label(name, config.description.as_deref());
            if errors.missing_required.contains(name) {
                missing_count += 1;
                eprintln!("{} {} {}", "✗".red(), label, "(required)".red());
            } else if errors.missing_optional.contains(name) {
                optional_count += 1;
                eprintln!("{} {} {}", "○".blue(), label, "(optional)".blue());
            } else {
                found_count += 1;
                if default_names.contains(name) {
                    eprintln!("{} {} {}", "○".yellow(), label, "(has default)".yellow());
                } else {
                    eprintln!("{} {}", "✓".green(), label);
                }
            }
        }

        eprintln!(
            "\n{}",
            Self::format_summary(found_count, missing_count, optional_count)
        );
        for violation in &errors.constraint_violations {
            eprintln!("{} {}", "Constraint failed:".red().bold(), violation);
        }

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

    /// Finds effective leaf aliases whose provider shares a storage container
    /// with a literal import source but whose active address mapping reaches a
    /// different entry for at least one imported secret.
    ///
    /// This is diagnostic only. A literal keeps convention semantics even when
    /// exactly one alias matches, because aliases are identities and multiple
    /// aliases may intentionally map one container in different ways. Candidate
    /// providers are built without resolving their declared credentials so a
    /// warning can never touch credential stores or break an otherwise valid
    /// literal import.
    fn literal_import_alias_divergences(
        &self,
        source_spec: &str,
        source_provider: &dyn ProviderTrait,
        planned: &[PlannedSecret],
        profile: &str,
    ) -> Vec<ImportAliasDivergence> {
        if self.lookup_provider_alias_entry(source_spec).is_some() {
            return Vec::new();
        }

        self.known_provider_aliases()
            .into_iter()
            .filter_map(|alias_name| {
                let alias = self.lookup_provider_alias_entry(&alias_name)?;
                if alias.is_cached() {
                    return None;
                }

                let has_active_mapping = alias.reference_template().is_some()
                    || planned.iter().any(|secret| {
                        secret
                            .config()
                            .refs
                            .as_ref()
                            .is_some_and(|refs| refs.contains_key(&alias_name))
                    });
                if !has_active_mapping {
                    return None;
                }

                // Identity comparison needs only provider configuration. Do not
                // resolve this alias's credentials merely to produce a warning.
                let alias_provider = self.build_source_provider(&alias_name).ok()?;
                if !same_storage_container(source_provider, alias_provider.as_ref()) {
                    return None;
                }

                let affected_secrets = planned
                    .iter()
                    .filter_map(|secret| {
                        let literal_address = self
                            .address_for_spec(
                                secret,
                                Some(source_spec),
                                &self.config.project.name,
                                profile,
                            )
                            .ok()?;
                        let alias_address = self
                            .address_for_spec(
                                secret,
                                Some(&alias_name),
                                &self.config.project.name,
                                profile,
                            )
                            .ok()?;

                        let differs = match source_provider.same_entries(
                            literal_address.as_address(),
                            alias_provider.as_ref(),
                            alias_address.as_address(),
                        ) {
                            Ok(same) => !same,
                            // An alias address that the provider cannot compare
                            // still represents behavior the literal bypasses.
                            // Keep the warning non-fatal and suppress it only if
                            // both address models are structurally identical.
                            Err(_) => literal_address != alias_address,
                        };
                        differs.then(|| secret.name.clone())
                    })
                    .collect::<Vec<_>>();

                (!affected_secrets.is_empty()).then_some(ImportAliasDivergence {
                    alias: alias_name,
                    affected_secrets,
                })
            })
            .collect()
    }

    fn warn_literal_import_alias_divergences(
        source_uri: &str,
        divergences: &[ImportAliasDivergence],
    ) {
        for divergence in divergences {
            let count = divergence.affected_secrets.len();
            let noun = if count == 1 { "secret" } else { "secrets" };
            let example = &divergence.affected_secrets[0];
            eprintln!(
                "{} import source {} uses convention naming, but provider alias {} addresses {} {} differently in the same storage container (for example, {}). Use that alias as the source if its alias-specific coordinates are intended; keep the literal source to use convention-named entries.",
                "warning:".yellow(),
                source_uri.bold(),
                format!("'{}'", divergence.alias).bold(),
                count,
                noun,
                example.bold(),
            );
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
        self.import_internal(from_provider, false)
    }

    /// Imports secrets and deletes each source value only after the destination
    /// is verified to contain the same value. Available since SecretSpec 0.18.
    ///
    /// A destination value that already differs is never overwritten and its
    /// source is retained. The source and destination must be different stores.
    pub fn import_with_delete_source(&self, from_provider: &str) -> Result<()> {
        self.import_internal(from_provider, true)
    }

    fn import_internal(&self, from_provider: &str, delete_source: bool) -> Result<()> {
        self.ensure_reason_for(AuditAction::Import, None)?;
        let profile_display = self.resolve_profile_name(None);

        let mut imported = 0;
        let mut already_exists = 0;
        let mut not_found = 0;
        let mut deleted_from_source = 0;
        let mut kept_in_source = 0;
        let mut read_names: Vec<String> = Vec::new();
        let mut source_uri: Option<String> = None;
        let mut source_display: Option<String> = None;

        let copy_result = (|| -> Result<()> {
            let from_provider_instance =
                self.build_provider(from_provider.to_string(), Some(&profile_display))?;
            let provider_uri = from_provider_instance.uri();
            source_uri = Some(provider_uri.clone());
            source_display = Some(
                if self.lookup_provider_alias_entry(from_provider).is_some() {
                    format!("provider alias '{from_provider}' ({provider_uri})")
                } else {
                    provider_uri.clone()
                },
            );

            if delete_source
                && !crate::provider::spec_provider_deletes(
                    &self.resolve_provider_spec(from_provider.to_string()),
                )
            {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "provider '{}' does not support deleting secrets and cannot be used with import --delete-source",
                    from_provider_instance.name()
                )));
            }

            eprintln!(
                "Importing secrets from {} (profile: {})...\n",
                source_display
                    .as_deref()
                    .expect("source display is set with the provider URI")
                    .blue(),
                profile_display.cyan()
            );

            let import_names = self.profile_secret_names_unscoped(Some(&profile_display))?;
            let mut planned_imports = Vec::new();

            // Resolve every effective secret before looking in either store so
            // the literal-vs-alias diagnostic reflects the complete import and
            // can be emitted before the first provider read.
            for name in import_names {
                let planned = self
                    .plan_secret(&name, &profile_display, None)?
                    .expect("Secret should exist since we're iterating over it");
                if planned.route.is_none() {
                    continue;
                }

                if planned.extract().is_some() {
                    return Err(SecretSpecError::ExtractedSecretReadOnly(
                        planned.name.clone(),
                    ));
                }
                planned_imports.push(planned);
            }

            let divergences = self.literal_import_alias_divergences(
                from_provider,
                from_provider_instance.as_ref(),
                &planned_imports,
                &profile_display,
            );
            Self::warn_literal_import_alias_divergences(&provider_uri, &divergences);

            // Resolve and read every endpoint before mutating either store.
            // This makes failures in a later secret harmless to earlier source
            // entries and gives --delete-source one destructive preflight.
            let mut prepared = Vec::new();
            for planned in planned_imports {
                let route = planned
                    .route
                    .as_ref()
                    .expect("planned imports are provider-backed");

                read_names.push(planned.name.clone());
                let source_address = self.address_for_spec(
                    &planned,
                    Some(from_provider),
                    &self.config.project.name,
                    &profile_display,
                )?;
                let target_address = self.address_for_spec(
                    &planned,
                    route.group_key(),
                    &self.config.project.name,
                    &profile_display,
                )?;
                let target_provider =
                    self.write_provider_for_route(route, Some(&profile_display))?;

                if delete_source
                    && from_provider_instance.same_entries(
                        source_address.as_address(),
                        target_provider.as_ref(),
                        target_address.as_address(),
                    )?
                {
                    return Err(SecretSpecError::ProviderOperationFailed(format!(
                        "refusing to delete '{}' from the import source because source and destination resolve to the same provider entry ({})",
                        planned.name,
                        from_provider_instance.uri()
                    )));
                }
                let source_value = from_provider_instance.get(source_address.as_address())?;
                let target_value = target_provider.get(target_address.as_address())?;

                if let Some(value) = &source_value {
                    Self::validate_import_value(&planned, &planned.name, value)?;
                    if target_value.is_none() {
                        target_provider.check_writable(target_address.as_address())?;
                    }
                    let target_will_match = target_value
                        .as_ref()
                        .is_none_or(|existing| existing.expose_secret() == value.expose_secret());
                    if delete_source && target_will_match {
                        from_provider_instance.check_deletable(source_address.as_address())?;
                    }
                }

                prepared.push(PreparedImport {
                    planned,
                    target_provider,
                    source_address,
                    target_address,
                    source_value,
                    target_value,
                    copied: false,
                    source_deleted: false,
                });
            }

            // A destination is one physical entry, even when aliases, URI
            // spellings, or templates make the configured endpoints look
            // different. Reject collisions before copying so two logical
            // secrets cannot both act on the same stale target snapshot.
            for left_index in 0..prepared.len() {
                let left = &prepared[left_index];
                for right in &prepared[left_index + 1..] {
                    if left.target_provider.same_entries(
                        left.target_address.as_address(),
                        right.target_provider.as_ref(),
                        right.target_address.as_address(),
                    )? {
                        return Err(SecretSpecError::ProviderOperationFailed(format!(
                            "refusing to import '{}' and '{}' because they resolve to the same destination provider entry ({})",
                            left.planned.name,
                            right.planned.name,
                            left.target_provider.uri()
                        )));
                    }
                }
            }

            if delete_source {
                // Cleanup must not remove any destination in this import. The
                // per-secret check above protects each source from its own
                // destination; this cross-product protects it from every other
                // secret's destination before the first write or deletion.
                for (source_index, source) in prepared.iter().enumerate() {
                    let Some(source_value) = &source.source_value else {
                        continue;
                    };
                    let source_will_be_deleted =
                        source.target_value.as_ref().is_none_or(|target_value| {
                            source_value.expose_secret() == target_value.expose_secret()
                        });
                    if !source_will_be_deleted {
                        continue;
                    }

                    for (target_index, target) in prepared.iter().enumerate() {
                        if source_index == target_index {
                            continue;
                        }
                        if from_provider_instance.same_entries(
                            source.source_address.as_address(),
                            target.target_provider.as_ref(),
                            target.target_address.as_address(),
                        )? {
                            return Err(SecretSpecError::ProviderOperationFailed(format!(
                                "refusing to delete '{}' from the import source because it resolves to the destination provider entry for '{}' ({})",
                                source.planned.name,
                                target.planned.name,
                                target.target_provider.uri()
                            )));
                        }
                    }
                }
            }

            // Copy every missing target. No source is deleted in this phase.
            for entry in &mut prepared {
                let (Some(value), None) = (&entry.source_value, &entry.target_value) else {
                    continue;
                };
                let route = entry
                    .planned
                    .route
                    .as_ref()
                    .expect("prepared imports are provider-backed");
                let set_result = entry
                    .target_provider
                    .set(entry.target_address.as_address(), value);
                self.audit_write_result(
                    &set_result,
                    &entry.planned.name,
                    &profile_display,
                    Some(entry.target_provider.uri()),
                    entry.target_address.native(),
                    None,
                );
                set_result?;
                self.sync_cache_after_write(&entry.planned, route, &profile_display, value);
                entry.copied = true;
                imported += 1;
            }

            // Verify all writes and validate their readable representation
            // before beginning source cleanup.
            if delete_source {
                for entry in prepared.iter_mut().filter(|entry| entry.copied) {
                    let expected = entry
                        .source_value
                        .as_ref()
                        .expect("copied entries have source values");
                    let stored = entry
                        .target_provider
                        .get(entry.target_address.as_address())?
                        .ok_or_else(|| {
                            SecretSpecError::ProviderOperationFailed(format!(
                                "destination verification failed for '{}'; the source value was retained",
                                entry.planned.name
                            ))
                        })?;
                    if stored.expose_secret() != expected.expose_secret() {
                        return Err(SecretSpecError::ProviderOperationFailed(format!(
                            "destination verification failed for '{}'; the source value was retained",
                            entry.planned.name
                        )));
                    }
                    Self::validate_import_value(&entry.planned, &entry.planned.name, &stored)?;
                    entry.target_value = Some(stored);
                }

                // Deletion is last: every planned target write has succeeded and
                // every copied value has been read back successfully.
                for entry in &mut prepared {
                    let (Some(source), Some(target)) = (&entry.source_value, &entry.target_value)
                    else {
                        continue;
                    };
                    if source.expose_secret() != target.expose_secret() {
                        continue;
                    }
                    let delete_result =
                        from_provider_instance.delete(entry.source_address.as_address());
                    self.audit_delete_result(
                        &delete_result,
                        &entry.planned.name,
                        &profile_display,
                        Some(from_provider_instance.uri()),
                        entry.source_address.native(),
                    );
                    entry.source_deleted = delete_result?;
                    deleted_from_source += usize::from(entry.source_deleted);
                }
            }

            // Emit stable per-secret results only after the operation phases
            // above have completed.
            for entry in &prepared {
                let name = &entry.planned.name;
                let label =
                    format_secret_label(name, entry.planned.config().description.as_deref());
                let target_name = entry.target_provider.name().blue();

                if entry.copied {
                    if delete_source && entry.source_deleted {
                        eprintln!(
                            "{} {} (→ {}; deleted from source)",
                            "✓".green(),
                            label,
                            target_name
                        );
                    } else {
                        eprintln!("{} {} (→ {})", "✓".green(), label, target_name);
                    }
                    continue;
                }

                match (&entry.source_value, &entry.target_value) {
                    (Some(source), Some(target)) => {
                        already_exists += 1;
                        if delete_source && source.expose_secret() != target.expose_secret() {
                            kept_in_source += 1;
                            eprintln!(
                                "{} {} {} (→ {}; source retained)",
                                "○".yellow(),
                                label,
                                "(target value differs)".yellow(),
                                target_name
                            );
                        } else if delete_source && entry.source_deleted {
                            eprintln!(
                                "{} {} {} (→ {}; deleted from source)",
                                "✓".green(),
                                label,
                                "(already exists in target)".yellow(),
                                target_name
                            );
                        } else {
                            eprintln!(
                                "{} {} {} (→ {})",
                                "○".yellow(),
                                label,
                                "(already exists in target)".yellow(),
                                target_name
                            );
                        }
                    }
                    (None, Some(_)) => {
                        already_exists += 1;
                        eprintln!(
                            "{} {} {} (→ {})",
                            "○".blue(),
                            label,
                            "(already in target, not in source)".blue(),
                            target_name
                        );
                    }
                    (None, None) => {
                        not_found += 1;
                        eprintln!("{} {} {}", "✗".red(), label, "(not found in source)".red());
                    }
                    (Some(_), None) => {
                        unreachable!("a prepared missing target was copied or returned an error")
                    }
                }
            }
            Ok(())
        })();

        if let Err(e) = copy_result {
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
        if delete_source {
            eprintln!(
                "Source cleanup: {} deleted, {} retained because the target differs",
                deleted_from_source.to_string().green(),
                kept_in_source.to_string().yellow()
            );
        }

        if imported > 0 {
            eprintln!(
                "\n{} Successfully imported {} secrets from {}",
                "✓".green(),
                imported,
                source_display.as_deref().unwrap_or("configured provider"),
            );
        }

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
        let gen_config = match &planned.config().generate {
            Some(config) if config.is_enabled() => config,
            _ => return Ok(None),
        };
        if planned.extract().is_some() {
            return Err(SecretSpecError::ExtractedSecretReadOnly(
                planned.name.clone(),
            ));
        }

        let secret_type = match &planned.config().secret_type {
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
        let route = planned
            .route
            .as_ref()
            .expect("a generating secret is provider-backed");
        let address = self.address_for_spec(
            planned,
            route.group_key(),
            &self.config.project.name,
            profile_name,
        )?;
        let addr = address.as_address();
        let backend = self.write_provider_for_route(route, Some(profile_name))?;

        if backend.generated_value_persistence() == ProducedValuePersistence::Ephemeral {
            eprintln!(
                "{} {} - generated for this resolution without provider storage (profile: {})",
                "✓".green(),
                name,
                profile_name
            );
            return Ok(Some(value));
        }

        // The provider states why a write is refused; wrapping it here would
        // only nest a second "Provider operation failed" prefix.
        backend.check_writable(addr)?;
        let encoded_value = Self::encoded_for_storage(planned, &value);
        let stored_value = encoded_value.as_ref().unwrap_or(&value);
        let set_result = backend.set(addr, stored_value);
        // Generating a secret writes a brand-new value to the provider; record it
        // like any other write so the audit log captures every stored secret.
        self.audit_write_result(
            &set_result,
            name,
            profile_name,
            Some(backend.uri()),
            address.native(),
            None,
        );
        set_result?;
        self.sync_cache_after_write(
            planned,
            planned
                .route
                .as_ref()
                .expect("a generating secret is provider-backed"),
            profile_name,
            stored_value,
        );

        eprintln!(
            "{} {} - generated and saved to {} (profile: {})",
            "✓".green(),
            name,
            backend.name(),
            profile_name
        );

        Ok(Some(value))
    }

    /// Reads one missing value from the controlling terminal during `run`.
    /// Inquire's crossterm backend opens `/dev/tty` on Unix (and the console
    /// input handle on Windows) when stdin is redirected, so the child retains
    /// its original stdin stream. Persistence is deliberately handled by
    /// [`Self::try_prompt_secret`], after this input-only step succeeds.
    fn prompt_run_secret(&self, name: &str, profile: &str) -> Result<SecretString> {
        let value = if let Some(reader) = &self.prompt_reader {
            reader(name, profile)?
        } else {
            let message = format!("Enter value for {name} (profile: {profile}):");
            let entered = inquire::Password::new(&message)
                .without_confirmation()
                .prompt()
                .map_err(|error| match error {
                    inquire::InquireError::NotTTY | inquire::InquireError::IO(_) => {
                        SecretSpecError::PromptUnavailable(name.to_string())
                    }
                    other => SecretSpecError::InquireError(other),
                })?;
            SecretString::new(entered.into())
        };

        if value.expose_secret().is_empty() {
            return Err(SecretSpecError::PromptValueEmpty(name.to_string()));
        }
        Ok(value)
    }

    /// Acquires a missing value for `prompt = true` and applies the primary
    /// provider's persistence policy. Storage providers persist by default,
    /// making the prompt a first-use provisioning step; explicitly ephemeral
    /// providers such as `null` return the answer only to this `run`.
    fn try_prompt_secret(
        &self,
        planned: &PlannedSecret,
        profile_name: &str,
    ) -> Result<SecretString> {
        let name = planned.name.as_str();
        let route = planned
            .route
            .as_ref()
            .expect("a prompted secret is provider-backed");
        let address = self.address_for_spec(
            planned,
            route.group_key(),
            &self.config.project.name,
            profile_name,
        )?;
        let addr = address.as_address();
        let backend = self.write_provider_for_route(route, Some(profile_name))?;
        let persistence = backend.prompted_value_persistence();

        // A durable answer is a write. Resolve and preview the exact target,
        // and reject a read-only destination, before asking the operator for a
        // value. Ephemeral providers explicitly bypass the write path.
        if persistence == ProducedValuePersistence::Persist {
            self.preflight_write(planned, profile_name, backend.as_ref())?;
        }

        let value = self.prompt_run_secret(name, profile_name)?;
        if persistence == ProducedValuePersistence::Ephemeral {
            eprintln!(
                "{} {} - entered for this run without provider storage (profile: {})",
                "✓".green(),
                name,
                profile_name
            );
            return Ok(value);
        }

        let encoded_value = Self::encoded_for_storage(planned, &value);
        let stored_value = encoded_value.as_ref().unwrap_or(&value);
        let set_result = backend.set(addr, stored_value);
        self.audit_write_result(
            &set_result,
            name,
            profile_name,
            Some(backend.uri()),
            address.native(),
            None,
        );
        set_result?;
        self.sync_cache_after_write(planned, route, profile_name, stored_value);

        eprintln!(
            "{} {} - entered and saved to {} (profile: {})",
            "✓".green(),
            name,
            backend.name(),
            profile_name
        );
        Ok(value)
    }

    /// Writes secret bytes to a temporary file and returns the file handle and path
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret bytes to write
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
        secret: &[u8],
    ) -> Result<(tempfile::NamedTempFile, String)> {
        use std::io::Write;

        let mut temp_file = tempfile::NamedTempFile::new().map_err(SecretSpecError::Io)?;

        temp_file.write_all(secret).map_err(SecretSpecError::Io)?;

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

    /// Resolve one declared secret by name.
    ///
    /// [`Self::resolve`] answers "can this whole profile be satisfied", which is
    /// the wrong question for a consumer that needs a single secret: an
    /// unrelated missing required secret fails the call and yields nothing, even
    /// though the requested secret is sitting there. This resolves only `name`
    /// and the composition inputs it derives from, so no other declaration can
    /// fail it, and it separates the outcomes a batch resolve conflates — see
    /// [`NamedResolution`].
    ///
    /// The active profile and scope both apply. A secret the scope hides is
    /// reported as [`NamedResolution::Undeclared`]: it is not on the surface
    /// this session resolves, and reporting it as merely missing would leak that
    /// the scope hides it. Genuine provider and configuration failures (an
    /// undefined alias, an unreachable vault) stay errors instead of collapsing
    /// into a missing value.
    ///
    /// Whole-profile presence constraints (`at_least_one`, `exactly_one`) are
    /// not evaluated, matching the CLI's single-secret `get`: whether a group is
    /// satisfied is a property of the profile, and this read deliberately never
    /// looks at the rest of it.
    ///
    /// Like [`Self::resolve`], this carries the value, mints a generatable
    /// secret, and persists an `as_path` temp file so the returned path outlives
    /// the call. Treat the payload as sensitive.
    ///
    /// Available since SecretSpec 0.19.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use secretspec::{NamedResolution, Secrets};
    ///
    /// let spec = Secrets::load().unwrap();
    /// match spec.resolve_named("DATABASE_URL").unwrap() {
    ///     NamedResolution::Resolved(secret) => println!("got {:?}", secret.source),
    ///     NamedResolution::Missing { required } => println!("missing (required: {required})"),
    ///     NamedResolution::Undeclared => println!("not declared in this profile"),
    /// }
    /// ```
    pub fn resolve_named(&self, name: &str) -> Result<NamedResolution> {
        self.resolve_named_within(name, Surface::Scoped)
    }

    /// Shared core of [`Self::resolve_named`] and [`Self::get`].
    ///
    /// They differ only in which surface decides that a name exists: the SDK
    /// resolves what the session exposes (a scope narrows it), while the CLI's
    /// `get` names one secret and has no `--scope`, so an ambient or configured
    /// scope must not hide a secret from it.
    fn resolve_named_within(&self, name: &str, surface: Surface) -> Result<NamedResolution> {
        self.ensure_reason_for(AuditAction::Get, Some(name))?;
        let profile_name = self.resolve_profile_name(None);

        // Decide whether this surface offers the name at all, before any
        // provider is contacted.
        let visible = match surface.names(self, &profile_name) {
            Ok(visible) => visible,
            Err(err) => {
                self.record_key_error(AuditAction::Get, &profile_name, name, None, None, &err);
                return Err(err);
            }
        };
        if !visible.iter().any(|declared| declared == name) {
            // An attempted read of a name this surface does not offer is still
            // an attempted read, and is audited as one (matching how `set`
            // records an undefined secret). No provider can be attributed.
            let err = SecretSpecError::SecretNotFound(name.to_string());
            self.record_key_error(AuditAction::Get, &profile_name, name, None, None, &err);
            return Ok(NamedResolution::Undeclared);
        }

        // The target plus its transitive composition inputs: the same
        // least-access plan `get` builds, so an unrelated required secret is
        // never read and can never fail this call.
        let names = self.composed_dependency_names(name, &profile_name);
        let plan = match self.build_plan_from_names(profile_name.clone(), names) {
            Ok(plan) => plan,
            Err(err) => {
                self.record_key_error(AuditAction::Get, &profile_name, name, None, None, &err);
                return Err(err);
            }
        };
        // No output filter: the dependency closure has to resolve, and a filter
        // would additionally enable the whole-profile constraint checks that a
        // single-secret read does not own.
        let mut read_addresses = HashMap::new();
        let outcome =
            match self.execute_plan(&plan, Materialize::Values, None, Some(&mut read_addresses)) {
                Ok(outcome) => outcome,
                Err(err) => {
                    let reference = read_addresses.get(name);
                    self.record_key_error(
                        AuditAction::Get,
                        &profile_name,
                        name,
                        None,
                        reference,
                        &err,
                    );
                    return Err(err);
                }
            };
        // Exactly the coordinates the read reached, never the declared ones: an
        // alias `ref` template resolves to a different address per provider, and
        // a read served from cache addressed no authoritative store at all.
        let reference = read_addresses.get(name);

        match outcome {
            Ok(mut validated) => {
                // Cloned so the entry outlives the `&mut` borrow that persisting
                // the temp files needs.
                let entry = validated
                    .resolution
                    .iter()
                    .find(|entry| entry.name == name)
                    .expect("the planned target always has a resolution entry")
                    .clone();
                if entry.status != ResolutionStatus::Resolved {
                    self.record(
                        AuditAction::Get,
                        &profile_name,
                        AuditOutcome::Missing,
                        AuditFields {
                            key: Some(name),
                            reference,
                            ..Default::default()
                        },
                    );
                    return Ok(NamedResolution::Missing {
                        required: entry.required,
                    });
                }

                // Persist as_path temp files so the returned path stays valid
                // for the caller, exactly as `resolve` does.
                validated.keep_temp_files()?;
                let raw = validated
                    .resolved
                    .secrets
                    .get(name)
                    .expect("a Resolved entry always has a value")
                    .expose_secret()
                    .to_string();
                let (value, path) = if entry.as_path {
                    (None, Some(raw))
                } else {
                    (Some(raw), None)
                };

                self.record(
                    AuditAction::Get,
                    &profile_name,
                    if entry.default_applied {
                        AuditOutcome::Default
                    } else {
                        AuditOutcome::Found
                    },
                    AuditFields {
                        key: Some(name),
                        provider_uri: entry.source_provider.clone(),
                        reference,
                        ..Default::default()
                    },
                );
                Ok(NamedResolution::Resolved(ResolvedSecret {
                    value,
                    path,
                    as_path: entry.as_path,
                    source: resolved_source(&entry),
                    source_provider: entry.source_provider,
                }))
            }
            Err(errors) => {
                // Constraints are skipped for this partial plan, so a violation
                // here would mean the resolver changed its mind about that;
                // surface it rather than reporting a missing value.
                if !errors.constraint_violations.is_empty() {
                    let err = SecretSpecError::ValidationFailed(Box::new(errors));
                    self.record_key_error(
                        AuditAction::Get,
                        &profile_name,
                        name,
                        None,
                        reference,
                        &err,
                    );
                    return Err(err);
                }
                // The target is missing; a composed target whose input is
                // missing reports against the target, which is what the caller
                // asked about.
                let required = errors
                    .resolution
                    .iter()
                    .find(|entry| entry.name == name)
                    .is_none_or(|entry| entry.required);
                self.record(
                    AuditAction::Get,
                    &profile_name,
                    AuditOutcome::Missing,
                    AuditFields {
                        key: Some(name),
                        reference,
                        ..Default::default()
                    },
                );
                Ok(NamedResolution::Missing { required })
            }
        }
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
                    let source = resolved_source(entry);
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
                    scope: self.resolve_scope_name(None),
                    secrets,
                    missing_required: Vec::new(),
                    missing_optional,
                })
            }
            Err(errors) => {
                if !errors.constraint_violations.is_empty() {
                    return Err(SecretSpecError::ValidationFailed(Box::new(errors)));
                }
                let mut missing_required = errors.missing_required.clone();
                missing_required.sort();
                let mut missing_optional = errors.missing_optional.clone();
                missing_optional.sort();
                Ok(ResolveResponse {
                    schema_version: RESOLVE_SCHEMA_VERSION,
                    provider: errors.provider.clone(),
                    profile: errors.profile.clone(),
                    scope: self.resolve_scope_name(None),
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
        let mut report = match self.validate_audited(true, Materialize::None)? {
            Ok(validated) => validated.report(),
            Err(errors) => errors.report(),
        };
        // Surface the active scope so `check --json`/`--explain` shows the scoped
        // surface it resolved against; `None` (unscoped) is omitted from output.
        report.scope = self.resolve_scope_name(None);
        Ok(report)
    }

    /// Resolves all secrets. `emit_check` controls whether this pass records a
    /// `Check` audit event.
    ///
    /// Top-level reads ([`Self::validate`], `check`) pass `true`. Internal
    /// re-validations inside [`Self::ensure_secrets`] and the `run` resolver pass
    /// `false`, so one user action does not also emit a `Check`. The trade-off:
    /// a direct
    /// `ensure_secrets` call (rare; not the path `secretspec-derive` uses) does
    /// not emit a `Check` read event, though any writes it performs are audited.
    ///
    /// `materialize` gates value production, generated-secret persistence,
    /// `as_path` files, and run-only prompting for missing values.
    /// [`Materialize::None`] runs the same provider resolution without those
    /// effects; see [`Materialize`].
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
        // The *visible* set (scope ∩ profile, or the whole profile when no scope
        // is active) is what the action exposes and audits. Resolved once; its
        // sorted names are the audit keys, and — when unscoped — the plan's input
        // directly.
        let visible_result = self.resolve_profile_secret_names(Some(&profile_name));
        let visible: Vec<String> = visible_result.as_ref().ok().cloned().unwrap_or_default();

        // When a scope is active, resolution must additionally fetch the
        // composed-secret dependency closure of the visible set (an in-scope
        // `DATABASE_URL` may reference out-of-scope `DB_USER`/`DB_PASSWORD`), then
        // filter the output back to `visible` so those inputs resolve without
        // being exposed. Unscoped, the closure equals the whole profile, so the
        // worklist is just `visible` and nothing is filtered.
        // Unscoped, `visible` moves into the worklist rather than being cloned:
        // there is no filter to build from it afterwards.
        let scoped = self.resolve_scope_name(None).is_some();
        let (worklist, output_filter): (Vec<String>, Option<HashSet<String>>) = if scoped {
            let worklist = self.accessed_names(&profile_name, &visible);
            (worklist, Some(visible.into_iter().collect()))
        } else {
            (visible, None)
        };

        // Keys for the single read-audit event, computed before any planning can
        // fail (e.g. on an undefined alias) so a failed read is still attributed
        // to every secret it attempted; they stay empty only if the
        // profile/scope itself fails to resolve. This is the *accessed* set, not
        // the visible one: the audit answers "what was read from a provider",
        // and a hidden composition input is read even though it is never
        // exposed. Recording only the visible names would understate provider
        // access, which is the one thing the log exists to capture. Cloned only
        // when auditing is on, like the other event sites.
        let audit_keys: Vec<String> = if self.audit.is_some() {
            worklist.clone()
        } else {
            Vec::new()
        };

        // Decide the whole plan up front (pure, no I/O), then execute it. Each
        // step returns `Result`, so *any* error — an undefined alias, an
        // unsupported `ref` coordinate, a fallback-chain outage, a report-URI
        // failure — is captured in `result` and recorded as the single `Check`
        // event below rather than escaping unaudited. `record` is a no-op when
        // auditing is off.
        let result: Result<std::result::Result<ValidatedSecrets, ValidationErrors>> =
            visible_result
                .and_then(|_| self.build_plan_from_names(profile_name.clone(), worklist))
                .and_then(|plan| {
                    self.execute_plan(&plan, materialize, output_filter.as_ref(), None)
                });

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

    /// The target plus its transitive declared dependencies, sorted for a
    /// deterministic, least-access `get` plan.
    fn composed_dependency_names(&self, target: &str, profile_name: &str) -> Vec<String> {
        fn visit(
            name: &str,
            profile: &crate::manifest::CompiledProfile,
            names: &mut HashSet<String>,
        ) {
            if !names.insert(name.to_string()) {
                return;
            }
            if let Some(template) = &profile.secrets[name].composition {
                for dependency in template.dependencies() {
                    visit(dependency, profile, names);
                }
            }
        }

        let profile = self
            .manifest
            .profile(profile_name)
            .expect("profile is validated before dependency planning");
        let mut names = HashSet::new();
        visit(target, profile, &mut names);
        let mut names: Vec<String> = names.into_iter().collect();
        names.sort();
        names
    }

    /// Replace missing derived nodes with the unresolved provider-backed leaves
    /// a user can actually set. This also permits an optional leaf to be
    /// prompted when a required composition depends on it.
    fn promptable_missing_names(
        &self,
        errors: &ValidationErrors,
        profile_name: &str,
    ) -> Vec<String> {
        let statuses: HashMap<&str, &ResolutionStatus> = errors
            .resolution
            .iter()
            .map(|entry| (entry.name.as_str(), &entry.status))
            .collect();
        let profile = self
            .manifest
            .profile(profile_name)
            .expect("profile is validated before prompting");

        fn visit(
            name: &str,
            profile: &crate::manifest::CompiledProfile,
            statuses: &HashMap<&str, &ResolutionStatus>,
            promptable: &mut HashSet<String>,
        ) {
            let Some(template) = &profile.secrets[name].composition else {
                promptable.insert(name.to_string());
                return;
            };
            for dependency in template.dependencies() {
                if statuses.get(dependency.as_str()).copied() != Some(&ResolutionStatus::Resolved) {
                    visit(dependency, profile, statuses, promptable);
                }
            }
        }

        let mut promptable = HashSet::new();
        for name in &errors.missing_required {
            visit(name, profile, &statuses, &mut promptable);
        }
        let mut promptable: Vec<String> = promptable.into_iter().collect();
        promptable.sort();
        promptable
    }

    /// The secrets an interactive resolution may prompt the operator for: the
    /// promptable missing leaves ([`Self::promptable_missing_names`]), restricted
    /// to the visible set when a scope is active.
    ///
    /// The restriction is load-bearing. A missing out-of-scope composition
    /// dependency reaches `promptable_missing_names` because the visible-only
    /// resolution list makes its status look unresolved, so the raw set descends
    /// into hidden leaves. Prompting for those would disclose a hidden secret's
    /// name (and overwrite an already-present value on entry), breaking the scope
    /// guarantee. When a scope is active the operator may therefore be prompted
    /// only for secrets the scope itself exposes; unscoped, nothing is filtered.
    pub(crate) fn scoped_promptable_missing(
        &self,
        errors: &ValidationErrors,
        profile_name: &str,
    ) -> Result<Vec<String>> {
        let mut missing = self.promptable_missing_names(errors, profile_name);
        if self.resolve_scope_name(None).is_some() {
            let visible: HashSet<String> = self
                .resolve_profile_secret_names(Some(profile_name))?
                .into_iter()
                .collect();
            missing.retain(|name| visible.contains(name));
        }
        Ok(missing)
    }

    /// What a provider diagnostic may call `name` under `output_filter`.
    ///
    /// A scoped resolution fetches the composed-secret dependencies of the
    /// visible set and then drops them from the output, so the consumer never
    /// receives their values. Naming one in a warning would hand over exactly
    /// what the filter removed, which is why prompting is filtered the same way
    /// (see [`Self::scoped_promptable_missing`]). The real name is still what
    /// the read is addressed by; only the text a human sees changes.
    ///
    /// Unfiltered (no scope active), every name is its own label.
    ///
    /// This governs secretspec's own diagnostics. A provider's error string is
    /// authored by the provider and may still embed the address it searched.
    pub(crate) fn diagnostic_secret_name<'a>(
        name: &'a str,
        output_filter: Option<&HashSet<String>>,
    ) -> &'a str {
        match output_filter {
            Some(filter) if !filter.contains(name) => HIDDEN_SECRET_LABEL,
            _ => name,
        }
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
        &self,
        provider_spec: Option<&str>,
        group: &[&PlannedSecret],
        provider: &dyn ProviderTrait,
        project: &str,
        profile: &str,
    ) -> Result<()> {
        for planned in group {
            // Only the routes that consult exactly one store; a chain with a
            // fallback defers coordinate checking to per-store read time.
            // (Groups never contain a routeless composed secret.)
            let Some(route) = &planned.route else {
                continue;
            };
            if route.fallback_specs().is_some() {
                continue;
            }
            let address = self.address_for_spec(planned, provider_spec, project, profile)?;
            if address.native().is_some() {
                provider.resolve_coords(address.as_address())?;
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
    /// its compiled missing-value policy (prompt, generation, default, or
    /// absence). A
    /// primary that *errored* (rather than merely lacked the secret) with no
    /// fallback to try surfaces that error instead of a spurious "missing", so a
    /// machine consumer can tell an outage from an unprovisioned secret.
    ///
    /// `materialize` gates values and their effects. [`Materialize::Run`] also
    /// enables explicit missing-value prompts; [`Materialize::None`] skips all value
    /// production, provider/cache writes, and temp files.
    ///
    /// `read_addresses` collects the native coordinates each secret was actually
    /// read from, for the callers that audit a single secret. A cache hit
    /// contributes nothing: the authoritative coordinates were not consulted, so
    /// recording them would overstate what the read touched.
    fn execute_plan(
        &self,
        plan: &ResolutionPlan,
        materialize: Materialize,
        output_filter: Option<&HashSet<String>>,
        mut read_addresses: Option<&mut HashMap<String, NativeAddress>>,
    ) -> Result<std::result::Result<ValidatedSecrets, ValidationErrors>> {
        let project = self.config.project.name.as_str();
        let profile = plan.profile.as_str();

        // An empty plan — the common cause is an empty scope intersection —
        // resolves to nothing and must **not** initialize or contact any
        // provider (naming the report provider alone would build the default
        // provider, which can fetch credentials). Return an empty successful
        // resolution attributed to no provider.
        if plan.secrets.is_empty() {
            return Ok(Ok(ValidatedSecrets {
                resolved: Resolved::new(HashMap::new(), String::new(), profile.to_string()),
                missing_optional: Vec::new(),
                with_defaults: Vec::new(),
                resolution: Vec::new(),
                temp_files: Vec::new(),
            }));
        }

        let mut secrets: HashMap<String, SecretString> = HashMap::new();
        let mut missing_required = Vec::new();
        let mut missing_optional = Vec::new();
        let mut with_defaults = Vec::new();
        // Not filtered by the output filter, deliberately: an `as_path` secret's
        // resolved value is its temp-file path, so a visible composition built
        // from a hidden `as_path` input embeds that path in its own value.
        // Dropping the file would delete it and hand the consumer a dangling
        // path. Keeping it is consistent with composition's existing contract —
        // a composed DSN already carries its inputs' content in derived form —
        // while the input itself stays out of the environment.
        let mut temp_files: Vec<tempfile::NamedTempFile> = Vec::new();
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
        let mut cached_uris: HashMap<String, String> = HashMap::new();

        // Consult caches before constructing source providers. Cache hits are
        // inserted into the same fetched-values map, and their names are
        // filtered out of source groups below. This ordering is what makes a
        // cached route useful when its remote provider is slow or unavailable.
        for (name, (value, uri)) in self.read_cached_group(plan, profile) {
            cached_uris.insert(name.clone(), uri);
            fetched_values.insert(name, value);
        }

        // Construction stays on this thread: the up-front single-store `ref`
        // check below must see every built provider before any store is
        // contacted. Building a credential-backed alias's provider already fetches
        // its provider credentials here (memoized per spec); only the group
        // fetches run concurrently below.
        let mut group_fetches: Vec<GroupFetch<'_>> = Vec::new();
        for (provider_uri, group) in plan.groups() {
            let group: Vec<&PlannedSecret> = group
                .into_iter()
                .filter(|planned| !cached_uris.contains_key(&planned.name))
                .collect();
            if group.is_empty() {
                continue;
            }
            match self.get_route_provider(provider_uri, Some(&plan.profile)) {
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
        for (provider_spec, group, provider) in &group_fetches {
            self.check_single_store_ref_coords(
                *provider_spec,
                group,
                provider.as_ref(),
                project,
                profile,
            )?;
        }

        // Fetch the groups concurrently: each group is at least one provider
        // round-trip. One thread per group mirrors the per-item threading
        // providers already do inside `get_many`. A single group (the common
        // case) stays on this thread.
        fn fetch_group<'a>(
            secrets: &Secrets,
            (provider_uri, group, provider): GroupFetch<'a>,
            project: &str,
            profile: &str,
        ) -> (Option<&'a str>, Result<HashMap<String, SecretString>>) {
            let result = secrets.fetch_group(&*provider, provider_uri, &group, project, profile);
            (provider_uri, result)
        }

        let fetch_results: Vec<(Option<&str>, Result<_>)> = if group_fetches.len() <= 1 {
            group_fetches
                .into_iter()
                .map(|group| fetch_group(self, group, project, profile))
                .collect()
        } else {
            std::thread::scope(|scope| {
                let handles: Vec<_> = group_fetches
                    .into_iter()
                    .map(|group| scope.spawn(|| fetch_group(self, group, project, profile)))
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

        // Primary misses walk their fallback chains independently, so resolve
        // those chains concurrently instead of paying one provider round-trip
        // per secret in series. Each worker still calls
        // `get_secret_from_providers`, preserving provider order, lazy alias
        // resolution, warnings, and the healthy-miss/error distinction for its
        // own secret. Providers themselves are shared through `ProviderCache`.
        let provider_cache = ProviderCache::default();
        let pending_fallbacks: Vec<&PlannedSecret> = plan
            .secrets
            .iter()
            .filter(|planned| {
                !fetched_values.contains_key(&planned.name)
                    && planned
                        .route
                        .as_ref()
                        .and_then(Route::fallback_specs)
                        .is_some()
            })
            .collect();
        let mut fallback_results: HashMap<String, FallbackReadResult> =
            crate::provider::map_concurrently(
                &pending_fallbacks,
                crate::provider::get_each_concurrency(),
                |planned| {
                    let route = planned
                        .route
                        .as_ref()
                        .expect("pending fallback has a provider route");
                    let fallback = route
                        .fallback_specs()
                        .expect("pending fallback has fallback specs");
                    let result = self.get_secret_from_providers(
                        &provider_cache,
                        planned,
                        Self::diagnostic_secret_name(&planned.name, output_filter),
                        Some(fallback),
                        project,
                        profile,
                        None,
                    );
                    (planned.name.clone(), result)
                },
            )
            .into_iter()
            .collect();

        // Process each planned secret: apply the fetched value, its fallback
        // chain, generation, or default, and record a value-free provenance entry
        // for the resolution report.
        for planned in &plan.secrets {
            // Composed secrets have no route; they render after this loop,
            // once their dependencies are decided.
            let Some(route) = &planned.route else {
                continue;
            };
            let name = &planned.name;
            let required = planned.required();
            let as_path = planned.as_path();
            let diagnostic_name = Self::diagnostic_secret_name(name, output_filter);
            // The group key (primary spec), matching how `group_uris` and
            // `failed_primary_uris` were keyed from `plan.groups()` above.
            let primary_uri = route.group_key();

            let status;
            let mut source_provider = None;
            let mut default_applied = false;
            let mut generated = false;

            match fetched_values.remove(name.as_str()) {
                Some(value) => {
                    let was_cached = cached_uris.contains_key(name);
                    source_provider = cached_uris
                        .remove(name)
                        .or_else(|| group_uris.get(&primary_uri).cloned());
                    if !was_cached && let Some(addresses) = read_addresses.as_deref_mut() {
                        // The primary answered, so it was addressed with the
                        // coordinates the group fetch computed for this spec.
                        if let Ok(address) =
                            self.address_for_spec(planned, primary_uri, project, profile)
                            && let Some(native) = address.native()
                        {
                            addresses.insert(name.clone(), native.clone());
                        }
                    }
                    if !was_cached && materialize.values() {
                        self.write_cached_secret(planned, route, profile, &value);
                    }
                    // Copy the value into the response only on a full pass; a
                    // value-free pass has the status it needs and never
                    // materializes a value or writes a temp file.
                    if materialize.values() {
                        self.insert_resolved(
                            &mut secrets,
                            &mut temp_files,
                            planned,
                            diagnostic_name,
                            value,
                            ResolvedRepresentation::Stored,
                        )?;
                    }
                    status = ResolutionStatus::Resolved;
                }
                None => {
                    let primary_failed = failed_primary_uris.contains_key(&primary_uri);

                    // The primary was addressed even though it did not answer.
                    // An audited failed read has to name the coordinates it
                    // attempted, so record them before the error paths below
                    // return. A fallback that answers overwrites this with the
                    // address that did.
                    if let Some(addresses) = read_addresses.as_deref_mut()
                        && let Ok(address) =
                            self.address_for_spec(planned, primary_uri, project, profile)
                        && let Some(native) = address.native()
                    {
                        addresses.insert(name.clone(), native.clone());
                    }

                    // The primary missed, so consume the fallback result fetched
                    // concurrently above. Each chain was still tried in order
                    // and received the diagnostic label rather than a hidden
                    // composition input's raw name.
                    let (fallback_value, fallback_uri, fallback_reference) =
                        match route.fallback_specs() {
                            Some(_) => {
                                let resolved = fallback_results
                                    .remove(name)
                                    .expect("primary miss with fallback was prefetched")?;
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
                            None => (None, None, None),
                        };

                    if let Some(addresses) = read_addresses.as_deref_mut()
                        && let Some(reference) = fallback_reference
                    {
                        // Recorded for a miss too: the attempted coordinates are
                        // what an audited failed read has to name.
                        addresses.insert(name.clone(), reference);
                    }
                    if let Some(value) = fallback_value {
                        source_provider = fallback_uri;
                        if materialize.values() {
                            self.write_cached_secret(planned, route, profile, &value);
                            self.insert_resolved(
                                &mut secrets,
                                &mut temp_files,
                                planned,
                                diagnostic_name,
                                value,
                                ResolvedRepresentation::Stored,
                            )?;
                        }
                        status = ResolutionStatus::Resolved;
                    } else {
                        match planned.secret.missing {
                            MissingPolicy::Prompt => {
                                // Prompt only for names the active scope exposes.
                                // A hidden composition dependency must never be
                                // disclosed merely because a visible derived
                                // secret depends on it.
                                if materialize.prompts()
                                    && output_filter.is_none_or(|filter| filter.contains(name))
                                {
                                    let prompted = self.try_prompt_secret(planned, profile)?;
                                    self.insert_resolved(
                                        &mut secrets,
                                        &mut temp_files,
                                        planned,
                                        diagnostic_name,
                                        prompted,
                                        ResolvedRepresentation::Logical,
                                    )?;
                                    status = ResolutionStatus::Resolved;
                                } else if required {
                                    missing_required.push(name.clone());
                                    status = ResolutionStatus::MissingRequired;
                                } else {
                                    missing_optional.push(name.clone());
                                    status = ResolutionStatus::MissingOptional;
                                }
                            }
                            MissingPolicy::Generate => {
                                // A full pass mints and stores; a value-free pass
                                // reports that generation would resolve without
                                // performing that side effect.
                                generated = true;
                                if materialize.values() {
                                    let generated_value = self
                                        .try_generate_secret(planned, profile)?
                                        .expect("compiled Generate policy has a generator");
                                    self.insert_resolved(
                                        &mut secrets,
                                        &mut temp_files,
                                        planned,
                                        diagnostic_name,
                                        generated_value,
                                        ResolvedRepresentation::Logical,
                                    )?;
                                }
                                status = ResolutionStatus::Resolved;
                            }
                            MissingPolicy::UseDefault => {
                                let default_value = planned
                                    .config()
                                    .default
                                    .as_ref()
                                    .expect("compiled UseDefault policy has a default");
                                default_applied = true;
                                if materialize.values() {
                                    self.insert_resolved(
                                        &mut secrets,
                                        &mut temp_files,
                                        planned,
                                        diagnostic_name,
                                        SecretString::new(default_value.clone().into()),
                                        ResolvedRepresentation::Logical,
                                    )?;
                                    with_defaults.push((name.clone(), default_value.clone()));
                                }
                                status = ResolutionStatus::Resolved;
                            }
                            MissingPolicy::Error => {
                                missing_required.push(name.clone());
                                status = ResolutionStatus::MissingRequired;
                            }
                            MissingPolicy::Omit => {
                                missing_optional.push(name.clone());
                                status = ResolutionStatus::MissingOptional;
                            }
                        }
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
                composed: false,
                as_path,
            });
        }

        // Render composed secrets after every provider-backed secret has been
        // decided, dependencies before dependents. Load-time graph validation
        // guarantees acyclicity, so a depth-first post-order over the composed
        // nodes is a topological order; rooting the walk at the plan's
        // name-sorted secrets keeps the report order deterministic.
        fn composition_order<'a>(
            planned: &'a PlannedSecret,
            composed: &HashMap<&str, &'a PlannedSecret>,
            visited: &mut HashSet<&'a str>,
            ordered: &mut Vec<&'a PlannedSecret>,
        ) {
            if !visited.insert(planned.name.as_str()) {
                return;
            }
            let template = planned
                .composition()
                .expect("only composed nodes are ordered");
            for dependency in template.dependencies() {
                if let Some(dependency) = composed.get(dependency.as_str()) {
                    composition_order(dependency, composed, visited, ordered);
                }
            }
            ordered.push(planned);
        }
        let composed: HashMap<&str, &PlannedSecret> = plan
            .secrets
            .iter()
            .filter(|secret| secret.is_composed())
            .map(|secret| (secret.name.as_str(), secret))
            .collect();
        let mut ordered = Vec::with_capacity(composed.len());
        let mut visited = HashSet::new();
        for planned in plan.secrets.iter().filter(|secret| secret.is_composed()) {
            composition_order(planned, &composed, &mut visited, &mut ordered);
        }

        if !ordered.is_empty() {
            // Statuses of the already-decided secrets, extended as each
            // composition renders so nested compositions see derived
            // dependencies. Built only when the plan has composed secrets.
            let mut statuses: HashMap<String, ResolutionStatus> = resolution
                .iter()
                .map(|entry| (entry.name.clone(), entry.status.clone()))
                .collect();
            for planned in ordered {
                let template = planned
                    .composition()
                    .expect("only composed nodes are ordered");
                let dependencies_resolved = template.dependencies().iter().all(|dependency| {
                    statuses.get(dependency) == Some(&ResolutionStatus::Resolved)
                });
                let status = if dependencies_resolved {
                    if materialize.values() {
                        let rendered = template
                            .render(|dependency| {
                                secrets.get(dependency).map(|value| value.expose_secret())
                            })
                            .map_err(SecretSpecError::CompositionFailed)?;
                        self.insert_resolved(
                            &mut secrets,
                            &mut temp_files,
                            planned,
                            Self::diagnostic_secret_name(&planned.name, output_filter),
                            SecretString::new(rendered.into()),
                            ResolvedRepresentation::Logical,
                        )?;
                    }
                    ResolutionStatus::Resolved
                } else {
                    match planned.secret.missing {
                        MissingPolicy::Error => {
                            missing_required.push(planned.name.clone());
                            ResolutionStatus::MissingRequired
                        }
                        MissingPolicy::Omit => {
                            missing_optional.push(planned.name.clone());
                            ResolutionStatus::MissingOptional
                        }
                        MissingPolicy::Generate
                        | MissingPolicy::UseDefault
                        | MissingPolicy::Prompt => {
                            unreachable!("composed source conflicts are rejected at load time")
                        }
                    }
                };

                statuses.insert(planned.name.clone(), status.clone());
                resolution.push(SecretResolution {
                    name: planned.name.clone(),
                    status,
                    required: planned.required(),
                    source_provider: None,
                    default_applied: false,
                    generated: false,
                    composed: true,
                    as_path: planned.as_path(),
                });
            }
        }

        // Composed secrets carry no route; the stores their leaves route to
        // name the report, exactly as for ordinary secrets.
        let report_provider_uri = self.validation_report_provider_uri(
            plan.override_uri.as_deref(),
            plan.secrets
                .iter()
                .filter_map(|secret| secret.route.as_ref())
                .map(|route| route.primary()),
            Some(&plan.profile),
        )?;

        // Restrict the output to the visible set. The plan resolved the wider
        // *accessed* set (visible plus the composed-secret dependency closure) so
        // in-scope compositions could render; their out-of-scope inputs are now
        // dropped from every output surface — the value map, the temp files
        // backing `as_path` values, the per-secret report, and the missing/default
        // lists — so the scope exposes exactly what it declares and nothing more.
        // `None` (no scope active) leaves everything untouched.
        if let Some(filter) = output_filter {
            secrets.retain(|name, _| filter.contains(name));
            resolution.retain(|entry| filter.contains(&entry.name));
            missing_required.retain(|name| filter.contains(name));
            missing_optional.retain(|name| filter.contains(name));
            with_defaults.retain(|(name, _)| filter.contains(name));
        }

        // Note that `temp_files` is not filtered alongside these; see its
        // declaration for why a hidden `as_path` input must keep its file.

        // Constraints are evaluated after scope filtering, so an out-of-scope
        // dependency resolved only to build a composition never counts as
        // "present" for a presence group.
        let resolved_names: HashSet<&str> = resolution
            .iter()
            .filter(|entry| entry.status == ResolutionStatus::Resolved)
            .map(|entry| entry.name.as_str())
            .collect();
        let compiled_profile = self
            .manifest
            .profile(profile)
            .expect("profile is validated before execution");
        // `get` executes a deliberately partial plan for a composed secret and
        // its dependencies. Profile constraints govern whole-profile
        // validation (`check`, `run`, and SDK resolution), not that least-access
        // read. A *scoped* resolution is also partial, but it is a whole-profile
        // validation of a declared subset, so constraints still apply — narrowed
        // to the visible set below rather than skipped.
        let constraints = (output_filter.is_some()
            || plan.secrets.len() == compiled_profile.secrets.len())
        .then_some(&compiled_profile.constraints);
        let mut constraint_violations = Vec::new();
        if let Some(constraints) = constraints {
            // Under a scope a group is judged on the members the consumer can
            // actually see: a group with no visible member is not this
            // consumer's concern, and one with some is enforced over those. The
            // reported member list is narrowed the same way, so a violation
            // message never names a secret the scope hides.
            let visible_members = |members: &Vec<String>| -> Vec<String> {
                match output_filter {
                    Some(filter) => members
                        .iter()
                        .filter(|name| filter.contains(name.as_str()))
                        .cloned()
                        .collect(),
                    None => members.clone(),
                }
            };
            for group in &constraints.at_least_one {
                let members = visible_members(&group.members);
                if members.is_empty() {
                    continue;
                }
                let present: Vec<String> = members
                    .iter()
                    .filter(|name| resolved_names.contains(name.as_str()))
                    .cloned()
                    .collect();
                if present.is_empty() {
                    constraint_violations.push(ConstraintViolation {
                        kind: ConstraintKind::AtLeastOne,
                        group: group.name.clone(),
                        secrets: members,
                        present,
                    });
                }
            }
            for group in &constraints.exactly_one {
                let members = visible_members(&group.members);
                if members.is_empty() {
                    continue;
                }
                let present: Vec<String> = members
                    .iter()
                    .filter(|name| resolved_names.contains(name.as_str()))
                    .cloned()
                    .collect();
                if present.len() != 1 {
                    constraint_violations.push(ConstraintViolation {
                        kind: ConstraintKind::ExactlyOne,
                        group: group.name.clone(),
                        secrets: members,
                        present,
                    });
                }
            }
        }

        if !missing_required.is_empty() || !constraint_violations.is_empty() {
            let mut errors = ValidationErrors::new(
                missing_required,
                missing_optional,
                with_defaults,
                report_provider_uri,
                profile.to_string(),
            );
            errors.resolution = resolution;
            errors.constraint_violations = constraint_violations;
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

        // Resolve all secrets for this invocation. `Materialize::Run` is the
        // only mode allowed to ask for an explicitly `prompt = true` value;
        // the prompt backend uses the controlling terminal and leaves the
        // child's inherited stdin untouched.
        // `validation_result` owns the temp files for `as_path` secrets and
        // must stay alive until the child process has terminated.
        let resolution = self
            .validate_audited(false, Materialize::Run)
            .and_then(|result| result.map_err(validation_failure));
        let validation_result = match resolution {
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

        // When a scope is active, the secrets it does not admit must not reach
        // the child even if the parent already holds them (a devenv shell, a
        // prior `eval "$(secretspec export)"`). Computed here and stripped at the
        // `Command` level below — filtering the overlay map is not enough, since
        // the child inherits the real parent environment by default. Resolution
        // already validated the scope (`ensure_secrets` above), so this cannot
        // fail on an unknown scope here.
        let excluded = self.scope_excluded_names()?;
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
        // `env_remove` overrides inheritance, so a scope-excluded secret the
        // parent exported is unset in the child rather than merely left out of
        // the overlay. No-ops when no scope is active (`excluded` is empty).
        for key in &excluded {
            cmd.env_remove(key);
        }

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

    /// Resolves every secret for the active profile and emits them in `format`,
    /// without executing a command. This is the non-interactive, scripting
    /// counterpart to [`Secrets::run`]: it never prompts and errors when a
    /// required secret is missing, so CI can gate on it.
    ///
    /// `as_path` secrets keep their backing temp files, like [`Secrets::check`],
    /// so the emitted paths stay valid for whatever consumes the output.
    ///
    /// Output is written to `out` rather than directly to stdout, so an SDK/FFI
    /// caller can capture the formatted bytes and a broken pipe surfaces as a
    /// returned error (and is audited) instead of a panic. The CLI passes a
    /// locked stdout handle.
    pub fn export(&self, format: ExportFormat, out: &mut dyn io::Write) -> Result<()> {
        self.ensure_reason_for(AuditAction::Export, None)?;
        let profile = self.resolve_profile_name(None);

        let mut validated = match self.ensure_secrets(None, None, false) {
            Ok(v) => v,
            Err(e) => {
                self.record(
                    AuditAction::Export,
                    &profile,
                    AuditOutcome::Error,
                    AuditFields {
                        error_kind: Some(e.kind()),
                        ..Default::default()
                    },
                );
                return Err(e);
            }
        };

        // Persist as_path temp files *before* emitting, so a persistence failure
        // aborts up front rather than after the paths have already been written
        // out (a consumer captures stdout regardless of the exit code) and the
        // temp files are then deleted on drop. The path strings already live in
        // `resolved.secrets`, so keeping first does not change what is emitted.
        if let Err(e) = validated.keep_temp_files() {
            let err = SecretSpecError::Io(e);
            self.record(
                AuditAction::Export,
                &validated.resolved.profile,
                AuditOutcome::Error,
                AuditFields {
                    error_kind: Some(err.kind()),
                    ..Default::default()
                },
            );
            return Err(err);
        }

        // Deterministic key order regardless of HashMap iteration. Values are
        // borrowed (not copied) out of the resolved map, so secret material is
        // not duplicated into a second set of heap buffers.
        let mut entries: Vec<(&str, &str)> = validated
            .resolved
            .secrets
            .iter()
            .map(|(key, value)| (key.as_str(), value.expose_secret()))
            .collect();
        entries.sort_by(|(a, _), (b, _)| a.cmp(b));

        let keys: Vec<String> = if self.audit.is_some() {
            entries.iter().map(|(key, _)| key.to_string()).collect()
        } else {
            Vec::new()
        };

        let result = write_export(format, &entries, out);
        self.record(
            AuditAction::Export,
            &validated.resolved.profile,
            if result.is_ok() {
                AuditOutcome::Found
            } else {
                AuditOutcome::Error
            },
            AuditFields {
                keys: &keys,
                error_kind: result.as_ref().err().map(|e| e.kind()),
                ..Default::default()
            },
        );
        result?;

        Ok(())
    }
}

/// Output format for [`Secrets::export`]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
pub enum ExportFormat {
    /// `export KEY='value'` lines for `eval "$(secretspec export)"`
    #[default]
    Shell,
    /// `KEY=value` lines in dotenv syntax
    Dotenv,
    /// A single JSON object mapping each secret name to its value
    Json,
    /// GitHub/Forgejo Actions `$GITHUB_ENV` file plus `::add-mask::` on stdout
    Gha,
}

/// Write entries (pre-sorted by key) to `out` in the given format. Writing to
/// an injected sink (rather than `print!`) lets an SDK caller capture the bytes
/// and turns a broken pipe into a returned error instead of a panic.
fn write_export(
    format: ExportFormat,
    entries: &[(&str, &str)],
    out: &mut dyn io::Write,
) -> Result<()> {
    match format {
        ExportFormat::Shell => {
            let mut buf = String::new();
            for (key, value) in entries {
                buf.push_str("export ");
                buf.push_str(key);
                buf.push('=');
                buf.push_str(&shell_single_quote(value));
                buf.push('\n');
            }
            out.write_all(buf.as_bytes()).map_err(SecretSpecError::Io)?;
        }
        ExportFormat::Dotenv => {
            // entries are already sorted, so serialize them directly instead of
            // rebuilding and re-sorting a map (which would also re-copy values).
            let content = crate::provider::dotenv::serialize_dotenv_pairs(
                entries.iter().map(|(key, value)| (*key, *value)),
            );
            out.write_all(content.as_bytes())
                .map_err(SecretSpecError::Io)?;
        }
        ExportFormat::Json => {
            let map: BTreeMap<&str, &str> = entries.iter().copied().collect();
            let json = serde_json::to_string(&map)
                .map_err(|e| SecretSpecError::Io(io::Error::other(e)))?;
            out.write_all(json.as_bytes())
                .and_then(|()| out.write_all(b"\n"))
                .map_err(SecretSpecError::Io)?;
        }
        ExportFormat::Gha => write_gha(entries, out)?,
    }

    Ok(())
}

/// POSIX single-quote escaping so the value survives `eval` verbatim
pub(crate) fn shell_single_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// GitHub/Forgejo Actions writer that masks every value line on `out` and
/// appends the assignments to `$GITHUB_ENV`. Multi-line values use the heredoc
/// form so they survive. Errors when `$GITHUB_ENV` is unset.
fn write_gha(entries: &[(&str, &str)], out: &mut dyn io::Write) -> Result<()> {
    use std::io::Write;

    let github_env = env::var("GITHUB_ENV").map_err(|_| {
        SecretSpecError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "GITHUB_ENV is not set; `--format gha` only works inside a GitHub/Forgejo Actions runner",
        ))
    })?;

    // Mask every value line so the runner scrubs accidental echoes. The data
    // must be percent-encoded the way the runner expects, since it *unescapes*
    // add-mask data before registering the mask; emitting the raw value would
    // register a different string and leave the true secret unmasked.
    let mut masks = String::new();
    for (_, value) in entries {
        for line in value.split('\n') {
            if !line.is_empty() {
                masks.push_str("::add-mask::");
                masks.push_str(&gha_escape_data(line));
                masks.push('\n');
            }
        }
    }
    out.write_all(masks.as_bytes())
        .map_err(SecretSpecError::Io)?;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&github_env)
        .map_err(SecretSpecError::Io)?;

    let mut block = String::new();
    for (key, value) in entries {
        if value.contains('\n') {
            let delimiter = gha_heredoc_delimiter(value);
            block.push_str(key);
            block.push_str("<<");
            block.push_str(&delimiter);
            block.push('\n');
            block.push_str(value);
            block.push('\n');
            block.push_str(&delimiter);
            block.push('\n');
        } else {
            block.push_str(key);
            block.push('=');
            block.push_str(value);
            block.push('\n');
        }
    }

    // Record the length before appending so a partial write can be rolled back:
    // a truncated heredoc opener with no closing delimiter would otherwise
    // corrupt `$GITHUB_ENV` parsing for every later step in the job.
    let start_len = file.metadata().map_err(SecretSpecError::Io)?.len();
    if let Err(e) = file.write_all(block.as_bytes()) {
        let _ = file.set_len(start_len);
        return Err(SecretSpecError::Io(e));
    }

    Ok(())
}

/// Percent-encodes workflow-command data the way the Actions runner expects (it
/// unescapes the data before registering the mask), so the masked string equals
/// the real secret. Mirrors `@actions/core`'s `escapeData`. `%` is escaped first
/// so an embedded `%25`/`%0D`/`%0A` in the value is not later read back as `%`,
/// CR, or LF.
fn gha_escape_data(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

/// A heredoc delimiter that does not collide with any line of `value`
fn gha_heredoc_delimiter(value: &str) -> String {
    loop {
        let delimiter = format!("ghadelimiter_{}", uuid::Uuid::new_v4().simple());
        if !value.lines().any(|line| line == delimiter) {
            return delimiter;
        }
    }
}

#[cfg(test)]
mod write_target_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingProvider {
        writability_checks: AtomicUsize,
        descriptions: AtomicUsize,
    }

    impl ProviderTrait for CountingProvider {
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

        fn get(&self, _addr: Address<'_>) -> Result<Option<SecretString>> {
            Ok(None)
        }

        fn set(&self, _addr: Address<'_>, _value: &SecretString) -> Result<()> {
            Ok(())
        }

        fn check_writable(&self, _addr: Address<'_>) -> Result<()> {
            self.writability_checks.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn describe_write_target(&self, _addr: Address<'_>) -> Result<String> {
            self.descriptions.fetch_add(1, Ordering::SeqCst);
            Ok("described".to_string())
        }

        fn name(&self) -> &'static str {
            "counting"
        }

        fn uri(&self) -> String {
            "counting".to_string()
        }
    }

    #[test]
    fn library_preflight_skips_target_description_without_a_reporter() {
        let config = crate::tests::resolve_test_config(HashMap::from([(
            "API_KEY".to_string(),
            crate::config::Secret {
                description: Some("API key".to_string()),
                ..Default::default()
            },
        )]));
        let spec = Secrets::new(config, None, None, None);
        let planned = spec
            .plan_secret("API_KEY", "default", None)
            .unwrap()
            .unwrap();
        let provider = CountingProvider {
            writability_checks: AtomicUsize::new(0),
            descriptions: AtomicUsize::new(0),
        };

        spec.preflight_write(&planned, "default", &provider)
            .unwrap();

        assert_eq!(provider.writability_checks.load(Ordering::SeqCst), 1);
        assert_eq!(provider.descriptions.load(Ordering::SeqCst), 0);
    }
}

#[cfg(test)]
mod display_tests {
    use super::*;

    #[test]
    fn secret_label_emphasizes_the_name_and_deemphasizes_the_description() {
        assert_eq!(
            format_secret_label("DATABASE_URL", Some("PostgreSQL connection string")),
            format!(
                "{} {} {}",
                "DATABASE_URL".cyan().bold(),
                "-".dimmed(),
                "PostgreSQL connection string".dimmed()
            )
        );
    }

    #[test]
    fn secret_label_omits_a_missing_description_without_a_placeholder() {
        let label = format_secret_label("DATABASE_URL", None);

        assert_eq!(label, "DATABASE_URL".cyan().bold().to_string());
        assert!(!label.contains("No description"));
        assert!(!label.contains('-'));
    }
}

#[cfg(test)]
mod export_tests {
    use super::*;

    /// A POSIX shell evaluating `export K=<quoted>` must read the variable back
    /// as exactly the original value. This round-trip is the real contract that
    /// `shell_single_quote` defends, across quotes, spaces, `$`, `"`, and empty.
    #[cfg(unix)]
    #[test]
    fn shell_single_quote_round_trips_through_sh() {
        let cases = ["abc'123", "a b c", "pa$$word", "he said \"hi\"", "", "'"];

        for value in cases {
            let script = format!("export K={}; printf '%s' \"$K\"", shell_single_quote(value));

            let output = std::process::Command::new("sh")
                .arg("-c")
                .arg(&script)
                .output()
                .expect("sh should be available in the test environment");

            assert!(
                output.status.success(),
                "sh failed for {value:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );

            let read_back = String::from_utf8(output.stdout).expect("sh stdout is utf-8");
            assert_eq!(read_back, value, "round-trip mismatch for {value:?}");
        }
    }

    fn rendered(format: ExportFormat, entries: &[(&str, &str)]) -> String {
        let mut buf = Vec::new();
        write_export(format, entries, &mut buf).expect("write_export should succeed");
        String::from_utf8(buf).expect("export output is utf-8")
    }

    #[test]
    fn shell_format_quotes_each_value() {
        let out = rendered(ExportFormat::Shell, &[("A", "x y"), ("B", "a'b")]);
        assert_eq!(out, "export A='x y'\nexport B='a'\\''b'\n");
    }

    #[test]
    fn json_format_is_compact() {
        let out = rendered(ExportFormat::Json, &[("A", "1"), ("B", "2")]);
        assert_eq!(out, "{\"A\":\"1\",\"B\":\"2\"}\n");
    }

    #[test]
    fn dotenv_format_double_quotes_and_escapes() {
        let out = rendered(ExportFormat::Dotenv, &[("A", "pa$$"), ("B", "x")]);
        assert_eq!(out, "A=\"pa\\$\\$\"\nB=\"x\"\n");
    }

    /// The runner unescapes add-mask data before registering it, so the data we
    /// emit must be percent-encoded or the true value is left unmasked.
    #[test]
    fn gha_escape_data_encodes_percent_cr_and_lf() {
        assert_eq!(gha_escape_data("plain"), "plain");
        assert_eq!(gha_escape_data("a%b"), "a%25b");
        assert_eq!(gha_escape_data("a\rb"), "a%0Db");
        assert_eq!(gha_escape_data("a\nb"), "a%0Ab");
        // `%` is escaped first, so a literal `%0A` is not decoded back to a newline.
        assert_eq!(gha_escape_data("a%0Ab"), "a%250Ab");
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

    /// A default reason fills the gap but never overwrites one the caller
    /// already supplied: a wrapper describing itself must not replace the more
    /// specific reason its own caller passed in.
    #[test]
    fn with_default_reason_only_fills_an_absent_reason() {
        let spec = || {
            Secrets::new(
                crate::tests::resolve_test_config(HashMap::new()),
                None,
                None,
                None,
            )
        };

        // No reason yet: the default is adopted, normalized like any other.
        assert_eq!(
            spec().with_default_reason("  nightly export  ").reason,
            Some("nightly export".to_string())
        );

        // A reason already in effect wins, whichever order the calls come in.
        assert_eq!(
            spec()
                .with_reason("running migrations")
                .with_default_reason("nightly export")
                .reason,
            Some("running migrations".to_string())
        );

        // A blank default is no reason at all, so the session stays unreasoned
        // rather than storing an empty string that would satisfy nothing.
        assert_eq!(spec().with_default_reason("   ").reason, None);
        // ...and a blank default cannot clear a real reason either.
        assert_eq!(
            spec().with_reason("deploy").with_default_reason("").reason,
            Some("deploy".to_string())
        );
    }

    #[test]
    fn caller_context_is_normalized_but_never_counts_as_a_reason() {
        let mut spec = Secrets::new(
            crate::tests::resolve_test_config(HashMap::new()),
            None,
            None,
            None,
        )
        .with_caller(
            CallerContext::new("  git  ")
                .with_operation(" credential_get ")
                .with_resource(" github.com "),
        );

        assert_eq!(
            spec.caller,
            Some(
                CallerContext::new("git")
                    .with_operation("credential_get")
                    .with_resource("github.com")
            )
        );
        spec.require_reason = RequireReason::Always;
        assert!(matches!(
            spec.ensure_reason(),
            Err(SecretSpecError::ReasonRequired)
        ));

        // A real reason remains independent and satisfies the policy.
        assert!(spec.with_reason("release package").ensure_reason().is_ok());
    }

    #[test]
    fn non_blank_trims_and_blanks_to_none() {
        // A padded-but-nonblank override (e.g. a `$(cat file)` trailing newline)
        // is trimmed, not used verbatim, so it cannot select a nonexistent
        // profile/provider.
        assert_eq!(non_blank("production\n"), Some("production".to_string()));
        assert_eq!(non_blank("  keyring  "), Some("keyring".to_string()));
        // Blank input (empty or whitespace-only) is dropped.
        assert_eq!(non_blank(""), None);
        assert_eq!(non_blank("   "), None);
        assert_eq!(non_blank("\t\n"), None);
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

#[cfg(test)]
mod provider_credentials_cache_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn concurrent_population_for_one_key_is_single_flight() {
        const CALLERS: usize = 8;
        let cache = Arc::new(ProviderCredentialsCache::default());
        let start = Arc::new(Barrier::new(CALLERS));
        let fetches = Arc::new(AtomicUsize::new(0));

        let threads: Vec<_> = (0..CALLERS)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let start = Arc::clone(&start);
                let fetches = Arc::clone(&fetches);
                thread::spawn(move || {
                    start.wait();
                    cache
                        .get_or_try_init(("default".into(), "target".into()), || {
                            fetches.fetch_add(1, Ordering::SeqCst);
                            // Keep the first population in flight long enough for
                            // every caller to contend on the same key.
                            thread::sleep(Duration::from_millis(50));
                            let mut credentials = ProviderCredentials::new();
                            credentials.insert("token".into(), SecretString::new("value".into()));
                            Ok(credentials)
                        })
                        .unwrap()
                })
            })
            .collect();

        for thread in threads {
            let credentials = thread.join().unwrap();
            assert_eq!(
                credentials.get("token").map(|value| value.expose_secret()),
                Some("value")
            );
        }
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }
}

#[cfg(test)]
mod provider_cache_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    fn env_provider() -> Result<Box<dyn ProviderTrait>> {
        crate::provider::provider_from_spec("env://", ProviderCredentials::new())
    }

    /// A fallback chain is walked per secret, so N secrets sharing one link
    /// must not build N providers.
    #[test]
    fn one_key_builds_once_and_hands_back_the_same_instance() {
        let cache = ProviderCache::default();
        let builds = AtomicUsize::new(0);
        let key = ("default".to_string(), "env://".to_string());

        let first = cache
            .get_or_try_init(key.clone(), || {
                builds.fetch_add(1, Ordering::SeqCst);
                env_provider()
            })
            .unwrap();
        let second = cache
            .get_or_try_init(key, || {
                builds.fetch_add(1, Ordering::SeqCst);
                env_provider()
            })
            .unwrap();

        assert_eq!(builds.load(Ordering::SeqCst), 1);
        assert!(Arc::ptr_eq(&first, &second));
    }

    /// The profile is part of the key: a provider carries the credentials of
    /// the profile it was built under.
    #[test]
    fn distinct_keys_build_independently() {
        let cache = ProviderCache::default();
        let builds = AtomicUsize::new(0);

        let build_under = |profile: &str| {
            cache
                .get_or_try_init((profile.to_string(), "env://".to_string()), || {
                    builds.fetch_add(1, Ordering::SeqCst);
                    env_provider()
                })
                .unwrap()
        };
        let default = build_under("default");
        let production = build_under("production");

        assert_eq!(builds.load(Ordering::SeqCst), 2);
        assert!(!Arc::ptr_eq(&default, &production));
    }

    /// Failures are not memoized, so a provider that was unavailable can be
    /// built by a later operation in the same session.
    #[test]
    fn failures_are_not_memoized() {
        let cache = ProviderCache::default();
        let key = ("default".to_string(), "env://".to_string());

        let failed = cache.get_or_try_init(key.clone(), || {
            Err(SecretSpecError::ProviderOperationFailed("nope".into()))
        });
        assert!(failed.is_err());

        assert!(cache.get_or_try_init(key, env_provider).is_ok());
    }

    #[test]
    fn concurrent_construction_for_one_key_is_single_flight() {
        const CALLERS: usize = 8;
        let cache = Arc::new(ProviderCache::default());
        let start = Arc::new(Barrier::new(CALLERS));
        let builds = Arc::new(AtomicUsize::new(0));

        let threads: Vec<_> = (0..CALLERS)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let start = Arc::clone(&start);
                let builds = Arc::clone(&builds);
                thread::spawn(move || {
                    start.wait();
                    cache
                        .get_or_try_init(("default".into(), "env://".into()), || {
                            builds.fetch_add(1, Ordering::SeqCst);
                            // Hold the first construction in flight long enough
                            // for every caller to contend on the same key.
                            thread::sleep(Duration::from_millis(50));
                            env_provider()
                        })
                        .unwrap()
                })
            })
            .collect();

        let providers: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();

        assert_eq!(builds.load(Ordering::SeqCst), 1);
        for provider in &providers {
            assert!(Arc::ptr_eq(provider, &providers[0]));
        }
    }
}

#[cfg(test)]
mod provider_credential_scope_tests {
    use super::*;
    use crate::config::{CredentialSource, Profile, ProviderAlias, Secret};
    use crate::tests::{resolve_test_config, scrub_resolution_env};
    use tempfile::TempDir;

    /// A provider's authentication credential belongs to the alias, not to any
    /// one profile: `config provider login` stores under the session profile,
    /// but the same credential must resolve when the provider is used under a
    /// different profile. Before the fix the convention path embedded the active
    /// profile, so a credential stored under `default` was invisible to
    /// `production` and resolution hard-errored "credential not found".
    #[test]
    fn provider_credentials_resolve_under_any_profile() {
        let _env = scrub_resolution_env();
        let _cwd = crate::secrets::lock_cwd();
        let _store = TempDir::new().unwrap();

        // `access_token` is sourced from a writable, profile-namespacing store.
        let providers = HashMap::from([(
            "bws".to_string(),
            ProviderAlias::leaf(
                "bws://proj",
                HashMap::from([(
                    "access_token".to_string(),
                    CredentialSource::from("memtest://"),
                )]),
            ),
        )]);

        let mut config =
            resolve_test_config(HashMap::from([("API_KEY".to_string(), Secret::default())]));
        config.profiles.insert(
            "production".to_string(),
            Profile {
                defaults: None,
                secrets: HashMap::new(),
            },
        );
        config.providers = Some(providers);

        // `login` runs under the session/default profile.
        let logged_in = Secrets::new(config.clone(), None, None, None);
        let source = logged_in
            .declared_provider_credentials("bws")
            .unwrap()
            .into_iter()
            .next()
            .expect("alias declares one credential")
            .1;
        logged_in
            .store_provider_credential(
                &source,
                "access_token",
                &SecretString::new("tok-123".into()),
            )
            .unwrap();

        // Resolving the same alias under `production` must still find it.
        let resolver = Secrets::new(config, None, None, Some("production".to_string()));
        let resolved = resolver
            .resolve_provider_credentials("bws", "production")
            .expect("a stored provider credential must resolve under any profile");
        assert_eq!(
            resolved
                .get("access_token")
                .map(|value| value.expose_secret()),
            Some("tok-123"),
        );
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
mod encoding_tests {
    use super::*;

    #[test]
    fn decoding_accepts_exactly_one_trailing_line_ending() {
        for encoded in ["Zg==\n", "Zg==\r\n"] {
            let value = SecretString::new(encoded.to_string().into());
            let decoded =
                Secrets::decode_stored_value(SecretEncoding::Base64, "VALUE", &value).unwrap();
            assert_eq!(decoded.expose_secret(), b"f");
        }

        let value = SecretString::new("Zg==\n\n".to_string().into());
        let error =
            Secrets::decode_stored_value(SecretEncoding::Base64, "VALUE", &value).unwrap_err();
        assert_eq!(error.kind(), "decode_failed");
    }

    #[test]
    fn encoding_uses_canonical_storage_representations() {
        let cases = [
            (SecretEncoding::Base64, "value", "dmFsdWU="),
            (SecretEncoding::Base64Url, "hello?", "aGVsbG8_"),
            (SecretEncoding::Hex, "value", "76616c7565"),
        ];

        for (encoding, logical, expected) in cases {
            let logical = SecretString::new(logical.to_string().into());
            let stored = Secrets::encode_logical_value(encoding, &logical);
            assert_eq!(stored.expose_secret(), expected);
        }
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
                scopes: None,
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
                None,
            )
            .unwrap();
        assert_eq!(got, "vault+token:host/db");
        assert!(!got.contains("s3cr3t") && !got.contains("abc"));

        // Per-secret alias branch: the first sorted primary URI is redacted too.
        let got = spec
            .validation_report_provider_uri(
                None,
                [Some("vault://host?token=zzz")].into_iter(),
                None,
            )
            .unwrap();
        assert_eq!(got, "vault://host");
        assert!(!got.contains("zzz"));
    }
}

#[cfg(test)]
mod run_prompt_tests {
    use super::*;
    use crate::config::Secret;
    use secrecy::ExposeSecret;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn prompted_spec() -> Secrets {
        let config = crate::tests::resolve_test_config(HashMap::from([(
            "DEPLOY_PASSWORD".to_string(),
            Secret {
                description: Some("One-time deployment password".to_string()),
                required: Some(true),
                providers: Some(vec!["null".to_string()]),
                prompt: Some(true),
                ..Default::default()
            },
        )]));
        Secrets::new(config, None, None, None)
    }

    fn prompted_dotenv_spec(path: &std::path::Path) -> Secrets {
        let config = crate::tests::resolve_test_config(HashMap::from([(
            "DEPLOY_PASSWORD".to_string(),
            Secret {
                description: Some("Deployment password".to_string()),
                required: Some(true),
                providers: Some(vec![format!("dotenv://{}", path.display())]),
                prompt: Some(true),
                ..Default::default()
            },
        )]));
        Secrets::new(config, None, None, None)
    }

    #[test]
    fn run_prompts_again_for_each_resolution_without_storing() {
        let _env = crate::tests::scrub_resolution_env();
        let prompts = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&prompts);
        let mut spec = prompted_spec();
        spec.set_prompt_reader(move |name, profile| {
            assert_eq!(name, "DEPLOY_PASSWORD");
            assert_eq!(profile, "default");
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(SecretString::new("entered-once".into()))
        });

        for expected_prompts in 1..=2 {
            let validated = spec
                .validate_audited(false, Materialize::Run)
                .unwrap()
                .unwrap();
            assert_eq!(
                validated.resolved.secrets["DEPLOY_PASSWORD"].expose_secret(),
                "entered-once"
            );
            assert_eq!(prompts.load(Ordering::SeqCst), expected_prompts);
        }

        // Ordinary library/SDK resolution never opens an interactive prompt.
        assert!(
            spec.validate_audited(false, Materialize::Values)
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn writable_provider_persists_the_prompted_value() {
        let _env = crate::tests::scrub_resolution_env();
        let temp_dir = tempfile::TempDir::new().unwrap();
        let dotenv_path = temp_dir.path().join("prompt.env");
        let prompts = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&prompts);
        let mut spec = prompted_dotenv_spec(&dotenv_path);
        spec.set_prompt_reader(move |name, profile| {
            assert_eq!(name, "DEPLOY_PASSWORD");
            assert_eq!(profile, "default");
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(SecretString::new("persisted-answer".into()))
        });

        for _ in 0..2 {
            let validated = spec
                .validate_audited(false, Materialize::Run)
                .unwrap()
                .unwrap();
            assert_eq!(
                validated.resolved.secrets["DEPLOY_PASSWORD"].expose_secret(),
                "persisted-answer"
            );
        }

        assert_eq!(prompts.load(Ordering::SeqCst), 1);
        assert_eq!(
            std::fs::read_to_string(dotenv_path).unwrap(),
            "DEPLOY_PASSWORD=\"persisted-answer\"\n"
        );
    }

    #[test]
    fn run_surfaces_an_unavailable_controlling_terminal() {
        let _env = crate::tests::scrub_resolution_env();
        let mut spec = prompted_spec();
        spec.set_prompt_reader(|name, _| Err(SecretSpecError::PromptUnavailable(name.to_string())));

        let error = match spec.validate_audited(false, Materialize::Run) {
            Err(error) => error,
            Ok(_) => panic!("run resolution should fail without a controlling terminal"),
        };
        assert!(matches!(
            error,
            SecretSpecError::PromptUnavailable(name) if name == "DEPLOY_PASSWORD"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn run_injects_the_prompted_value_into_the_child() {
        let _env = crate::tests::scrub_resolution_env();
        let mut spec = prompted_spec();
        spec.set_prompt_reader(|_, _| Ok(SecretString::new("entered-once".into())));

        let exit = spec
            .run_command(vec![
                "sh".to_string(),
                "-c".to_string(),
                "test \"$DEPLOY_PASSWORD\" = entered-once".to_string(),
            ])
            .unwrap();
        assert_eq!(exit, 0);
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
                scopes: None,
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
        let override_spec = spec.explicit_provider_spec(override_arg);
        spec.route_for(config, &override_spec).unwrap().specs()
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
            let override_spec = spec.explicit_provider_spec(override_arg);
            let route = spec
                .route_for(
                    &ref_secret(Some(vec!["onepassword://Production"])),
                    &override_spec,
                )
                .unwrap();
            spec.write_provider_for_route(&route, None).unwrap()
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
            let provider = spec.get_route_provider(primary, None).unwrap();
            spec.check_single_store_ref_coords(
                primary,
                &group,
                provider.as_ref(),
                &spec.config.project.name,
                "default",
            )?;
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
