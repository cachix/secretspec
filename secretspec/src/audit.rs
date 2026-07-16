//! Append-only audit logging for secret access.
//!
//! Every secret operation that reaches a provider is recorded as one JSON object
//! per line (JSON Lines). A policy-denied attempt (the `require_reason` gate) is
//! recorded too, so a blocked access still leaves a trace. Auditing is **on by
//! default**; it is configured via the `[audit]` table in the user-global config
//! (see [`crate::config::AuditConfig`]) and written to a single file capped at a
//! fixed size (1 MiB by default). At the cap the file is truncated in place and
//! restarted with whole-line granularity, so the log is a size-bounded record,
//! not a complete history, and never contains a partially written line.
//!
//! Two invariants hold throughout:
//!
//! - **Secret values are never logged.** Only metadata (key name, provider,
//!   outcome, reason, actor) is recorded. Credentials embedded in provider URIs
//!   are redacted via [`redact_uri`].
//! - **Auditing never blocks secret access.** Every failure path (bad path,
//!   write error, serialization error) emits a single `warning:` to stderr and
//!   returns, so a logging problem can never break `get`/`set`/`run`.
//!
//! The log assumes a single writer at a time. Several secretspec processes
//! writing the same log file concurrently may, around the size-cap rotation,
//! interleave or lose entries, because rotation is not synchronized across
//! processes. Operators who need strong guarantees should give each concurrent
//! context its own `[audit] path`.

use crate::config::AuditConfig;
use crate::secrets::{detect_agent_id, running_as_agent};
use colored::Colorize;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Schema version embedded in every event; bump on incompatible field changes.
const SCHEMA_VERSION: u32 = 1;

/// The kind of secret operation being audited.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuditAction {
    /// Read a single secret (`secretspec get`).
    Get,
    /// Write a single secret (`secretspec set`).
    Set,
    /// Validate availability of all secrets (`secretspec check`).
    Check,
    /// Inject all secrets into a subprocess (`secretspec run`).
    Run,
    /// Copy secrets from one provider to another (`secretspec import`).
    Import,
    /// Resolve all secrets and emit them for another tool (`secretspec export`)
    Export,
}

/// The result of an audited operation.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuditOutcome {
    /// The secret was found and returned.
    Found,
    /// The secret was not found in any provider and had no default.
    Missing,
    /// The secret was not found but a configured default was used.
    Default,
    /// The secret was written successfully.
    Written,
    /// The audited subprocess (`run`) was successfully started with the secrets
    /// injected. Distinct from `found`, which is about a secret lookup.
    Started,
    /// The operation failed; see `error_kind`.
    Error,
}

/// Who performed the operation. Captured once per process.
#[derive(Debug, Clone, Serialize)]
struct Actor {
    /// Local OS username, best-effort from `USER`/`USERNAME`.
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    /// Detected coding-agent id (e.g. `claude-code`), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    agent: Option<&'static str>,
    /// Whether secretspec considers this an agent session.
    is_agent: bool,
}

impl Actor {
    fn current() -> Self {
        // Detect the specific coding agent once; reuse the result for `is_agent`
        // instead of re-scanning the environment. A recognized agent always
        // implies an agent session, so only fall back to the broader
        // `running_as_agent()` probe (env opt-in + heuristics) when none was named.
        // Both helpers route through a UTF-8 env snapshot so a non-UTF-8 variable
        // cannot panic the process (env vars are arbitrary bytes on Unix).
        let agent = detect_agent_id();
        let is_recognized_agent = agent.is_some();
        Actor {
            user: std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .ok(),
            agent,
            is_agent: is_recognized_agent || running_as_agent(),
        }
    }
}

/// The variable, per-call context for one audit event, supplied by the call site.
pub(crate) struct AuditContext<'a> {
    pub project: &'a str,
    pub profile: &'a str,
    /// The single secret involved (`get`/`set`).
    pub key: Option<&'a str>,
    /// The set of secrets involved in a bulk action (`check`/`run`/`import`).
    pub keys: &'a [String],
    /// For `run`, the program that was executed (argv[0] only — never arguments,
    /// which may contain secrets).
    pub command: Option<&'a str>,
    /// The provider URI that served (or was consulted for) the access. Redacted
    /// before it is written.
    pub provider_uri: Option<String>,
    /// Canonical rendering of the secret's native `ref` coordinates, when the
    /// access resolved one (e.g. `item=db field=password`). Keeps per-address
    /// granularity now that `provider` names only the store.
    pub reference: Option<String>,
    pub outcome: AuditOutcome,
    pub error_kind: Option<&'a str>,
    pub reason: Option<&'a str>,
}

/// One serialized audit record (one JSON Lines entry).
#[derive(Serialize)]
struct AuditEvent<'a> {
    /// Schema version.
    v: u32,
    /// Unique event id.
    id: String,
    /// RFC 3339 UTC timestamp.
    ts: String,
    /// Identifier shared by all events from one process invocation.
    session_id: &'a str,
    /// Monotonic sequence within the session.
    seq: u64,
    action: AuditAction,
    project: &'a str,
    profile: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<&'a str>,
    /// The set of secrets for a bulk action; omitted for single-key actions.
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    keys: &'a [String],
    /// For `run`, the executed program (argv[0]); omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<&'a str>,
    /// Redacted provider URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    /// Canonical rendering of the native `ref` coordinates, if any.
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    reference: Option<&'a str>,
    outcome: AuditOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_kind: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    actor: &'a Actor,
    /// secretspec version that produced the event.
    version: &'static str,
}

/// A destination for audit events.
///
/// Implementations must be fail-open: a write error is handled internally (e.g.
/// reported to stderr) and never propagated, so audit logging can never block
/// secret access.
pub(crate) trait AuditSink: Send + Sync {
    fn write_line(&self, line: &str);
}

/// A JSON Lines sink: a single append-only file capped at a fixed size. When the
/// next line would exceed the cap the file is truncated in place and restarted,
/// so the log is bounded to one file with no rotation history — and, because the
/// cap is enforced with whole-line granularity, it never contains a partially
/// written entry.
struct JsonlSink {
    file: Mutex<std::fs::File>,
    path: PathBuf,
    /// Hard cap on the file size in bytes; a write that would cross it truncates
    /// and restarts the file first.
    max_size_bytes: u64,
}

/// Default log size cap (1 MiB) used when the configured `max_size_bytes` is
/// invalid (zero), which would otherwise truncate the file on every write.
const DEFAULT_MAX_SIZE_BYTES: u64 = 1_048_576;

impl JsonlSink {
    fn new(path: PathBuf, max_size_bytes: u64) -> std::io::Result<Self> {
        // Require a parent directory; a bare root like "/" has none and cannot
        // hold a log. Fail open rather than panic.
        let Some(parent) = path.parent() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "audit log path has no parent directory",
            ));
        };
        // Keep the audit directory owner-only, matching the 0o600 log file.
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(parent)?;

        // A zero cap would truncate the file on every write; fall back to the
        // default and warn rather than render the log useless.
        let max_size_bytes = if max_size_bytes == 0 {
            eprintln!(
                "{} [audit] max_size_bytes = 0 is invalid; using the default of {} bytes",
                "warning:".yellow(),
                DEFAULT_MAX_SIZE_BYTES
            );
            DEFAULT_MAX_SIZE_BYTES
        } else {
            max_size_bytes
        };

        let mut open_options = OpenOptions::new();
        open_options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Audit logs may reference secret names; keep them owner-only.
            open_options.mode(0o600);
        }
        // Open eagerly so an unwritable location (read-only fs, no permission on an
        // existing dir) surfaces here — the caller then warns and disables auditing
        // instead of silently dropping events.
        let file = open_options.open(&path)?;

        Ok(Self {
            file: Mutex::new(file),
            path,
            max_size_bytes,
        })
    }

    /// Resets the log file to empty at the size cap. The append handle's next
    /// write then lands at the new end-of-file (offset 0).
    #[cfg(not(windows))]
    fn truncate(&self, file: &std::fs::File) -> std::io::Result<()> {
        file.set_len(0)
    }

    /// On Windows an append-only handle lacks `FILE_WRITE_DATA`, so `set_len`
    /// fails with "access is denied". Truncate through a separate write handle
    /// instead; the caller still holds the mutex, so no other writer races us.
    #[cfg(windows)]
    fn truncate(&self, _file: &std::fs::File) -> std::io::Result<()> {
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.path)
            .map(|_| ())
    }
}

impl AuditSink for JsonlSink {
    fn write_line(&self, line: &str) {
        // A poisoned lock just means a previous writer panicked; the file handle is
        // still usable for appending, so recover the guard rather than give up.
        let mut guard = self.file.lock().unwrap_or_else(|e| e.into_inner());

        // Enforce the size cap with whole-line granularity: if appending this line
        // would cross the cap, truncate and restart the file first so a line is
        // never split across the boundary. A single line larger than the cap is
        // still written intact (the cap bounds retained history, not one event).
        let projected = line.len() as u64 + 1; // + trailing newline
        match guard.metadata().map(|m| m.len()) {
            Ok(size) if size > 0 && size + projected > self.max_size_bytes => {
                // With O_APPEND the next write lands at the new end-of-file (0).
                if let Err(e) = self.truncate(&guard) {
                    warn_audit_failure(&self.path, &e);
                }
            }
            Ok(_) => {}
            Err(e) => warn_audit_failure(&self.path, &e),
        }

        if let Err(e) = writeln!(guard, "{line}") {
            warn_audit_failure(&self.path, &e);
        }
    }
}

/// Records secret access to a sink, stamping each event with shared session
/// context (id, monotonic sequence, actor).
pub(crate) struct AuditLogger {
    sink: Box<dyn AuditSink>,
    session_id: String,
    seq: AtomicU64,
    actor: Actor,
}

impl AuditLogger {
    /// Builds a logger from the effective audit configuration, or `None` when
    /// auditing is disabled or no log location can be established. Never fails:
    /// any problem is reported to stderr and yields `None` (auditing off) rather
    /// than blocking secret access.
    pub(crate) fn from_config(config: &AuditConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }

        let Some(path) = config.resolved_path() else {
            if config.has_relative_path() {
                eprintln!(
                    "{} [audit] path {} is not absolute; auditing is disabled \
                     (use an absolute path, e.g. ~/.local/state/secretspec/audit.log)",
                    "warning:".yellow(),
                    config
                        .path
                        .as_deref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default()
                        .bold()
                );
            } else {
                eprintln!(
                    "{} could not determine an audit log location; auditing is disabled \
                     (set [audit] path in ~/.config/secretspec/config.toml)",
                    "warning:".yellow()
                );
            }
            return None;
        };

        // First-run disclosure: if the log file does not exist yet, announce where
        // it lives and how to disable it. Auditing is on by default, so users must
        // be told a file is being written.
        let first_run = !path.exists();

        let sink = match JsonlSink::new(path.clone(), config.max_size_bytes) {
            Ok(sink) => sink,
            Err(e) => {
                warn_audit_failure(&path, &e);
                return None;
            }
        };

        if first_run {
            eprintln!(
                "{} secretspec is now recording secret access to {} \
                 (disable with [audit] enabled = false in ~/.config/secretspec/config.toml)",
                "note:".cyan(),
                path.display().to_string().bold()
            );
        }

        Some(Self {
            sink: Box::new(sink),
            session_id: uuid::Uuid::new_v4().to_string(),
            seq: AtomicU64::new(0),
            actor: Actor::current(),
        })
    }

    /// Records one event. Fail-open: serialization errors are reported and dropped.
    pub(crate) fn record(&self, action: AuditAction, ctx: AuditContext<'_>) {
        let event = AuditEvent {
            v: SCHEMA_VERSION,
            id: uuid::Uuid::new_v4().to_string(),
            ts: jiff::Timestamp::now().to_string(),
            session_id: &self.session_id,
            seq: self.seq.fetch_add(1, Ordering::Relaxed),
            action,
            project: ctx.project,
            profile: ctx.profile,
            key: ctx.key,
            keys: ctx.keys,
            command: ctx.command,
            provider: ctx.provider_uri.as_deref().map(redact_uri),
            reference: ctx.reference.as_deref(),
            outcome: ctx.outcome,
            error_kind: ctx.error_kind,
            reason: ctx.reason,
            actor: &self.actor,
            version: env!("CARGO_PKG_VERSION"),
        };

        match serde_json::to_string(&event) {
            Ok(line) => self.sink.write_line(&line),
            Err(e) => eprintln!(
                "{} failed to serialize audit event: {e}; skipping",
                "warning:".yellow()
            ),
        }
    }
}

/// Locates the userinfo of a URI's authority: the span between the scheme
/// separator (after `://` for a hierarchical URI, or after `scheme:` for an
/// opaque one) and the first `@` that precedes any `/`, `?` or `#`. Returns
/// `(userinfo_start, at)` so callers can slice `uri[userinfo_start..at]` (the
/// userinfo) and `uri[at..]` (`@host...`). `None` when there is no userinfo.
///
/// Operates only on byte positions of ASCII delimiters (`:` `/` `?` `#` `@`), so
/// it is correct for non-ASCII hosts/paths and handles the empty-host case
/// (`vault://user:pass@`) that `url`'s component setters refuse.
fn userinfo_span(uri: &str) -> Option<(usize, usize)> {
    let scheme_end = uri.find(':')?;
    let after_scheme = &uri[scheme_end + 1..];
    let (userinfo_start, authority) = match after_scheme.strip_prefix("//") {
        Some(rest) => (scheme_end + 3, rest),
        None => (scheme_end + 1, after_scheme),
    };
    let authority_len = authority.find(['/', '?', '#']).unwrap_or(authority.len());
    // Use the LAST `@` in the authority as the userinfo/host boundary: a host
    // cannot contain `@`, so any earlier `@` belongs to a userinfo credential
    // (e.g. a raw, un-percent-encoded password like `p@ss`). Anchoring to the
    // first `@` would leave the post-`@` portion of such a credential intact.
    let at_rel = authority[..authority_len].rfind('@')?;
    Some((userinfo_start, userinfo_start + at_rel))
}

/// Redacts a `:password` credential from a provider URI's userinfo
/// (`scheme://user:pass@host` becomes `scheme://user@host`), leaving the username,
/// host, path, query and fragment intact.
///
/// Providers encode *non-secret* attribution in those positions — a 1Password
/// account (`onepassword://acct@vault`), an AWS profile/region and `?prefix=`
/// (`awssm://profile@region?prefix=...`). Stripping the whole userinfo/query (as a
/// generic redactor would) corrupts the audit log's provider attribution, e.g.
/// collapsing two different accounts to the same string. The audit log only ever
/// records a provider's own already-secret-free `uri()`, so the only credential
/// that can appear is an explicit `:password`, which this removes.
///
/// A bare userinfo token with no `:` (`scheme://TOKEN@host`) is preserved — it is
/// structurally indistinguishable from an account/profile identifier, so the
/// secret-free guarantee rests on each provider's `uri()`, not on this function.
/// To redact a raw, possibly-credential-bearing URI for display, use
/// [`redact_uri_strict`].
fn redact_uri(uri: &str) -> String {
    let Some((userinfo_start, at)) = userinfo_span(uri) else {
        return uri.to_string();
    };
    let userinfo = &uri[userinfo_start..at];
    match userinfo.find(':') {
        // Keep the username (before `:`), drop the password, keep `@host...`.
        Some(colon) => format!("{}{}", &uri[..userinfo_start + colon], &uri[at..]),
        None => uri.to_string(),
    }
}

/// Redacts a raw provider URI for human-facing diagnostics (e.g. a fallback-chain
/// warning) by dropping the entire userinfo and any query or fragment, so a
/// user-authored alias that embeds a credential — `vault+token:s3cr3t@host`,
/// `vault://host?token=...` — is not echoed to the terminal. Unlike [`redact_uri`]
/// it sacrifices attribution detail (account/profile/prefix) for safety, which is
/// acceptable for a transient warning that also names the affected secret.
pub(crate) fn redact_uri_strict(uri: &str) -> String {
    let without_userinfo = match userinfo_span(uri) {
        // Drop `userinfo@`, keeping the scheme prefix and everything from the host.
        Some((userinfo_start, at)) => format!("{}{}", &uri[..userinfo_start], &uri[at + 1..]),
        None => uri.to_string(),
    };
    let cut = without_userinfo
        .find(['?', '#'])
        .unwrap_or(without_userinfo.len());
    without_userinfo[..cut].to_string()
}

/// Warns that the audit log could not be written, without aborting the operation
/// that triggered it.
fn warn_audit_failure(path: &Path, err: &dyn std::fmt::Display) {
    eprintln!(
        "{} could not write audit log {}: {err}; continuing without auditing this event",
        "warning:".yellow(),
        path.display().to_string().bold()
    );
}

/// In-memory audit helpers shared by this module's tests and by `secrets.rs`
/// tests that need to assert which audit events a `Secrets` operation emits.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::sync::Arc;

    /// A sink that records written lines in memory for assertions.
    #[derive(Clone, Default)]
    pub(crate) struct CollectSink {
        pub(crate) lines: Arc<Mutex<Vec<String>>>,
    }

    impl AuditSink for CollectSink {
        fn write_line(&self, line: &str) {
            self.lines.lock().unwrap().push(line.to_string());
        }
    }

    impl AuditLogger {
        pub(crate) fn for_test(sink: Box<dyn AuditSink>) -> Self {
            Self {
                sink,
                session_id: "test-session".to_string(),
                seq: AtomicU64::new(0),
                actor: Actor {
                    user: Some("tester".to_string()),
                    agent: None,
                    is_agent: false,
                },
            }
        }
    }

    /// Builds a logger that collects emitted JSON lines, returning both the
    /// logger and a handle to read the lines back.
    pub(crate) fn collecting_logger() -> (AuditLogger, Arc<Mutex<Vec<String>>>) {
        let sink = CollectSink::default();
        let lines = sink.lines.clone();
        (AuditLogger::for_test(Box::new(sink)), lines)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::CollectSink;
    use super::*;

    #[test]
    fn redact_uri_strips_password_but_keeps_attribution() {
        // A `:password` is removed; the username is kept.
        assert_eq!(
            redact_uri("vault://user:pass@host:8200"),
            "vault://user@host:8200"
        );
        // ...even with an empty host, which `url`'s setters refuse to touch.
        assert_eq!(redact_uri("vault://user:pass@"), "vault://user@");
        // Opaque `:password` is stripped too, username kept.
        assert_eq!(
            redact_uri("vault+token:user:pass@host"),
            "vault+token:user@host"
        );
        // No userinfo / no password: returned unchanged.
        assert_eq!(redact_uri("keyring://"), "keyring://");
        assert_eq!(redact_uri("dotenv:.env"), "dotenv:.env");
        // Provider attribution (1Password account, AWS profile + prefix) is
        // preserved — these are identifiers, not secrets, and stripping them would
        // make two distinct providers indistinguishable in the audit log.
        assert_eq!(
            redact_uri("onepassword://work@Production"),
            "onepassword://work@Production"
        );
        assert_eq!(
            redact_uri("onepassword://personal@Production"),
            "onepassword://personal@Production"
        );
        assert_eq!(
            redact_uri("awssm://prod@us-east-1?prefix=myapp"),
            "awssm://prod@us-east-1?prefix=myapp"
        );
        // A bare userinfo token (structurally identical to an account identifier)
        // is preserved; the audit log's secret-free guarantee rests on the
        // provider's own `uri()`, not on this backstop.
        assert_eq!(
            redact_uri("vault+token:s3cr3t@host"),
            "vault+token:s3cr3t@host"
        );
        // A `:password` that itself contains a literal `@` is still fully removed:
        // the userinfo extends to the LAST `@` before the host, so no fragment of
        // the password survives.
        assert_eq!(redact_uri("vault://user:p@ss@host"), "vault://user@host");
        assert_eq!(
            redact_uri("vault+token:user:p@ss@host"),
            "vault+token:user@host"
        );
    }

    #[test]
    fn redact_uri_strict_drops_userinfo_and_query() {
        // The display redactor (used for fallback-chain warnings) strips the whole
        // userinfo and any query/fragment, so a raw configured alias cannot leak a
        // credential to the terminal.
        assert_eq!(
            redact_uri_strict("vault://user:pass@host:8200"),
            "vault://host:8200"
        );
        assert_eq!(
            redact_uri_strict("vault+token:s3cr3t@host/path"),
            "vault+token:host/path"
        );
        assert_eq!(
            redact_uri_strict("vault://host?token=SECRET"),
            "vault://host"
        );
        assert_eq!(redact_uri_strict("vault://user:pass@"), "vault://");
        // No userinfo / no query: unchanged.
        assert_eq!(redact_uri_strict("keyring://"), "keyring://");
        assert_eq!(redact_uri_strict("dotenv:.env"), "dotenv:.env");
        let strict = redact_uri_strict("vault+token:s3cr3t@host?x=y#f");
        assert_eq!(strict, "vault+token:host");
        assert!(!strict.contains("s3cr3t"));
        // A credential containing a literal `@` is dropped whole — no portion of
        // it survives past the userinfo/host boundary (the last `@`).
        let strict = redact_uri_strict("vault://user:p@ss@host");
        assert_eq!(strict, "vault://host");
        assert!(!strict.contains("p@ss") && !strict.contains("ss@"));
        let strict = redact_uri_strict("vault+token:gh@p_realtoken@host");
        assert_eq!(strict, "vault+token:host");
        assert!(!strict.contains("realtoken"));
    }

    #[test]
    fn records_metadata_but_never_the_value() {
        let sink = CollectSink::default();
        let logger = AuditLogger::for_test(Box::new(sink.clone()));

        logger.record(
            AuditAction::Get,
            AuditContext {
                project: "demo",
                profile: "production",
                key: Some("DATABASE_URL"),
                keys: &[],
                command: None,
                provider_uri: Some("vault://user:s3cr3t@host/kv".to_string()),
                reference: None,
                outcome: AuditOutcome::Found,
                error_kind: None,
                reason: Some("deploy web frontend"),
            },
        );

        let lines = sink.lines.lock().unwrap();
        assert_eq!(lines.len(), 1);
        let event: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();

        assert_eq!(event["v"], SCHEMA_VERSION);
        assert_eq!(event["action"], "get");
        assert_eq!(event["outcome"], "found");
        assert_eq!(event["project"], "demo");
        assert_eq!(event["profile"], "production");
        assert_eq!(event["key"], "DATABASE_URL");
        assert_eq!(event["reason"], "deploy web frontend");
        assert_eq!(event["session_id"], "test-session");
        assert_eq!(event["seq"], 0);
        // Provider credentials (the `:password`) are redacted; the username,
        // host and path — provider attribution — are kept.
        assert_eq!(event["provider"], "vault://user@host/kv");
        // The secret value never appears anywhere in the record.
        assert!(!lines[0].contains("s3cr3t"));
    }

    #[test]
    fn bulk_event_records_keys_and_command() {
        let sink = CollectSink::default();
        let logger = AuditLogger::for_test(Box::new(sink.clone()));
        let keys = vec!["DATABASE_URL".to_string(), "API_KEY".to_string()];

        logger.record(
            AuditAction::Run,
            AuditContext {
                project: "demo",
                profile: "production",
                key: None,
                keys: &keys,
                command: Some("./deploy.sh"),
                provider_uri: None,
                reference: None,
                outcome: AuditOutcome::Found,
                error_kind: None,
                reason: None,
            },
        );

        let lines = sink.lines.lock().unwrap();
        let event: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(event["action"], "run");
        assert_eq!(event["command"], "./deploy.sh");
        assert_eq!(event["keys"][0], "DATABASE_URL");
        assert_eq!(event["keys"][1], "API_KEY");
        // Single-key field is omitted for bulk actions.
        assert!(event.get("key").is_none());
    }

    #[test]
    fn seq_increments_per_event() {
        let sink = CollectSink::default();
        let logger = AuditLogger::for_test(Box::new(sink.clone()));
        for _ in 0..3 {
            logger.record(
                AuditAction::Set,
                AuditContext {
                    project: "demo",
                    profile: "default",
                    key: Some("K"),
                    keys: &[],
                    command: None,
                    provider_uri: None,
                    reference: None,
                    outcome: AuditOutcome::Written,
                    error_kind: None,
                    reason: None,
                },
            );
        }
        let lines = sink.lines.lock().unwrap();
        let seqs: Vec<u64> = lines
            .iter()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["seq"]
                    .as_u64()
                    .unwrap()
            })
            .collect();
        assert_eq!(seqs, vec![0, 1, 2]);
    }

    /// A log file that cannot be opened (here: an unwritable parent directory)
    /// must make `JsonlSink::new` fail, so `from_config` warns and disables
    /// auditing — rather than returning a sink whose writes silently no-op.
    #[cfg(unix)]
    #[test]
    fn jsonlsink_errors_when_log_file_cannot_be_opened() {
        use std::os::unix::fs::PermissionsExt;

        let base = std::env::temp_dir().join(format!("ss_audit_ro_{}", std::process::id()));
        let ro_dir = base.join("ro");
        std::fs::create_dir_all(&ro_dir).unwrap();
        // Read+execute only: creating the log file inside must fail.
        std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = JsonlSink::new(ro_dir.join("audit.log"), 1_048_576);
        let is_err = result.is_err();

        // Restore permissions so cleanup can remove the directory.
        std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(&base);

        assert!(
            is_err,
            "JsonlSink::new must fail when the log file cannot be opened"
        );
    }

    /// At the size cap the file is truncated and restarted with whole-line
    /// granularity: a write that would cross the cap resets the file first, so the
    /// log never grows past the cap and never retains a partial line.
    #[test]
    fn jsonlsink_truncates_and_restarts_at_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        // 20-byte payload + newline = 21 bytes per write; two of them (42) cross
        // the 40-byte cap, forcing a truncate-and-restart on the second write.
        let sink = JsonlSink::new(path.clone(), 40).unwrap();
        let line = "X".repeat(20);

        sink.write_line(&line);
        sink.write_line(&line);

        let contents = std::fs::read_to_string(&path).unwrap();
        // Only the most recent line survives the reset, intact and newline-terminated.
        assert_eq!(contents, format!("{line}\n"));
        assert!(contents.len() as u64 <= 40);
    }

    /// A single line larger than the cap is still written whole, not dropped or
    /// split: the cap bounds retained history, not one event.
    #[test]
    fn jsonlsink_writes_oversized_line_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = JsonlSink::new(path.clone(), 16).unwrap();
        let big = "Y".repeat(100);

        sink.write_line(&big);

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, format!("{big}\n"));
    }

    /// A configured `max_size_bytes` of 0 would truncate on every write; it must
    /// fall back to the default cap so writes accumulate normally.
    #[test]
    fn jsonlsink_zero_cap_falls_back_to_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = JsonlSink::new(path.clone(), 0).unwrap();

        sink.write_line("first");
        sink.write_line("second");

        let contents = std::fs::read_to_string(&path).unwrap();
        // Both lines retained -> the zero cap was replaced by the default, not honored.
        assert_eq!(contents, "first\nsecond\n");
    }

    /// The audit log may reference secret names, so it must be created owner-only.
    #[cfg(unix)]
    #[test]
    fn jsonlsink_creates_owner_only_log() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let sink = JsonlSink::new(path.clone(), 1_048_576).unwrap();
        sink.write_line("{}");

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// Auditing disabled in config yields no logger.
    #[test]
    fn from_config_disabled_returns_none() {
        let cfg = AuditConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(AuditLogger::from_config(&cfg).is_none());
    }

    /// A relative configured path is rejected (it would scatter the log per-CWD),
    /// so auditing is disabled rather than written to an unexpected location.
    #[test]
    fn from_config_relative_path_disables_auditing() {
        let cfg = AuditConfig {
            enabled: true,
            path: Some(PathBuf::from("relative/audit.log")),
            ..Default::default()
        };
        assert!(AuditLogger::from_config(&cfg).is_none());
    }

    /// Enabled with an absolute path builds a logger that creates and writes the
    /// configured file.
    #[test]
    fn from_config_absolute_path_builds_and_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let cfg = AuditConfig {
            enabled: true,
            path: Some(path.clone()),
            ..Default::default()
        };

        let logger = AuditLogger::from_config(&cfg).expect("auditing should be enabled");
        logger.record(
            AuditAction::Get,
            AuditContext {
                project: "demo",
                profile: "default",
                key: Some("K"),
                keys: &[],
                command: None,
                provider_uri: None,
                reference: None,
                outcome: AuditOutcome::Found,
                error_kind: None,
                reason: None,
            },
        );

        assert!(path.exists());
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"action\":\"get\""));
    }
}
