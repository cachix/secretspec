//! The value-carrying resolve payload: the FFI/SDK boundary.
//!
//! Unlike the value-free [`crate::report::ResolutionReport`] (which powers
//! `check --json` and must never expose a value), this payload **does** carry
//! the resolved secret values. It is the single authoritative output that any
//! other-language SDK consumes over the C ABI. Producing it deliberately exposes
//! secrets, so it is only built at an explicit resolve boundary and its bytes
//! must be treated as sensitive by the caller.
//!
//! On a successful resolution `secrets` holds one entry per declared secret
//! that produced a value; `missing_optional` lists optional secrets with no
//! value. When a required secret is missing, resolution is an error: `secrets`
//! is empty and `missing_required` is populated, mirroring the derive crate's
//! `load()` which fails rather than returning partial secrets.
//!
//! The `no_values` request variant (and [`crate::Secrets::resolve_without_values`])
//! produces the same shape with every `value`/`path` set to `None`, and is
//! additionally side-effect-free: it never mints a generated secret and never
//! writes an `as_path` temp file.
//!
//! The shape is versioned via [`RESOLVE_SCHEMA_VERSION`]. The canonical JSON
//! Schema lives at `schema/resolve-response.schema.json`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Version of the [`ResolveResponse`] wire format.
pub const RESOLVE_SCHEMA_VERSION: u32 = 1;

/// Where a resolved value came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvedSource {
    /// Returned by a storage provider.
    Provider,
    /// Freshly minted by the secret's `generate` config.
    Generated,
    /// The manifest's committed `default` value.
    Default,
}

/// One resolved secret. Exactly one of `value` or `path` is set: `path` when
/// the secret is materialized to a temp file (`as_path`), `value` otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedSecret {
    /// The secret value, when exposed inline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Path to the temp file holding the value, when `as_path` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Whether this secret is exposed as a file path rather than inline.
    pub as_path: bool,
    /// Whether the value came from a provider, a generator, or a default.
    pub source: ResolvedSource,
    /// Credential-free URI of the provider that answered, when `source` is
    /// `provider`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_provider: Option<String>,
}

/// A complete value-carrying resolution result for one profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveResponse {
    /// Wire-format version; see [`RESOLVE_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Credential-free URI of the provider the resolution reported against.
    pub provider: String,
    /// The profile that was resolved.
    pub profile: String,
    /// Resolved secrets by name. Empty when a required secret is missing.
    /// `BTreeMap` keeps the JSON object key order deterministic.
    pub secrets: BTreeMap<String, ResolvedSecret>,
    /// Required secrets that were not found anywhere. Non-empty means the
    /// resolution failed; `secrets` is then empty.
    pub missing_required: Vec<String>,
    /// Optional secrets that were not found.
    pub missing_optional: Vec<String>,
}

impl ResolveResponse {
    /// True when no required secret is missing (the resolution succeeded).
    pub fn is_ok(&self) -> bool {
        self.missing_required.is_empty()
    }

    /// Drop every inline value, keeping structure and provenance. Useful for an
    /// inventory/policy consumer that wants the resolve shape without secrets.
    pub fn without_values(mut self) -> Self {
        for secret in self.secrets.values_mut() {
            secret.value = None;
            secret.path = None;
        }
        self
    }
}

/// Which resolution shape a request asks for.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RequestMode {
    /// The value-carrying [`ResolveResponse`] (the default).
    #[default]
    Resolve,
    /// The value-free [`crate::report::ResolutionReport`]: per-secret status and
    /// provenance, never a value, and a missing required secret is reported as a
    /// status rather than failing the call. This is the inventory/preflight view
    /// the CLI exposes as `check --json`.
    Report,
}

#[derive(Debug, Default, Deserialize)]
struct JsonRequest {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    no_values: bool,
    #[serde(default)]
    mode: RequestMode,
}

fn error_envelope(kind: &str, message: impl Into<String>) -> serde_json::Value {
    serde_json::json!({
        "ok": false,
        "error": { "kind": kind, "message": message.into() },
    })
}

fn ok_envelope(response: impl Serialize) -> serde_json::Value {
    serde_json::json!({ "ok": true, "response": response })
}

fn dispatch(request_json: &str) -> serde_json::Value {
    let request: JsonRequest = match serde_json::from_str(request_json) {
        Ok(request) => request,
        Err(e) => return error_envelope("invalid_request", format!("invalid request JSON: {e}")),
    };

    let loaded = match &request.path {
        Some(path) => crate::Secrets::load_from(std::path::Path::new(path)),
        None => crate::Secrets::load(),
    };
    let mut app = match loaded {
        Ok(app) => app,
        Err(e) => return error_envelope(e.kind(), e.to_string()),
    };

    if let Some(provider) = request.provider {
        app.set_provider(provider);
    }
    if let Some(profile) = request.profile {
        app.set_profile(profile);
    }
    if let Some(reason) = request.reason {
        app = app.with_reason(reason);
    }

    match request.mode {
        // Value-free report: never fails on a missing required secret, so an
        // inventory/preflight consumer always gets the shape back.
        RequestMode::Report => match app.report() {
            Ok(report) => ok_envelope(report),
            Err(e) => error_envelope(e.kind(), e.to_string()),
        },
        // Value-carrying resolve. `no_values` takes the path that never copies a
        // secret value into the response (and persists no temp file).
        RequestMode::Resolve => {
            let resolved = if request.no_values {
                app.resolve_without_values()
            } else {
                app.resolve()
            };
            match resolved {
                Ok(response) => ok_envelope(response),
                Err(e) => error_envelope(e.kind(), e.to_string()),
            }
        }
    }
}

/// Resolve secrets from a JSON request string and return the JSON response
/// envelope: `{"ok": true, "response": <ResolveResponse | ResolutionReport>}` or
/// `{"ok": false, "error": {"kind", "message"}}`.
///
/// This is the shared JSON boundary used by every native binding (the C ABI in
/// `secretspec-ffi` and the napi-rs Node addon), so the envelope contract is
/// defined in exactly one place. The request accepts optional `path`,
/// `provider`, `profile`, `reason`, `no_values`, and `mode` (`"resolve"` by
/// default, or `"report"` for the value-free [`crate::report::ResolutionReport`]).
/// A `resolve` response carries secret values; treat its bytes as sensitive. A
/// `report` response never does.
pub fn resolve_json(request_json: &str) -> String {
    // Catch panics here, at the one place both native boundaries funnel through
    // (the C ABI in `secretspec-ffi` and the napi-rs Node addon). Unwinding across
    // either is undefined behavior, and turning a panic into the same
    // `{"ok":false,"error":...}` envelope every binding already parses means all
    // bindings behave identically — the C ABI no longer needs to be the only one
    // guarding the boundary.
    let envelope =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dispatch(request_json)))
            .unwrap_or_else(|_| error_envelope("internal", "internal panic during resolve"));

    serde_json::to_string(&envelope).unwrap_or_else(|_| {
        "{\"ok\":false,\"error\":{\"kind\":\"serialize\",\"message\":\"failed to serialize response\"}}".to_string()
    })
}
