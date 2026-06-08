//! The value-carrying resolve payload: the FFI/SDK boundary.
//!
//! Unlike the value-free [`crate::report::ResolutionReport`] (which powers
//! `check --json` and must never expose a value), this payload **does** carry
//! the resolved secret values. It is the single authoritative output that any
//! other-language SDK consumes, either over the C ABI (in-process) or via
//! `secretspec resolve --json` (subprocess). Producing it deliberately exposes
//! secrets, so it is only built at an explicit resolve boundary and its bytes
//! must be treated as sensitive by the caller.
//!
//! On a successful resolution `secrets` holds one entry per declared secret
//! that produced a value; `missing_optional` lists optional secrets with no
//! value. When a required secret is missing, resolution is an error: `secrets`
//! is empty and `missing_required` is populated, mirroring the derive crate's
//! `load()` which fails rather than returning partial secrets.
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
