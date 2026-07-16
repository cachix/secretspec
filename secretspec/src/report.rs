//! The resolution report: a value-free, versioned description of how every
//! declared secret resolved.
//!
//! This is the stable, machine-readable contract that surfaces the resolution
//! waterfall the resolver already computes (which provider answered, whether a
//! value was generated, whether a default was applied, whether a required
//! secret is missing) without ever exposing a secret value. It is emitted by
//! `secretspec check --json` and rendered by `secretspec check --explain`.
//!
//! The shape is versioned via [`RESOLUTION_REPORT_SCHEMA_VERSION`] so that
//! out-of-process consumers (other-language SDKs, CI tooling) can refuse a
//! mismatched version rather than silently misparse. The canonical JSON Schema
//! lives at `schema/resolution-report.schema.json` in the repository root.

use serde::{Deserialize, Serialize};

/// Version of the [`ResolutionReport`] wire format.
///
/// Bump this whenever the serialized shape changes in a way that is not purely
/// additive-and-optional, and update `schema/resolution-report.schema.json`.
pub const RESOLUTION_REPORT_SCHEMA_VERSION: u32 = 1;

/// How a single declared secret resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStatus {
    /// A value was produced (from a provider, a generator, or a default).
    Resolved,
    /// Required by the active profile but not found anywhere.
    MissingRequired,
    /// Optional and not found; resolution still succeeds overall.
    MissingOptional,
}

/// The resolution outcome for one declared secret. Never carries the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretResolution {
    /// The declared secret name (the `UPPER_SNAKE` key from the manifest).
    pub name: String,
    /// Whether the secret resolved, and if not, whether that is an error.
    pub status: ResolutionStatus,
    /// Whether the secret is *declared* required in the active profile: `true`
    /// when it is marked `required = true` or has neither a `default` nor a
    /// `generate`. A secret carrying a committed `default`/`generate` is not
    /// required (it always resolves), even when written as `required = true` in
    /// one profile and overridden with a default in another. Orthogonal to
    /// [`status`](Self::status), which reports whether it actually resolved.
    pub required: bool,
    /// Credential-free URI of the provider that actually answered, when the
    /// value came from a provider. `None` when generated, defaulted, or missing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_provider: Option<String>,
    /// Whether the value came from the manifest's committed `default`.
    pub default_applied: bool,
    /// Whether the value was freshly minted by the secret's `generate` config.
    pub generated: bool,
    /// Whether the value is materialized to a temp file and exposed as a path.
    pub as_path: bool,
}

/// A complete, value-free snapshot of one resolution pass over a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionReport {
    /// Wire-format version; see [`RESOLUTION_REPORT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Credential-free URI of the provider resolution reported against.
    pub provider: String,
    /// The profile that was resolved.
    pub profile: String,
    /// One entry per declared secret, sorted by name for deterministic output.
    pub secrets: Vec<SecretResolution>,
}

impl ResolutionReport {
    /// Build a report from its parts, stamping the current schema version and
    /// sorting entries by name so the output is deterministic (important for
    /// golden conformance vectors).
    pub fn new(provider: String, profile: String, mut secrets: Vec<SecretResolution>) -> Self {
        secrets.sort_by(|a, b| a.name.cmp(&b.name));
        Self {
            schema_version: RESOLUTION_REPORT_SCHEMA_VERSION,
            provider,
            profile,
            secrets,
        }
    }

    /// True when no required secret is missing (i.e. resolution would succeed).
    pub fn all_required_present(&self) -> bool {
        !self
            .secrets
            .iter()
            .any(|s| s.status == ResolutionStatus::MissingRequired)
    }

    /// Render a human-readable resolution trace. Value-free, word-based status
    /// (no reliance on color) for accessibility.
    pub fn to_explain_string(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("profile:  {}\n", self.profile));
        out.push_str(&format!("provider: {}\n", self.provider));

        let width = self.secrets.iter().map(|s| s.name.len()).max().unwrap_or(0);

        for s in &self.secrets {
            let detail = match s.status {
                ResolutionStatus::Resolved => {
                    if s.generated {
                        "ok        generated".to_string()
                    } else if s.default_applied {
                        "ok        default value".to_string()
                    } else if let Some(uri) = &s.source_provider {
                        format!("ok        source {}", uri)
                    } else {
                        "ok".to_string()
                    }
                }
                ResolutionStatus::MissingRequired => "MISSING   required".to_string(),
                ResolutionStatus::MissingOptional => "missing   optional".to_string(),
            };
            let path = if s.as_path { "  (as path)" } else { "" };
            out.push_str(&format!(
                "  {:width$}  {}{}\n",
                s.name,
                detail,
                path,
                width = width
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ResolutionReport {
        // Deliberately unsorted input to exercise the sort in `new`.
        ResolutionReport::new(
            "keyring://".to_string(),
            "production".to_string(),
            vec![
                SecretResolution {
                    name: "STRIPE_KEY".to_string(),
                    status: ResolutionStatus::MissingRequired,
                    required: true,
                    source_provider: None,
                    default_applied: false,
                    generated: false,
                    as_path: false,
                },
                SecretResolution {
                    name: "DATABASE_URL".to_string(),
                    status: ResolutionStatus::Resolved,
                    required: true,
                    source_provider: Some("keyring://".to_string()),
                    default_applied: false,
                    generated: false,
                    as_path: false,
                },
                SecretResolution {
                    name: "JWT_SECRET".to_string(),
                    status: ResolutionStatus::Resolved,
                    required: true,
                    source_provider: None,
                    default_applied: false,
                    generated: true,
                    as_path: false,
                },
                SecretResolution {
                    name: "LOG_LEVEL".to_string(),
                    status: ResolutionStatus::Resolved,
                    required: false,
                    source_provider: None,
                    default_applied: true,
                    generated: false,
                    as_path: false,
                },
                SecretResolution {
                    name: "SENTRY_DSN".to_string(),
                    status: ResolutionStatus::MissingOptional,
                    required: false,
                    source_provider: None,
                    default_applied: false,
                    generated: false,
                    as_path: false,
                },
            ],
        )
    }

    #[test]
    fn entries_are_sorted_by_name() {
        let report = sample();
        let names: Vec<&str> = report.secrets.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "DATABASE_URL",
                "JWT_SECRET",
                "LOG_LEVEL",
                "SENTRY_DSN",
                "STRIPE_KEY"
            ]
        );
    }

    #[test]
    fn all_required_present_tracks_missing_required() {
        assert!(!sample().all_required_present());
        let mut report = sample();
        report
            .secrets
            .retain(|s| s.status != ResolutionStatus::MissingRequired);
        assert!(report.all_required_present());
    }

    #[test]
    fn explain_string_renders_resolution_details() {
        assert_eq!(
            sample().to_explain_string(),
            concat!(
                "profile:  production\n",
                "provider: keyring://\n",
                "  DATABASE_URL  ok        source keyring://\n",
                "  JWT_SECRET    ok        generated\n",
                "  LOG_LEVEL     ok        default value\n",
                "  SENTRY_DSN    missing   optional\n",
                "  STRIPE_KEY    MISSING   required\n",
            )
        );
    }

    #[test]
    fn explain_string_marks_plain_resolved_secrets_exposed_as_paths() {
        let report = ResolutionReport::new(
            "env://".to_string(),
            "development".to_string(),
            vec![SecretResolution {
                name: "FILE".to_string(),
                status: ResolutionStatus::Resolved,
                required: true,
                source_provider: None,
                default_applied: false,
                generated: false,
                as_path: true,
            }],
        );

        assert_eq!(
            report.to_explain_string(),
            "profile:  development\nprovider: env://\n  FILE  ok  (as path)\n"
        );
    }

    #[test]
    fn explain_string_handles_a_report_without_secrets() {
        let report = ResolutionReport::new(
            "dotenv://.env".to_string(),
            "default".to_string(),
            Vec::new(),
        );

        assert_eq!(
            report.to_explain_string(),
            "profile:  default\nprovider: dotenv://.env\n"
        );
    }

    /// Locks the wire format. The golden file is the contract other-language
    /// SDKs and CI consumers parse; any change here is a deliberate contract
    /// change that must bump `RESOLUTION_REPORT_SCHEMA_VERSION` and the schema.
    #[test]
    fn serializes_to_golden_wire_format() {
        let golden = include_str!("../tests/fixtures/resolution_report.golden.json");
        let actual = serde_json::to_string_pretty(&sample()).unwrap();
        // Normalize line endings: on Windows the golden file is checked out with
        // CRLF, while serde always emits LF.
        assert_eq!(
            actual.replace("\r\n", "\n").trim(),
            golden.replace("\r\n", "\n").trim()
        );
    }

    #[test]
    fn round_trips_through_json() {
        let report = sample();
        let json = serde_json::to_string(&report).unwrap();
        let back: ResolutionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }
}
