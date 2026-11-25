//! Structured identity for software integrations that invoke SecretSpec.

use serde::{Deserialize, Serialize};

/// Describes the software integration that requested secret access.
///
/// Caller context answers *what* invoked SecretSpec (for example, `git`). It is
/// deliberately separate from the user-supplied access reason, which answers
/// *why* the access is happening and may be required by a project's
/// `require_reason` policy. Caller context never satisfies that policy.
///
/// The context is caller-asserted metadata, not an authenticated identity. It is
/// included in audit events and forwarded to providers that choose to consume it.
/// Do not put credentials or secret values in any field.
///
/// Available since SecretSpec 0.20.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerContext {
    /// Stable name of the integration, such as `git`.
    pub name: String,
    /// Version of the integration, when useful for diagnostics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Integration-specific operation, such as `credential_get` or
    /// `credential_store`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    /// Non-secret resource being accessed, such as a repository host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

impl CallerContext {
    /// Creates caller context with the integration's stable name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: None,
            operation: None,
            resource: None,
        }
    }

    /// Sets the integration version.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Sets the integration-specific operation.
    pub fn with_operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = Some(operation.into());
        self
    }

    /// Sets the non-secret resource being accessed.
    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// Trims every field and drops blank optional values. A blank name makes the
    /// whole context absent, matching the handling of blank provider/profile and
    /// reason inputs at public boundaries.
    pub(crate) fn normalized(mut self) -> Option<Self> {
        self.name = normalize(&self.name)?;
        self.version = self.version.as_deref().and_then(normalize);
        self.operation = self.operation.as_deref().and_then(normalize);
        self.resource = self.resource.as_deref().and_then(normalize);
        Some(self)
    }
}

fn normalize(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_trims_fields_and_drops_blank_options() {
        assert_eq!(
            CallerContext::new("  git  ")
                .with_version(" 2.51.0 ")
                .with_operation(" credential_get\n")
                .with_resource("   ")
                .normalized(),
            Some(CallerContext {
                name: "git".to_string(),
                version: Some("2.51.0".to_string()),
                operation: Some("credential_get".to_string()),
                resource: None,
            })
        );
        assert!(CallerContext::new("  ").normalized().is_none());
    }
}
