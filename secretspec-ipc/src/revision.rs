//! Opaque, non-secret revision metadata (0.21+).

use crate::error::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize};

/// A provider-defined identity and generation token, or a resolver-derived
/// token for the logical value. Equality is meaningful; ordering is not.
///
/// Providers must derive this only from non-secret identity/version metadata
/// associated with the returned value, never from secret bytes or lease handles.
/// Syntax validation cannot establish that an endpoint honored this contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Revision(String);

impl Revision {
    /// Accept a bounded ASCII token without echoing rejected input.
    pub fn new(value: String) -> Result<Self> {
        if value.is_empty()
            || value.len() > 256
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
        {
            return Err(Error::Protocol("invalid revision token"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Revision {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        // Avoid Serde's string visitor diagnostics, which can echo a wrong-type
        // input. Even malformed metadata must not appear in error messages.
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::String(value) => {
                Self::new(value).map_err(|_| serde::de::Error::custom("invalid revision token"))
            }
            _ => Err(serde::de::Error::custom("invalid revision token")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{provider, resolver};
    use serde_json::json;

    #[test]
    fn revisions_are_optional_on_old_single_batch_and_resolver_results() {
        for revision in [None, Some(json!(null)), Some(json!("provider:version-1"))] {
            let expected = revision.as_ref().and_then(|v| v.as_str());
            let mut found = json!({"status":"found", "value":"value", "expires_at_unix_ms":null});
            if let Some(revision) = &revision {
                found["revision"] = revision.clone();
            }
            let single: provider::GetResult = serde_json::from_value(found.clone()).unwrap();
            let provider::GetResult::Found {
                revision: ref actual,
                ..
            } = single
            else {
                panic!()
            };
            assert_eq!(actual.as_ref().map(Revision::as_str), expected);
            found["name"] = json!("TOKEN");
            let batch: provider::NamedGetResult = serde_json::from_value(found).unwrap();
            assert_eq!(batch.outcome, single);
            for representation in ["value", "path"] {
                let mut resolved = json!({"status":"resolved", "representation":representation,
                    "value":"value", "path":"/tmp/value", "path_lease_id":"lease",
                    "source":"provider", "expires_at_unix_ms":null, "refresh_at_unix_ms":null});
                if let Some(revision) = &revision {
                    resolved["revision"] = revision.clone();
                }
                let result: resolver::GetResult = serde_json::from_value(resolved).unwrap();
                let actual = match result {
                    resolver::GetResult::Value(v) => v.revision,
                    resolver::GetResult::Path(v) => v.revision,
                    _ => panic!(),
                };
                assert_eq!(actual.as_ref().map(Revision::as_str), expected);
            }
        }
    }

    #[test]
    fn malformed_revision_diagnostics_do_not_echo_input() {
        for bad in [
            json!("CANARY/secret"),
            json!({"CANARY":"secret"}),
            json!(""),
            json!("x".repeat(257)),
            json!("é"),
        ] {
            let error = serde_json::from_value::<Revision>(bad)
                .unwrap_err()
                .to_string();
            assert_eq!(error, "invalid revision token");
        }
    }
}
