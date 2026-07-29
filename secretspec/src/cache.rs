//! Cache-entry encoding, ownership, and freshness policy.
//!
//! Provider I/O, auditing, warning output, and remediation remain in
//! [`crate::secrets`]. This module owns the provider-independent envelope
//! format and the decisions that can be made from a stored value alone.

use secrecy::zeroize::Zeroizing;
use secrecy::{ExposeSecret, SecretString};
use std::time::{SystemTime, UNIX_EPOCH};

/// Marker every cache entry starts with, identifying the value as SecretSpec's
/// own and naming the format version — without parsing it.
///
/// Ownership has to be decidable even when the payload is not readable. A
/// truncated write leaves something only SecretSpec could have put there, which
/// is safe to replace; a value with no marker belongs to someone else and must
/// never be touched.
pub(crate) const CACHE_ENVELOPE_MARKER: &str = "secretspec-cache-v2:";

/// Value stored inside the configured cache provider. The provider remains
/// responsible for encryption; the envelope adds freshness, route invalidation,
/// and ownership metadata.
#[derive(serde::Serialize, serde::Deserialize)]
struct CacheEnvelope {
    project: String,
    profile: String,
    cached_at: u64,
    route_fingerprint: String,
    /// The cached plaintext stays in a zeroizing buffer on both serialization
    /// and deserialization.
    #[serde(with = "zeroizing_string")]
    value: Zeroizing<String>,
}

/// Serde for the envelope's plaintext, keeping it in a zeroizing buffer in both
/// directions. Deserialization moves serde's `String` directly into the buffer.
mod zeroizing_string {
    use secrecy::zeroize::Zeroizing;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &Zeroizing<String>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Zeroizing<String>, D::Error> {
        String::deserialize(deserializer).map(Zeroizing::new)
    }
}

/// Who wrote the value sitting at a cache address.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CacheOwnership {
    /// This project and profile wrote a readable entry.
    Ours,
    /// Another project or profile wrote the entry.
    Foreign { project: String, profile: String },
    /// The ownership marker is ours, but the payload is damaged or incompatible.
    OursUnreadable,
    /// No SecretSpec ownership marker is present.
    Unrecognized,
}

/// What a stored cache entry can do for the read that found it.
pub(crate) enum CacheEntryStatus {
    /// Fresh, and written for the expected authoritative route.
    Fresh(SecretString),
    /// Readable and ours, but expired or written for another route.
    Stale,
    /// Marked as ours but not readable as this envelope version.
    OursUnreadable,
    /// Owned by another project or profile.
    Foreign { project: String, profile: String },
    /// Not a SecretSpec cache entry.
    Unrecognized,
}

/// Errors that can prevent encoding a cache entry.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CacheEncodeError {
    #[error(transparent)]
    Clock(#[from] std::time::SystemTimeError),
    #[error(transparent)]
    Serialize(#[from] serde_json::Error),
}

fn decode(stored: &SecretString) -> Option<Result<CacheEnvelope, serde_json::Error>> {
    stored
        .expose_secret()
        .strip_prefix(CACHE_ENVELOPE_MARKER)
        .map(serde_json::from_str)
}

/// Classify cache ownership without trusting the provider address.
pub(crate) fn ownership(stored: &SecretString, project: &str, profile: &str) -> CacheOwnership {
    match decode(stored) {
        None => CacheOwnership::Unrecognized,
        Some(Err(_)) => CacheOwnership::OursUnreadable,
        Some(Ok(envelope)) if envelope.project == project && envelope.profile == profile => {
            CacheOwnership::Ours
        }
        Some(Ok(envelope)) => CacheOwnership::Foreign {
            project: envelope.project,
            profile: envelope.profile,
        },
    }
}

/// Inspect an entry using the current wall clock.
///
/// Clock errors are returned separately so the caller can preserve the
/// fail-open cache policy while deciding how to report the failure.
pub(crate) fn inspect_entry(
    stored: &SecretString,
    project: &str,
    profile: &str,
    route_fingerprint: &str,
    max_age_secs: u64,
) -> Result<CacheEntryStatus, std::time::SystemTimeError> {
    inspect_entry_with_clock(
        stored,
        project,
        profile,
        route_fingerprint,
        max_age_secs,
        || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
        },
    )
}

fn inspect_entry_with_clock<E>(
    stored: &SecretString,
    project: &str,
    profile: &str,
    route_fingerprint: &str,
    max_age_secs: u64,
    clock: impl FnOnce() -> Result<u64, E>,
) -> Result<CacheEntryStatus, E> {
    let Some(decoded) = decode(stored) else {
        return Ok(CacheEntryStatus::Unrecognized);
    };
    let envelope = match decoded {
        Ok(envelope) if envelope.project == project && envelope.profile == profile => envelope,
        Ok(envelope) => {
            return Ok(CacheEntryStatus::Foreign {
                project: envelope.project,
                profile: envelope.profile,
            });
        }
        Err(_) => return Ok(CacheEntryStatus::OursUnreadable),
    };
    if envelope.route_fingerprint != route_fingerprint {
        return Ok(CacheEntryStatus::Stale);
    }
    let now = clock()?;
    Ok(inspect_owned_entry_at(envelope, max_age_secs, now))
}

#[cfg(test)]
fn inspect_entry_at(
    stored: &SecretString,
    project: &str,
    profile: &str,
    route_fingerprint: &str,
    max_age_secs: u64,
    now: u64,
) -> CacheEntryStatus {
    inspect_entry_with_clock(
        stored,
        project,
        profile,
        route_fingerprint,
        max_age_secs,
        || Ok::<u64, std::convert::Infallible>(now),
    )
    .expect("an infallible test clock cannot fail")
}

fn inspect_owned_entry_at(
    envelope: CacheEnvelope,
    max_age_secs: u64,
    now: u64,
) -> CacheEntryStatus {
    // A timestamp in the future means a clock moved. It is unusable rather than
    // valid until it happens to fall inside the freshness window.
    if envelope.cached_at > now || now.saturating_sub(envelope.cached_at) > max_age_secs {
        return CacheEntryStatus::Stale;
    }
    CacheEntryStatus::Fresh(SecretString::new(envelope.value.as_str().into()))
}

/// Encode an entry using the current wall clock.
pub(crate) fn encode_entry(
    project: &str,
    profile: &str,
    route_fingerprint: String,
    value: &SecretString,
) -> Result<SecretString, CacheEncodeError> {
    let cached_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    encode_entry_at(project, profile, cached_at, route_fingerprint, value).map_err(Into::into)
}

fn encode_entry_at(
    project: &str,
    profile: &str,
    cached_at: u64,
    route_fingerprint: String,
    value: &SecretString,
) -> Result<SecretString, serde_json::Error> {
    let envelope = CacheEnvelope {
        project: project.to_string(),
        profile: profile.to_string(),
        cached_at,
        route_fingerprint,
        value: Zeroizing::new(value.expose_secret().to_string()),
    };
    // Both plaintext renderings of the envelope are held in buffers that
    // zeroize on drop.
    let json = serde_json::to_string(&envelope)?;
    let serialized = Zeroizing::new(format!("{CACHE_ENVELOPE_MARKER}{json}"));
    Ok(SecretString::new(serialized.as_str().into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROJECT: &str = "project";
    const PROFILE: &str = "default";
    const FINGERPRINT: &str = "route-v1";
    const WRITTEN_AT: u64 = 1_000;

    fn entry() -> SecretString {
        encode_entry_at(
            PROJECT,
            PROFILE,
            WRITTEN_AT,
            FINGERPRINT.to_string(),
            &SecretString::new("sensitive".into()),
        )
        .expect("cache envelope serializes")
    }

    #[test]
    fn encoded_entry_round_trips_at_the_freshness_boundary() {
        let decoded = decode(&entry())
            .expect("marker present")
            .expect("valid envelope");
        let status = inspect_owned_entry_at(decoded, 60, WRITTEN_AT + 60);
        let CacheEntryStatus::Fresh(value) = status else {
            panic!("an entry is fresh through its exact max-age boundary");
        };
        assert_eq!(value.expose_secret(), "sensitive");
    }

    #[test]
    fn entry_is_stale_one_second_past_its_max_age() {
        let decoded = decode(&entry())
            .expect("marker present")
            .expect("valid envelope");
        assert!(matches!(
            inspect_owned_entry_at(decoded, 60, WRITTEN_AT + 61),
            CacheEntryStatus::Stale
        ));
    }

    #[test]
    fn future_timestamp_is_stale_after_a_clock_change() {
        let decoded = decode(&entry())
            .expect("marker present")
            .expect("valid envelope");
        assert!(matches!(
            inspect_owned_entry_at(decoded, 60, WRITTEN_AT - 1),
            CacheEntryStatus::Stale
        ));
    }

    #[test]
    fn ownership_distinguishes_ours_foreign_unreadable_and_unrecognized() {
        assert_eq!(ownership(&entry(), PROJECT, PROFILE), CacheOwnership::Ours);
        assert_eq!(
            ownership(&entry(), "other-project", PROFILE),
            CacheOwnership::Foreign {
                project: PROJECT.to_string(),
                profile: PROFILE.to_string(),
            }
        );
        assert_eq!(
            ownership(
                &SecretString::new(format!("{CACHE_ENVELOPE_MARKER}{{truncated").into()),
                PROJECT,
                PROFILE
            ),
            CacheOwnership::OursUnreadable
        );
        assert_eq!(
            ownership(
                &SecretString::new("someone else's value".into()),
                PROJECT,
                PROFILE
            ),
            CacheOwnership::Unrecognized
        );
    }

    #[test]
    fn changed_route_is_stale_even_inside_the_time_window() {
        assert!(matches!(
            inspect_entry_at(
                &entry(),
                PROJECT,
                PROFILE,
                "different-route",
                60,
                WRITTEN_AT
            ),
            CacheEntryStatus::Stale
        ));
    }
}
