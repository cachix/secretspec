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
pub(crate) const CACHE_ENVELOPE_MARKER: &str = "secretspec-cache-v3:";

/// The 0.17 envelope recorded when an entry was written rather than when it
/// expires. Keep recognizing it so an upgrade can replace its own entries
/// without mistaking another project or profile's entry for ours.
const LEGACY_CACHE_ENVELOPE_MARKER: &str = "secretspec-cache-v2:";

/// Value stored inside the configured cache provider. The provider remains
/// responsible for encryption; the envelope adds freshness, route invalidation,
/// and ownership metadata.
#[derive(serde::Serialize, serde::Deserialize)]
struct CacheEnvelope {
    project: String,
    profile: String,
    expires_at: u64,
    max_age_secs: u64,
    route_fingerprint: String,
    /// The cached plaintext stays in a zeroizing buffer on both serialization
    /// and deserialization.
    #[serde(with = "zeroizing_string")]
    value: Zeroizing<String>,
}

/// The 0.17 envelope can still serve its owner while it remains fresh under the
/// active route's policy. Another owner cannot infer its expiry because v2 did
/// not store the `max_age` that created it, so foreign v2 entries remain
/// untouched.
#[derive(serde::Deserialize)]
struct LegacyCacheEnvelope {
    project: String,
    profile: String,
    cached_at: u64,
    route_fingerprint: String,
    #[serde(with = "zeroizing_string")]
    value: Zeroizing<String>,
}

enum DecodedEnvelope {
    Current(CacheEnvelope),
    Legacy(LegacyCacheEnvelope),
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

/// Whether the caller may change the value sitting at a cache address.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CacheOwnership {
    /// This project and profile wrote a readable entry.
    Ours,
    /// A readable SecretSpec entry whose declared lifetime has ended. Its
    /// original owner no longer has an interest in preserving it.
    Expired,
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
    /// Expired (regardless of owner), or ours but no longer usable because its
    /// authoritative route or freshness policy changed.
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
    #[error("cache expiration timestamp is too large")]
    ExpirationOverflow,
    #[error(transparent)]
    Serialize(#[from] serde_json::Error),
}

fn decode(stored: &SecretString) -> Option<Result<DecodedEnvelope, serde_json::Error>> {
    let stored = stored.expose_secret();
    if let Some(payload) = stored.strip_prefix(CACHE_ENVELOPE_MARKER) {
        return Some(serde_json::from_str(payload).map(DecodedEnvelope::Current));
    }
    stored
        .strip_prefix(LEGACY_CACHE_ENVELOPE_MARKER)
        .map(|payload| serde_json::from_str(payload).map(DecodedEnvelope::Legacy))
}

fn unix_timestamp() -> Result<u64, std::time::SystemTimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
}

/// Classify cache ownership without trusting the provider address.
pub(crate) fn ownership(stored: &SecretString, project: &str, profile: &str) -> CacheOwnership {
    ownership_at(stored, project, profile, unix_timestamp().ok())
}

fn ownership_at(
    stored: &SecretString,
    project: &str,
    profile: &str,
    now: Option<u64>,
) -> CacheOwnership {
    match decode(stored) {
        None => CacheOwnership::Unrecognized,
        Some(Err(_)) => CacheOwnership::OursUnreadable,
        Some(Ok(DecodedEnvelope::Current(envelope))) => {
            if now.is_some_and(|now| now >= envelope.expires_at) {
                CacheOwnership::Expired
            } else if envelope.project == project && envelope.profile == profile {
                CacheOwnership::Ours
            } else {
                CacheOwnership::Foreign {
                    project: envelope.project,
                    profile: envelope.profile,
                }
            }
        }
        Some(Ok(DecodedEnvelope::Legacy(envelope)))
            if envelope.project == project && envelope.profile == profile =>
        {
            CacheOwnership::Ours
        }
        Some(Ok(DecodedEnvelope::Legacy(envelope))) => CacheOwnership::Foreign {
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
        unix_timestamp,
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
        Ok(DecodedEnvelope::Current(envelope)) => envelope,
        Ok(DecodedEnvelope::Legacy(envelope)) => {
            if envelope.project != project || envelope.profile != profile {
                return Ok(CacheEntryStatus::Foreign {
                    project: envelope.project,
                    profile: envelope.profile,
                });
            }
            if envelope.route_fingerprint != route_fingerprint {
                return Ok(CacheEntryStatus::Stale);
            }
            let now = clock()?;
            if envelope.cached_at > now || now.saturating_sub(envelope.cached_at) > max_age_secs {
                return Ok(CacheEntryStatus::Stale);
            }
            return Ok(CacheEntryStatus::Fresh(SecretString::new(
                envelope.value.as_str().into(),
            )));
        }
        Err(_) => return Ok(CacheEntryStatus::OursUnreadable),
    };
    let now = clock()?;
    if now >= envelope.expires_at {
        // Expiration is intrinsic to a v3 entry, so whoever encounters it can
        // discard it even when its project/profile no longer has a manifest.
        return Ok(CacheEntryStatus::Stale);
    }
    if envelope.project != project || envelope.profile != profile {
        return Ok(CacheEntryStatus::Foreign {
            project: envelope.project,
            profile: envelope.profile,
        });
    }
    // Reconstructing the write time from the self-contained v3 policy preserves
    // clock-rollback detection without retaining `cached_at` in the envelope.
    let Some(cached_at) = envelope.expires_at.checked_sub(envelope.max_age_secs) else {
        return Ok(CacheEntryStatus::Stale);
    };
    if cached_at > now || envelope.max_age_secs != max_age_secs {
        return Ok(CacheEntryStatus::Stale);
    }
    if envelope.route_fingerprint != route_fingerprint {
        return Ok(CacheEntryStatus::Stale);
    }
    Ok(CacheEntryStatus::Fresh(SecretString::new(
        envelope.value.as_str().into(),
    )))
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

/// Encode an entry using the current wall clock.
pub(crate) fn encode_entry(
    project: &str,
    profile: &str,
    max_age_secs: u64,
    route_fingerprint: String,
    value: &SecretString,
) -> Result<SecretString, CacheEncodeError> {
    encode_entry_at(
        project,
        profile,
        unix_timestamp()?,
        max_age_secs,
        route_fingerprint,
        value,
    )
}

fn encode_entry_at(
    project: &str,
    profile: &str,
    now: u64,
    max_age_secs: u64,
    route_fingerprint: String,
    value: &SecretString,
) -> Result<SecretString, CacheEncodeError> {
    let expires_at = now
        .checked_add(max_age_secs)
        .ok_or(CacheEncodeError::ExpirationOverflow)?;
    let envelope = CacheEnvelope {
        project: project.to_string(),
        profile: profile.to_string(),
        expires_at,
        max_age_secs,
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
    const MAX_AGE: u64 = 60;
    const EXPIRES_AT: u64 = 1_060;

    fn entry() -> SecretString {
        encode_entry_at(
            PROJECT,
            PROFILE,
            WRITTEN_AT,
            MAX_AGE,
            FINGERPRINT.to_string(),
            &SecretString::new("sensitive".into()),
        )
        .expect("cache envelope serializes")
    }

    #[test]
    fn encoded_entry_round_trips_before_expiration() {
        let decoded = decode(&entry())
            .expect("marker present")
            .expect("valid envelope");
        let DecodedEnvelope::Current(envelope) = decoded else {
            panic!("new entries use the current envelope");
        };
        let status = inspect_entry_at(
            &entry(),
            PROJECT,
            PROFILE,
            FINGERPRINT,
            MAX_AGE,
            EXPIRES_AT - 1,
        );
        let CacheEntryStatus::Fresh(value) = status else {
            panic!("an entry is fresh before its expiration timestamp");
        };
        assert_eq!(envelope.expires_at, EXPIRES_AT);
        assert_eq!(envelope.max_age_secs, MAX_AGE);
        assert_eq!(value.expose_secret(), "sensitive");
    }

    #[test]
    fn entry_is_stale_at_its_expiration() {
        assert!(matches!(
            inspect_entry_at(&entry(), PROJECT, PROFILE, FINGERPRINT, MAX_AGE, EXPIRES_AT),
            CacheEntryStatus::Stale
        ));
    }

    #[test]
    fn clock_rollback_makes_an_implausibly_distant_expiration_stale() {
        assert!(matches!(
            inspect_entry_at(
                &entry(),
                PROJECT,
                PROFILE,
                FINGERPRINT,
                MAX_AGE,
                WRITTEN_AT - 1
            ),
            CacheEntryStatus::Stale
        ));
    }

    #[test]
    fn changed_max_age_invalidates_an_unexpired_entry() {
        assert!(matches!(
            inspect_entry_at(
                &entry(),
                PROJECT,
                PROFILE,
                FINGERPRINT,
                MAX_AGE / 2,
                WRITTEN_AT
            ),
            CacheEntryStatus::Stale
        ));
    }

    #[test]
    fn encoded_entry_stores_expiration_instead_of_write_time() {
        let entry = entry();
        let payload = entry
            .expose_secret()
            .strip_prefix(CACHE_ENVELOPE_MARKER)
            .expect("marker present");
        let envelope: serde_json::Value = serde_json::from_str(payload).unwrap();
        assert_eq!(envelope["expires_at"], EXPIRES_AT);
        assert_eq!(envelope["max_age_secs"], MAX_AGE);
        assert!(envelope.get("cached_at").is_none());
    }

    #[test]
    fn expiration_timestamp_overflow_refuses_the_cache_entry() {
        assert!(matches!(
            encode_entry_at(
                PROJECT,
                PROFILE,
                u64::MAX,
                MAX_AGE,
                FINGERPRINT.to_string(),
                &SecretString::new("sensitive".into()),
            ),
            Err(CacheEncodeError::ExpirationOverflow)
        ));
    }

    #[test]
    fn ownership_distinguishes_ours_foreign_unreadable_and_unrecognized() {
        assert_eq!(
            ownership_at(&entry(), PROJECT, PROFILE, Some(EXPIRES_AT - 1)),
            CacheOwnership::Ours
        );
        assert_eq!(
            ownership_at(&entry(), "other-project", PROFILE, Some(EXPIRES_AT - 1)),
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
    fn expired_entry_can_be_removed_by_whichever_project_encounters_it() {
        assert_eq!(
            ownership_at(&entry(), "other-project", "other-profile", Some(EXPIRES_AT)),
            CacheOwnership::Expired
        );
        assert!(matches!(
            inspect_entry_at(
                &entry(),
                "other-project",
                "other-profile",
                "different-route",
                MAX_AGE,
                EXPIRES_AT,
            ),
            CacheEntryStatus::Stale
        ));
    }

    fn legacy_entry() -> SecretString {
        SecretString::new(
            format!(
                "{LEGACY_CACHE_ENVELOPE_MARKER}{}",
                serde_json::json!({
                    "project": PROJECT,
                    "profile": PROFILE,
                    "cached_at": WRITTEN_AT,
                    "route_fingerprint": FINGERPRINT,
                    "value": "sensitive",
                })
            )
            .into(),
        )
    }

    #[test]
    fn legacy_entries_preserve_ownership_during_migration() {
        let legacy = legacy_entry();
        assert_eq!(
            ownership_at(&legacy, PROJECT, PROFILE, Some(EXPIRES_AT)),
            CacheOwnership::Ours
        );
        assert_eq!(
            ownership_at(&legacy, "other-project", PROFILE, Some(EXPIRES_AT)),
            CacheOwnership::Foreign {
                project: PROJECT.to_string(),
                profile: PROFILE.to_string(),
            }
        );
    }

    #[test]
    fn fresh_legacy_entry_remains_usable_during_migration() {
        let legacy = legacy_entry();
        let status = inspect_entry_at(&legacy, PROJECT, PROFILE, FINGERPRINT, MAX_AGE, EXPIRES_AT);
        let CacheEntryStatus::Fresh(value) = status else {
            panic!("v2 preserves its original inclusive freshness boundary");
        };
        assert_eq!(value.expose_secret(), "sensitive");
    }

    #[test]
    fn expired_legacy_entry_is_stale_for_its_owner() {
        assert!(matches!(
            inspect_entry_at(
                &legacy_entry(),
                PROJECT,
                PROFILE,
                FINGERPRINT,
                MAX_AGE,
                EXPIRES_AT + 1
            ),
            CacheEntryStatus::Stale
        ));
    }

    #[test]
    fn changed_route_is_stale_even_inside_the_time_window() {
        assert!(matches!(
            inspect_entry_at(
                &entry(),
                PROJECT,
                PROFILE,
                "different-route",
                MAX_AGE,
                EXPIRES_AT - 1
            ),
            CacheEntryStatus::Stale
        ));
    }
}
