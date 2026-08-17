use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Returns an absolute Unix-millisecond deadline after `duration`.
///
/// Saturation keeps the wire value valid even when the wall clock or duration
/// is close to the representable limit.
pub fn unix_ms_after(duration: Duration) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .saturating_add(duration.as_millis())
        .min(u64::MAX as u128) as u64
}

/// Largest interval a peer-supplied deadline may place in the future.
///
/// The wire type is an unbounded `u64`, so without this a peer could name a
/// deadline centuries away. The timer would then never fire, the request would
/// hold its in-flight permit for the life of the process, and no amount of
/// server-side timeout logic would reclaim it. Clamping (rather than rejecting)
/// keeps a generous caller working while bounding what a hostile one can hold.
pub const MAX_DEADLINE_HORIZON: Duration = Duration::from_secs(300);

/// Clamps a wire deadline to [`MAX_DEADLINE_HORIZON`] past now.
///
/// Senders apply this so the value they put on the wire matches the deadline
/// they enforce locally; a receiver that clamped only locally would let the
/// peer believe it had longer than the sender was actually willing to wait.
pub fn clamp_unix_ms(deadline_unix_ms: u64) -> u64 {
    unix_ms_after(MAX_DEADLINE_HORIZON).min(deadline_unix_ms)
}

/// Converts an absolute Unix-millisecond deadline into a monotonic instant,
/// clamped to [`MAX_DEADLINE_HORIZON`] past now. An already-elapsed deadline
/// yields the current instant so callers reject it as expired.
#[cfg(feature = "tokio")]
pub(crate) fn instant_from_unix_ms(deadline_unix_ms: u64) -> tokio::time::Instant {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64;
    let remaining =
        Duration::from_millis(deadline_unix_ms.saturating_sub(now_ms)).min(MAX_DEADLINE_HORIZON);
    tokio::time::Instant::now() + remaining
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_deadline_is_not_in_the_past() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        assert!(unix_ms_after(Duration::from_secs(1)) >= before.saturating_add(1_000));
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn far_future_deadlines_are_clamped_to_the_horizon() {
        // A peer naming a deadline centuries out must not win an unbounded
        // in-flight permit; the horizon caps what it can hold. The ceiling is
        // sampled after the call so its `now` is never earlier than the
        // function's own.
        let saturated = instant_from_unix_ms(u64::MAX);
        let far = instant_from_unix_ms(unix_ms_after(Duration::from_secs(86_400)));
        let ceiling = tokio::time::Instant::now() + MAX_DEADLINE_HORIZON;
        assert!(saturated <= ceiling);
        assert!(far <= ceiling);
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn deadlines_inside_the_horizon_are_preserved() {
        let floor = tokio::time::Instant::now() + Duration::from_secs(25);
        let instant = instant_from_unix_ms(unix_ms_after(Duration::from_secs(30)));
        let ceiling = tokio::time::Instant::now() + Duration::from_secs(31);
        assert!(instant > floor);
        assert!(instant <= ceiling);
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn clamping_a_wire_deadline_is_idempotent_and_bounded() {
        let clamped = clamp_unix_ms(u64::MAX);
        assert!(clamped <= unix_ms_after(MAX_DEADLINE_HORIZON));
        // A deadline already inside the horizon passes through untouched.
        let near = unix_ms_after(Duration::from_secs(5));
        assert_eq!(clamp_unix_ms(near), near);
    }

    #[test]
    fn horizon_covers_the_documented_operation_timeout() {
        // External provider operations use a 30s timeout and startup 10s; the
        // horizon must not clamp SecretSpec's own legitimate deadlines.
        assert!(MAX_DEADLINE_HORIZON >= Duration::from_secs(30));
    }
}
