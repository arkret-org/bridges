//! Retry-delay helpers for bridge receive loops.
//!
//! The curve, the jitter span and the `Retry-After` semantics all come from
//! [`arkret_retry`]; this module only binds them to the bridges' wall-clock
//! jitter seed. `sync/api-conventions.md` §9 is the normative source: first
//! wait at least 1,000 ms, factor 2, ceiling at least 60,000 ms, 0–20% jitter.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arkret_retry::{Jitter, RetryPolicy, SPEC_JITTER_RATIO};

/// The reconnect / retry curve every bridge loop uses.
pub const BRIDGE_RETRY: RetryPolicy = RetryPolicy::arkret_default();

/// Seed the jitter mixer from sub-second clock nanoseconds.
///
/// This intentionally avoids a `rand` dependency: the sub-second sample is
/// enough to de-correlate retry timing across a reconnecting bridge fleet, and
/// jitter is never a security boundary.
fn jitter() -> Jitter {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| u64::from(elapsed.subsec_nanos()));
    Jitter::from_seed(nanos)
}

/// Add the spec's 0–20% jitter to a fixed delay so reconnecting bridge fleets
/// do not retry in lockstep.
#[must_use]
pub fn jittered_delay(base: Duration) -> Duration {
    arkret_retry::apply_jitter(base, SPEC_JITTER_RATIO, &mut jitter())
}

/// The delay before retry number `attempt` (0-based) on the shared bridge
/// curve, with the spec's 0–20% jitter added on top of the capped delay.
///
/// The jitter is deliberately *not* re-clamped into the ceiling: clamping would
/// collapse the jitter window to zero exactly once the ladder saturates, which
/// is when a fleet most needs de-correlating.
#[must_use]
pub fn bridge_retry_delay(attempt: u32) -> Duration {
    BRIDGE_RETRY.delay(attempt, &mut jitter())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_only_ever_lengthens_a_fixed_delay() {
        let base = Duration::from_secs(4);
        for _ in 0..64 {
            let delay = jittered_delay(base);
            assert!(delay >= base, "{delay:?} fell below the base delay");
            assert!(delay <= Duration::from_millis(4_800), "{delay:?}");
        }
    }

    #[test]
    fn bridge_ladder_scales_and_saturates() {
        assert_eq!(BRIDGE_RETRY.base_delay(0), Duration::from_secs(1));
        assert_eq!(BRIDGE_RETRY.base_delay(3), Duration::from_secs(8));
        assert_eq!(BRIDGE_RETRY.base_delay(20), Duration::from_secs(60));
    }

    #[test]
    fn saturated_ladder_still_carries_jitter() {
        for _ in 0..64 {
            let delay = bridge_retry_delay(20);
            assert!(delay >= Duration::from_secs(60), "{delay:?}");
            assert!(delay <= Duration::from_secs(72), "{delay:?}");
        }
    }

    #[test]
    fn bridge_retry_curve_is_the_spec_default() {
        assert_eq!(BRIDGE_RETRY.initial_delay(), Duration::from_secs(1));
        assert_eq!(BRIDGE_RETRY.max_delay(), Duration::from_secs(60));
        assert_eq!(BRIDGE_RETRY.factor(), 2);
    }
}
