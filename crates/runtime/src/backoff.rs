//! Shared retry-delay helpers for bridge receive loops.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_JITTER_RATIO: f64 = 0.25;
const NANOS_PER_SECOND: f64 = 1_000_000_000.0;
const MAX_BACKOFF_SHIFT: u32 = 16;

fn jitter_fraction() -> f64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    f64::from(nanos) / NANOS_PER_SECOND
}

fn jittered_delay_from_fraction(base: Duration, fraction: f64) -> Duration {
    let factor = 1.0 - DEFAULT_JITTER_RATIO + fraction.clamp(0.0, 1.0) * DEFAULT_JITTER_RATIO * 2.0;
    base.mul_f64(factor)
}

/// Apply +/-25% process-local jitter to a delay so reconnecting bridge fleets
/// do not retry in lockstep. This intentionally avoids a `rand` dependency:
/// sub-second clock nanoseconds are enough to de-correlate retry timing.
pub fn jittered_delay(base: Duration) -> Duration {
    jittered_delay_from_fraction(base, jitter_fraction())
}

fn exponential_backoff_with_jitter_from_fraction(
    attempt: u32,
    base: Duration,
    max: Duration,
    fraction: f64,
) -> Duration {
    let exponent = attempt.min(MAX_BACKOFF_SHIFT);
    let scaled = base.saturating_mul(1u32 << exponent).min(max);
    jittered_delay_from_fraction(scaled, fraction).min(max)
}

/// Exponential backoff (`base * 2^attempt`) capped at `max`, with +/-25%
/// process-local jitter applied to the capped delay.
pub fn exponential_backoff_with_jitter(attempt: u32, base: Duration, max: Duration) -> Duration {
    exponential_backoff_with_jitter_from_fraction(attempt, base, max, jitter_fraction())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jittered_delay_uses_expected_window() {
        let base = Duration::from_secs(4);

        assert_eq!(
            jittered_delay_from_fraction(base, 0.0),
            Duration::from_secs(3)
        );
        assert_eq!(
            jittered_delay_from_fraction(base, 0.5),
            Duration::from_secs(4)
        );
        assert_eq!(
            jittered_delay_from_fraction(base, 1.0),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn exponential_backoff_scales_and_caps_final_delay() {
        let base = Duration::from_secs(2);
        let max = Duration::from_secs(60);

        assert_eq!(
            exponential_backoff_with_jitter_from_fraction(0, base, max, 0.5),
            Duration::from_secs(2)
        );
        assert_eq!(
            exponential_backoff_with_jitter_from_fraction(3, base, max, 0.5),
            Duration::from_secs(16)
        );
        assert_eq!(
            exponential_backoff_with_jitter_from_fraction(20, base, max, 1.0),
            max
        );
    }

    #[test]
    fn jitter_fraction_inputs_are_clamped() {
        let base = Duration::from_secs(4);

        assert_eq!(
            jittered_delay_from_fraction(base, -1.0),
            Duration::from_secs(3)
        );
        assert_eq!(
            jittered_delay_from_fraction(base, 2.0),
            Duration::from_secs(5)
        );
    }
}
