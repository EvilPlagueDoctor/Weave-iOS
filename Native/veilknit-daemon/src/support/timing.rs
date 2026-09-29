//! Shared wall-clock, monotonic-duration, retry, and sliding-window helpers.
//!
//! Network modules should not each invent a timestamp or backoff function.
//! Persisted/user-visible times use Unix time; retries and elapsed durations use
//! monotonic `Instant` values so wall-clock corrections cannot alter deadlines.

use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

pub fn unix_nanos_low64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

pub fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

#[derive(Debug, Clone)]
pub struct OperationTimer {
    started_at: Instant,
}

impl OperationTimer {
    pub fn start() -> Self {
        Self { started_at: Instant::now() }
    }

    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    pub fn elapsed_ms(&self) -> u64 {
        duration_millis(self.elapsed())
    }
}

/// Bounded exponential retry policy. Callers retain ownership of scheduling;
/// this type only centralizes the timing calculation.
#[derive(Debug, Clone, Copy)]
pub struct ExponentialBackoff {
    pub initial: Duration,
    pub maximum: Duration,
    pub multiplier: u32,
}

impl ExponentialBackoff {
    pub fn delay(self, retry: u8) -> Duration {
        let multiplier = self.multiplier.max(1) as u128;
        let factor = multiplier.saturating_pow(retry as u32);
        let millis = self.initial.as_millis().saturating_mul(factor);
        Duration::from_millis(
            millis.min(self.maximum.as_millis()).min(u64::MAX as u128) as u64,
        )
    }
}

/// Small reusable rolling-window counter for rate limits and protocol abuse.
#[derive(Debug, Clone)]
pub struct SlidingWindowCounter {
    window_secs: u64,
    values: VecDeque<u64>,
}

impl SlidingWindowCounter {
    pub fn new(window_secs: u64) -> Self {
        Self { window_secs, values: VecDeque::new() }
    }

    pub fn record(&mut self, now: u64) -> usize {
        self.prune(now);
        self.values.push_back(now);
        self.values.len()
    }

    pub fn len_at(&mut self, now: u64) -> usize {
        self.prune(now);
        self.values.len()
    }

    pub fn prune(&mut self, now: u64) {
        while self
            .values
            .front()
            .is_some_and(|value| value.saturating_add(self.window_secs) <= now)
        {
            self.values.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sliding_window_discards_expired_values() {
        let mut counter = SlidingWindowCounter::new(10);
        assert_eq!(counter.record(1), 1);
        assert_eq!(counter.record(5), 2);
        assert_eq!(counter.record(11), 2);
        assert_eq!(counter.len_at(16), 1);
    }

    #[test]
    fn backoff_is_capped() {
        let backoff = ExponentialBackoff {
            initial: Duration::from_secs(2),
            maximum: Duration::from_secs(10),
            multiplier: 2,
        };
        assert_eq!(backoff.delay(0), Duration::from_secs(2));
        assert_eq!(backoff.delay(2), Duration::from_secs(8));
        assert_eq!(backoff.delay(10), Duration::from_secs(10));
    }
}
