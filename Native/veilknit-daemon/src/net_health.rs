//! Tracks consecutive "offline" outcomes from DHT operations.
//!
//! Veilid reports `TryAgain: offline, try again later` when the node believes it has no
//! usable network. That condition is normally transient, but the daemon's re-attach logic
//! lives inside `node::wait_for_network`, which returns once startup completes — so nothing
//! watches attachment afterwards, and a node that goes offline hours later stays offline
//! until the process is restarted.
//!
//! This module does not fix that. It exists so the condition is *visible*: it counts
//! consecutive offline results and emits one log line once the streak looks like a stuck
//! node rather than a blip, then keeps reporting at a decreasing rate so a long outage
//! leaves a trail without flooding the log.

use std::sync::atomic::{AtomicU64, Ordering};

/// Consecutive offline results before the first report.
const OFFLINE_REPORT_THRESHOLD: u64 = 5;

/// After the first report, log again every this many further failures.
const OFFLINE_REPORT_INTERVAL: u64 = 50;

static OFFLINE_STREAK: AtomicU64 = AtomicU64::new(0);

/// True when an error string is Veilid's "node believes it is offline" condition.
///
/// Matched on the rendered error because it arrives here as a formatted string from several
/// layers; `VeilidAPIError::TryAgain` alone is too broad, since it also covers "route failed
/// to test" and other recoverable-but-online cases.
pub fn is_offline_error(rendered: &str) -> bool {
    let lowered = rendered.to_ascii_lowercase();
    lowered.contains("tryagain") && lowered.contains("offline")
}

/// Records one DHT operation outcome. Call with the rendered error on failure.
pub fn record_result(error: Option<&str>) {
    match error {
        Some(rendered) if is_offline_error(rendered) => note_offline(),
        _ => note_reachable(),
    }
}

fn note_offline() {
    let streak = OFFLINE_STREAK.fetch_add(1, Ordering::Relaxed) + 1;

    let should_report = streak == OFFLINE_REPORT_THRESHOLD
        || (streak > OFFLINE_REPORT_THRESHOLD
            && (streak - OFFLINE_REPORT_THRESHOLD) % OFFLINE_REPORT_INTERVAL == 0);
    if !should_report {
        return;
    }

    crate::teprintln!(
        "[net-health] {streak} consecutive DHT operations reported the node as offline. \
         Veilid is not reachable and the daemon does not re-attach after startup, so this \
         will not recover on its own; restart the daemon.",
    );

    #[cfg(any(target_os = "android", target_os = "ios"))]
    crate::teprintln!(
        "[net-health] Mobile active network: {}",
        crate::mobile_bridge::network_description(),
    );
}

fn note_reachable() {
    // Only log the recovery when there was something to recover from.
    let previous = OFFLINE_STREAK.swap(0, Ordering::Relaxed);
    if previous >= OFFLINE_REPORT_THRESHOLD {
        crate::tprintln!(
            "[net-health] DHT operations are succeeding again after {previous} offline results.",
        );
    }
}

/// Current streak length. Zero means the last observed operation reached the network.
pub fn offline_streak() -> u64 {
    OFFLINE_STREAK.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_the_offline_error_only() {
        assert!(is_offline_error("DHT error: VeilidError(\"TryAgain: offline, try again later\")"));
        assert!(!is_offline_error(
            "new_private_route failed: TryAgain: allocated route failed to test"
        ));
        assert!(!is_offline_error("invalid_record_key"));
    }

    #[test]
    fn streak_resets_on_success() {
        OFFLINE_STREAK.store(0, Ordering::Relaxed);
        for _ in 0..3 {
            record_result(Some("TryAgain: offline, try again later"));
        }
        assert_eq!(offline_streak(), 3);
        record_result(None);
        assert_eq!(offline_streak(), 0);
    }
}
