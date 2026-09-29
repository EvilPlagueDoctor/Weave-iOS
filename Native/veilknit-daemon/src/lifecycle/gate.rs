//! Startup "traffic lights" for modules that depend on each other.
//!
//! Some parts of the daemon cannot safely start until another part is ready. For example, a
//! worker may need the main DHT before it can publish anything. A `StageGate` is a tiny signal
//! that says "still waiting", "ready", or "unavailable".
//!
//! Modules wait on the signal instead of repeatedly polling or depending on the exact order of
//! statements in `main.rs`. When a stage changes, every waiter wakes immediately.

use std::{collections::HashMap, sync::Arc, time::Duration};

use tokio::sync::watch;

use crate::events::network_events::StartupStage;

/// Every stage a module might wait on.
const ALL_STAGES: [StartupStage; 16] = [
    StartupStage::Configuration,
    StartupStage::Identity,
    StartupStage::Reputation,
    StartupStage::Veilid,
    StartupStage::NetworkAttachment,
    StartupStage::DhtRestore,
    StartupStage::MainDht,
    StartupStage::DhtNetworkVerification,
    StartupStage::Presence,
    StartupStage::Routes,
    StartupStage::Handshake,
    StartupStage::Mailbox,
    StartupStage::Walker,
    StartupStage::ApplicationInfo,
    StartupStage::BackgroundServices,
    StartupStage::Ready,
];

/// The three answers a waiter can receive from a startup gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageOutcome {
    Pending,
    Ready,
    /// The stage failed or was skipped. Waiters are released rather than left hanging, and
    /// decide for themselves whether they can proceed without it.
    Unavailable,
}

/// Read-only handle used by a module waiting for one startup stage.
#[derive(Clone)]
pub struct StageGate {
    stage: StartupStage,
    rx: watch::Receiver<StageOutcome>,
}

impl StageGate {
    /// Sleeps efficiently until this stage becomes ready or unavailable.
    /// If it already finished, this returns immediately.
    pub async fn wait(&self) -> StageOutcome {
        let mut rx = self.rx.clone();
        loop {
            let current = *rx.borrow();
            if current != StageOutcome::Pending {
                return current;
            }
            if rx.changed().await.is_err() {
                // Sender dropped, which means startup is being torn down. Release the waiter
                // rather than parking it forever.
                return StageOutcome::Unavailable;
            }
        }
    }

    /// Same as `wait`, but gives up after `limit` so optional features cannot stall startup forever.
    pub async fn wait_for(&self, limit: Duration) -> StageOutcome {
        match tokio::time::timeout(limit, self.wait()).await {
            Ok(outcome) => outcome,
            Err(_) => {
                crate::teprintln!(
                    "[lifecycle] waited {}ms for {:?} without it becoming ready",
                    limit.as_millis(),
                    self.stage
                );
                StageOutcome::Pending
            }
        }
    }

    /// Non-blocking check.
    pub fn peek(&self) -> StageOutcome {
        *self.rx.borrow()
    }

    pub fn stage(&self) -> StartupStage {
        self.stage
    }
}

/// Shared collection containing one gate for every known startup stage.
#[derive(Clone)]
pub struct StageGates {
    senders: Arc<HashMap<StartupStage, watch::Sender<StageOutcome>>>,
    receivers: Arc<HashMap<StartupStage, watch::Receiver<StageOutcome>>>,
}

impl Default for StageGates {
    fn default() -> Self {
        Self::new()
    }
}

impl StageGates {
    /// Creates every startup gate in the pending state.
    pub fn new() -> Self {
        let mut senders = HashMap::new();
        let mut receivers = HashMap::new();
        for stage in ALL_STAGES {
            let (tx, rx) = watch::channel(StageOutcome::Pending);
            senders.insert(stage, tx);
            receivers.insert(stage, rx);
        }
        Self {
            senders: Arc::new(senders),
            receivers: Arc::new(receivers),
        }
    }

    /// A handle a module can await. Declare these where the module is constructed, so its
    /// dependencies are visible at its own definition rather than in `lib.rs`.
    /// Returns a waiter for one startup stage.
    pub fn gate(&self, stage: StartupStage) -> StageGate {
        let rx = self
            .receivers
            .get(&stage)
            .expect("every StartupStage variant is registered in ALL_STAGES")
            .clone();
        StageGate { stage, rx }
    }

    /// Marks a stage ready and wakes everything waiting on it.
    /// Opens a gate successfully and wakes everyone waiting on it.
    pub fn mark_ready(&self, stage: StartupStage) {
        self.set(stage, StageOutcome::Ready);
    }

    /// Marks a stage as failed or skipped. Waiters are released with `Unavailable` so they can
    /// decide whether to degrade or give up, rather than being parked forever.
    /// Opens a gate as unavailable so dependants can degrade/abort instead of hanging.
    pub fn mark_unavailable(&self, stage: StartupStage) {
        self.set(stage, StageOutcome::Unavailable);
    }

    fn set(&self, stage: StartupStage, outcome: StageOutcome) {
        if let Some(tx) = self.senders.get(&stage) {
            let _ = tx.send(outcome);
        }
    }

    /// Convenience for waiting on several stages at once. Returns the worst outcome, so a
    /// caller needing everything can check one value.
    /// Waits for several prerequisites; returns unavailable if any required stage is unavailable.
    pub async fn wait_all(&self, stages: &[StartupStage]) -> StageOutcome {
        let mut worst = StageOutcome::Ready;
        for stage in stages {
            match self.gate(*stage).wait().await {
                StageOutcome::Ready => {}
                StageOutcome::Unavailable => worst = StageOutcome::Unavailable,
                StageOutcome::Pending => {
                    if worst == StageOutcome::Ready {
                        worst = StageOutcome::Pending;
                    }
                }
            }
        }
        worst
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn waiter_wakes_when_the_stage_completes() {
        let gates = StageGates::new();
        let gate = gates.gate(StartupStage::MainDht);

        let waiter = tokio::spawn(async move { gate.wait().await });
        tokio::task::yield_now().await;
        gates.mark_ready(StartupStage::MainDht);

        assert_eq!(waiter.await.unwrap(), StageOutcome::Ready);
    }

    #[tokio::test]
    async fn already_ready_returns_without_waiting() {
        let gates = StageGates::new();
        gates.mark_ready(StartupStage::Veilid);
        assert_eq!(gates.gate(StartupStage::Veilid).wait().await, StageOutcome::Ready);
    }

    #[tokio::test]
    async fn failed_stage_releases_waiters() {
        let gates = StageGates::new();
        let gate = gates.gate(StartupStage::Routes);

        let waiter = tokio::spawn(async move { gate.wait().await });
        tokio::task::yield_now().await;
        gates.mark_unavailable(StartupStage::Routes);

        assert_eq!(waiter.await.unwrap(), StageOutcome::Unavailable);
    }

    #[tokio::test]
    async fn wait_for_gives_up_rather_than_hanging() {
        let gates = StageGates::new();
        let outcome = gates
            .gate(StartupStage::Mailbox)
            .wait_for(Duration::from_millis(50))
            .await;
        assert_eq!(outcome, StageOutcome::Pending);
    }
}
