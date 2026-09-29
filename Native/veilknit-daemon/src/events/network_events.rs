//! Structured, timestamped events emitted by the long-running network core.
//!
//! These events are the stable observation boundary for the console UI, future
//! desktop/mobile UIs, tests, and attached applications. Diagnostic text may
//! change freely; event variants should evolve through explicit versioning.

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::types::{current_timestamp, current_timestamp_millis};

pub const NETWORK_EVENT_FORMAT_VERSION: u16 = 1;
pub const DEFAULT_NETWORK_EVENT_BUFFER: usize = 2_048;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum StartupStage {
    Configuration,
    Identity,
    Reputation,
    Veilid,
    NetworkAttachment,
    DhtRestore,
    MainDht,
    DhtNetworkVerification,
    Presence,
    Routes,
    Handshake,
    Mailbox,
    Walker,
    ApplicationInfo,
    BackgroundServices,
    Ready,
}

impl StartupStage {
    pub fn label(self) -> &'static str {
        match self {
            Self::Configuration => "Loading configuration",
            Self::Identity => "Loading identities",
            Self::Reputation => "Loading reputation state",
            Self::Veilid => "Starting Veilid",
            Self::NetworkAttachment => "Waiting for network attachment",
            Self::DhtRestore => "Restoring owned DHTs",
            Self::MainDht => "Opening main DHT",
            Self::DhtNetworkVerification => "Verifying DHT network access",
            Self::Presence => "Publishing presence",
            Self::Routes => "Publishing private route",
            Self::Handshake => "Starting handshake service",
            Self::Mailbox => "Starting mailbox service",
            Self::Walker => "Starting network walker",
            Self::ApplicationInfo => "Publishing application capabilities",
            Self::BackgroundServices => "Starting background services",
            Self::Ready => "Network core ready",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StartupStageState {
    Pending,
    Running,
    Complete,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventSeverity {
    Trace,
    Info,
    Notice,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkEventSource {
    Supervisor,
    Dht,
    Presence,
    RouteManager,
    Handshake,
    Walker,
    Mailbox,
    Reputation,
    Identity,
    Application(String),
    CoreModule(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkEvent {
    StartupStageChanged {
        stage: StartupStage,
        state: StartupStageState,
        detail: Option<String>,
        duration_ms: Option<u64>,
    },
    StartupCompleted {
        duration_ms: u64,
    },
    StartupFailed {
        failed_stages: Vec<StartupStage>,
    },
    NetworkAttachmentChanged {
        attached: bool,
        state: String,
    },
    DhtNetworkVerified {
        record_key: String,
        subkey: u32,
        duration_ms: u64,
    },
    HandshakeStarted {
        peer: String,
        verification: bool,
    },
    HandshakeSucceeded {
        peer: String,
        duration_ms: u64,
    },
    HandshakeFailed {
        peer: String,
        reason: String,
        duration_ms: u64,
    },
    HandshakeSkipped {
        peer: String,
        reason: String,
    },
    WalkScheduled {
        reason: String,
        delay_ms: u64,
    },
    WalkStarted {
        reason: String,
        requested_hops: usize,
    },
    WalkProgress {
        completed_hops: usize,
        requested_hops: usize,
        current_target: Option<String>,
    },
    WalkFinished {
        requested_hops: usize,
        completed_hops: usize,
        new_nodes: usize,
        updated_nodes: usize,
        reachable: usize,
        unreachable: usize,
        duration_ms: u64,
    },
    WalkFailed {
        reason: String,
        duration_ms: u64,
    },
    MailStored {
        message_id: String,
        recipient: String,
        duration_ms: u64,
    },
    MailboxActivity {
        activity: String,
        detail: String,
    },
    MailOperationFailed {
        operation: String,
        reason: String,
        duration_ms: u64,
    },
    ReputationChanged {
        subject: String,
        reason: String,
    },
    AppAuthenticated {
        app_id: String,
        session_id: String,
        expires_at: u64,
    },
    AppRegistrationChanged {
        app_id: String,
        enabled: bool,
    },
    AppSessionRevoked {
        app_id: String,
        session_id: String,
    },
    AppObservationsRetracted {
        app_id: String,
        active_observations: usize,
        historical_observations: u64,
        decisions_revoked: usize,
        affected_subjects: usize,
        reason: String,
    },
    ServiceStopping {
        service: String,
    },
    ServiceStopped {
        service: String,
        duration_ms: u64,
        error: Option<String>,
    },
    Diagnostic {
        message: String,
        duration_ms: Option<u64>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEventEnvelope {
    pub format_version: u16,
    pub event_id: u64,
    /// Unix timestamp in whole seconds for compatibility with existing data.
    pub occurred_at: u64,
    /// Millisecond timestamp for console/event ordering and performance logs.
    pub occurred_at_ms: u64,
    pub uptime_ms: u64,
    pub source: NetworkEventSource,
    pub severity: EventSeverity,
    pub event: NetworkEvent,
}

struct NetworkEventBusInner {
    sender: broadcast::Sender<NetworkEventEnvelope>,
    next_id: AtomicU64,
    started_at: Instant,
}

#[derive(Clone)]
pub struct NetworkEventBus {
    inner: Arc<NetworkEventBusInner>,
}

impl Default for NetworkEventBus {
    fn default() -> Self {
        Self::new(DEFAULT_NETWORK_EVENT_BUFFER)
    }
}

impl NetworkEventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(16));
        Self {
            inner: Arc::new(NetworkEventBusInner {
                sender,
                next_id: AtomicU64::new(1),
                started_at: Instant::now(),
            }),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<NetworkEventEnvelope> {
        self.inner.sender.subscribe()
    }

    pub fn uptime(&self) -> Duration {
        self.inner.started_at.elapsed()
    }

    pub fn emit(
        &self,
        source: NetworkEventSource,
        severity: EventSeverity,
        event: NetworkEvent,
    ) -> NetworkEventEnvelope {
        let envelope = NetworkEventEnvelope {
            format_version: NETWORK_EVENT_FORMAT_VERSION,
            event_id: self.inner.next_id.fetch_add(1, Ordering::Relaxed),
            occurred_at: current_timestamp(),
            occurred_at_ms: current_timestamp_millis(),
            uptime_ms: duration_millis(self.inner.started_at.elapsed()),
            source,
            severity,
            event,
        };
        let _ = self.inner.sender.send(envelope.clone());
        envelope
    }

    pub fn diagnostic(
        &self,
        source: NetworkEventSource,
        severity: EventSeverity,
        message: impl Into<String>,
    ) {
        self.emit(
            source,
            severity,
            NetworkEvent::Diagnostic {
                message: message.into(),
                duration_ms: None,
            },
        );
    }
}

/// Re-export shared timing utilities at the historical event-module path so
/// existing callers do not need an all-at-once migration.
pub use crate::support::timing::{duration_millis, OperationTimer};
