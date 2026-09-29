//! The daemon's network control desk.
//!
//! `NetworkSupervisor` keeps the easy-to-read big picture: startup stages, whether the network
//! is attached, background walk scheduling, status/events for the UI, and access to the shared
//! `Lifecycle` coordinator.
//!
//! It does **not** have a separate shutdown engine anymore. Modules register their cleanup with
//! `Lifecycle`, and the supervisor simply asks Lifecycle to stop them in the safe order. This
//! keeps the UI/status responsibilities here while leaving shutdown ordering in one place.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{broadcast, mpsc, watch, Mutex, RwLock},
    task::JoinHandle,
    time,
};

use crate::{
    lifecycle::{
        HookOutcome, HookResult, HookSpec, Lifecycle, Progress, Reachability, StopReason,
    },
    network_events::{
        duration_millis, EventSeverity, NetworkEvent, NetworkEventBus,
        NetworkEventEnvelope, NetworkEventSource, OperationTimer, StartupStage,
        StartupStageState,
    },
    walk_task::{
        WalkConfig, WalkRunReport, WalkStartResult, WalkSubscriber, WalkTask,
        DEFAULT_MAX_HOPS_PER_WALK,
    },
    walk_settings::{WalkMode, WalkModeSettings, WalkSettings},
};

pub const MAX_GLOBAL_DHT_OPERATIONS: usize = 1_024;
pub const NORMAL_DHT_READ_CONCURRENCY: usize = 256;
pub const NORMAL_DHT_WRITE_CONCURRENCY: usize = 128;
pub const SINGLE_RECORD_BULK_CONCURRENCY: usize = 64;

pub const PRESENCE_CHECKIN_INTERVAL_SECS: u64 = 10 * 60;
pub const PRESENCE_STALE_AFTER_SECS: u64 = 15 * 60;
pub const PRESENCE_FUTURE_SKEW_ALLOWANCE_SECS: u64 = 2 * 60;
pub const ESTABLISHED_HANDSHAKE_REVERIFY_SECS: u64 = 24 * 60 * 60;

/// Limits how many DHT operations the daemon tries to do at once.
/// Lower values reduce load; higher values can improve throughput on stronger devices.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DhtConcurrencyPolicy {
    pub max_global_operations: usize,
    pub normal_read_concurrency: usize,
    pub normal_write_concurrency: usize,
    pub single_record_bulk_concurrency: usize,
}

impl Default for DhtConcurrencyPolicy {
    fn default() -> Self {
        Self {
            max_global_operations: MAX_GLOBAL_DHT_OPERATIONS,
            normal_read_concurrency: NORMAL_DHT_READ_CONCURRENCY,
            normal_write_concurrency: NORMAL_DHT_WRITE_CONCURRENCY,
            single_record_bulk_concurrency: SINGLE_RECORD_BULK_CONCURRENCY,
        }
    }
}

/// Timing rules for "I am still online" presence information.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PresencePolicy {
    pub checkin_interval_secs: u64,
    pub stale_after_secs: u64,
    pub future_skew_allowance_secs: u64,
}

impl Default for PresencePolicy {
    fn default() -> Self {
        Self {
            checkin_interval_secs: PRESENCE_CHECKIN_INTERVAL_SECS,
            stale_after_secs: PRESENCE_STALE_AFTER_SECS,
            future_skew_allowance_secs: PRESENCE_FUTURE_SKEW_ALLOWANCE_SECS,
        }
    }
}

/// Rules used by the automatic network walker to decide when/how far to walk.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WalkSchedulePolicy {
    pub initial_delay_secs: u64,
    pub minimum_interval_secs: u64,
    pub normal_interval_secs: u64,
    pub maximum_interval_secs: u64,
    pub jitter_percent: u8,
    pub requested_hops: usize,
}

impl Default for WalkSchedulePolicy {
    fn default() -> Self {
        Self {
            initial_delay_secs: 60,
            minimum_interval_secs: 5 * 60,
            normal_interval_secs: 30 * 60,
            maximum_interval_secs: 2 * 60 * 60,
            jitter_percent: 20,
            requested_hops: DEFAULT_MAX_HOPS_PER_WALK,
        }
    }
}

impl WalkSchedulePolicy {
    fn clamp_interval(&self, seconds: u64) -> u64 {
        seconds.clamp(
            self.minimum_interval_secs.max(1),
            self.maximum_interval_secs.max(self.minimum_interval_secs.max(1)),
        )
    }

    pub fn next_interval_secs(
        &self,
        consecutive_empty_walks: u32,
        report: Option<&WalkRunReport>,
    ) -> u64 {
        let mut seconds = self.normal_interval_secs.max(1);

        if let Some(report) = report {
            let discoveries = report.new_nodes;
            if discoveries != 0 {
                // Productive walks become somewhat more frequent, never more
                // often than the five-minute floor.
                let divisor = discoveries.min(4).saturating_add(1) as u64;
                seconds = seconds.saturating_div(divisor).max(1);
            }

            if report.unreachable > report.reachable {
                seconds = seconds.saturating_mul(2);
            }
        }

        if consecutive_empty_walks != 0 {
            let shift = consecutive_empty_walks.min(5);
            seconds = seconds.saturating_mul(1u64 << shift);
        }

        self.clamp_interval(seconds)
    }

    pub fn jittered(&self, seconds: u64) -> Duration {
        let percent = self.jitter_percent.min(90) as i64;
        if percent == 0 {
            return Duration::from_secs(seconds.max(1));
        }

        let span = ((seconds as u128 * percent as u128) / 100)
            .min(i64::MAX as u128) as i64;
        let offset = rand::thread_rng().gen_range(-span..=span);
        Duration::from_secs(seconds.saturating_add_signed(offset).max(1))
    }
}

/// Very high-level daemon state shown to observers such as the GUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SupervisorLifecycle {
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}

/// UI-friendly snapshot of one startup stage and how long it took.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupStageSnapshot {
    pub state: StartupStageState,
    pub detail: Option<String>,
    pub started_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub duration_ms: Option<u64>,
}

impl Default for StartupStageSnapshot {
    fn default() -> Self {
        Self {
            state: StartupStageState::Pending,
            detail: None,
            started_at: None,
            completed_at: None,
            duration_ms: None,
        }
    }
}

/// A copyable/readable summary of the daemon network state at one moment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub lifecycle: SupervisorLifecycle,
    pub network_attached: bool,
    pub dht_network_verified: bool,
    pub startup_stages: BTreeMap<StartupStage, StartupStageSnapshot>,
    pub started_at: u64,
    pub ready_at: Option<u64>,
    pub stopping_at: Option<u64>,
}

impl NetworkStatus {
    fn new() -> Self {
        let startup_stages = all_startup_stages()
            .into_iter()
            .map(|stage| (stage, StartupStageSnapshot::default()))
            .collect();
        Self {
            lifecycle: SupervisorLifecycle::Starting,
            network_attached: false,
            dht_network_verified: false,
            startup_stages,
            started_at: crate::types::current_timestamp(),
            ready_at: None,
            stopping_at: None,
        }
    }
}

/// Shared owner of status/events/policies plus a handle to the single Lifecycle coordinator.
#[derive(Clone)]
pub struct NetworkSupervisor {
    events: NetworkEventBus,
    status: Arc<RwLock<NetworkStatus>>,
    lifecycle: Lifecycle,
    startup_started: Instant,
    dht_policy: DhtConcurrencyPolicy,
    presence_policy: PresencePolicy,
    walk_policy: WalkSchedulePolicy,
}

impl Default for NetworkSupervisor {
    fn default() -> Self {
        Self::new(
            DhtConcurrencyPolicy::default(),
            PresencePolicy::default(),
            WalkSchedulePolicy::default(),
        )
    }
}

impl NetworkSupervisor {
    /// Builds a supervisor with the policies that control DHT load, presence, and auto-walking.
    pub fn new(
        dht_policy: DhtConcurrencyPolicy,
        presence_policy: PresencePolicy,
        walk_policy: WalkSchedulePolicy,
    ) -> Self {
        Self {
            events: NetworkEventBus::default(),
            status: Arc::new(RwLock::new(NetworkStatus::new())),
            lifecycle: Lifecycle::new(),
            startup_started: Instant::now(),
            dht_policy,
            presence_policy,
            walk_policy,
        }
    }

    /// Returns the event broadcaster used by the console/GUI and other observers.
    pub fn event_bus(&self) -> NetworkEventBus {
        self.events.clone()
    }

    /// Returns another handle to the daemon-wide lifecycle coordinator.
    pub fn lifecycle(&self) -> Lifecycle {
        self.lifecycle.clone()
    }

    /// Subscribes to future supervisor/network events.
    pub fn subscribe(&self) -> broadcast::Receiver<NetworkEventEnvelope> {
        self.events.subscribe()
    }

    pub fn dht_policy(&self) -> DhtConcurrencyPolicy {
        self.dht_policy
    }

    pub fn presence_policy(&self) -> PresencePolicy {
        self.presence_policy
    }

    pub fn walk_policy(&self) -> WalkSchedulePolicy {
        self.walk_policy
    }

    /// Takes a snapshot of the current high-level network/startup status.
    pub async fn status(&self) -> NetworkStatus {
        self.status.read().await.clone()
    }

    /// Marks a startup stage as running and returns a timer used to finish that stage later.
    pub async fn stage_running(
        &self,
        stage: StartupStage,
        detail: Option<String>,
    ) -> StartupStageTimer {
        let now = crate::types::current_timestamp();
        {
            let mut status = self.status.write().await;
            let snapshot = status.startup_stages.entry(stage).or_default();
            snapshot.state = StartupStageState::Running;
            snapshot.detail = detail.clone();
            snapshot.started_at = Some(now);
            snapshot.completed_at = None;
            snapshot.duration_ms = None;
        }
        self.events.emit(
            NetworkEventSource::Supervisor,
            EventSeverity::Info,
            NetworkEvent::StartupStageChanged {
                stage,
                state: StartupStageState::Running,
                detail,
                duration_ms: None,
            },
        );
        StartupStageTimer {
            supervisor: self.clone(),
            stage,
            timer: OperationTimer::start(),
            finished: false,
        }
    }

    /// Common bookkeeping used when a startup stage finishes successfully, fails, or is skipped.
    async fn finish_stage(
        &self,
        stage: StartupStage,
        state: StartupStageState,
        detail: Option<String>,
        duration_ms: u64,
    ) {
        let now = crate::types::current_timestamp();
        {
            let mut status = self.status.write().await;
            let snapshot = status.startup_stages.entry(stage).or_default();
            snapshot.state = state;
            snapshot.detail = detail.clone();
            snapshot.completed_at = Some(now);
            snapshot.duration_ms = Some(duration_ms);
            if state == StartupStageState::Failed {
                status.lifecycle = SupervisorLifecycle::Failed;
            }
        }
        self.events.emit(
            NetworkEventSource::Supervisor,
            if state == StartupStageState::Failed {
                EventSeverity::Error
            } else {
                EventSeverity::Info
            },
            NetworkEvent::StartupStageChanged {
                stage,
                state,
                detail,
                duration_ms: Some(duration_ms),
            },
        );
    }

    /// Updates the supervisor's simple "attached or not" view and tells UI/event listeners.
    pub async fn set_network_attachment(&self, attached: bool, state: impl Into<String>) {
        self.status.write().await.network_attached = attached;
        self.events.emit(
            NetworkEventSource::Supervisor,
            EventSeverity::Info,
            NetworkEvent::NetworkAttachmentChanged {
                attached,
                state: state.into(),
            },
        );
    }

    pub async fn set_dht_network_verified(
        &self,
        record_key: impl Into<String>,
        subkey: u32,
        duration: Duration,
    ) {
        self.status.write().await.dht_network_verified = true;
        self.events.emit(
            NetworkEventSource::Dht,
            EventSeverity::Notice,
            NetworkEvent::DhtNetworkVerified {
                record_key: record_key.into(),
                subkey,
                duration_ms: duration_millis(duration),
            },
        );
    }

    /// Declares startup complete after checking that no required startup stage failed.
    pub async fn mark_ready(&self) -> Result<(), String> {
        let now = crate::types::current_timestamp();
        let mut skipped = Vec::new();
        let failed_stages = {
            let status = self.status.read().await;
            status
                .startup_stages
                .iter()
                .filter_map(|(stage, snapshot)| {
                    (snapshot.state == StartupStageState::Failed).then_some(*stage)
                })
                .collect::<Vec<_>>()
        };

        if !failed_stages.is_empty() {
            self.status.write().await.lifecycle = SupervisorLifecycle::Failed;
            self.events.emit(
                NetworkEventSource::Supervisor,
                EventSeverity::Error,
                NetworkEvent::StartupFailed {
                    failed_stages: failed_stages.clone(),
                },
            );
            return Err(format!(
                "critical startup stage(s) failed: {}",
                failed_stages
                    .iter()
                    .map(|stage| stage.label())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        {
            let mut status = self.status.write().await;
            status.lifecycle = SupervisorLifecycle::Running;
            status.ready_at = Some(now);

            // A startup host may not instrument every optional subsystem. Do
            // not leave those rows looking permanently stuck once the service
            // has deliberately declared itself ready.
            for (stage, snapshot) in status.startup_stages.iter_mut() {
                if *stage != StartupStage::Ready
                    && snapshot.state == StartupStageState::Pending
                {
                    snapshot.state = StartupStageState::Skipped;
                    snapshot.detail = Some("Not enabled by this host".to_string());
                    snapshot.completed_at = Some(now);
                    snapshot.duration_ms = Some(0);
                    skipped.push(*stage);
                }
            }

            let ready = status
                .startup_stages
                .entry(StartupStage::Ready)
                .or_default();
            ready.state = StartupStageState::Complete;
            ready.started_at = Some(now);
            ready.completed_at = Some(now);
            ready.duration_ms = Some(0);
        }

        for stage in skipped {
            self.events.emit(
                NetworkEventSource::Supervisor,
                EventSeverity::Info,
                NetworkEvent::StartupStageChanged {
                    stage,
                    state: StartupStageState::Skipped,
                    detail: Some("Not enabled by this host".to_string()),
                    duration_ms: Some(0),
                },
            );
        }
        self.events.emit(
            NetworkEventSource::Supervisor,
            EventSeverity::Notice,
            NetworkEvent::StartupStageChanged {
                stage: StartupStage::Ready,
                state: StartupStageState::Complete,
                detail: None,
                duration_ms: Some(0),
            },
        );
        self.events.emit(
            NetworkEventSource::Supervisor,
            EventSeverity::Notice,
            NetworkEvent::StartupCompleted {
                duration_ms: duration_millis(self.startup_started.elapsed()),
            },
        );
        Ok(())
    }

    /// Register a shutdown hook with the lifecycle coordinator while preserving supervisor
    /// service-stop events for GUI/console clients.
    pub async fn register_shutdown_hook<F, Fut>(&self, spec: HookSpec, action: F)
    where
        F: Fn(Progress) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        let events = self.events.clone();
        let service = spec.module.clone();
        self.lifecycle
            .register(spec, move |progress| {
                let events = events.clone();
                let service = service.clone();
                let future = action(progress);
                async move {
                    events.emit(
                        NetworkEventSource::Supervisor,
                        EventSeverity::Info,
                        NetworkEvent::ServiceStopping {
                            service: service.clone(),
                        },
                    );
                    future.await
                }
            })
            .await;
    }

    /// The supervisor remains the public status/event facade, but lifecycle is the sole
    /// shutdown executor. No second hook registry or reverse-registration ordering exists.
    pub async fn shutdown(&self, reason: StopReason) -> Vec<HookOutcome> {
        crate::shutdown_debug!("NetworkSupervisor::shutdown ENTER reason={reason:?}");
        {
            let mut status = self.status.write().await;
            if matches!(
                status.lifecycle,
                SupervisorLifecycle::Stopping | SupervisorLifecycle::Stopped
            ) || self.lifecycle.is_stopping()
            {
                return Vec::new();
            }
            status.lifecycle = SupervisorLifecycle::Stopping;
            status.stopping_at = Some(crate::types::current_timestamp());
        }

        let initial_reachability = if self.status.read().await.network_attached {
            Reachability::Reachable
        } else {
            Reachability::Unreachable
        };
        let refresh = self.clone();
        crate::shutdown_debug!(
            "supervisor calling lifecycle.stop; initial_reachability={initial_reachability:?}"
        );
        let outcomes = self
            .lifecycle
            .stop(reason, initial_reachability, async move {
                if refresh.status.read().await.network_attached {
                    Reachability::Reachable
                } else {
                    Reachability::Unreachable
                }
            })
            .await;
        crate::shutdown_debug!(
            "supervisor returned from lifecycle.stop with {} outcomes",
            outcomes.len()
        );

        for outcome in &outcomes {
            let error = match &outcome.result {
                HookResult::Ok | HookResult::Skipped(_) => None,
                HookResult::Failed(error) => Some(error.clone()),
                HookResult::Overran => Some(format!(
                    "shutdown budget exceeded while {}",
                    outcome.detail
                )),
            };
            self.events.emit(
                NetworkEventSource::Supervisor,
                if error.is_some() {
                    EventSeverity::Warning
                } else {
                    EventSeverity::Info
                },
                NetworkEvent::ServiceStopped {
                    service: outcome.module.clone(),
                    duration_ms: outcome.elapsed.as_millis().min(u64::MAX as u128) as u64,
                    error,
                },
            );
        }

        let had_shutdown_error = outcomes.iter().any(|outcome| {
            matches!(&outcome.result, HookResult::Failed(_) | HookResult::Overran)
        });
        crate::shutdown_debug!(
            "supervisor final classification inputs: had_shutdown_error={} running_hooks={} watchdog_left_armed={}",
            had_shutdown_error, self.lifecycle.has_running_hooks(), self.lifecycle.watchdog_left_armed()
        );
        self.status.write().await.lifecycle = if had_shutdown_error
            || self.lifecycle.has_running_hooks()
            || self.lifecycle.watchdog_left_armed()
        {
            SupervisorLifecycle::Failed
        } else {
            SupervisorLifecycle::Stopped
        };
        crate::shutdown_debug!("NetworkSupervisor::shutdown RETURN");
        outcomes
    }

}

pub struct StartupStageTimer {
    supervisor: NetworkSupervisor,
    stage: StartupStage,
    timer: OperationTimer,
    finished: bool,
}

impl StartupStageTimer {
    pub async fn complete(mut self, detail: Option<String>) {
        self.finished = true;
        self.supervisor
            .finish_stage(
                self.stage,
                StartupStageState::Complete,
                detail,
                self.timer.elapsed_ms(),
            )
            .await;
    }

    pub async fn skip(mut self, detail: Option<String>) {
        self.finished = true;
        self.supervisor
            .finish_stage(
                self.stage,
                StartupStageState::Skipped,
                detail,
                self.timer.elapsed_ms(),
            )
            .await;
    }

    pub async fn fail(mut self, detail: impl Into<String>) {
        self.finished = true;
        self.supervisor
            .finish_stage(
                self.stage,
                StartupStageState::Failed,
                Some(detail.into()),
                self.timer.elapsed_ms(),
            )
            .await;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkReason {
    Periodic,
    MailboxCoverageUnhealthy,
    UserRequested,
    MailRequested,
}

impl WalkReason {
    fn label(self) -> &'static str {
        match self {
            Self::Periodic => "periodic",
            Self::MailboxCoverageUnhealthy => "mailbox coverage unhealthy",
            Self::UserRequested => "user requested",
            Self::MailRequested => "mail mode requested",
        }
    }

    fn is_explicit_mail(self) -> bool {
        matches!(
            self,
            Self::MailboxCoverageUnhealthy | Self::MailRequested
        )
    }

    fn bypasses_interval_floor(self) -> bool {
        matches!(self, Self::UserRequested | Self::MailRequested)
    }
}

#[derive(Clone)]
pub struct AutoWalkHandle {
    request_tx: mpsc::Sender<WalkReason>,
    settings_tx: watch::Sender<WalkSettings>,
    stop_tx: watch::Sender<bool>,
    task: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl AutoWalkHandle {
    pub async fn request(&self, reason: WalkReason) -> Result<(), String> {
        self.request_tx
            .send(reason)
            .await
            .map_err(|_| "automatic walk scheduler is stopped".to_string())
    }

    pub fn update_settings(&self, settings: WalkSettings) -> Result<(), String> {
        self.settings_tx
            .send(settings.sanitized())
            .map_err(|_| "automatic walk scheduler is stopped".to_string())
    }

    pub fn settings(&self) -> WalkSettings {
        *self.settings_tx.borrow()
    }

    pub async fn shutdown(&self) {
        crate::shutdown_debug!(
            "auto-walk scheduler shutdown: sending stop signal"
        );
        match self.stop_tx.send(true) {
            Ok(()) => crate::shutdown_debug!(
                "auto-walk scheduler shutdown: stop signal sent"
            ),
            Err(_) => crate::shutdown_debug!(
                "auto-walk scheduler shutdown: stop receiver already gone"
            ),
        }

        crate::shutdown_debug!(
            "auto-walk scheduler shutdown: taking scheduler JoinHandle"
        );
        let task = self.task.lock().await.take();
        if let Some(task) = task {
            crate::shutdown_debug!(
                "auto-walk scheduler shutdown: awaiting scheduler task"
            );
            match task.await {
                Ok(()) => crate::shutdown_debug!(
                    "auto-walk scheduler shutdown: scheduler task joined"
                ),
                Err(error) => crate::shutdown_debug!(
                    "auto-walk scheduler shutdown: scheduler task join error: {error}"
                ),
            }
        } else {
            crate::shutdown_debug!(
                "auto-walk scheduler shutdown: scheduler JoinHandle already taken"
            );
        }
    }
}

pub fn spawn_auto_walk_scheduler(
    walker: WalkTask,
    subscribers: Vec<Arc<dyn WalkSubscriber>>,
    policy: WalkSchedulePolicy,
    settings: WalkSettings,
    events: NetworkEventBus,
) -> AutoWalkHandle {
    let (request_tx, request_rx) = mpsc::channel(32);
    let (settings_tx, settings_rx) = watch::channel(settings.sanitized());
    let (stop_tx, stop_rx) = watch::channel(false);
    let task = tokio::spawn(auto_walk_loop(
        walker,
        subscribers,
        policy,
        events,
        request_rx,
        settings_rx,
        stop_rx,
    ));
    let task_slot = Arc::new(Mutex::new(Some(task)));

    AutoWalkHandle {
        request_tx,
        settings_tx,
        stop_tx,
        task: task_slot,
    }
}

async fn auto_walk_loop(
    walker: WalkTask,
    subscribers: Vec<Arc<dyn WalkSubscriber>>,
    policy: WalkSchedulePolicy,
    events: NetworkEventBus,
    mut request_rx: mpsc::Receiver<WalkReason>,
    mut settings_rx: watch::Receiver<WalkSettings>,
    mut stop_rx: watch::Receiver<bool>,
) {
    const MAIL_BOOST_LIFETIME: Duration = Duration::from_secs(30 * 60);

    let mut last_walk_finished: Option<Instant> = None;
    let mut last_report: Option<WalkRunReport> = None;
    let mut low_discovery_streak = 0u32;
    let mut mail_boost_until: Option<Instant> = None;
    let mut next_delay = policy.jittered(policy.initial_delay_secs.max(1));

    loop {
        let current_settings = (*settings_rx.borrow()).sanitized();
        let mail_boost_active = mail_boost_until.is_some_and(|until| until > Instant::now());
        let scheduled_mode = if current_settings.mail_mode_enabled || mail_boost_active {
            WalkMode::Mail
        } else {
            WalkMode::Normal
        };

        events.emit(
            NetworkEventSource::Walker,
            EventSeverity::Info,
            NetworkEvent::WalkScheduled {
                reason: match scheduled_mode {
                    WalkMode::Normal => WalkReason::Periodic.label().to_string(),
                    WalkMode::Mail => "periodic mail mode".to_string(),
                },
                delay_ms: duration_millis(next_delay),
            },
        );

        let reason = tokio::select! {
            _ = time::sleep(next_delay) => WalkReason::Periodic,
            request = request_rx.recv() => match request {
                Some(reason) => reason,
                None => break,
            },
            changed = settings_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                next_delay = Duration::from_secs(1);
                continue;
            },
            changed = stop_rx.changed() => {
                if changed.is_err() || *stop_rx.borrow() {
                    break;
                }
                continue;
            }
        };

        if *stop_rx.borrow() {
            break;
        }

        if reason.is_explicit_mail() {
            mail_boost_until = Some(Instant::now() + MAIL_BOOST_LIFETIME);
        }

        let settings = (*settings_rx.borrow()).sanitized();
        let mail_boost_active = mail_boost_until.is_some_and(|until| until > Instant::now());
        let mode = if reason.is_explicit_mail()
            || (matches!(reason, WalkReason::Periodic)
                && (settings.mail_mode_enabled || mail_boost_active))
        {
            WalkMode::Mail
        } else {
            WalkMode::Normal
        };
        let mode_settings = settings.for_mode(mode);

        if !reason.bypasses_interval_floor() {
            if let Some(finished_at) = last_walk_finished {
                let elapsed = finished_at.elapsed();
                let floor = Duration::from_secs(mode_settings.minimum_interval_secs);
                if elapsed < floor {
                    next_delay = floor - elapsed;
                    continue;
                }
            }
        }

        let list = walker.get_internal_list_copy().await;
        let verified_nodes = list.entries.len();
        let eligible_nodes = verified_nodes.saturating_add(list.candidates.len());
        let requested_hops = adaptive_hop_target(
            mode,
            mode_settings,
            verified_nodes,
            eligible_nodes,
            last_report.as_ref(),
            low_discovery_streak,
        );
        let event_reason = format!("{} ({mode:?}, adaptive)", reason.label());
        let config = WalkConfig::random(requested_hops)
            .with_event_reason(event_reason.clone())
            .with_subscribers(subscribers.clone());
        let timer = OperationTimer::start();

        events.emit(
            NetworkEventSource::Walker,
            EventSeverity::Notice,
            NetworkEvent::WalkStarted {
                reason: event_reason,
                requested_hops,
            },
        );

        match walker.start_walk(config).await {
            Ok(WalkStartResult::Started(handle)) => {
                crate::shutdown_debug!(
                    "auto-walk scheduler: active walk started; waiting for completion or stop signal"
                );

                // The old scheduler waited only on `handle.wait()`. If shutdown arrived while a
                // walk was active, the stop flag could not be observed until that entire walk
                // finished. Lifecycle then timed the scheduler out after three seconds and,
                // conservatively, refused to run the later walker shutdown hook. Listen for the
                // stop signal *while* the walk is running instead. The scheduler requests
                // cancellation and exits; the dedicated walker hook later proves that the actual
                // WalkSession task has stopped before Veilid teardown is allowed.
                let wait_handle = handle.clone();
                let walk_result = tokio::select! {
                    result = wait_handle.wait() => Some(result),
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() {
                            crate::shutdown_debug!(
                                "auto-walk scheduler: stop observed during active walk; requesting walk cancellation and exiting scheduler"
                            );
                            handle.cancel();
                            None
                        } else {
                            continue;
                        }
                    }
                };

                let Some(walk_result) = walk_result else {
                    break;
                };

                match walk_result {
                    Ok(report) => {
                        events.emit(
                            NetworkEventSource::Walker,
                            EventSeverity::Notice,
                            NetworkEvent::WalkFinished {
                                requested_hops: report.requested_hops,
                                completed_hops: report.completed_hops,
                                new_nodes: report.new_nodes,
                                updated_nodes: report.updated_nodes,
                                reachable: report.reachable,
                                unreachable: report.unreachable,
                                duration_ms: timer.elapsed_ms(),
                            },
                        );

                        let discovery_rate = rate(report.new_nodes, report.completed_hops);
                        if discovery_rate < 0.02 {
                            low_discovery_streak = low_discovery_streak.saturating_add(1);
                        } else {
                            low_discovery_streak = 0;
                        }
                        last_report = Some(report);
                        last_walk_finished = Some(Instant::now());
                    }
                    Err(error) => {
                        events.emit(
                            NetworkEventSource::Walker,
                            EventSeverity::Warning,
                            NetworkEvent::WalkFailed {
                                reason: error.to_string(),
                                duration_ms: timer.elapsed_ms(),
                            },
                        );
                        last_walk_finished = Some(Instant::now());
                    }
                }
            }
            Ok(WalkStartResult::AlreadyRunning(_)) => {
                events.diagnostic(
                    NetworkEventSource::Walker,
                    EventSeverity::Info,
                    "Adaptive walk request skipped because a walk is already active",
                );
            }
            Err(error) => {
                events.emit(
                    NetworkEventSource::Walker,
                    EventSeverity::Warning,
                    NetworkEvent::WalkFailed {
                        reason: error.to_string(),
                        duration_ms: timer.elapsed_ms(),
                    },
                );
                last_walk_finished = Some(Instant::now());
            }
        }

        let settings = (*settings_rx.borrow()).sanitized();
        let mail_boost_active = mail_boost_until.is_some_and(|until| until > Instant::now());
        let next_mode = if settings.mail_mode_enabled || mail_boost_active {
            WalkMode::Mail
        } else {
            WalkMode::Normal
        };
        let next_mode_settings = settings.for_mode(next_mode);
        let interval_secs = adaptive_interval_secs(
            next_mode_settings,
            eligible_nodes,
            last_report.as_ref(),
            low_discovery_streak,
        );
        next_delay = jittered_and_clamped(&policy, interval_secs, next_mode_settings);
    }

    crate::shutdown_debug!("auto-walk scheduler: loop exited");
}

fn adaptive_hop_target(
    mode: WalkMode,
    settings: WalkModeSettings,
    verified_nodes: usize,
    eligible_nodes: usize,
    report: Option<&WalkRunReport>,
    low_discovery_streak: u32,
) -> usize {
    let settings = settings.sanitized();

    // Small networks are cheap enough to cover completely. This also prevents
    // a high minimum from asking for more unique nodes than actually exist.
    if (1..=20).contains(&eligible_nodes) {
        return eligible_nodes.min(settings.maximum_hops).max(1);
    }

    let known = verified_nodes.max(eligible_nodes).max(1) as f64;
    let baseline = (6.0 + 1.5 * known.sqrt()).round();
    let mut target = baseline.max(settings.minimum_hops as f64);

    if let Some(report) = report {
        let discovery_rate = rate(report.new_nodes, report.completed_hops);
        let change_rate = rate(report.updated_nodes, report.completed_hops);
        let coverage = rate(report.completed_hops, eligible_nodes);

        if discovery_rate > 0.25 {
            target *= 1.50;
        } else if discovery_rate >= 0.10 {
            target *= 1.25;
        } else if discovery_rate < 0.02 && low_discovery_streak >= 3 && coverage >= 0.50 {
            target *= 0.80;
        }

        if change_rate > 0.25 {
            target *= 1.20;
        }

        // Low discovery plus poor coverage means the walk probably sampled the
        // wrong region; do not shorten it merely because it found little.
        if discovery_rate < 0.02 && coverage < 0.50 {
            target = target.max(baseline);
        }
    }

    if mode == WalkMode::Mail {
        target *= 1.35;
    }

    (target.round() as usize).clamp(settings.minimum_hops, settings.maximum_hops)
}

fn adaptive_interval_secs(
    settings: WalkModeSettings,
    eligible_nodes: usize,
    report: Option<&WalkRunReport>,
    low_discovery_streak: u32,
) -> u64 {
    let settings = settings.sanitized();
    let mut seconds = settings.target_interval_secs as f64;

    if let Some(report) = report {
        let discovery_rate = rate(report.new_nodes, report.completed_hops);
        let change_rate = rate(report.updated_nodes, report.completed_hops);
        let coverage = rate(report.completed_hops, eligible_nodes);

        if discovery_rate > 0.25 || change_rate > 0.25 {
            seconds *= 0.50;
        } else if discovery_rate >= 0.10 {
            seconds *= 0.80;
        }

        if discovery_rate < 0.02 && low_discovery_streak >= 3 {
            if coverage >= 0.50 {
                seconds *= 1.50;
            } else {
                seconds = seconds.min(settings.target_interval_secs as f64);
            }
        }

        if report.unreachable > report.reachable {
            seconds *= 1.25;
        }
    }

    (seconds.round() as u64).clamp(
        settings.minimum_interval_secs,
        settings.maximum_interval_secs,
    )
}

fn jittered_and_clamped(
    policy: &WalkSchedulePolicy,
    seconds: u64,
    settings: WalkModeSettings,
) -> Duration {
    let settings = settings.sanitized();
    let jittered = policy.jittered(seconds).as_secs();
    Duration::from_secs(jittered.clamp(
        settings.minimum_interval_secs,
        settings.maximum_interval_secs,
    ))
}

fn rate(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn all_startup_stages() -> Vec<StartupStage> {
    vec![
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
    ]
}

// Future branching-walk design (intentionally not implemented yet):
//
// 1. Select one stale/never-visited root from the internal node list.
// 2. Read its selected record-table pages.
// 3. Pick two or three unvisited entries from that table.
// 4. Visit that entire level concurrently.
// 5. Repeat for two or three levels with one walk-wide deduplication set.
// 6. Respect explicit offline status and the normal handshake-verification
//    policy; discovering a node must not automatically force a handshake.
//
// A branch factor of two or three over two/three expansion levels yields a
// quick fan-out of roughly 4-39 descendant visits depending on counting rules.


#[cfg(test)]
mod shutdown_order_tests {
    use super::NetworkSupervisor;
    use crate::lifecycle::{HookSpec, ResourceNeed, StopReason};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn declared_tiers_place_presence_and_snapshot_before_veilid_shutdown() {
        let supervisor = NetworkSupervisor::default();
        supervisor.set_network_attachment(true, "test attached").await;
        let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));

        {
            let order = order.clone();
            supervisor
                .register_shutdown_hook(
                    HookSpec::teardown("Veilid"),
                    move |_| {
                        let order = order.clone();
                        async move {
                            order.lock().await.push("Veilid");
                            Ok(())
                        }
                    },
                )
                .await;
        }
        {
            let order = order.clone();
            supervisor
                .register_shutdown_hook(
                    HookSpec::new("DHT snapshot", ResourceNeed::Storage),
                    move |_| {
                        let order = order.clone();
                        async move {
                            order.lock().await.push("DHT snapshot");
                            Ok(())
                        }
                    },
                )
                .await;
        }
        {
            let order = order.clone();
            supervisor
                .register_shutdown_hook(
                    HookSpec::new("Presence", ResourceNeed::Network),
                    move |_| {
                        let order = order.clone();
                        async move {
                            order.lock().await.push("Presence");
                            Ok(())
                        }
                    },
                )
                .await;
        }

        let results = supervisor.shutdown(StopReason::Shutdown).await;
        assert_eq!(
            results.iter().map(|outcome| outcome.module.as_str()).collect::<Vec<_>>(),
            vec!["Presence", "DHT snapshot", "Veilid"]
        );
        assert_eq!(
            order.lock().await.as_slice(),
            ["Presence", "DHT snapshot", "Veilid"]
        );
    }
}
