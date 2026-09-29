//! The daemon's startup/shutdown traffic controller.
//!
//! Think of this module as the person turning off a building at night. It does not know how
//! to shut down the mailbox, walker, API, or Veilid itself. Each module knows how to clean up
//! its own things. Lifecycle only decides **when** each cleanup is allowed to run and how long
//! it is allowed to take.
//!
//! Shutdown happens in broad groups (called tiers):
//! 1. stop accepting new work,
//! 2. tell peers we are leaving (when the network is reachable),
//! 3. stop work that still needs the Veilid node,
//! 4. save local state,
//! 5. shut Veilid itself down,
//! 6. finish anything that is safe to do afterward.
//!
//! Hooks in the same tier may run at the same time. Every hook has its own timeout, and every
//! tier has a larger timeout. If shutdown becomes badly stuck, a watchdog running on a normal
//! OS thread can still force the process to exit even if Tokio's async workers are jammed.
//!
//! The important rule is: **this module owns the order, not the cleanup code.** That keeps
//! shutdown logic in one place without making Lifecycle reach into every other module's state.

use std::{
    any::Any,
    collections::BTreeMap,
    fmt,
    panic::AssertUnwindSafe,
    sync::Arc,
    time::{Duration, Instant},
};

use futures::FutureExt;
use tokio::{sync::Mutex, task::JoinSet, time::timeout};

mod gate;
mod record;

#[allow(unused_imports)] // Intentional lifecycle API re-export.
pub use gate::{StageGate, StageGates, StageOutcome};
#[allow(unused_imports)] // Intentional lifecycle API re-export.
pub use record::{RawRecord, RecordedHook, ShutdownRecord};

// ---------------------------------------------------------------------------
// Budgets
// ---------------------------------------------------------------------------

/// Default time limits for each shutdown step.
///
/// These are intentionally generous enough for slower hardware. The watchdog is longer than
/// all normal tiers combined so it is a last-resort escape hatch, not the normal timeout.
pub mod budget {
    use std::time::Duration;

    pub const INTAKE: Duration = Duration::from_secs(4);
    pub const ANNOUNCE: Duration = Duration::from_secs(12);
    pub const NODE: Duration = Duration::from_secs(18);
    pub const PERSIST: Duration = Duration::from_secs(6);
    pub const TEARDOWN: Duration = Duration::from_secs(10);
    pub const AFTER: Duration = Duration::from_secs(2);

    /// Hard exit if graceful shutdown overruns this. Comfortably above the sum of the tiers,
    /// which is roughly 52 seconds.
    pub const WATCHDOG: Duration = Duration::from_secs(65);

    /// Default per-hook ceiling when a module does not state one.
    pub const DEFAULT_HOOK: Duration = Duration::from_secs(3);
}

// ---------------------------------------------------------------------------
// Declarations
// ---------------------------------------------------------------------------

/// What must still be alive while a shutdown hook runs.
///
/// Lifecycle uses this to work out the hook's place in the shutdown order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResourceNeed {
    /// Nothing. In-memory teardown only.
    None,
    /// Local persistence that should complete before Veilid teardown. Use an explicit
    /// post-teardown phase for work intentionally placed after Veilid.
    Storage,
    /// The Veilid node object alive, but not necessarily reachable.
    VeilidNode,
    /// Genuine reachability. Skipped as a tier when the node cannot reach anyone.
    Network,
}

/// Manual placement for the two special phases that resource needs alone cannot describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownPhase {
    Automatic,
    Teardown,
    After,
}

/// The actual shutdown groups, in the order they run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Stop accepting new work. Runs first so everything after it faces a quiet system.
    Intake,
    /// Tell the network we are going away. Requires reachability.
    Announce,
    /// Needs the node object but not the network.
    NodeDependent,
    /// Local persistence.
    Persist,
    /// Veilid detach and shutdown.
    Teardown,
    /// Anything that must outlive Veilid. Log flushing today.
    After,
}

impl Tier {
    /// Short human-readable name used in logs and shutdown records.
    pub fn label(self) -> &'static str {
        match self {
            Self::Intake => "intake stop",
            Self::Announce => "announce",
            Self::NodeDependent => "node",
            Self::Persist => "persist",
            Self::Teardown => "teardown",
            Self::After => "after",
        }
    }

    /// Tiers in execution order.
    pub const ORDER: [Tier; 6] = [
        Tier::Intake,
        Tier::Announce,
        Tier::NodeDependent,
        Tier::Persist,
        Tier::Teardown,
        Tier::After,
    ];

    /// A timeout in one of these tiers means we cannot prove it is safe to continue into
    /// Veilid teardown. Dropping an async waiter cancels that waiter, but actor-style shutdown
    /// APIs may already have handed work to another task. Intake is included because a service
    /// that failed to stop accepting work can still create fresh node-dependent work while the
    /// remaining tiers run.
    fn timeout_blocks_later_tiers(self) -> bool {
        matches!(
            self,
            Tier::Intake | Tier::Announce | Tier::NodeDependent | Tier::Teardown
        )
    }
}

/// Why we are stopping. A restart skips work that would only create pointless network churn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    Shutdown,
    /// Coming back in seconds. The announce tier is skipped entirely: a logout immediately
    /// followed by a login is presence churn that tells peers nothing, and the presence
    /// heartbeat interval leaves far more margin than a restart consumes.
    Restart,
}

/// Whether we currently believe the network can be reached.
///
/// `Unknown` means Lifecycle should refresh the answer once before trying network-only hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reachability {
    Reachable,
    Unreachable,
    Unknown,
}

/// A unique number for one registered shutdown hook.
///
/// Names are for humans and may repeat. This ID is what Lifecycle uses internally so two hooks
/// with the same label can never be confused with each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HookId(u64);

impl HookId {
    /// Returns the numeric ID, mainly for logs and shutdown records.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for HookId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

type HookFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>>;
type HookAction = Box<dyn Fn(Progress) -> HookFuture + Send + Sync>;

/// A small status message a hook can update while it shuts down.
///
/// This turns "mailbox timed out" into something useful like "mailbox timed out while writing
/// page 3/7". The text lives outside the hook future so the watchdog can still read the last
/// known step even if that future is cancelled.
#[derive(Clone)]
pub struct Progress {
    step: Arc<std::sync::Mutex<String>>,
    /// Set by a hook that knows being interrupted here leaves state needing a check on the
    /// next start. The coordinator never infers this: only the module knows whether its own
    /// half-finished write is survivable.
    needs_verification: Arc<std::sync::atomic::AtomicBool>,
}

impl Progress {
    /// Creates a progress tracker with the first human-readable step.
    fn new(initial: &str) -> Self {
        Self {
            step: Arc::new(std::sync::Mutex::new(initial.to_string())),
            needs_verification: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Records what the hook is doing now. Call it before each phase, not after.
    /// Replaces the current "what I am doing" text.
    pub fn step(&self, description: impl Into<String>) {
        if let Ok(mut guard) = self.step.lock() {
            *guard = description.into();
        }
    }

    /// Marks the current step as one that leaves state needing verification if interrupted.
    /// Pair with [`Progress::step`] around anything that rewrites a file in place.
    /// Marks the current step as one that may need checking next startup if shutdown is interrupted.
    pub fn fragile(&self, description: impl Into<String>) {
        self.needs_verification
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.step(description);
    }

    /// Clears the fragile flag once the risky part is safely behind us.
    /// Marks the current step as safely finished and clears the verification flag.
    pub fn settled(&self, description: impl Into<String>) {
        self.needs_verification
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.step(description);
    }

    fn read(&self) -> String {
        self.step
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_else(|_| "unknown".to_string())
    }

    fn verification_needed(&self) -> bool {
        self.needs_verification
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

struct Hook {
    id: HookId,
    module: String,
    detail: String,
    need: ResourceNeed,
    phase: ShutdownPhase,
    budget: Duration,
    /// Non-announcement work that is safe and useful to omit during an in-process restart.
    skip_on_restart: bool,
    /// Some hooks can prove that once their stop signal is sent, a timeout only means their
    /// bookkeeping task is slow -- not that they can create new work or keep a required
    /// resource in use. Those hooks may allow Lifecycle to continue to later tiers.
    continue_after_timeout: bool,
    action: HookAction,
}

impl Hook {
    /// Converts this hook's declared need/phase into the tier Lifecycle will actually run.
    fn tier(&self) -> Tier {
        match self.phase {
            ShutdownPhase::Teardown => Tier::Teardown,
            ShutdownPhase::After => Tier::After,
            ShutdownPhase::Automatic => match self.need {
                ResourceNeed::Network => Tier::Announce,
                ResourceNeed::VeilidNode => Tier::NodeDependent,
                ResourceNeed::Storage => Tier::Persist,
                ResourceNeed::None => Tier::Intake,
            },
        }
    }
}

/// How a hook finished. Recorded for every hook, whether or not timings are being collected.
#[derive(Debug, Clone)]
pub struct HookOutcome {
    pub id: HookId,
    pub module: String,
    /// What the hook was doing when it finished or was abandoned.
    pub detail: String,
    pub tier: Tier,
    pub elapsed: Duration,
    pub budget: Duration,
    pub result: HookResult,
    /// The hook was interrupted somewhere it considers unsafe, and said so itself.
    pub needs_verification: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookResult {
    Ok,
    Failed(String),
    /// Exceeded its budget and was dropped mid-flight.
    Overran,
    /// Not attempted. Carries the reason so the log explains itself.
    Skipped(&'static str),
}

#[derive(Clone)]
struct RunningHook {
    id: HookId,
    module: String,
    tier: Tier,
    started: Instant,
    budget: Duration,
    progress: Progress,
}

impl fmt::Display for HookOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = match &self.result {
            HookResult::Ok => "ok".to_string(),
            HookResult::Failed(error) => format!("failed: {error}"),
            HookResult::Overran => "OVERRAN".to_string(),
            HookResult::Skipped(reason) => format!("skipped ({reason})"),
        };
        let detail = if self.detail.is_empty() {
            String::new()
        } else {
            format!("  [{}]", self.detail)
        };
        let flag = if self.needs_verification {
            "  NEEDS VERIFICATION"
        } else {
            ""
        };
        write!(
            f,
            "{:<10} {:<26} {:>6}ms / {:>5}ms  {}{}{}",
            self.tier.label(),
            self.module,
            self.elapsed.as_millis(),
            self.budget.as_millis(),
            status,
            detail,
            flag
        )
    }
}

// ---------------------------------------------------------------------------
// Coordinator
// ---------------------------------------------------------------------------

/// Shared coordinator used by the whole daemon.
///
/// Cloning `Lifecycle` does not make a second shutdown system; every clone points at the same
/// hook list, startup gates, progress state, and watchdog state.
#[derive(Clone)]
pub struct Lifecycle {
    hooks: Arc<Mutex<Vec<Hook>>>,
    next_hook_id: Arc<std::sync::atomic::AtomicU64>,
    gates: StageGates,
    stopping: Arc<std::sync::atomic::AtomicBool>,
    collect_timings: Arc<std::sync::atomic::AtomicBool>,
    budgets: Budgets,
    watchdog_action: WatchdogAction,
    watchdog_fired: Arc<std::sync::atomic::AtomicBool>,
    /// Set when stop() intentionally returns without disarming the independent watchdog.
    /// This is distinct from `watchdog_fired`: normally the process should exit before it fires.
    watchdog_left_armed: Arc<std::sync::atomic::AtomicBool>,
    /// Where the shutdown record is written. None disables it, which is what the bench wants.
    data_dir: Arc<std::sync::Mutex<Option<std::path::PathBuf>>>,
    /// Completed hook outcomes are written immediately, rather than only after a whole tier,
    /// so the watchdog always has the newest trustworthy information.
    completed: Arc<std::sync::Mutex<Vec<HookOutcome>>>,
    /// Hooks currently in flight, including their externally-owned progress handles.
    running: Arc<std::sync::Mutex<BTreeMap<HookId, RunningHook>>>,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl Lifecycle {
    /// Creates the production lifecycle coordinator with normal time limits and a hard-exit watchdog.
    pub fn new() -> Self {
        Self::with(Budgets::default(), WatchdogAction::Exit)
    }

    /// Creates a coordinator with custom limits/action. Mostly useful for the shutdown test bench.
    pub fn with(budgets: Budgets, watchdog_action: WatchdogAction) -> Self {
        Self {
            hooks: Arc::new(Mutex::new(Vec::new())),
            next_hook_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            gates: StageGates::new(),
            stopping: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            collect_timings: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            budgets,
            watchdog_action,
            watchdog_fired: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            watchdog_left_armed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            data_dir: Arc::new(std::sync::Mutex::new(None)),
            completed: Arc::new(std::sync::Mutex::new(Vec::new())),
            running: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        }
    }

    /// Enables the shutdown record and says where to keep it.
    pub fn set_data_dir(&self, path: impl Into<std::path::PathBuf>) {
        if let Ok(mut guard) = self.data_dir.lock() {
            *guard = Some(path.into());
        }
    }

    /// Reads and clears any record the previous run left behind.
    ///
    /// Call once at startup, before anything else. A record still present means the last
    /// shutdown did not end the way it intended.
    pub fn take_previous_record(&self) -> Option<RawRecord> {
        let guard = self.data_dir.lock().ok()?;
        let dir = guard.as_ref()?;
        ShutdownRecord::take(dir)
    }

    /// Returns the time limits this coordinator is using.
    pub fn budgets(&self) -> Budgets {
        self.budgets
    }

    /// True when the watchdog tripped. Only meaningful under [`WatchdogAction::Report`].
    pub fn watchdog_fired(&self) -> bool {
        self.watchdog_fired
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// True when shutdown returned while deliberately leaving the independent watchdog armed.
    /// This protects the process when cancellation could not prove that all resource-sensitive
    /// work actually stopped.
    pub fn watchdog_left_armed(&self) -> bool {
        self.watchdog_left_armed
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Startup readiness. Modules await the stages they declared rather than relying on the
    /// order of statements in `lib.rs`.
    pub fn gates(&self) -> &StageGates {
        &self.gates
    }

    /// Enables the opt-in timing report. Off by default; driven by a setting in the GUI.
    pub fn set_collect_timings(&self, enabled: bool) {
        self.collect_timings
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    /// True once a stop has begun. Long-running loops should check this and bail rather than
    /// starting new work the coordinator will have to wait for.
    pub fn is_stopping(&self) -> bool {
        self.stopping.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// True when shutdown returned while at least one hook may still be executing. This is
    /// the uncooperative fallback path; production leaves the watchdog armed in this state.
    pub fn has_running_hooks(&self) -> bool {
        self.running
            .lock()
            .map(|guard| !guard.is_empty())
            .unwrap_or(true)
    }

    /// Registers a hook.
    ///
    /// The closure receives a [`Progress`] handle. Using it is optional but strongly
    /// encouraged for anything with more than one phase: it is the difference between a log
    /// that names a module and one that names a step.
    pub async fn register<F, Fut>(&self, spec: HookSpec, action: F) -> HookId
    where
        F: Fn(Progress) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        let id = HookId(
            self.next_hook_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        );
        self.hooks.lock().await.push(Hook {
            id,
            module: spec.module,
            detail: spec.detail,
            need: spec.need,
            phase: spec.phase,
            budget: spec.budget,
            skip_on_restart: spec.skip_on_restart,
            continue_after_timeout: spec.continue_after_timeout,
            action: Box::new(move |progress| Box::pin(action(progress))),
        });
        id
    }

    /// Runs the tiers in order and returns every outcome.
    ///
    /// Idempotent: a second call while a stop is already running returns immediately rather
    /// than executing hooks twice. Pressing shutdown twice is normal user behaviour.
    pub async fn stop(
        &self,
        reason: StopReason,
        reachability: Reachability,
        refresh_reachability: impl std::future::Future<Output = Reachability> + Send,
    ) -> Vec<HookOutcome> {
        if self
            .stopping
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            crate::tprintln!("[lifecycle] stop already in progress; ignoring duplicate request");
            return Vec::new();
        }

        if let Ok(mut guard) = self.completed.lock() {
            guard.clear();
        }
        if let Ok(mut guard) = self.running.lock() {
            guard.clear();
        }
        self.watchdog_left_armed
            .store(false, std::sync::atomic::Ordering::Relaxed);

        crate::shutdown_debug!(
            "lifecycle.stop entered: reason={reason:?}, initial_reachability={reachability:?}, watchdog={}ms",
            self.budgets.watchdog.as_millis()
        );
        let watchdog = Watchdog::arm(
            self.budgets.watchdog,
            self.watchdog_action,
            self.watchdog_fired.clone(),
            self.data_dir.lock().ok().and_then(|guard| guard.clone()),
            self.completed.clone(),
            self.running.clone(),
            reason,
        );
        let started = Instant::now();
        crate::shutdown_debug!("watchdog armed; beginning graceful shutdown");
        crate::tprintln!("[lifecycle] stopping ({reason:?})");

        // Resolve Unknown once, before the announce tier, with a cheap read rather than by
        // attempting the tier and discovering it the expensive way. The watchdog is already
        // armed, so even a broken reachability refresh cannot escape shutdown supervision.
        let reachable = match reachability {
            Reachability::Reachable => true,
            Reachability::Unreachable => false,
            Reachability::Unknown => {
                matches!(refresh_reachability.await, Reachability::Reachable)
            }
        };
        crate::shutdown_debug!("reachability resolved: reachable={reachable}");

        let mut hooks = std::mem::take(&mut *self.hooks.lock().await);
        let mut by_tier: BTreeMap<Tier, Vec<Hook>> = BTreeMap::new();
        for hook in hooks.drain(..) {
            by_tier.entry(hook.tier()).or_default().push(hook);
        }
        crate::shutdown_debug!("registered shutdown plan:");
        for tier in Tier::ORDER {
            if let Some(planned) = by_tier.get(&tier) {
                for hook in planned {
                    crate::shutdown_debug!(
                        "  PLAN tier={} id={} module={} hook_budget={}ms",
                        tier.label(), hook.id, hook.module, hook.budget.as_millis()
                    );
                }
            }
        }

        let mut outcomes = Vec::new();
        let mut leave_watchdog_armed = false;
        let mut timing_emitted = false;

        for tier in Tier::ORDER {
            if tier == Tier::After
                && self.collect_timings.load(std::sync::atomic::Ordering::Relaxed)
            {
                emit_timing_report(&outcomes, started.elapsed());
                timing_emitted = true;
            }
            let Some(mut tier_hooks) = by_tier.remove(&tier) else {
                continue;
            };
            if tier_hooks.is_empty() {
                continue;
            }

            crate::shutdown_debug!(
                "TIER START tier={} hooks={} ceiling={}ms",
                tier.label(), tier_hooks.len(), self.budgets.for_tier(tier).as_millis()
            );

            let whole_tier_skip = match tier {
                Tier::Announce if reason == StopReason::Restart => Some("restart"),
                Tier::Announce if !reachable => Some("network unreachable"),
                _ => None,
            };
            if let Some(skip_reason) = whole_tier_skip {
                for hook in tier_hooks {
                    let outcome = HookOutcome {
                        id: hook.id,
                        module: hook.module,
                        detail: hook.detail,
                        tier,
                        elapsed: Duration::ZERO,
                        budget: hook.budget,
                        result: HookResult::Skipped(skip_reason),
                        needs_verification: false,
                    };
                    remember_completed(&self.completed, &outcome);
                    outcomes.push(outcome);
                }
                crate::shutdown_debug!(
                    "TIER SKIP tier={} reason={skip_reason}",
                    tier.label()
                );
                crate::tprintln!("[lifecycle] {} tier skipped ({skip_reason})", tier.label());
                continue;
            }

            if reason == StopReason::Restart {
                let mut runnable = Vec::with_capacity(tier_hooks.len());
                for hook in tier_hooks.drain(..) {
                    if hook.skip_on_restart {
                        let outcome = HookOutcome {
                            id: hook.id,
                            module: hook.module,
                            detail: hook.detail,
                            tier,
                            elapsed: Duration::ZERO,
                            budget: hook.budget,
                            result: HookResult::Skipped("restart"),
                            needs_verification: false,
                        };
                        remember_completed(&self.completed, &outcome);
                        outcomes.push(outcome);
                    } else {
                        runnable.push(hook);
                    }
                }
                tier_hooks = runnable;
            }

            if tier_hooks.is_empty() {
                continue;
            }

            crate::shutdown_debug!("TIER EXECUTE tier={}", tier.label());
            let tier_run = run_tier(
                tier,
                tier_hooks,
                self.budgets,
                self.completed.clone(),
                self.running.clone(),
            )
            .await;
            let hook_timed_out = tier_run
                .outcomes
                .iter()
                .any(|outcome| matches!(&outcome.result, HookResult::Overran));
            let blocking_timeout = tier_run.blocking_timeout;
            for outcome in &tier_run.outcomes {
                crate::shutdown_debug!(
                    "HOOK RESULT tier={} id={} module={} elapsed={}ms result={:?} detail={}",
                    tier.label(), outcome.id, outcome.module, outcome.elapsed.as_millis(), outcome.result, outcome.detail
                );
            }
            crate::shutdown_debug!(
                "TIER END tier={} uncooperative={} hook_timed_out={} blocking_timeout={}",
                tier.label(), tier_run.uncooperative, hook_timed_out, blocking_timeout
            );
            outcomes.extend(tier_run.outcomes);

            // A tier-level timeout is qualitatively different from a hook's own async timeout.
            // It means at least one task did not yield enough for cancellation to complete. Do
            // not tear resources down underneath it; leave the OS watchdog armed and stop here.
            if tier_run.uncooperative {
                crate::teprintln!(
                    "[lifecycle] {} tier contains an uncooperative hook; later tiers will not run",
                    tier.label()
                );
                crate::shutdown_debug!(
                    "ABORTING LATER TIERS: tier={} was uncooperative; watchdog remains armed",
                    tier.label()
                );
                leave_watchdog_armed = true;
                break;
            }

            // An ordinary async timeout does cancel the hook future, but that is not enough to
            // prove every module is quiescent: actor-style APIs can enqueue shutdown work and
            // then merely await its reply. If a timeout occurs before/during Veilid-sensitive
            // phases, never tear the node down underneath possibly surviving work. The
            // independent watchdog remains the final exit guard.
            if blocking_timeout {
                crate::teprintln!(
                    "[lifecycle] {} tier timed out before safe quiescence was proven; later tiers will not run",
                    tier.label()
                );
                crate::shutdown_debug!(
                    "ABORTING LATER TIERS: tier={} had a resource-sensitive timeout; watchdog remains armed",
                    tier.label()
                );
                leave_watchdog_armed = true;
                break;
            }

            // Production hard-exits when the watchdog fires. Report mode has to model that or
            // the bench sits through work the real daemon would never have reached.
            if self.watchdog_action == WatchdogAction::Report && self.watchdog_fired() {
                crate::teprintln!(
                    "[lifecycle] watchdog fired; abandoning the remaining tiers as a hard exit would"
                );
                leave_watchdog_armed = true;
                break;
            }
        }

        let elapsed = started.elapsed();
        crate::shutdown_debug!(
            "tier loop finished after {}ms; leave_watchdog_armed={}",
            elapsed.as_millis(), leave_watchdog_armed
        );
        if !leave_watchdog_armed {
            crate::shutdown_debug!("disarming watchdog");
            watchdog.disarm();
            crate::shutdown_debug!("watchdog disarm requested");
        } else {
            crate::shutdown_debug!("watchdog intentionally LEFT ARMED");
        }
        self.watchdog_left_armed
            .store(leave_watchdog_armed, std::sync::atomic::Ordering::Relaxed);

        crate::shutdown_debug!("about to emit lifecycle summary");
        report(&outcomes, elapsed);
        crate::shutdown_debug!("lifecycle summary emitted");

        // Written whether or not anything went wrong: a clean record is deleted immediately
        // below, and its absence is itself the signal that the last shutdown was fine.
        if let Ok(guard) = self.data_dir.lock() {
            if let Some(dir) = guard.as_ref() {
                let record = ShutdownRecord::build(reason, false, elapsed, &outcomes);
                if record.is_clean() {
                    let _ = std::fs::remove_file(dir.join("last-shutdown.json"));
                } else {
                    record.write(dir);
                }
            }
        }
        if self.collect_timings.load(std::sync::atomic::Ordering::Relaxed) && !timing_emitted {
            emit_timing_report(&outcomes, elapsed);
        }
        crate::shutdown_debug!("lifecycle.stop returning {} outcomes", outcomes.len());
        outcomes
    }

}

/// Time limits used by Lifecycle. Tests can replace these with tiny values so timeout cases run fast.
#[derive(Debug, Clone, Copy)]
pub struct Budgets {
    pub intake: Duration,
    pub announce: Duration,
    pub node: Duration,
    pub persist: Duration,
    pub teardown: Duration,
    pub after: Duration,
    pub watchdog: Duration,
    pub default_hook: Duration,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            intake: budget::INTAKE,
            announce: budget::ANNOUNCE,
            node: budget::NODE,
            persist: budget::PERSIST,
            teardown: budget::TEARDOWN,
            after: budget::AFTER,
            watchdog: budget::WATCHDOG,
            default_hook: budget::DEFAULT_HOOK,
        }
    }
}

impl Budgets {
    /// Returns the maximum wall-clock time allowed for one whole tier.
    pub fn for_tier(&self, tier: Tier) -> Duration {
        match tier {
            Tier::Intake => self.intake,
            Tier::Announce => self.announce,
            Tier::NodeDependent => self.node,
            Tier::Persist => self.persist,
            Tier::Teardown => self.teardown,
            Tier::After => self.after,
        }
    }

    /// Scales every ceiling. Used by the bench so a watchdog scenario finishes in under a
    /// second rather than forty.
    /// Multiplies every limit by `factor`; used by tests to make slow paths finish quickly.
    pub fn scaled(mut self, factor: f64) -> Self {
        let scale = |d: Duration| Duration::from_secs_f64((d.as_secs_f64() * factor).max(0.001));
        self.intake = scale(self.intake);
        self.announce = scale(self.announce);
        self.node = scale(self.node);
        self.persist = scale(self.persist);
        self.teardown = scale(self.teardown);
        self.after = scale(self.after);
        self.watchdog = scale(self.watchdog);
        self.default_hook = scale(self.default_hook);
        self
    }
}

/// What the watchdog does when graceful shutdown overruns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogAction {
    /// Production: hard-exit. Nothing downstream depends on a clean exit.
    Exit,
    /// Bench: record that it fired so the scenario can assert on it. A process that exits
    /// cannot report what it observed, which makes the production behaviour untestable.
    Report,
}

/// Conventional display name for the Veilid teardown hook. Placement is explicit; this string
/// has no special behaviour inside the coordinator.
pub const TEARDOWN_MODULE: &str = "node/veilid";

/// The simple description a module gives Lifecycle when registering a shutdown hook.
pub struct HookSpec {
    pub module: String,
    pub detail: String,
    pub need: ResourceNeed,
    pub phase: ShutdownPhase,
    pub budget: Duration,
    pub skip_on_restart: bool,
    pub continue_after_timeout: bool,
}

impl HookSpec {
    /// Starts a hook description with automatic tier placement and the default hook timeout.
    pub fn new(module: impl Into<String>, need: ResourceNeed) -> Self {
        Self {
            module: module.into(),
            detail: String::new(),
            need,
            phase: ShutdownPhase::Automatic,
            budget: budget::DEFAULT_HOOK,
            skip_on_restart: false,
            continue_after_timeout: false,
        }
    }

    /// Convenience constructor for the one hook that actually tears Veilid down.
    pub fn teardown(module: impl Into<String>) -> Self {
        Self::new(module, ResourceNeed::VeilidNode)
            .phase(ShutdownPhase::Teardown)
            .budget(budget::TEARDOWN)
    }

    /// Convenience constructor for work that is safe only after Veilid has stopped.
    pub fn after_teardown(module: impl Into<String>) -> Self {
        Self::new(module, ResourceNeed::None)
            .phase(ShutdownPhase::After)
            .budget(budget::AFTER)
    }

    /// Overrides automatic placement for teardown/post-teardown work.
    pub fn phase(mut self, phase: ShutdownPhase) -> Self {
        self.phase = phase;
        self
    }

    /// Adds an initial progress description shown before the hook reports its own steps.
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    /// Gives this individual hook a custom time limit.
    pub fn budget(mut self, budget: Duration) -> Self {
        self.budget = budget;
        self
    }

    /// Marks non-announcement work that may be omitted during an in-process restart.
    pub fn skip_on_restart(mut self) -> Self {
        self.skip_on_restart = true;
        self
    }

    /// Allows later tiers to continue if this hook alone exceeds its personal timeout.
    ///
    /// Use this sparingly. It is intended for hooks such as the automatic walk scheduler:
    /// shutdown first sends a durable stop signal, so timing out while joining the scheduler
    /// task cannot cause it to schedule another walk. The active walker itself still has its
    /// own later shutdown hook.
    pub fn continue_after_timeout(mut self) -> Self {
        self.continue_after_timeout = true;
        self
    }

    /// Compatibility spelling for early lifecycle experiments.
    #[deprecated(note = "use skip_on_restart()")]
    pub fn optional(self) -> Self {
        self.skip_on_restart()
    }
}

// ---------------------------------------------------------------------------
// Tier execution
// ---------------------------------------------------------------------------

struct TierRun {
    outcomes: Vec<HookOutcome>,
    /// True only when the *outer tier* timed out, meaning cancellation itself could not be
    /// observed on schedule. Ordinary per-hook async timeouts do not set this.
    uncooperative: bool,
    /// At least one timed-out hook in this tier did not explicitly prove that it is safe for
    /// Lifecycle to continue. This preserves the conservative default while allowing a small
    /// number of well-understood stop-signal hooks to opt out.
    blocking_timeout: bool,
}

/// Copies a finished result into the watchdog-visible list immediately.
/// This way a crash in the next hook does not erase information about hooks that already finished.
fn remember_completed(
    completed: &Arc<std::sync::Mutex<Vec<HookOutcome>>>,
    outcome: &HookOutcome,
) {
    if let Ok(mut guard) = completed.lock() {
        guard.push(outcome.clone());
    }
}

/// Turns Rust's loosely-typed panic payload into readable text for the shutdown report.
fn panic_payload(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// Runs every hook in one tier concurrently and gathers their results.
///
/// This is where per-hook timeouts, panic catching, progress tracking, and the larger tier
/// timeout are enforced.
async fn run_tier(
    tier: Tier,
    hooks: Vec<Hook>,
    budgets: Budgets,
    completed: Arc<std::sync::Mutex<Vec<HookOutcome>>>,
    running: Arc<std::sync::Mutex<BTreeMap<HookId, RunningHook>>>,
) -> TierRun {
    let tier_budget = budgets.for_tier(tier);
    let mut set = JoinSet::new();
    let mut expected: BTreeMap<HookId, (String, Progress, Duration)> = BTreeMap::new();
    let mut continue_after_timeout: BTreeMap<HookId, bool> = BTreeMap::new();

    for hook in hooks {
        // Never let a hook's own budget exceed its tier's, or a single module could consume
        // the whole tier and starve its neighbours out of their share.
        let hook_budget = hook.budget.min(tier_budget);
        let progress = Progress::new(if hook.detail.is_empty() {
            "starting"
        } else {
            &hook.detail
        });
        expected.insert(
            hook.id,
            (hook.module.clone(), progress.clone(), hook_budget),
        );
        continue_after_timeout.insert(hook.id, hook.continue_after_timeout);

        let running_hook = RunningHook {
            id: hook.id,
            module: hook.module.clone(),
            tier,
            started: Instant::now(),
            budget: hook_budget,
            progress: progress.clone(),
        };
        if let Ok(mut guard) = running.lock() {
            guard.insert(hook.id, running_hook);
        }

        let id = hook.id;
        let module = hook.module;
        let action = hook.action;
        let reporter = progress.clone();
        let handle = progress;

        // Hooks are ordinary async tasks. Lifecycle deliberately does not move them onto
        // spawn_blocking: a started blocking-pool task is not cancellable, which can let it
        // outlive its tier and later stall Tokio runtime destruction.
        set.spawn(async move {
            let started = Instant::now();
            crate::shutdown_debug!(
                "HOOK START tier={} id={} module={} budget={}ms",
                tier.label(), id, module, hook_budget.as_millis()
            );
            let guarded = AssertUnwindSafe(async move { action(reporter).await }).catch_unwind();
            let result = match timeout(hook_budget, guarded).await {
                Ok(Ok(Ok(()))) => HookResult::Ok,
                Ok(Ok(Err(error))) => HookResult::Failed(error),
                Ok(Err(payload)) => HookResult::Failed(format!(
                    "shutdown hook panicked: {}",
                    panic_payload(payload.as_ref())
                )),
                Err(_) => HookResult::Overran,
            };
            let elapsed = started.elapsed();

            // A synchronously-blocking hook can prevent Tokio's timer from being polled until
            // after the blocking call returns. `timeout()` polls its inner future as well, so
            // such a hook can otherwise appear to have completed successfully even though it
            // exceeded its budget by seconds. Measured wall time is the independent backstop.
            let result = if matches!(&result, HookResult::Ok) && elapsed > hook_budget {
                HookResult::Overran
            } else {
                result
            };

            let final_detail = handle.read();
            crate::shutdown_debug!(
                "HOOK FINISH tier={} id={} module={} elapsed={}ms result={:?} detail={}",
                tier.label(), id, module, elapsed.as_millis(), result, final_detail
            );
            HookOutcome {
                id,
                module,
                detail: final_detail,
                tier,
                elapsed,
                budget: hook_budget,
                result,
                needs_verification: handle.verification_needed(),
            }
        });
    }

    let mut outcomes = Vec::new();
    // Hooks whose own budget equals the tier ceiling need a tiny collection grace so their
    // ordinary timeout can be observed before we classify the tier itself as uncooperative.
    // This does not grant the hook more work time; it only gives JoinSet time to return the
    // already-timed-out outcome.
    let tier_join_budget = tier_budget.saturating_add(Duration::from_millis(50));
    crate::shutdown_debug!(
        "waiting for tier={} JoinSet; join ceiling={}ms",
        tier.label(), tier_join_budget.as_millis()
    );
    let joined_all = timeout(tier_join_budget, async {
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(outcome) => {
                    crate::shutdown_debug!(
                        "JOINED tier={} id={} module={} result={:?}",
                        tier.label(), outcome.id, outcome.module, outcome.result
                    );
                    if let Ok(mut guard) = running.lock() {
                        guard.remove(&outcome.id);
                    }
                    expected.remove(&outcome.id);
                    remember_completed(&completed, &outcome);
                    outcomes.push(outcome);
                }
                Err(error) => {
                    // Hook panics are caught inside each task and attributed to the hook. A
                    // JoinError here therefore means the task itself was externally cancelled
                    // or the runtime failed it outside the hook future.
                    crate::teprintln!("[lifecycle] hook task failed to join: {error}");
                }
            }
        }
    })
    .await
    .is_ok();

    if joined_all {
        crate::shutdown_debug!("all hooks joined for tier={}", tier.label());
        let blocking_timeout = tier.timeout_blocks_later_tiers()
            && outcomes.iter().any(|outcome| {
                matches!(&outcome.result, HookResult::Overran)
                    && !continue_after_timeout
                        .get(&outcome.id)
                        .copied()
                        .unwrap_or(false)
            });
        return TierRun {
            outcomes,
            uncooperative: false,
            blocking_timeout,
        };
    }

    crate::teprintln!(
        "[lifecycle] {} tier exceeded its {}ms ceiling; cancelling outstanding hooks",
        tier.label(),
        tier_budget.as_millis()
    );
    set.abort_all();

    // Anything still absent from `outcomes` exceeded the tier as a whole. Keep its RunningHook
    // entry intact: an ordinary async task should disappear as soon as aborted, but a task that
    // blocked a Tokio worker may genuinely still be executing. The watchdog needs to continue
    // seeing its live progress until it forces the process out.
    for (id, (module, handle, hook_budget)) in expected {
        let elapsed = running
            .lock()
            .ok()
            .and_then(|guard| guard.get(&id).map(|hook| hook.started.elapsed()))
            .unwrap_or(tier_budget);
        outcomes.push(HookOutcome {
            id,
            module,
            detail: handle.read(),
            tier,
            elapsed,
            budget: hook_budget,
            result: HookResult::Overran,
            needs_verification: handle.verification_needed(),
        });
    }

    TierRun {
        outcomes,
        uncooperative: true,
        blocking_timeout: true,
    }
}

/// Prints the compact human-readable shutdown summary.
fn report(outcomes: &[HookOutcome], elapsed: Duration) {
    let overran: Vec<&HookOutcome> = outcomes
        .iter()
        .filter(|outcome| matches!(&outcome.result, HookResult::Overran))
        .collect();
    let failed: Vec<&HookOutcome> = outcomes
        .iter()
        .filter(|outcome| matches!(&outcome.result, HookResult::Failed(_)))
        .collect();

    // The point of the whole exercise: the next hang names its own cause.
    for outcome in &overran {
        crate::teprintln!(
            "[lifecycle] {} exceeded its {}ms budget and was abandoned while {}",
            outcome.module,
            outcome.budget.as_millis(),
            outcome.detail
        );
    }
    for outcome in outcomes.iter().filter(|o| o.needs_verification) {
        crate::teprintln!(
            "[lifecycle] {} was interrupted somewhere it considers unsafe ({}); it should verify its own state on the next start",
            outcome.module,
            outcome.detail
        );
    }
    for outcome in &failed {
        if let HookResult::Failed(error) = &outcome.result {
            crate::teprintln!("[lifecycle] {} reported an error: {error}", outcome.module);
        }
    }

    crate::tprintln!(
        "[lifecycle] stopped in {}ms: {} ok, {} failed, {} overran, {} skipped",
        elapsed.as_millis(),
        outcomes
            .iter()
            .filter(|o| matches!(o.result, HookResult::Ok))
            .count(),
        failed.len(),
        overran.len(),
        outcomes
            .iter()
            .filter(|o| matches!(o.result, HookResult::Skipped(_)))
            .count(),
    );
}

/// Emits the opt-in timing report as a GUI marker.
///
/// The daemon emits, the Kotlin layer copies. Clipboard access is an Android API and reaching
/// for it from here would widen the JNI surface for no benefit; the log poller already handles
/// `GUI_` markers.
///
/// Emitted before the `After` tier tears the bridge down, so the slowest shutdowns - the ones
/// actually worth reading - are not the ones whose report gets lost.
/// Prints the optional timing-oriented report used while tuning shutdown performance.
fn emit_timing_report(outcomes: &[HookOutcome], elapsed: Duration) {
    let mut body = format!("total={}ms\n", elapsed.as_millis());
    for outcome in outcomes {
        body.push_str(&format!("{outcome}\n"));
    }
    crate::tprintln!("[gui] GUI_SHUTDOWN_TIMINGS={}", hex::encode(body.as_bytes()));
}

// ---------------------------------------------------------------------------
// Watchdog
// ---------------------------------------------------------------------------

/// Hard-exit backstop on its own OS thread.
///
/// Deliberately not a runtime task: a hook doing blocking work occupies a worker, and enough
/// of them means a timer task never gets polled. A thread cannot be starved that way.
struct Watchdog {
    disarmed: Arc<std::sync::atomic::AtomicBool>,
}

impl Watchdog {
    /// Starts the independent OS-thread watchdog before graceful shutdown work begins.
    fn arm(
        limit: Duration,
        action: WatchdogAction,
        fired: Arc<std::sync::atomic::AtomicBool>,
        data_dir: Option<std::path::PathBuf>,
        completed: Arc<std::sync::Mutex<Vec<HookOutcome>>>,
        running: Arc<std::sync::Mutex<BTreeMap<HookId, RunningHook>>>,
        reason: StopReason,
    ) -> Self {
        let disarmed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = disarmed.clone();
        std::thread::Builder::new()
            .name("veilknit-shutdown-watchdog".into())
            .spawn(move || {
                crate::shutdown_debug!(
                    "WATCHDOG THREAD STARTED: limit={}ms action={:?}",
                    limit.as_millis(), action
                );
                let deadline = Instant::now() + limit;
                while Instant::now() < deadline {
                    if flag.load(std::sync::atomic::Ordering::Relaxed) {
                        crate::shutdown_debug!("WATCHDOG THREAD observed disarm; exiting");
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(10).min(limit / 4));
                }
                if flag.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                fired.store(true, std::sync::atomic::Ordering::Relaxed);
                crate::shutdown_debug!("WATCHDOG FIRED after {}ms", limit.as_millis());
                if let Ok(guard) = running.lock() {
                    if guard.is_empty() {
                        crate::shutdown_debug!("WATCHDOG: no hooks listed as running");
                    } else {
                        for hook in guard.values() {
                            crate::shutdown_debug!(
                                "WATCHDOG RUNNING tier={} id={} module={} elapsed={}ms budget={}ms detail={}",
                                hook.tier.label(), hook.id, hook.module, hook.started.elapsed().as_millis(),
                                hook.budget.as_millis(), hook.progress.read()
                            );
                        }
                    }
                } else {
                    crate::shutdown_debug!("WATCHDOG: could not lock running-hook table");
                }

                // The important copy. A shutdown that completed cleanly is the one nobody
                // needs to investigate; this is the one that vanishes without a trace unless
                // it is written here, before the exit.
                if let Some(dir) = &data_dir {
                    let collected = snapshot_for_watchdog(&completed, &running);
                    ShutdownRecord::build(reason, true, limit, &collected).write(dir);
                }

                match action {
                    WatchdogAction::Exit => {
                        eprintln!(
                            "[lifecycle] graceful shutdown exceeded {}s; forcing exit",
                            limit.as_secs()
                        );
                        std::process::exit(0);
                    }
                    WatchdogAction::Report => {
                        eprintln!(
                            "[lifecycle] watchdog would have forced exit after {}ms",
                            limit.as_millis()
                        );
                    }
                }
            })
            .ok();
        Self { disarmed }
    }

    /// Tells the watchdog that graceful shutdown reached a safe stopping point.
    fn disarm(&self) {
        crate::shutdown_debug!("Watchdog::disarm called");
        self.disarmed
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Builds the best shutdown picture available right now, including hooks still in flight.
fn snapshot_for_watchdog(
    completed: &Arc<std::sync::Mutex<Vec<HookOutcome>>>,
    running: &Arc<std::sync::Mutex<BTreeMap<HookId, RunningHook>>>,
) -> Vec<HookOutcome> {
    let mut out = completed
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_default();

    if let Ok(guard) = running.lock() {
        out.extend(guard.values().map(|hook| HookOutcome {
            id: hook.id,
            module: hook.module.clone(),
            detail: hook.progress.read(),
            tier: hook.tier,
            elapsed: hook.started.elapsed(),
            budget: hook.budget,
            result: HookResult::Overran,
            needs_verification: hook.progress.verification_needed(),
        }));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_map_to_tiers() {
        let hook = |need| Hook {
            id: HookId(1),
            module: "test".into(),
            detail: String::new(),
            need,
            phase: ShutdownPhase::Automatic,
            budget: budget::DEFAULT_HOOK,
            skip_on_restart: false,
            continue_after_timeout: false,
            action: Box::new(|_| Box::pin(async { Ok(()) })),
        };
        assert_eq!(hook(ResourceNeed::None).tier(), Tier::Intake);
        assert_eq!(hook(ResourceNeed::Network).tier(), Tier::Announce);
        assert_eq!(hook(ResourceNeed::VeilidNode).tier(), Tier::NodeDependent);
        assert_eq!(hook(ResourceNeed::Storage).tier(), Tier::Persist);

        let mut teardown = hook(ResourceNeed::VeilidNode);
        teardown.phase = ShutdownPhase::Teardown;
        assert_eq!(teardown.tier(), Tier::Teardown);

        let mut after = hook(ResourceNeed::None);
        after.phase = ShutdownPhase::After;
        assert_eq!(after.tier(), Tier::After);
    }

    #[test]
    fn tiers_are_ordered() {
        assert!(Tier::Intake < Tier::Announce);
        assert!(Tier::Announce < Tier::NodeDependent);
        assert!(Tier::Persist < Tier::Teardown);
        assert!(Tier::Teardown < Tier::After);
    }

    #[tokio::test]
    async fn overrunning_hook_is_recorded_not_awaited() {
        let lifecycle = Lifecycle::with(Budgets::default().scaled(0.02), WatchdogAction::Report);
        lifecycle
            .register(
                HookSpec::new("slow", ResourceNeed::Storage).budget(Duration::from_millis(50)),
                |_| async {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Ok(())
                },
            )
            .await;

        let started = Instant::now();
        let outcomes = lifecycle
            .stop(StopReason::Shutdown, Reachability::Unreachable, async {
                Reachability::Unreachable
            })
            .await;

        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].result, HookResult::Overran);
    }

    #[tokio::test]
    async fn node_timeout_blocks_veilid_teardown_and_leaves_watchdog_armed() {
        let mut budgets = Budgets::default().scaled(0.02);
        budgets.watchdog = Duration::from_millis(200);
        let lifecycle = Lifecycle::with(budgets, WatchdogAction::Report);
        let teardown_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));

        lifecycle
            .register(
                HookSpec::new("slow-node-cleanup", ResourceNeed::VeilidNode)
                    .budget(Duration::from_millis(20)),
                |_| async {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Ok(())
                },
            )
            .await;
        {
            let teardown_ran = teardown_ran.clone();
            lifecycle
                .register(HookSpec::teardown("node/veilid"), move |_| {
                    let teardown_ran = teardown_ran.clone();
                    async move {
                        teardown_ran.store(true, std::sync::atomic::Ordering::Relaxed);
                        Ok(())
                    }
                })
                .await;
        }

        let outcomes = lifecycle
            .stop(StopReason::Shutdown, Reachability::Unreachable, async {
                Reachability::Unreachable
            })
            .await;

        assert!(outcomes.iter().any(|outcome| {
            outcome.module == "slow-node-cleanup" && outcome.result == HookResult::Overran
        }));
        assert!(!teardown_ran.load(std::sync::atomic::Ordering::Relaxed));
        assert!(lifecycle.watchdog_left_armed());

        tokio::time::sleep(Duration::from_millis(225)).await;
        assert!(lifecycle.watchdog_fired());
    }

    #[tokio::test]
    async fn explicitly_safe_intake_timeout_allows_later_teardown() {
        let mut budgets = Budgets::default().scaled(0.02);
        budgets.watchdog = Duration::from_millis(300);
        let lifecycle = Lifecycle::with(budgets, WatchdogAction::Report);
        let teardown_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));

        lifecycle
            .register(
                HookSpec::new("slow-stop-signal", ResourceNeed::None)
                    .budget(Duration::from_millis(20))
                    .continue_after_timeout(),
                |_| async {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Ok(())
                },
            )
            .await;
        {
            let teardown_ran = teardown_ran.clone();
            lifecycle
                .register(HookSpec::teardown("node/veilid"), move |_| {
                    let teardown_ran = teardown_ran.clone();
                    async move {
                        teardown_ran.store(true, std::sync::atomic::Ordering::Relaxed);
                        Ok(())
                    }
                })
                .await;
        }

        let outcomes = lifecycle
            .stop(StopReason::Shutdown, Reachability::Unreachable, async {
                Reachability::Unreachable
            })
            .await;

        assert!(outcomes.iter().any(|outcome| {
            outcome.module == "slow-stop-signal" && outcome.result == HookResult::Overran
        }));
        assert!(teardown_ran.load(std::sync::atomic::Ordering::Relaxed));
        assert!(!lifecycle.watchdog_left_armed());
    }

    #[tokio::test]
    async fn announce_tier_is_skipped_when_unreachable() {
        let lifecycle = Lifecycle::with(Budgets::default().scaled(0.02), WatchdogAction::Report);
        lifecycle
            .register(HookSpec::new("presence", ResourceNeed::Network), |_| async {
                panic!("announce hook must not run when the network is unreachable")
            })
            .await;

        let outcomes = lifecycle
            .stop(StopReason::Shutdown, Reachability::Unreachable, async {
                Reachability::Unreachable
            })
            .await;

        assert_eq!(
            outcomes[0].result,
            HookResult::Skipped("network unreachable")
        );
    }

    #[tokio::test]
    async fn restart_skips_announce_even_when_reachable() {
        let lifecycle = Lifecycle::with(Budgets::default().scaled(0.02), WatchdogAction::Report);
        lifecycle
            .register(HookSpec::new("presence", ResourceNeed::Network), |_| async {
                panic!("restart must not announce")
            })
            .await;

        let outcomes = lifecycle
            .stop(StopReason::Restart, Reachability::Reachable, async {
                Reachability::Reachable
            })
            .await;

        assert_eq!(outcomes[0].result, HookResult::Skipped("restart"));
    }

    #[tokio::test]
    async fn second_stop_is_ignored() {
        let lifecycle = Lifecycle::with(Budgets::default().scaled(0.02), WatchdogAction::Report);
        lifecycle
            .register(HookSpec::new("once", ResourceNeed::None), |_| async { Ok(()) })
            .await;

        let first = lifecycle
            .stop(StopReason::Shutdown, Reachability::Unreachable, async {
                Reachability::Unreachable
            })
            .await;
        let second = lifecycle
            .stop(StopReason::Shutdown, Reachability::Unreachable, async {
                Reachability::Unreachable
            })
            .await;

        assert_eq!(first.len(), 1);
        assert!(second.is_empty());
    }

    #[tokio::test]
    async fn panicking_hook_is_attributed_and_does_not_take_its_tier_down() {
        let lifecycle = Lifecycle::with(Budgets::default().scaled(0.02), WatchdogAction::Report);
        lifecycle
            .register(HookSpec::new("exploding", ResourceNeed::Storage), |_| async {
                panic!("boom")
            })
            .await;
        lifecycle
            .register(HookSpec::new("bystander", ResourceNeed::Storage), |_| async { Ok(()) })
            .await;

        let outcomes = lifecycle
            .stop(StopReason::Shutdown, Reachability::Unreachable, async {
                Reachability::Unreachable
            })
            .await;

        let exploding = outcomes.iter().find(|o| o.module == "exploding").unwrap();
        assert!(matches!(
            &exploding.result,
            HookResult::Failed(error) if error.contains("panicked") && error.contains("boom")
        ));
        assert!(outcomes
            .iter()
            .any(|o| o.module == "bystander" && o.result == HookResult::Ok));
    }

    #[tokio::test]
    async fn duplicate_module_names_keep_distinct_hook_ids() {
        let lifecycle = Lifecycle::with(Budgets::default().scaled(0.02), WatchdogAction::Report);
        lifecycle
            .register(HookSpec::new("duplicate", ResourceNeed::Storage), |_| async { Ok(()) })
            .await;
        lifecycle
            .register(HookSpec::new("duplicate", ResourceNeed::Storage), |_| async { Ok(()) })
            .await;

        let outcomes = lifecycle
            .stop(StopReason::Shutdown, Reachability::Unreachable, async {
                Reachability::Unreachable
            })
            .await;
        assert_eq!(outcomes.len(), 2);
        assert_ne!(outcomes[0].id, outcomes[1].id);
    }

    #[test]
    fn watchdog_snapshot_includes_current_progress() {
        let completed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let running = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
        let progress = Progress::new("starting");
        progress.fragile("writing mailbox page 3/7");
        running.lock().unwrap().insert(
            HookId(7),
            RunningHook {
                id: HookId(7),
                module: "mailbox".into(),
                tier: Tier::NodeDependent,
                started: Instant::now(),
                budget: Duration::from_secs(3),
                progress,
            },
        );

        let snapshot = snapshot_for_watchdog(&completed, &running);
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].module, "mailbox");
        assert!(snapshot[0].detail.contains("page 3/7"));
        assert!(snapshot[0].needs_verification);
        assert_eq!(snapshot[0].result, HookResult::Overran);
    }

    #[tokio::test]
    async fn skip_on_restart_works_outside_announce_tier() {
        let lifecycle = Lifecycle::with(Budgets::default().scaled(0.02), WatchdogAction::Report);
        lifecycle
            .register(
                HookSpec::new("optional-cache", ResourceNeed::Storage).skip_on_restart(),
                |_| async { panic!("restart-skippable hook must not run") },
            )
            .await;

        let outcomes = lifecycle
            .stop(StopReason::Restart, Reachability::Reachable, async {
                Reachability::Reachable
            })
            .await;
        assert_eq!(outcomes[0].result, HookResult::Skipped("restart"));
    }
}
