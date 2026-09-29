# VeilKnit Daemon — Lifecycle / Shutdown Rework

This document describes the shutdown changes agreed on for the current `Daemon Testing` tree. The goal is to make `lifecycle` the **single owner of shutdown sequencing**, while `NetworkSupervisor` remains the daemon's status/event/startup facade.

## 1. Required invariants

After this rework, shutdown should obey these rules:

1. There is exactly **one real shutdown path**.
   - Console `Q`
   - Android/service stop sentinel
   - Ctrl+C / host stop
   - restart
   - future GUI shutdown buttons

   These should only request a stop and then flow through `Lifecycle::stop(...)`.

2. Nothing performs persistence or network cleanup **before** lifecycle supervision begins.
   - No manual mailbox flush in the `Q` branch.
   - No manual DHT snapshot in the `Q` branch.
   - Any operation that can hang must be a registered lifecycle hook and therefore have progress reporting, a hook budget, a tier ceiling, and the OS watchdog behind it.

3. Lifecycle hooks are ordinary async futures.
   - `Lifecycle` must **not** blanket-wrap hooks in `spawn_blocking`.
   - A normal async hook can be cancelled by dropping/aborting its future when its deadline expires.
   - A module that genuinely needs blocking work owns that decision itself and must keep it bounded/cancellable where possible.

4. Veilid is never deliberately torn down while a known node-dependent hook is still running.

5. The watchdog must be able to report both:
   - hooks that already finished; and
   - hooks that are currently running, including their latest `Progress` step.

6. Every hook has a stable internal identity. Human-readable module names are labels, not identities.

7. Panics become explicit failed outcomes instead of disappearing as anonymous JoinSet errors.

8. Teardown and post-teardown placement are explicit declarations, not magic module-name tests.

---

## 2. Public lifecycle API changes

### 2.1 Add a stable HookId

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HookId(u64);

impl fmt::Display for HookId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
```

`Lifecycle` should own an `AtomicU64` and allocate IDs during registration.

```rust
next_hook_id: Arc<AtomicU64>,
```

Registration:

```rust
let id = HookId(self.next_hook_id.fetch_add(1, Ordering::Relaxed));
```

Use `HookId` for all internal maps/sets. Duplicate display/module names are then harmless.

### 2.2 Make placement explicit

Keep `ResourceNeed` as the normal automatic placement mechanism, but add a small phase override for the two special cases that cannot be inferred from resources.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownPhase {
    Automatic,
    Teardown,
    After,
}
```

`Hook` and `HookSpec` gain:

```rust
phase: ShutdownPhase,
```

Tier selection becomes:

```rust
impl Hook {
    fn tier(&self) -> Tier {
        match self.phase {
            ShutdownPhase::Teardown => Tier::Teardown,
            ShutdownPhase::After => Tier::After,
            ShutdownPhase::Automatic => match self.need {
                ResourceNeed::None => Tier::Intake,
                ResourceNeed::Network => Tier::Announce,
                ResourceNeed::VeilidNode => Tier::NodeDependent,
                ResourceNeed::Storage => Tier::Persist,
            },
        }
    }
}
```

This removes the current special case that recognizes teardown by comparing the module string to `"node/veilid"`.

### 2.3 HookSpec constructors/builders

Recommended interface:

```rust
impl HookSpec {
    pub fn new(module: impl Into<String>, need: ResourceNeed) -> Self {
        Self {
            module: module.into(),
            detail: String::new(),
            need,
            phase: ShutdownPhase::Automatic,
            budget: budget::DEFAULT_HOOK,
            skip_on_restart: false,
        }
    }

    pub fn teardown(module: impl Into<String>) -> Self {
        Self::new(module, ResourceNeed::VeilidNode)
            .phase(ShutdownPhase::Teardown)
            .budget(budget::TEARDOWN)
    }

    pub fn after_teardown(module: impl Into<String>) -> Self {
        Self::new(module, ResourceNeed::None)
            .phase(ShutdownPhase::After)
            .budget(budget::AFTER)
    }

    pub fn phase(mut self, phase: ShutdownPhase) -> Self {
        self.phase = phase;
        self
    }

    pub fn skip_on_restart(mut self) -> Self {
        self.skip_on_restart = true;
        self
    }
}
```

### 2.4 Remove or redefine `optional`

The current `optional` flag is stored but not used, and its documentation does not match the internal comment.

Preferred change:

```rust
optional: bool
```

becomes:

```rust
skip_on_restart: bool
```

If source compatibility is temporarily useful, keep:

```rust
#[deprecated(note = "use skip_on_restart()")]
pub fn optional(self) -> Self {
    self.skip_on_restart()
}
```

Do not implement vague "drop if the tier is short" behaviour. Hook budgets and tier ceilings already provide a deterministic answer to that problem.

---

## 3. Correct the ResourceNeed documentation

The current documentation says `Storage` can run after Veilid teardown, but automatic `Storage` hooks map to `Persist`, which is before teardown.

Change the contract to:

- `None` -> `Intake`
- `Network` -> `Announce`
- `VeilidNode` -> `NodeDependent`
- `Storage` -> `Persist`
- explicit `ShutdownPhase::Teardown` -> `Teardown`
- explicit `ShutdownPhase::After` -> `After`

Suggested wording for `Storage`:

> Local persistence that should be completed before Veilid teardown. Use `HookSpec::after_teardown(...)` for work intentionally placed after Veilid.

That makes the docs describe what the code actually guarantees.

---

## 4. Replace spawn_blocking lifecycle hooks with ordinary async hooks

### 4.1 Why

The coordinator currently puts every hook in `JoinSet::spawn_blocking`. A started Tokio blocking task cannot be reliably aborted. That means a tier can time out, `abort_all()` can return, and the blocking hook can still be alive while later teardown runs. Tokio runtime destruction may then wait for that blocking task.

The lifecycle coordinator should supervise async work, not convert every hook into blocking work.

### 4.2 Recommended execution shape

Use `JoinSet::spawn`:

```rust
set.spawn(async move {
    let started = Instant::now();

    let result = match timeout(hook_budget, action(reporter)).await {
        Ok(Ok(())) => HookResult::Ok,
        Ok(Err(error)) => HookResult::Failed(error),
        Err(_) => HookResult::Overran,
    };

    HookOutcome {
        id,
        module,
        detail: progress.read(),
        tier,
        elapsed: started.elapsed(),
        budget: hook_budget,
        result,
        needs_verification: progress.verification_needed(),
    }
});
```

The timeout drops the hook future when it expires. Well-behaved async cleanup therefore genuinely stops before the coordinator advances. As a second backstop, compare measured wall time with the hook budget: a synchronously-blocking hook can prevent Tokio's timer from being polled until after the blocking call returns, so a late `Ok(())` must still be classified as `Overran` when elapsed time exceeded the declared budget.

### 4.3 Module rule for truly blocking work

Add this rule to the lifecycle module documentation:

> A lifecycle hook must not perform an unbounded blocking operation on a Tokio worker. If a module must call blocking code, that module owns the blocking boundary and its cancellation/timeout strategy. Lifecycle intentionally does not wrap hooks in `spawn_blocking` because doing so makes started hooks non-cancellable from the coordinator.

The independent OS watchdog remains the protection against a bug that violates this rule.

---

## 5. Catch panics and record the offending hook

`futures = "0.3"` is already a dependency, so use `FutureExt::catch_unwind`.

Imports:

```rust
use futures::FutureExt;
use std::panic::AssertUnwindSafe;
```

Wrap each action:

```rust
let future = AssertUnwindSafe(action(reporter)).catch_unwind();

let result = match timeout(hook_budget, future).await {
    Ok(Ok(Ok(()))) => HookResult::Ok,
    Ok(Ok(Err(error))) => HookResult::Failed(error),
    Ok(Err(payload)) => HookResult::Failed(format!(
        "shutdown hook panicked: {}",
        panic_payload(&payload)
    )),
    Err(_) => HookResult::Overran,
};
```

Helper:

```rust
fn panic_payload(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_string()
    }
}
```

This means a hook called `exploding` produces a real outcome such as:

```text
failed: shutdown hook panicked: boom
```

instead of only printing an anonymous JoinSet error.

---

## 6. Track currently-running hooks for the watchdog

### 6.1 Problem

The watchdog currently receives only `progress_so_far`, and that list is extended only after an entire tier returns. A watchdog firing in the middle of a tier can therefore omit the exact hook that is hanging.

### 6.2 RunningHook snapshot

Add:

```rust
#[derive(Clone)]
struct RunningHook {
    id: HookId,
    module: String,
    tier: Tier,
    started: Instant,
    budget: Duration,
    progress: Progress,
}
```

Lifecycle fields:

```rust
completed: Arc<std::sync::Mutex<Vec<HookOutcome>>>,
running: Arc<std::sync::Mutex<BTreeMap<HookId, RunningHook>>>,
```

Replace `progress_so_far` with those two structures.

Before spawning a hook:

```rust
let progress = Progress::new(...);
running.lock()?.insert(id, RunningHook {
    id,
    module: module.clone(),
    tier,
    started: Instant::now(),
    budget: hook_budget,
    progress: progress.clone(),
});
```

When a hook reports an outcome:

```rust
running.lock()?.remove(&outcome.id);
completed.lock()?.push(outcome.clone());
```

### 6.3 Watchdog snapshot

Immediately before writing its forced record, the watchdog should build a snapshot containing completed outcomes plus synthetic outcomes for every running hook:

```rust
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
```

Now a forced record can say, for example:

```text
mailbox — OVERRAN — writing mailbox page 3/7 — NEEDS VERIFICATION
```

rather than ending with the previous completed tier.

---

## 7. Distinguish a hook timeout from an uncooperative tier timeout

These are not equivalent failures.

### Hook timeout

An async hook exceeds its own deadline. `timeout(...)` drops the hook future, so ordinary self-contained async cleanup is cancelled. There is one conservative exception: actor-style shutdown APIs may already have enqueued work elsewhere and merely be awaiting a reply. Cancelling that waiter does not prove the underlying service is quiescent.

Accordingly, an individual timeout in `Intake`, `Announce`, or `NodeDependent` must stop the lifecycle before Veilid teardown and leave the independent watchdog armed. `Teardown` timing out also leaves the watchdog armed. A `Persist` timeout may continue into teardown because that tier explicitly declares that its work no longer requires Veilid.

### Tier timeout

The tier itself expires while one or more spawned tasks have still not returned. After switching to normal async tasks, this should be exceptional and strongly suggests a hook blocked a Tokio worker or otherwise violated cancellation assumptions.

Return a small structure from `run_tier`:

```rust
struct TierRun {
    outcomes: Vec<HookOutcome>,
    uncooperative: bool,
}
```

Set `uncooperative = true` only when the outer tier timeout fires.

Recommended policy:

- `set.abort_all()` immediately.
- Mark outstanding hooks `Overran` from their `HookId`/Progress records.
- **Do not enter a later destructive resource tier such as Veilid teardown if the timed-out task may still be touching that resource.**
- Leave the OS watchdog armed as the backstop for runtime destruction.
- In benchmark `Report` mode, stop processing additional tiers and return the recorded results.

This prevents the coordinator from saying "NodeDependent is over" while an uncooperative node-dependent hook can still race the Veilid teardown hook.

For individually timed-out `Persist`/post-teardown hooks, continue normally. For pre-teardown resource-sensitive tiers, treat the timeout as "safe quiescence not proven" and do not enter later destructive tiers.

---

## 8. Do not disarm the watchdog when an uncooperative task may still exist

For a clean lifecycle completion, disarm the watchdog normally.

For a tier-level uncooperative timeout, or an individual timeout in a resource-sensitive tier where quiescence cannot be proven, do **not** disarm it before returning from shutdown. This preserves protection against the following last-resort case:

```text
bad hook blocks worker
 -> lifecycle records/abandons it
 -> main returns
 -> Tokio runtime waits for the blocked worker
 -> watchdog hard-exits process
```

A `Persist`/post-teardown `HookResult::Overran` can still be treated as ordinary cancellation because its declaration says it does not require the Veilid resource being dismantled. Resource-sensitive overruns retain the watchdog even though their waiter future was dropped, because detached actor work may still exist.

---

## 9. Record format changes

Add the stable hook ID to `HookOutcome` and `RecordedHook`:

```rust
pub id: HookId,
```

Serialized form can use the numeric value.

Bump shutdown-record version from `1` to `2` if the JSON structure changes.

Also update `RawRecord::looks_dirty()` to treat explicit hook failure as dirty:

```rust
self.json.contains(r#"\"forced\":true"#)
    || self.json.contains(r#"\"outcome\":\"overran\""#)
    || self.json.contains(r#"\"outcome\":\"failed:"#)
    || self.json.contains(r#"\"needs_verification\":true"#)
```

`ShutdownRecord::is_clean()` already treats failed hooks as dirty; `looks_dirty()` should agree.

---

## 10. NetworkSupervisor becomes the facade around Lifecycle

Do **not** keep two shutdown registries.

Remove from `NetworkSupervisor`:

```rust
type ShutdownFuture = ...;
type ShutdownAction = ...;
struct ShutdownHook { ... }
shutdown_hooks: Arc<Mutex<Vec<ShutdownHook>>>,
```

Add:

```rust
lifecycle: Lifecycle,
```

Initialize it in `NetworkSupervisor::new()`:

```rust
lifecycle: Lifecycle::new(),
```

Expose it when a subsystem needs gates/settings:

```rust
pub fn lifecycle(&self) -> Lifecycle {
    self.lifecycle.clone()
}
```

### 10.1 Registration wrapper

Keep registration on the supervisor if that makes `main.rs` clean, but delegate immediately to lifecycle:

```rust
pub async fn register_shutdown_hook<F, Fut>(&self, spec: HookSpec, action: F)
where
    F: Fn(Progress) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), String>> + Send + 'static,
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
```

This preserves the existing supervisor event stream while lifecycle owns sequencing.

### 10.2 The supervisor's shutdown method delegates to Lifecycle::stop

Recommended shape:

```rust
pub async fn shutdown(&self, reason: StopReason) -> Vec<HookOutcome> {
    {
        let mut status = self.status.write().await;
        if matches!(
            status.lifecycle,
            SupervisorLifecycle::Stopping | SupervisorLifecycle::Stopped
        ) {
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

    self.status.write().await.lifecycle = SupervisorLifecycle::Stopped;
    outcomes
}
```

The important property is not the exact wrapper syntax; it is that `NetworkSupervisor::shutdown()` is no longer a second executor. It becomes a facade over the single lifecycle coordinator.

---

## 11. Re-register the current main.rs services by declared resource need

The current reverse-registration ordering should disappear.

### Intake — stop sources of new work first

These hooks mostly abort schedulers/bridges or stop local clients from creating new work:

```rust
HookSpec::new("api/local", ResourceNeed::None)
HookSpec::new("walk/automatic-scheduler", ResourceNeed::None)
HookSpec::new("events/mailbox-bridge", ResourceNeed::None)
HookSpec::new("events/reputation-bridge", ResourceNeed::None)
HookSpec::new("app/advertisement-publisher", ResourceNeed::None)
```

Suggested progress examples:

```rust
progress.step("stopping local API intake");
progress.step("aborting automatic walk scheduler");
```

### Announce — network-visible departure only

Ideally split the current combined `Presence and attachment observer` shutdown into two responsibilities:

1. `presence/offline` — network-visible offline/withdrawal announcement, `ResourceNeed::Network`.
2. local attachment observer / presence worker cleanup — `ResourceNeed::VeilidNode`.

The Announce hook can be skipped on restart or when unreachable without accidentally skipping required local cleanup.

**Do not classify the existing combined hook as Network until it is split.** Its `node.clear_attachment_handler()` and runtime cleanup must happen even when unreachable.

### NodeDependent — still needs Veilid alive

```rust
HookSpec::new("presence/runtime", ResourceNeed::VeilidNode)
HookSpec::new("mailbox", ResourceNeed::VeilidNode)
HookSpec::new("walker", ResourceNeed::VeilidNode)
```

If `mailbox.shutdown()` performs a final remote flush, keep it here. If mailbox has a separate purely local on-disk flush, that local part can be split into Persist.

### Persist — local state before Veilid teardown

```rust
HookSpec::new("dht/snapshot", ResourceNeed::Storage)
HookSpec::new("reputation", ResourceNeed::Storage)
```

DHT snapshot should report useful steps:

```rust
progress.step("exporting DHT snapshot");
let snapshot = background.export_snapshot().await;

progress.fragile("writing encrypted DHT snapshot");
auth.write_user_encrypted(&session, DHT_SNAPSHOT_KEY, &snapshot)
    .map_err(|error| error.to_string())?;

progress.settled("DHT snapshot committed");
Ok(())
```

If `Reputation::shutdown()` still performs network work, classify it `VeilidNode` instead; the resource declaration must describe what the hook actually touches.

### Teardown — exactly one explicit Veilid hook

```rust
HookSpec::teardown("node/veilid")
    .detail("detach and stop Veilid")
    .budget(Duration::from_secs(10))
```

Action:

```rust
move |progress| {
    let node = node.clone();
    async move {
        progress.step("detaching and stopping Veilid");
        node.shutdown().await;
        progress.step("Veilid stopped");
        Ok(())
    }
}
```

No module-name magic is needed to put it in `Tier::Teardown`.

### After — UI/log infrastructure that should outlive networking

Move the current post-`supervisor.shutdown()` dashboard cleanup into explicit After hooks where practical:

```rust
HookSpec::after_teardown("ui/dashboard-event-bridge")
HookSpec::after_teardown("ui/dashboard")
```

This gives `Tier::After` a real purpose and means the timing/post-mortem infrastructure stays available until the network teardown is complete.

If `ConsoleDashboard::shutdown()` cannot be put in an async/shared hook cleanly because of ownership, it can remain immediately after lifecycle as a narrow UI-only exception; network/persistence work must not.

---

## 12. main.rs shutdown becomes intentionally boring

### 12.1 Console Q command

Replace the current manual mailbox flush and DHT snapshot with:

```rust
"q" | "Q" => {
    crate::tprintln!("Shutting down...");
    stop_reason = StopReason::Shutdown;
    break;
}
```

No mailbox call. No snapshot call. No direct node shutdown.

### 12.2 Android stop sentinel

Use the same stop reason and leave the loop:

```rust
if android_bridge::is_stop_sentinel(&choice) {
    crate::tprintln!("Android stop requested.");
    stop_reason = StopReason::Shutdown;
    break;
}
```

### 12.3 Central call after the command loop

```rust
let outcomes = supervisor.shutdown(stop_reason).await;

for outcome in &outcomes {
    match &outcome.result {
        HookResult::Failed(error) => {
            crate::tprintln!("{} shutdown warning: {}", outcome.module, error);
        }
        HookResult::Overran => {
            crate::tprintln!(
                "{} shutdown warning: timed out while {}",
                outcome.module,
                outcome.detail
            );
        }
        _ => {}
    }
}
```

Underneath this supervisor method, there is exactly one executor: `self.lifecycle.stop(...)`.

If you prefer the command path to literally contain `lifecycle.stop(...)`, expose `let lifecycle = supervisor.lifecycle()` and call it from a shared `stop_daemon(...)` function. Architecturally, however, having `NetworkSupervisor::shutdown(reason)` delegate directly to lifecycle is cleaner because it keeps supervisor status/events synchronized.

---

## 13. Restart semantics

`StopReason::Restart` should continue skipping the whole Announce tier, as the current design intends.

For non-Announce hooks that are individually safe to skip on restart, use `skip_on_restart`.

Inside the tier loop:

```rust
if reason == StopReason::Restart && hook.skip_on_restart {
    // emit HookResult::Skipped("restart")
}
```

Do not use this flag as general priority scheduling.

Important distinction:

- network departure announcement: may be skipped on restart;
- local worker cancellation, mailbox quiescence, persistence, and Veilid ownership cleanup: generally should still run.

---

## 14. Update the lifecycle tests

At minimum add/fix the following.

### A. resource -> tier mapping

- None -> Intake
- Network -> Announce
- VeilidNode -> NodeDependent
- Storage -> Persist
- explicit teardown -> Teardown
- explicit after -> After

### B. ordinary async overrun is actually cancelled

Use an atomic/drop guard so the test checks that the future was dropped, not merely that the result was called Overran.

### C. panicking hook has a named Failed outcome

Register:

```rust
"exploding" => panic!("boom")
"bystander" => Ok(())
```

Assert:

- both hooks have outcomes;
- `exploding` is `HookResult::Failed(...)`;
- failure text contains `boom`;
- bystander remains `Ok`.

### D. duplicate module names are independent

Register two hooks both displayed as `"mailbox"` but with different details/behaviour. Assert two distinct `HookId`s and two outcomes.

### E. watchdog snapshot includes current hook

Run a deliberately uncooperative test hook in watchdog Report mode and assert the forced snapshot contains its current `Progress` detail.

This may be easiest to test through a factored `snapshot_for_watchdog()` unit test rather than making the unit test actually starve Tokio.

### F. failed record is dirty

Add a `RawRecord::looks_dirty()` assertion for `HookResult::Failed`.

### G. after tier really runs after teardown

Push tier names into an `Arc<Mutex<Vec<_>>>` and assert:

```text
persist < teardown < after
```

### H. restart skips announce but not local cleanup

Register one Network and one VeilidNode hook, stop with Restart, and assert:

- Network -> Skipped("restart")
- VeilidNode -> Ok

### I. unreachable skips announce but not local cleanup

Same arrangement with `Reachability::Unreachable`.

### J. second stop is idempotent

Keep/expand the existing duplicate-stop test.

---

## 15. Update shutdown scenarios / bench

### shutdown-panicking-hook.json

The scenario should no longer merely prove that the bystander survived. It should explicitly expect:

```text
exploding = failed
bystander = ok
```

### Blocking-hook scenario

After removing lifecycle-level `spawn_blocking`, the bench should distinguish:

1. `slow_async` — uses `tokio::time::sleep`; expected to be cancelled by its hook timeout.
2. `blocking_bug` — deliberately uses a synchronous blocking call inside an async hook; represents a module violating the hook contract and is used to verify the independent OS watchdog path.

Do not accidentally make the normal blocking-work recommendation "put every hook in spawn_blocking" again. The scenario is testing a bug, not prescribing the architecture.

### New watchdog-progress scenario

Have a hook do:

```rust
progress.fragile("writing pages 3/7");
```

and then trigger the watchdog path. Assert the captured record/snapshot includes both the module and `writing pages 3/7`.

### Explicit-after scenario

Register hooks in arbitrary registration order and assert runtime order is still:

```text
Intake -> Announce -> NodeDependent -> Persist -> Teardown -> After
```

---

## 16. Suggested implementation order

This order keeps intermediate builds understandable.

### Pass 1 — lifecycle internals

1. Add `HookId`.
2. Add `ShutdownPhase`.
3. Remove module-name teardown magic.
4. Replace `optional` with `skip_on_restart`.
5. Convert `spawn_blocking` to ordinary async `JoinSet::spawn`.
6. Catch panics.
7. Add running-hook registry and watchdog snapshot.
8. Add tier-timeout/uncooperative distinction.
9. Fix record dirty detection and version/ID fields.
10. Fix lifecycle unit tests.

### Pass 2 — supervisor integration

1. Put `Lifecycle` inside `NetworkSupervisor`.
2. Remove old `shutdown_hooks` registry and reverse executor.
3. Delegate registration to Lifecycle.
4. Have `NetworkSupervisor::shutdown(reason)` call Lifecycle once.
5. Re-emit `ServiceStopping` / `ServiceStopped` around lifecycle activity/outcomes.
6. Replace old reverse-order supervisor test with resource-order integration tests.

### Pass 3 — production main.rs wiring

1. Replace all string-only registrations with `HookSpec`s.
2. Remove the reverse-registration-order comment/assumption.
3. Remove mailbox flush from Q.
4. Remove DHT snapshot from Q.
5. Ensure Android stop reaches the same post-loop shutdown call.
6. Move or register dashboard cleanup as After work.
7. Run all shutdown entry points through the same `StopReason` path.

### Pass 4 — scenarios

1. Strengthen panic scenario.
2. Add watchdog current-progress assertion.
3. Distinguish async timeout from deliberately blocking-bug scenario.
4. Add explicit After-tier test.
5. Run repeated shutdown and restart loops.

---

## 17. Proposed production hook table

| Hook | Need / phase | Why |
|---|---|---|
| Local application API | None / Intake | Stop apps creating new work |
| Automatic walk scheduler | None / Intake | Stop scheduling walks |
| Mailbox event bridge | None / Intake | Stop background event intake |
| Reputation event bridge | None / Intake | Stop background event intake |
| Application advertisement publisher | None / Intake | Stop new periodic publishing |
| Presence offline announcement | Network / Announce | Requires actual reachability; safe to skip on restart/unreachable |
| Presence runtime/local attachment observer cleanup | VeilidNode / NodeDependent | Must clean up even if unreachable |
| Mailbox shutdown | VeilidNode / NodeDependent | May still require daemon network/node services |
| Walker shutdown | VeilidNode / NodeDependent | Stop node-dependent traversal cleanly |
| DHT snapshot | Storage / Persist | Local encrypted persistence, supervised and timed |
| Reputation persistence | Storage / Persist* | Local persistence; use VeilidNode instead if shutdown still accesses network |
| Veilid node shutdown | explicit Teardown | Sole owner of actual Veilid teardown |
| Dashboard/event UI cleanup | explicit After | Should not disappear before shutdown diagnostics finish |

`*` Verify what `reputation_manager.shutdown()` currently touches before assigning it permanently.

---

## 18. Resulting shutdown flow

The intended final flow is:

```text
User/OS asks daemon to stop
        |
        v
set StopReason + leave command/event loop
        |
        v
NetworkSupervisor::shutdown(reason)
        |
        v
Lifecycle::stop(...)
        |
        +-- arm independent OS watchdog
        |
        +-- Intake
        |     stop API / schedulers / publishers / bridges
        |
        +-- Announce
        |     publish offline/withdrawals when useful
        |
        +-- NodeDependent
        |     stop mailbox / walker / presence local runtime
        |
        +-- Persist
        |     encrypted DHT snapshot / reputation / local state
        |
        +-- Teardown
        |     Veilid shutdown
        |
        +-- After
        |     final UI/log/diagnostic cleanup
        |
        +-- write dirty record only if needed
        +-- disarm watchdog only when safe
        |
        v
NetworkSupervisor status = Stopped
        |
        v
main returns
```

No shutdown entry point is allowed to bypass this path for network or persistence work.

---

## 19. Definition of done

The rework is complete when all of these are true:

- [ ] `Q` performs no mailbox/DHT cleanup itself.
- [ ] Android/service stop performs no cleanup itself.
- [ ] `NetworkSupervisor` has no second shutdown-hook vector/executor.
- [ ] Production shutdown reaches `Lifecycle::stop(...)` exactly once.
- [ ] Lifecycle uses `JoinSet::spawn`, not blanket `spawn_blocking`, for hooks.
- [ ] Async hook timeout actually drops/cancels the hook future.
- [ ] Hook panic yields a named `Failed` outcome.
- [ ] Duplicate module labels cannot confuse hook bookkeeping.
- [ ] Watchdog record includes currently-running hooks and latest Progress text.
- [ ] Veilid teardown is explicit, not selected by magic string.
- [ ] `After` is explicit and exercised by at least one test/hook.
- [ ] Failed shutdown records are recognized as dirty on the next boot.
- [ ] Tier-level uncooperative timeout cannot silently race a later destructive tier.
- [ ] A genuinely blocked Tokio runtime still has the independent OS-thread hard-exit watchdog.
- [ ] Panic/timeout/restart/unreachable/duplicate-stop scenarios all pass.

