# Weave Phase 6.11 — Embedded VeilKnit

Date: 2026-09-24

## Goal

Package the existing Android VeilKnit Rust daemon/core inside Weave without rewriting the networking stack in Kotlin. The Rust modules, command dispatcher, DHT/mailbox/gossip/reputation/handshake/custody logic and standalone local API listener remain Rust code. Weave replaces its external Android Binder/local-socket client hop with an in-process JNI bridge.

## Startup flow

1. If VeilKnit is not already running, Weave's first visible screen is the existing VeilKnit **Sign in / Create account** UI.
2. Starting an account immediately starts `DaemonForegroundService` and its persistent VeilKnit networking notification. Notification persistence is enabled by default.
3. The UI changes to Weave's loading surface while the Rust daemon starts. The status line is fed by `DaemonStateStore` from native logs, including states such as:
   - Attaching to Veilid: Attaching…
   - Attaching to Veilid: Connected
   - Restoring saved network data…
   - Creating main DHT…
   - Main DHT ready…
   - Creating mailbox…
   - Preparing application services…
   - Starting application connection service…
4. Only after the embedded daemon reports ready does `SocialNetworkController` start and authenticate Weave to the local protocol-v3 application API.
5. Weave then continues through its normal saved-profile / first-run profile flow.

If the foreground daemon survived while the Weave activity was closed, reopening Weave does not require another daemon login; it resumes against the already-running core.

## Transport change

Previous Android path:

```
Weave Kotlin
    -> AIDL/Binder
    -> VeilKnitApiService
    -> Android LocalSocket / Unix socket
    -> Rust protocol-v3 dispatcher
```

Phase 6.11 path:

```
Weave Kotlin
    -> NativeDaemonBridge JNI
    -> in-memory Tokio duplex stream
    -> same Rust protocol-v3 dispatcher
```

`src/api/local.rs` now installs an Android-only embedded bridge when the normal local API context is created. Direct one-shot requests and long-lived subscriptions use `tokio::io::duplex`, so request parsing, authentication, capability checks, work-lane limits, timeout handling and response/event serialization still run through the existing `handle_connection` / `process_request` path.

The standalone socket listener is intentionally preserved in the Rust module. The embedded Weave client simply does not traverse it.

## Bundled Weave authorization

The protocol-v3 app credential/session model is still used. This keeps application capabilities and private-storage namespacing intact.

Because Weave and the embedded VeilKnit core are now one installed APK/trust boundary, a missing `weave.v1` app credential is automatically approved through the daemon's existing `app-approve` command. The normal pending-application notification/dialog is suppressed only for `weave.v1`; other app requests keep the existing explicit approval behavior.

## Embedded daemon GUI

The Android VeilKnit Compose GUI is included in the Weave source tree and uses the same shared `DaemonStateStore` and foreground service.

The normal Weave Settings button also acts as the hidden unlock gesture:

- Enter Settings.
- Back out to Me.
- Enter Settings again.
- Repeat until Settings has been entered **5 times within 5 seconds**.
- On the fifth entry, Weave opens the full VeilKnit GUI instead of normal Settings.

The rolling entry window automatically expires after five seconds and clears after a successful unlock. The embedded VeilKnit screen has an explicit back control and also participates in Weave's back stack.

## Foreground behavior

The existing foreground service and persistent notification remain enabled by default. `stopWithTask=false` is retained, so dismissing/closing the Weave activity does not automatically kill VeilKnit. The notification retains the safe-stop path.

A later Weave setting can change this policy to stop networking when the UI closes; that option is deliberately not implemented in this phase.

## Backup behavior

The daemon's current encrypted account/backup model is retained. Android automatic application backup is disabled in the manifest. A future regular Weave setting can expose the planned **Setup account backup** flow without changing the embedded core design.

## Build changes

The Weave Gradle project now builds `native/veilknit-daemon` as an Android Rust `cdylib` with cargo-ndk for:

- `arm64-v8a`
- `x86_64`

`build_project.bat/.sh` and `build_debug.bat/.sh` now check for Rust/cargo-ndk and add the Android Rust targets before invoking Gradle.

Required host tools are therefore JDK 17+, Android SDK/NDK, Rust/rustup and cargo-ndk.

## First device test checklist

1. Install the combined APK over a clean test install if possible.
2. Confirm launch lands on VeilKnit Sign in / Create account, not Weave profile creation.
3. Sign in or create an account.
4. Confirm the persistent **VeilKnit networking** notification appears and remains after leaving Weave.
5. Watch the Weave loading page and confirm native startup status advances through Veilid/DHT/mailbox stages.
6. Confirm Weave reaches the existing profile without a separate app-approval prompt for `weave.v1`.
7. Create/read a post and enter a group to exercise one-shot API requests and subscriptions.
8. From Me, enter Settings and back out five times within five seconds. Confirm the fifth entry opens the full VeilKnit GUI.
9. From the hidden GUI, inspect Overview, DHT, Mailbox, Handshake, Applications, Network and Logs.
10. Close Weave and confirm VeilKnit remains alive in the foreground; reopen Weave and confirm it reconnects without a daemon login.
11. Use Stop Safely and confirm Weave returns to the VeilKnit login screen after shutdown.

## Validation note

Static integration checks are recorded in `WEAVE_PHASE6_11_STATIC_VALIDATION.txt`. A full Android/Rust compile could not be performed in the packaging environment because it does not contain Cargo/Rust or an Android SDK/NDK and the Gradle wrapper distribution is not cached. The source-level validation passed all integration checks; the first real compiler pass should be done on the normal Android build machine.
