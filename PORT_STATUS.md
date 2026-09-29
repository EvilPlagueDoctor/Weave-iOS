# Weave iOS conversion status — Phase 6.12.6

Source base: `Weave-Android-Groups-v2-Phase6.12.6-Startup-Tips` (Android version `0.11.6-startup-tips`, version code 44).

This is a fresh native iOS conversion baseline, not a wrapper around the Android UI. The iOS host is SwiftUI and the current VeilKnit Rust daemon is compiled into the app through a small C ABI.

## Ported in this tree

- Embedded VeilKnit Rust source, including the current protocol-v3 dispatcher and app authorization model.
- iOS C bridge for start/stop, command input, protocol transactions, subscriptions, credential recovery, log draining, profile ID and local-backup restore.
- Protocol-v3 `weave.v1` authentication with the same capability list and HMAC proof domain as Android.
- Weave app credential storage in iOS Keychain.
- Private-value/private-blob vault RPCs, including named encrypted blobs.
- VSPF v4 profile model and binary/text codec, including legacy decode paths carried by the Android format.
- First-run VeilKnit sign-in/create-account screen.
- Startup screen using the current 41 tips, changing every four seconds without immediate repeats.
- EN/FR/ES/RU/ZH-CN translation map imported from the current Android language table.
- Home / Search / People / Me / Groups / Curator navigation.
- Profile renderer for backgrounds, blocks, text, links, buttons, stamps, media placeholders and widgets.
- Basic editor plus the Phase 6.12 editor shape: remembered collapsed sidebar, Pages & Layers, Background/Foreground modes, Add inside the inspector, Move/Size, Appearance, Content, Previous/Next page order, page creation and undo snapshots.
- VSPF import/export.
- Local encrypted group draft/post/comment persistence and branch selector UI.
- `weave://` deep-link routing skeleton.
- Current red individual/profile and blue group/curator section theming.
- Diagnostics and Stop Safely controls.

## Deliberately marked partial instead of faked

These Android subsystems are present in the source/reference material but still need their iOS runtime-specific adapter before feature parity can honestly be claimed:

1. **Profile network publish/unpublish record writer.** VSPF local persistence is compatible; `publishProfile()` currently records a pending publish rather than writing the Android `weave-profile-page-v1` DHT record.
2. **Groups-v2 live network runtime.** The iOS UI/local model is present, but event-store transport, witness/private mailbox custody, authority-presence, claim continuity and reputation events are not yet wired to Swift views.
3. **Widget VM/compiler and full Chess execution.** Widget rectangles remain click-to-load and safe placeholders; the Kotlin widget language/runtime cannot execute on iOS without a Swift/Rust port.
4. **Image content classifier.** The setting is present, but the Android ONNX Mobile classifier needs an iOS ONNX Runtime or Core ML adapter. The port does not pretend filtering occurred when it did not.
5. **Network media upload/fetch pipeline.** VSPF media records render as placeholders; iOS PhotosPicker/audio import plus encrypted thumbnail/full-media network sync still needs its adapter.
6. **Background execution.** iOS has no equivalent of the Android permanent foreground service. The embedded daemon runs with Weave while the app process is active; background behavior must follow iOS background-execution rules.

## Validation performed here

- Swift source parser passes on the complete Swift tree (`swiftc -parse`).
- The C bridge header passes Clang syntax validation.
- Static checks verify all C functions used by Swift exist in the iOS Rust bridge/header.
- VSPF remains version 4 and startup tip count remains 41.
- This environment is Linux and does not contain Xcode or a Rust Apple target toolchain, so a real iOS link/run cannot be claimed here. The supplied macOS build script and GitHub Actions job perform that next validation.
