# Weave for iOS — reconversion from Android Phase 6.12.6

This tree starts from the current Android `Phase6.12.6-Startup-Tips` source rather than patching the older iOS prototype. It keeps Weave's portable formats/protocols and replaces Android platform layers with SwiftUI, Keychain and a C bridge into the embedded Rust VeilKnit core.

See **PORT_STATUS.md** before treating this as release-ready; it distinguishes working conversion code from runtime adapters that still need parity work.

## Build on a Mac

Requirements: current Xcode, Xcode command-line tools, Rust/rustup and XcodeGen.

```bash
brew install xcodegen
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
./Scripts/build_simulator.sh
open WeaveIOS.xcodeproj
```

`build_native.sh` builds the Rust core for arm64 iPhone plus arm64/x86_64 Simulator and creates `Native/VeilKnit.xcframework`. `generate_project.sh` then creates the Xcode project from `project.yml`.

For a physical iPhone, open the generated project, select your Apple Development Team, change the bundle identifier if your account requires a unique one, and build for your device. Code signing is intentionally disabled only in the command-line simulator validation path.

## Build validation from Windows/Linux

The repository contains `.github/workflows/ios-build.yml`. Push the tree to GitHub and run **Actions → iOS build → Run workflow**. GitHub's macOS runner installs Rust/XcodeGen, builds the Rust XCFramework and compiles the Simulator app. This is useful for compile validation when your main machine is Windows/Linux; Apple still requires macOS/Xcode and signing credentials for a distributable device build.

## Compatibility carried over

- App identity on the VeilKnit API: `weave.v1`
- Daemon API: protocol v3
- Profile format: VSPF v4
- Local active profile name: `profiles/active.txt`
- Five interface languages: English, French, Spanish, Russian, Simplified Chinese
- Startup tips: current Phase 6.12.6 set, randomized every four seconds

## Layout

- `WeaveIOS/` — SwiftUI app, codec, protocol client and UI
- `Native/veilknit-daemon/` — current Rust VeilKnit core with iOS bridge
- `Native/include/veilknit_ios.h` — Swift/C bridge header
- `Scripts/` — Apple-target Rust/XCFramework and Xcode project builds
- `WeaveIOS/Resources/ReferenceAndroid/` — current feature notes used during reconversion
