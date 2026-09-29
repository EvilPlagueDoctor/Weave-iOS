#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRATE="$ROOT/Native/veilknit-daemon"
OUT="$ROOT/Native/VeilKnit.xcframework"
BUILD="$ROOT/Native/build-ios"

command -v rustup >/dev/null || { echo "rustup is required" >&2; exit 1; }
command -v cargo >/dev/null || { echo "cargo is required" >&2; exit 1; }
command -v xcodebuild >/dev/null || { echo "Xcode is required" >&2; exit 1; }

rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
rm -rf "$BUILD" "$OUT"
mkdir -p "$BUILD/device" "$BUILD/simulator"

pushd "$CRATE" >/dev/null
CARGO_TARGET_DIR="$BUILD/cargo-device" cargo build --release --lib --target aarch64-apple-ios
CARGO_TARGET_DIR="$BUILD/cargo-sim-arm64" cargo build --release --lib --target aarch64-apple-ios-sim
CARGO_TARGET_DIR="$BUILD/cargo-sim-x64" cargo build --release --lib --target x86_64-apple-ios
popd >/dev/null

cp "$BUILD/cargo-device/aarch64-apple-ios/release/libveilknit_daemon.a" "$BUILD/device/libVeilKnit.a"
lipo -create \
  "$BUILD/cargo-sim-arm64/aarch64-apple-ios-sim/release/libveilknit_daemon.a" \
  "$BUILD/cargo-sim-x64/x86_64-apple-ios/release/libveilknit_daemon.a" \
  -output "$BUILD/simulator/libVeilKnit.a"

xcodebuild -create-xcframework \
  -library "$BUILD/device/libVeilKnit.a" -headers "$ROOT/Native/include" \
  -library "$BUILD/simulator/libVeilKnit.a" -headers "$ROOT/Native/include" \
  -output "$OUT"

echo "Created $OUT"
