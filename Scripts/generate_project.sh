#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
command -v xcodegen >/dev/null || { echo "Install XcodeGen: brew install xcodegen" >&2; exit 1; }
[[ -d Native/VeilKnit.xcframework ]] || "$ROOT/Scripts/build_native.sh"
xcodegen generate
