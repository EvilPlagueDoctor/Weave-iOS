#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
"$ROOT/Scripts/generate_project.sh"
cd "$ROOT"
xcodebuild -project WeaveIOS.xcodeproj -scheme WeaveIOS -sdk iphonesimulator -configuration Debug \
  CODE_SIGNING_ALLOWED=NO -derivedDataPath "$ROOT/build/DerivedData" build
