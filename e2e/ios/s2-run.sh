#!/usr/bin/env bash
# Spike S2 harness: build the app + NSE, install it on a Simulator, send the sealed pushes with `xcrun simctl push`
# (which does NOT start the NSE), then run the NSE class in-process (`-nse-selftest`) and print its results.
#
# Needs macOS with Xcode (tested: Xcode 27.0, iOS 18.3.1 and 27.0 runtimes), xcodegen, xcrun, uv.
# Not run in CI: it needs a Simulator. Usage: e2e/ios/s2-run.sh <device-udid>
#   xcrun simctl create "S2 iPhone 16" com.apple.CoreSimulator.SimDeviceType.iPhone-16 <any installed iOS runtime id>
set -euo pipefail

DEV="${1:?usage: s2-run.sh <device-udid>}"
for tool in xcodegen xcrun uv xcodebuild; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool (brew install xcodegen; Xcode; uv)" >&2; exit 2; }
done
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
S2="$ROOT/spikes/s2"
BID=io.severin.orch
GROUP=group.io.severin.orch
SHOTS="${SHOTS:-$S2/out/shots}"
BOOTED_BY_US=0
mkdir -p "$SHOTS"

cleanup() {
  xcrun simctl terminate "$DEV" "$BID" >/dev/null 2>&1 || true
  xcrun simctl uninstall "$DEV" "$BID" >/dev/null 2>&1 || true
  if [ "$BOOTED_BY_US" = 1 ]; then xcrun simctl shutdown "$DEV" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

cd "$ROOT"
uv run python spikes/s2/make_push.py "$S2/out"
cp "$S2/out/demo_material.json" "$S2/App/demo_material.json"      # generated, gitignored
(cd "$S2/App" && xcodegen generate >/dev/null)

if ! xcrun simctl list devices booted | grep -q "$DEV"; then xcrun simctl boot "$DEV"; BOOTED_BY_US=1; fi
xcrun simctl bootstatus "$DEV" >/dev/null
BUILD_LOG="$S2/out/xcodebuild-$DEV.log"
if ! (cd "$S2/App" && xcodebuild -project OrchS2.xcodeproj -scheme OrchApp -destination "id=$DEV" \
      -derivedDataPath "$S2/DerivedData-$DEV" build >"$BUILD_LOG" 2>&1); then
  grep -E "error:" "$BUILD_LOG" | head -20 || true; echo "build failed, see $BUILD_LOG" >&2; exit 1
fi
grep -E "BUILD" "$BUILD_LOG" || true
APP="$S2/DerivedData-$DEV/Build/Products/Debug-iphonesimulator/OrchApp.app"

xcrun simctl uninstall "$DEV" "$BID" 2>/dev/null || true
xcrun simctl install "$DEV" "$APP"
xcrun simctl launch "$DEV" "$BID"; sleep 4; xcrun simctl terminate "$DEV" "$BID"

echo "== part 1: simctl push (the NSE is expected NOT to run)"
for f in 01_question 02_tampered 03_forged_by_member_device 04_stale_25h 05_question_closed; do
  echo "-- push $f"; xcrun simctl push "$DEV" "$BID" "$S2/out/$f.apns"; sleep 3
done
xcrun simctl launch "$DEV" "$BID" >/dev/null; sleep 3
xcrun simctl io "$DEV" screenshot "$SHOTS/after-simctl-push.png" 2>/dev/null || true
xcrun simctl terminate "$DEV" "$BID"
echo "NSE lines in the app subsystem after simctl push (expected 0):"
xcrun simctl spawn "$DEV" log show --predicate 'subsystem == "io.severin.orch" AND eventMessage BEGINSWITH "NSE"' --last 3m --style compact --info 2>/dev/null | grep -c "NSE " || true

echo "== part 2: the NSE class called in-process (positive control)"
xcrun simctl uninstall "$DEV" "$BID"; xcrun simctl install "$DEV" "$APP"
xcrun simctl launch "$DEV" "$BID" -nse-selftest "$S2/out"
for _ in $(seq 1 60); do
  if xcrun simctl spawn "$DEV" log show --predicate 'subsystem == "io.severin.orch" AND eventMessage == "selftest done"' --last 2m --style compact --info 2>/dev/null | grep -q "selftest done"; then break; fi
  sleep 2
done
xcrun simctl io "$DEV" screenshot "$SHOTS/selftest-end.png" 2>/dev/null || true
echo "-- selftest-result.jsonl"
cat "$(xcrun simctl get_app_container "$DEV" "$BID" "$GROUP")/selftest-result.jsonl"
echo "-- log (reasons only)"
xcrun simctl spawn "$DEV" log show --predicate 'subsystem == "io.severin.orch"' --last 3m --style compact --info 2>/dev/null | grep -E "NSE|selftest" || true
