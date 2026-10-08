#!/bin/zsh
# Spike S2: build the app + NSE, install it on a Simulator and send the sealed pushes with `xcrun simctl push`.
# Usage: e2e/ios/s2-run.sh <device-udid>      (create one: xcrun simctl create "S2 iPhone 16" \
#          com.apple.CoreSimulator.SimDeviceType.iPhone-16 com.apple.CoreSimulator.SimRuntime.iOS-18-3)
set -eu
DEV=${1:?device udid}
ROOT=${0:A:h:h:h}
S2=$ROOT/spikes/s2
BID=io.severin.orch
SHOTS=${SHOTS:-$S2/out/shots}
mkdir -p $SHOTS
cd $ROOT
uv run python spikes/s2/make_push.py $S2/out
cp $S2/out/demo_material.json $S2/App/demo_material.json
(cd $S2/App && xcodegen generate >/dev/null)
xcrun simctl boot $DEV 2>/dev/null || true
xcrun simctl bootstatus $DEV >/dev/null
(cd $S2/App && xcodebuild -project OrchS2.xcodeproj -scheme OrchApp -destination "id=$DEV" \
   -derivedDataPath $S2/DerivedData-$DEV build 2>&1 | grep -E "error:|BUILD")
xcrun simctl uninstall $DEV $BID 2>/dev/null || true
xcrun simctl install $DEV $S2/DerivedData-$DEV/Build/Products/Debug-iphonesimulator/OrchApp.app
xcrun simctl launch $DEV $BID; sleep 4; xcrun simctl terminate $DEV $BID
for f in 01_question 02_tampered 03_forged_by_member_device 04_stale_25h 05_question_closed; do
  echo "== push $f"; xcrun simctl push $DEV $BID $S2/out/$f.apns; sleep 4
  xcrun simctl launch $DEV $BID >/dev/null; sleep 2
  xcrun simctl io $DEV screenshot $SHOTS/$f.png 2>/dev/null; xcrun simctl terminate $DEV $BID
done
echo "== selftest: the same NSE code driven in-process (simctl push does not start the extension)"
xcrun simctl uninstall $DEV $BID; xcrun simctl install $DEV $S2/DerivedData-$DEV/Build/Products/Debug-iphonesimulator/OrchApp.app
xcrun simctl launch $DEV $BID -nse-selftest $S2/out; sleep 22
xcrun simctl io $DEV screenshot $SHOTS/selftest-end.png 2>/dev/null
echo "== log"; xcrun simctl spawn $DEV log show --predicate 'subsystem == "io.severin.orch"' --last 3m --style compact --info | grep -v "^Timestamp\|getpwuid"
