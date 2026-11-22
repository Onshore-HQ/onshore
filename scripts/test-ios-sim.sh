#!/usr/bin/env bash
# Runs the iOS SDK's real views on a simulator against a fresh install.
# Destroys this project's Compose containers and volumes, like scripts/e2e.sh.
# Needs Xcode with an iOS simulator runtime. Set DEVELOPER_DIR if it is not the selected Xcode.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
OUT="${RV_IOS_OUT:-$(mktemp -d)}"
mkdir -p "$OUT"
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.e2e.yml --profile logs --profile ai --profile proxy --profile adapters --profile files"

# RV_IOS_REUSE=1 keeps the install from an earlier run with the same RV_IOS_OUT, while working on the SDK.
if [ "${RV_IOS_REUSE:-}" = "1" ] && [ -f "$OUT/setup.json" ]; then
  echo "== reusing the install"
else
  rm -f "$OUT/setup.json"
  echo "== installing"
  RV_E2E_SETUP_ONLY=1 "$ROOT/scripts/e2e.sh" > "$OUT/install.log" 2>&1 || { tail -20 "$OUT/install.log"; exit 1; }
  export RV_E2E_BOOTSTRAP="$(sed -n 's/^BOOTSTRAP=//p' "$OUT/install.log")"
  # One heavy thing at a time: these do not take part, and a simulator is heavy enough.
  (cd "$ROOT/deploy/compose" && $COMPOSE stop log-processor ai-gateway http-proxy adapters file-redactor console) >/dev/null 2>&1
fi
(cd "$ROOT/sdks/node" && npm run -s build)

rm -rf "$OUT/result.xcresult"
RUNTIME="$(xcrun simctl list runtimes -j | python3 -I -c 'import json,sys; r=[x for x in json.load(sys.stdin)["runtimes"] if x["platform"]=="iOS" and x["isAvailable"]]; print(r[-1]["identifier"])')"
[ -n "$RUNTIME" ] || { echo "no iOS simulator runtime"; exit 1; }
TYPE="${RV_IOS_DEVICE_TYPE:-com.apple.CoreSimulator.SimDeviceType.iPhone-16}"
xcrun simctl delete rv-ios-test >/dev/null 2>&1
DEVICE="$(xcrun simctl create rv-ios-test "$TYPE" "$RUNTIME")" || exit 1
echo "== simulator $DEVICE on $RUNTIME"
xcrun simctl boot "$DEVICE"
xcrun simctl bootstatus "$DEVICE" -b >/dev/null 2>&1

RV_E2E_SDK="$ROOT/sdks/node/dist/index.js" RV_IOS_PROJECT="$ROOT/sdks/ios/TestHost/RVTestHost.xcodeproj" RV_IOS_RESULT="$OUT/result.xcresult" RV_IOS_DERIVED="$OUT/derived" RV_IOS_DEVICE="$DEVICE" RV_IOS_SETUP="$OUT/setup.json" NODE_TLS_REJECT_UNAUTHORIZED=0 \
  node --no-warnings "$ROOT/scripts/test-ios-sim.mjs"
RC=$?

rm -rf "$OUT/shots"; mkdir -p "$OUT/shots"
xcrun xcresulttool export attachments --path "$OUT/result.xcresult" --output-path "$OUT/shots" >/dev/null 2>&1
xcrun simctl shutdown "$DEVICE" >/dev/null 2>&1
xcrun simctl delete "$DEVICE" >/dev/null 2>&1
echo "== results in $OUT, exit $RC"
exit $RC
