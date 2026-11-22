#!/usr/bin/env bash
# Installs the product the way a customer does, then runs scripts/e2e.mjs against
# it. Destroys this project's containers and volumes first.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/deploy/compose"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export COMPOSE_PROGRESS=quiet
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.e2e.yml --profile logs --profile ai --profile proxy --profile adapters --profile files"

$COMPOSE --profile tools down -v --remove-orphans >/dev/null 2>&1 || true
rm -rf .env shares.e2e report.e2e.pdf e2e-py.env e2e-load.env internal-tls

# A vendor licence key pair, built into these test images.
(cd "$ROOT/data-plane" && go run ./cmd/rv license keygen) > "$WORK/vendor"
export RV_LICENCE_PUBLIC_KEY="$(sed -n 's/^public[^:]*: //p' "$WORK/vendor")"
sed -n 's/^private[^:]*: //p' "$WORK/vendor" > "$WORK/vendor.key"
(cd "$ROOT/data-plane" && go run ./cmd/rv license sign -key "$WORK/vendor.key" -customer "${RV_E2E_CUSTOMER:-E2E Test Bank}" -modules logs,enterprise -days 365) > "$WORK/licence"

# One image at a time: with an empty build cache, building them all at once exhausts a 16 GB laptop.
PROFILES="--profile logs --profile ai --profile proxy --profile adapters --profile files --profile tools"
for service in $(docker compose $PROFILES config --services 2>/dev/null); do
  docker compose $PROFILES build --quiet "$service"
done
cp "$WORK/licence" ./licence.e2e
./rv init -host localhost -license /work/licence.e2e | tee "$WORK/init.out"
rm -f ./licence.e2e
BOOTSTRAP="$(sed -n 's/^Bootstrap token for the first admin: //p' "$WORK/init.out")"
printf "RV_HTTPS_PORT=8443\nRV_PUBLIC_PORT=8443\n" >> .env

# The key service must come up before the vault can.
$COMPOSE up -d keys postgres
for _ in $(seq 1 30); do
  docker compose --profile tools run --rm tools keys status >/dev/null 2>&1 && break
  sleep 1
done
docker compose --profile tools run --rm tools keys init -shares-file /work/shares.e2e
$COMPOSE up -d
for path in /healthz /control/healthz /login; do
  for _ in $(seq 1 60); do
    curl -skf "https://localhost:8443$path" >/dev/null 2>&1 && break
    sleep 2
  done
done
curl -sk https://localhost:8443/healthz; echo

if [ "${RV_E2E_SETUP_ONLY:-}" = "1" ]; then
  echo "BOOTSTRAP=$BOOTSTRAP"
  exit 0
fi

# The tests import the built SDK, so it must match the source.
(cd "$ROOT/sdks/node" && npm run -s build)
(cd "$ROOT/sdks/react-native" && npm run -s build)
export RV_E2E_RN="$ROOT/sdks/react-native/dist/client.js" RV_E2E_IOS="$ROOT/sdks/ios" RV_E2E_ANDROID_DIR="$ROOT/sdks/android"
export RV_CONTROL_API_DIR="$ROOT/control-api" RV_E2E_BOOTSTRAP="$BOOTSTRAP" RV_E2E_SDK="$ROOT/sdks/node/dist/index.js" RV_E2E_COMPOSE_DIR="$PWD" RV_E2E_PY="$ROOT/sdks/python" NODE_TLS_REJECT_UNAUTHORIZED=0
node --no-warnings "$ROOT/scripts/e2e.mjs"

python3 -m venv "$WORK/venv" >/dev/null
"$WORK/venv/bin/pip" install -q cryptography >/dev/null
PYTHONPATH="$ROOT/sdks/python" "$WORK/venv/bin/python" "$ROOT/scripts/e2e_python.py" "$PWD/e2e-py.env"
"$ROOT/scripts/test-sdks.sh" "$PWD/e2e-py.env"
rm -f e2e-py.env
