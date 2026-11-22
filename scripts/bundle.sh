#!/usr/bin/env bash
# Builds the release bundle: images as a tar with checksums, for connected and
# air-gapped installs. Signs with cosign when COSIGN_KEY is set.
set -euo pipefail
VERSION="${1:?usage: bundle.sh <version>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/deploy/compose/bundle/$VERSION"
mkdir -p "$OUT"
cd "$ROOT/deploy/compose"
export RV_VERSION="$VERSION"
docker compose --profile logs --profile ai --profile proxy --profile adapters --profile files --profile tools build --quiet
docker save -o "$OUT/images.tar" rv/vault-api:"$VERSION" rv/control-api:"$VERSION" rv/console:"$VERSION" rv/log-processor:"$VERSION" rv/ai-gateway:"$VERSION" rv/http-proxy:"$VERSION" rv/adapters:"$VERSION" rv/file-redactor:"$VERSION" rv/tools:"$VERSION" caddy:2-alpine postgres:16-alpine openbao/openbao:2.4
cp docker-compose.yml Caddyfile openbao.hcl pg_hba.conf rv "$OUT/"
(cd "$OUT" && shasum -a 256 images.tar docker-compose.yml Caddyfile openbao.hcl pg_hba.conf rv > SHA256SUMS)
if [ -n "${RV_VENDOR_KEY_FILE:-}" ]; then
  docker run --rm -v "$OUT:/work" -v "$RV_VENDOR_KEY_FILE:/vendor.key:ro" rv/tools:"$VERSION" bundle sign /work /vendor.key
else
  echo "RV_VENDOR_KEY_FILE is not set: this bundle is UNSIGNED, and rv bundle verify will refuse it." >&2
fi
echo "$OUT"
