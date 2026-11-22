#!/usr/bin/env bash
# Tests the PKCS#11 backend against SoftHSM2. A hardware HSM uses the same interface,
# with the vendor's module, slot label and PIN.
set -euo pipefail
cd "$(dirname "$0")/.."
docker run --rm -v "$PWD/data-plane:/src:ro" -v rv-gomod:/go/pkg/mod -w /src golang:1.27.3-bookworm sh -c '
  apt-get update -qq && apt-get install -y -qq softhsm2 >/dev/null
  softhsm2-util --init-token --free --label rv --pin 1234 --so-pin 5678 >/dev/null
  PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so PKCS11_SLOT_LABEL=rv PKCS11_PIN=1234 CGO_ENABLED=1 go test -tags hsm ./internal/keys/ -count=1 -v 2>&1 | grep -E "^(---|ok|FAIL|PASS|panic)|pkcs11_test"
'
