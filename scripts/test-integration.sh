#!/usr/bin/env bash
# Runs the data-plane integration suite against a disposable PostgreSQL container.
set -euo pipefail
cd "$(dirname "$0")/../data-plane"
PORT="${RV_TEST_PG_PORT:-55432}"
docker rm -f rv-test-pg >/dev/null 2>&1 || true
docker run -d --name rv-test-pg -e POSTGRES_USER=rv -e POSTGRES_PASSWORD=rvtest -e POSTGRES_DB=rv_test -p "127.0.0.1:${PORT}:5432" postgres:16-alpine >/dev/null
trap 'docker rm -f rv-test-pg >/dev/null 2>&1 || true' EXIT
for _ in $(seq 1 60); do
  docker exec rv-test-pg pg_isready -U rv -d rv_test >/dev/null 2>&1 && break
  sleep 1
done
sleep 1
RV_TEST_DATABASE_URL="postgres://rv:rvtest@127.0.0.1:${PORT}/rv_test?sslmode=disable" go test ./internal/integration/ -count=1 -v "$@" 2>&1 | grep -E '^(--- |ok|FAIL|PASS|panic|    integration)'
