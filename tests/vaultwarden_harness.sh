#!/bin/bash
# Fully-automated bitwarden_integration.sh run against a disposable local
# Vaultwarden — no real vault, no repository secrets, works on fork PRs.
# Implements the FUTURE WORK plan from bitwarden_integration.sh.
#
# Pipeline:
#   1. vaultwarden container (volatile storage) + caddy TLS proxy in front —
#      the 2026+ `bw` CLI refuses plain http:// servers, so TLS with an
#      internal self-signed cert is REQUIRED, with NODE_TLS_REJECT_UNAUTHORIZED=0
#      for the fixture run only.
#   2. Fixture account registered via the identity API (vaultwarden_bootstrap.py
#      implements the client-side registration crypto that `bw` doesn't expose).
#   3. `bw` CLI pointed at the disposable server via an isolated
#      BITWARDENCLI_APPDATA_DIR — the developer's real bw config is untouched.
#   4. tests/bitwarden_integration.sh runs unchanged.
#
# Requirements: docker, python3 (+`cryptography`, auto-installed in a venv),
# bw CLI, jq, cargo. Fixture credentials are committable constants, not secrets.
#
# Usage: tests/vaultwarden_harness.sh [--keep]   # --keep: leave containers up
set -euo pipefail

HARNESS_DIR=$(mktemp -d)
VW_NAME="vw-harness-$$"
TLS_NAME="vw-harness-tls-$$"
NET_NAME="vw-harness-net-$$"
TLS_PORT="${VW_TLS_PORT:-18443}"
FIXTURE_EMAIL="ci-fixture@example.test"
FIXTURE_PASSWORD="fixture-master-password"
KEEP=false
[ "${1:-}" = "--keep" ] && KEEP=true

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)

cleanup() {
  local rc=$?
  if [ "$KEEP" = false ]; then
    docker stop "$TLS_NAME" "$VW_NAME" >/dev/null 2>&1 || true
    docker network rm "$NET_NAME" >/dev/null 2>&1 || true
    rm -rf "$HARNESS_DIR"
  else
    echo "--keep: containers $VW_NAME / $TLS_NAME left running (port $TLS_PORT)"
  fi
  exit $rc
}
trap cleanup EXIT

for dep in docker python3 bw jq cargo; do
  command -v "$dep" >/dev/null || { echo "Missing dependency: $dep" >&2; exit 1; }
done

echo "── 1/4 disposable vaultwarden + TLS proxy ──"
docker network create "$NET_NAME" >/dev/null
docker run -d --rm --name "$VW_NAME" --network "$NET_NAME" \
  -e SIGNUPS_ALLOWED=true -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  vaultwarden/server:latest >/dev/null
docker run -d --rm --name "$TLS_NAME" --network "$NET_NAME" -p "$TLS_PORT:$TLS_PORT" \
  caddy:latest caddy reverse-proxy --from "https://localhost:$TLS_PORT" \
  --to "$VW_NAME:80" --internal-certs >/dev/null

for _ in $(seq 1 30); do
  curl -sk -o /dev/null "https://localhost:$TLS_PORT/alive" && break
  sleep 1
done
curl -sk -o /dev/null "https://localhost:$TLS_PORT/alive" \
  || { echo "vaultwarden did not come up" >&2; exit 1; }
echo "✓ vaultwarden alive on https://localhost:$TLS_PORT"

echo "── 2/4 fixture account ──"
if ! python3 -c "import cryptography" 2>/dev/null; then
  python3 -m venv "$HARNESS_DIR/venv"
  "$HARNESS_DIR/venv/bin/pip" install -q cryptography
  PYTHON="$HARNESS_DIR/venv/bin/python"
else
  PYTHON=python3
fi
"$PYTHON" "$REPO_ROOT/tests/vaultwarden_bootstrap.py" \
  --server "https://localhost:$TLS_PORT" --email "$FIXTURE_EMAIL" \
  --password "$FIXTURE_PASSWORD"

echo "── 3/4 bw login (isolated appdata) ──"
export BITWARDENCLI_APPDATA_DIR="$HARNESS_DIR/bw-appdata"
export NODE_TLS_REJECT_UNAUTHORIZED=0   # self-signed internal cert, local only
mkdir -p "$BITWARDENCLI_APPDATA_DIR"
bw config server "https://localhost:$TLS_PORT" >/dev/null
BW_SESSION=$(bw login "$FIXTURE_EMAIL" "$FIXTURE_PASSWORD" --raw)
export BW_SESSION
echo "✓ logged in as $FIXTURE_EMAIL"

echo "── 4/4 integration suite ──"
cd "$REPO_ROOT"
bash tests/bitwarden_integration.sh "$BW_SESSION" </dev/null

# Optional: regression tests for the PR #166 review findings. They exit
# non-zero while any finding is still REPRODUCED, so they're opt-in until
# the fixes land — then they become part of the green path.
if [ "${RUN_REGRESSIONS:-0}" = "1" ]; then
  echo "── regressions: review findings ──"
  bash tests/bitwarden_regression_findings.sh </dev/null
fi
