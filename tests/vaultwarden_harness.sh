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
# The devenv shell provides the docker *client*; the container runtime itself is
# yours to supply and start (Docker Desktop, colima, or `podman machine start`
# with /var/run/docker.sock symlinked to the podman socket).
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
	command -v "$dep" >/dev/null || {
		echo "Missing dependency: $dep" >&2
		exit 1
	}
done

# The `bw` CLI is the client under test, so its version changes what the suites
# below observe. One difference has already cost a round of confused reports:
# before bitwarden/clients e1aa943b (2026-07-13, first shipped in CLI 2026.7.0)
# `searchCiphersBasic` stripped diacritics from a search query but not from the
# item names it compared against, so `--search überblick` found nothing for an
# item named `Überblick`.
#
# The provider no longer depends on that — it re-lists unfiltered when the
# narrowed search comes back empty — so this is a warning rather than a gate:
# an older CLI still exercises the fix, which is exactly where it matters.
BW_VERSION=$(bw --version 2>/dev/null | tr -d '[:space:]')
BW_DIACRITIC_FIX="2026.7.0"
if [ -n "$BW_VERSION" ] && [ "$BW_VERSION" != "$BW_DIACRITIC_FIX" ] &&
	[ "$(printf '%s\n%s\n' "$BW_VERSION" "$BW_DIACRITIC_FIX" | sort -V | head -1)" = "$BW_VERSION" ]; then
	echo "note: bw $BW_VERSION predates $BW_DIACRITIC_FIX, whose searchCiphersBasic" >&2
	echo "      fixed diacritic normalization. R11 exercises the provider's fallback" >&2
	echo "      for exactly this; if it fails, that fallback is the thing to look at." >&2
fi

echo "── 1/5 disposable vaultwarden + TLS proxy ──"
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
curl -sk -o /dev/null "https://localhost:$TLS_PORT/alive" ||
	{
		echo "vaultwarden did not come up" >&2
		exit 1
	}
echo "✓ vaultwarden alive on https://localhost:$TLS_PORT"

echo "── 2/5 fixture account ──"
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

echo "── 3/5 bw login (isolated appdata) ──"
export BITWARDENCLI_APPDATA_DIR="$HARNESS_DIR/bw-appdata"
export NODE_TLS_REJECT_UNAUTHORIZED=0 # self-signed internal cert, local only
mkdir -p "$BITWARDENCLI_APPDATA_DIR"

# Isolate Monosecret's own config the same way, and for the same reason. A
# `[defaults] profile = "..."` in the developer's ~/.config/monosecret/config.toml
# applies to the suites below, whose monosecret.toml defines only `default`, so
# every get/set fails with "Invalid profile: ... is not defined in
# monosecret.toml". That reads as a wholesale provider failure and has nothing
# to do with the provider. XDG_CONFIG_HOME is the path Monosecret resolves the
# user config through on macOS too.
export XDG_CONFIG_HOME="$HARNESS_DIR/xdg-config"
mkdir -p "$XDG_CONFIG_HOME"
bw config server "https://localhost:$TLS_PORT" >/dev/null
BW_SESSION=$(bw login "$FIXTURE_EMAIL" "$FIXTURE_PASSWORD" --raw)
export BW_SESSION
echo "✓ logged in as $FIXTURE_EMAIL"

echo "── 4/5 organization + collections fixture ──"
# The `bw` CLI cannot create an organization, so the bootstrap does it through
# the API; collections it *can* create, so those go through the CLI. Two of
# them, because a collection name duplicated across collections is what proves
# an address resolves to one specific collection rather than to the whole
# organization.
if [ "${SKIP_ORG_FIXTURE:-0}" = "1" ]; then
	echo "SKIP_ORG_FIXTURE=1 — collection addressing tests will be skipped"
else
	BW_TEST_ORG_NAME="Monosecret CI"
	BW_TEST_ORG_ID=$("$PYTHON" "$REPO_ROOT/tests/vaultwarden_bootstrap.py" \
		--server "https://localhost:$TLS_PORT" --email "$FIXTURE_EMAIL" \
		--password "$FIXTURE_PASSWORD" --create-org "$BW_TEST_ORG_NAME" \
		--collection-name "default")

	# The organization is created through the API behind the CLI's back, so the
	# CLI only learns about it — and about the key it needs to decrypt anything
	# inside it — on the next sync. A single sync is not reliably enough: this
	# step failed intermittently (2 runs in 4) with `bw` falling back to an
	# interactive master-password prompt, which then swallowed the piped
	# base64 payload and reported the misleading "Invalid master password."
	# Wait for the organization to actually appear before creating collections.
	#
	# --nointeraction everywhere below is what keeps a future variant of that
	# failure honest: `bw` errors out instead of prompting, so the message names
	# the real problem rather than whatever landed on stdin.
	for _ in $(seq 1 10); do
		bw sync --nointeraction >/dev/null 2>&1 || true
		if bw list organizations --nointeraction 2>/dev/null |
			jq -e --arg o "$BW_TEST_ORG_ID" 'any(.[]; .id == $o)' >/dev/null; then
			break
		fi
		sleep 1
	done
	bw list organizations --nointeraction 2>/dev/null |
		jq -e --arg o "$BW_TEST_ORG_ID" 'any(.[]; .id == $o)' >/dev/null ||
		{
			echo "organization $BW_TEST_ORG_ID never reached the bw CLI" >&2
			exit 1
		}

	mk_collection() { # mk_collection <name> -> echoes the new collection's id
		jq -nc --arg o "$BW_TEST_ORG_ID" --arg n "$1" \
			'{organizationId:$o,name:$n,externalId:null,groups:[]}' |
			bw encode |
			bw create org-collection --nointeraction \
				--organizationid "$BW_TEST_ORG_ID" |
			jq -r '.id'
	}
	BW_TEST_COLL_DEV_ID=$(mk_collection "dev-secrets")
	BW_TEST_COLL_PROD_ID=$(mk_collection "prod-secrets")

	# The organization race above, one level down. `bw create org-collection`
	# returns the id the server assigned, but `bw list collections` answers from
	# the locally-synced vault, which may not carry the new collection yet. A
	# single blind `bw sync` was enough most of the time; when it wasn't, the
	# fixture still printed both ids and `collection addressing` then failed 9 of
	# 11 with "No collection matching 'prod-secrets' is visible", naming only the
	# org's `default` collection. Wait for both to actually be listable.
	collections_visible() {
		bw list collections --nointeraction 2>/dev/null |
			jq -e --arg d "$BW_TEST_COLL_DEV_ID" --arg p "$BW_TEST_COLL_PROD_ID" \
				'any(.[]; .id == $d) and any(.[]; .id == $p)' >/dev/null
	}
	for _ in $(seq 1 10); do
		bw sync --nointeraction >/dev/null 2>&1 || true
		if collections_visible; then break; fi
		sleep 1
	done
	collections_visible || {
		echo "collections dev-secrets ($BW_TEST_COLL_DEV_ID) and prod-secrets" \
			"($BW_TEST_COLL_PROD_ID) never reached the bw CLI" >&2
		exit 1
	}

	export BW_TEST_ORG_ID BW_TEST_ORG_NAME BW_TEST_COLL_DEV_ID BW_TEST_COLL_PROD_ID
	echo "✓ org '$BW_TEST_ORG_NAME' ($BW_TEST_ORG_ID)"
	echo "  dev-secrets  $BW_TEST_COLL_DEV_ID"
	echo "  prod-secrets $BW_TEST_COLL_PROD_ID"
fi

# Every suite runs even when an earlier one fails, and the worst status wins.
# Under `set -e` the first failure would abort the harness, so one unrelated
# integration failure would hide every regression finding -- exactly the report
# you need when checking which findings are still REPRODUCED.
SUITES_FAILED=0
run_suite() { # run_suite <label> <script> [args...]
	local label="$1"
	shift
	local rc=0
	echo "── $label ──"
	# `|| rc=$?` both captures the status and keeps `set -e` from aborting here,
	# which is the point: a failing suite must not stop the ones after it.
	bash "$@" </dev/null || rc=$?
	if [ "$rc" -ne 0 ]; then
		SUITES_FAILED=$((SUITES_FAILED + 1))
		echo "!! $label failed (exit $rc)" >&2
	fi
}

cd "$REPO_ROOT"
run_suite "5/5 integration suite" tests/bitwarden_integration.sh "$BW_SESSION"

# Optional: regression tests for the PR #166 review findings. They exit
# non-zero while any finding is still REPRODUCED, so they're opt-in until
# the fixes land — then they become part of the green path.
if [ "${RUN_REGRESSIONS:-0}" = "1" ]; then
	run_suite "regressions: review findings" tests/bitwarden_regression_findings.sh
fi

# C3: organization and collection name resolution. Skips itself when the
# fixture above did not run.
run_suite "collection addressing" tests/bitwarden_collection_addressing.sh

if [ "$SUITES_FAILED" -ne 0 ]; then
	echo "$SUITES_FAILED suite(s) failed" >&2
	exit 1
fi
echo "all suites passed"
