#!/bin/bash
# End-to-end tests for organization and collection addressing (review finding C3).
#
# `bw list items --collectionid` accepts a UUID, but `bw://myorg@dev-secrets`
# reads as a pair of names, so the provider resolves names to ids. These tests
# prove that resolution reaches one specific collection rather than the whole
# organization.
#
# The fixture that makes them meaningful is two collections holding an item of
# the *same name* with different values. Without name resolution both addresses
# find nothing; if the two `bw list` filters were combined (the CLI ORs them)
# both addresses would find the same superset and the dev/prod assertions could
# not both hold. Only a correct implementation passes.
#
# Requires the organization fixture from tests/vaultwarden_harness.sh. Skips
# cleanly when it is absent, so this stays runnable against a personal vault.
set -uo pipefail

if [ -z "${BW_TEST_ORG_ID:-}" ]; then
  echo "── collection addressing: SKIPPED (no BW_TEST_ORG_ID fixture) ──"
  echo "   Run via tests/vaultwarden_harness.sh, which creates the organization."
  exit 0
fi

: "${BW_SESSION:?BW_SESSION required (unlocked vault)}"
: "${BW_TEST_ORG_NAME:?BW_TEST_ORG_NAME required}"
: "${BW_TEST_COLL_DEV_ID:?BW_TEST_COLL_DEV_ID required}"
: "${BW_TEST_COLL_PROD_ID:?BW_TEST_COLL_PROD_ID required}"
export BW_SESSION

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="$REPO_ROOT/target/debug/secretspec"
[ -x "$BIN" ] || { echo "Build first: cargo build --bin secretspec" >&2; exit 2; }

WORKDIR=$(mktemp -d)
CREATED_IDS=()
PASSED=0; FAILED=0

cleanup() {
  for id in ${CREATED_IDS[@]+"${CREATED_IDS[@]}"}; do
    bw delete item "$id" >/dev/null 2>&1 || true
  done
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

# A collection name reaches the provider through a URI host, which the URL
# parser lowercases, so only the collection's lowercase form is addressable by
# name. Spaces in an organization name must be percent-encoded.
ORG_ENC=${BW_TEST_ORG_NAME// /%20}

mk_item_in() { # mk_item_in <collection-id> <name> <password> -> echoes id
  local id
  id=$(jq -nc --arg o "$BW_TEST_ORG_ID" --arg c "$1" --arg n "$2" --arg p "$3" \
        '{organizationId:$o, collectionIds:[$c], folderId:null, type:1,
          name:$n, notes:null, favorite:false, fields:[],
          login:{username:null, password:$p, totp:null, uris:[]}}' \
      | bw encode | bw create item --organizationid "$BW_TEST_ORG_ID" | jq -r '.id')
  [ -n "$id" ] && [ "$id" != "null" ] || { echo "item creation failed" >&2; return 1; }
  CREATED_IDS+=("$id")
  echo "$id"
}

pass() { PASSED=$((PASSED+1)); printf '  \033[0;32mPASS\033[0m  %s\n' "$1"; }
fail() { FAILED=$((FAILED+1)); printf '  \033[0;31mFAIL\033[0m  %s\n     %s\n' "$1" "$2"; }

check_eq() { # check_eq <desc> <expected> <actual>
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "expected '$2', got '$3'"; fi
}

check_contains() { # check_contains <desc> <needle> <haystack>
  if grep -qi -- "$2" <<<"$3"; then pass "$1"; else fail "$1" "no '$2' in: $(head -c 300 <<<"$3")"; fi
}

cat > "$WORKDIR/secretspec.toml" <<'EOF'
[project]
name = "bw-collections"
revision = "1.0"

[profiles.default]
shared_secret = { required = false, description = "same name in two collections", ref = { item = "Shared Secret" } }
fresh_secret = { required = false, description = "created by secretspec", ref = { item = "Fresh Collection Secret" } }
EOF
cd "$WORKDIR" || exit 2

SS() { "$BIN" "$@" 2>&1; }

echo "── fixture: one item name, two collections ──"
mk_item_in "$BW_TEST_COLL_DEV_ID"  "Shared Secret" "dev-value"  >/dev/null || exit 2
mk_item_in "$BW_TEST_COLL_PROD_ID" "Shared Secret" "prod-value" >/dev/null || exit 2
bw sync >/dev/null 2>&1
echo "✓ 'Shared Secret' exists in dev-secrets (dev-value) and prod-secrets (prod-value)"

echo
echo "── names resolve to the collection they name ──"
check_eq "bw://ORG@dev-secrets reads the dev copy" \
  "dev-value" "$(SS get shared_secret --provider "bw://$ORG_ENC@dev-secrets")"

# The discriminating assertion: this and the one above cannot both hold unless
# each address narrows to its own collection.
check_eq "bw://ORG@prod-secrets reads the prod copy" \
  "prod-value" "$(SS get shared_secret --provider "bw://$ORG_ENC@prod-secrets")"

echo
echo "── a collection addressed alone supplies its organization ──"
check_eq "bw://dev-secrets resolves without naming the organization" \
  "dev-value" "$(SS get shared_secret --provider "bw://dev-secrets")"

echo
echo "── ids remain addressable ──"
check_eq "bw://<org-uuid>@<collection-uuid> still works" \
  "prod-value" "$(SS get shared_secret --provider "bw://$BW_TEST_ORG_ID@$BW_TEST_COLL_PROD_ID")"

echo
echo "── unresolvable addresses fail loudly ──"
OUT=$(SS get shared_secret --provider "bw://$ORG_ENC@no-such-collection")
check_contains "an unknown collection name is an error" "No collection matching" "$OUT"
check_contains "the error lists what does exist" "prod-secrets" "$OUT"

OUT=$(SS get shared_secret --provider "bw://$ORG_ENC@ffffffff-ffff-4fff-8fff-ffffffffffff")
check_contains "an unknown collection id is an error, not an empty result" \
  "No collection matching" "$OUT"

echo
echo "── writes stay inside the addressed collection ──"
# Under the CLI's OR semantics a second filter would widen the candidate set to
# the whole organization, and the name match would update whichever copy came
# back first — silently overwriting the prod secret with a dev value.
SS set shared_secret updated-dev-value --provider "bw://$ORG_ENC@dev-secrets" >/dev/null
bw sync >/dev/null 2>&1
check_eq "set updated the addressed collection" \
  "updated-dev-value" "$(SS get shared_secret --provider "bw://$ORG_ENC@dev-secrets")"
check_eq "set left the sibling collection untouched" \
  "prod-value" "$(SS get shared_secret --provider "bw://$ORG_ENC@prod-secrets")"

echo
echo "── created items are filed into the addressed collection ──"
SS set fresh_secret fresh-value --provider "bw://$ORG_ENC@prod-secrets" >/dev/null
bw sync >/dev/null 2>&1
FRESH=$(bw list items --collectionid "$BW_TEST_COLL_PROD_ID" \
        | jq -r '[.[] | select(.name=="Fresh Collection Secret")] | .[0].id // empty')
[ -n "$FRESH" ] && CREATED_IDS+=("$FRESH")
if [ -n "$FRESH" ]; then
  pass "a new item lands in the collection that was addressed"
else
  fail "a new item lands in the collection that was addressed" \
    "not found in prod-secrets; it likely went to the personal vault"
fi
check_eq "and is readable back through that address" \
  "fresh-value" "$(SS get fresh_secret --provider "bw://$ORG_ENC@prod-secrets")"

echo
echo "Collection addressing — passed: $PASSED · failed: $FAILED"
[ "$FAILED" -eq 0 ]
