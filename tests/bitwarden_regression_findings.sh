#!/bin/bash
# Regression tests for the PR #166 review findings that are reproducible
# against a live vault (designed for the disposable-Vaultwarden harness, but
# any unlocked vault works). Each test prints:
#   REPRODUCED — the bug is present (expected before the fix)
#   FIXED      — the documented behavior is correct
# Exit 0 iff all findings are FIXED, so this script goes green as the review
# is addressed. Run via: RUN_REGRESSIONS=1 tests/vaultwarden_harness.sh
#
# Covered findings (bw.rs review, 2026-07-23):
#   R1  P1  linked custom field (type 3) anywhere in the vault aborts writes
#   R2  P1  named custom field lost when creating a new item (field=api_key)
#   R3  P1  updates to non-login items write `password` while reads use the
#           type-specific default (set succeeds, get returns the old value)
#   R4  P2  update matches field names case-sensitively while reads are
#           case-insensitive (duplicate field, stale reads)
set -uo pipefail

: "${BW_SESSION:?BW_SESSION required (unlocked vault)}"
export BW_SESSION

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="$REPO_ROOT/target/debug/secretspec"
[ -x "$BIN" ] || { echo "Build first: cargo build --bin secretspec" >&2; exit 2; }

WORKDIR=$(mktemp -d)
CREATED_IDS=()
FIXED=0; REPRODUCED=0

cleanup() {
  for id in ${CREATED_IDS[@]+"${CREATED_IDS[@]}"}; do
    bw delete item "$id" >/dev/null 2>&1 || true
  done
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

mk_item() { # mk_item <json> -> echoes id, tracks for cleanup
  local id
  id=$(printf '%s' "$1" | bw encode | bw create item | jq -r '.id')
  [ -n "$id" ] && [ "$id" != "null" ] || { echo "item creation failed" >&2; return 1; }
  CREATED_IDS+=("$id")
  echo "$id"
}

item_json() { # item_json <name> <type:1 login|2 note> [fields-json]
  jq -n --arg name "$1" --argjson type "$2" --argjson fields "${3:-[]}" '
    {organizationId: null, collectionIds: null, folderId: null, type: $type,
     name: $name, notes: (if $type == 2 then "old-note-value" else null end),
     favorite: false, fields: $fields,
     login: (if $type == 1 then {username: null, password: "unused", totp: null} else null end),
     secureNote: (if $type == 2 then {type: 0} else null end)}'
}

report() { # report <id> <desc> <fixed:0|1> [detail]
  if [ "$3" = "1" ]; then
    FIXED=$((FIXED+1));      printf '  \033[0;32mFIXED\033[0m      %s — %s\n' "$1" "$2"
  else
    REPRODUCED=$((REPRODUCED+1)); printf '  \033[0;31mREPRODUCED\033[0m %s — %s%s\n' "$1" "$2" "${4:+ ($4)}"
  fi
}

cat > "$WORKDIR/secretspec.toml" <<'EOF'
[project]
name = "bw-regression"
revision = "1.0"

[profiles.default]
regr_canary = { required = false, description = "R1 canary write", ref = { item = "Regr Canary Login" } }
regr_new_api_key = { required = false, description = "R2 named field on create", ref = { item = "Regr New Login", field = "api_key" } }
regr_note = { required = false, description = "R3 secure note default", ref = { item = "Regr Note" } }
regr_case = { required = false, description = "R4 case-insensitive update", ref = { item = "Regr Case Item", field = "api_key" } }
EOF
cd "$WORKDIR" || exit 2

SS() { "$BIN" "$@" --provider bw:// 2>&1; }

echo "── R1: linked custom field (type 3) poisons unrelated writes ──"
LINKED_ID=$(mk_item "$(item_json "Regr Linked Item" 1 '[{"name":"linked_username","value":null,"type":3,"linkedId":100}]')")
OUT=$(SS set regr_canary canary-value); RC=$?
if [ $RC -eq 0 ] && ! grep -qi "unknown field type" <<<"$OUT"; then
  report R1 "write succeeds with a linked field present in the vault" 1
else
  report R1 "any write aborts while a linked field exists" 0 "$(grep -oi 'unknown field type[^\"]*' <<<"$OUT" | head -1)"
fi
bw delete item "$LINKED_ID" >/dev/null 2>&1 && CREATED_IDS=(${CREATED_IDS[@]+"${CREATED_IDS[@]/$LINKED_ID}"})
bw sync >/dev/null 2>&1

echo "── R2: named custom field preserved when creating a new item ──"
SS set regr_new_api_key sk_regr_12345 >/dev/null
NEW_ID=$(bw get item "Regr New Login" 2>/dev/null | jq -r '.id' || true)
[ -n "$NEW_ID" ] && [ "$NEW_ID" != "null" ] && CREATED_IDS+=("$NEW_ID")
GOT=$(SS get regr_new_api_key) || true
if [ "$GOT" = "sk_regr_12345" ]; then
  report R2 "get returns the value through the declared custom field" 1
else
  report R2 "value not readable via field=api_key after create" 0 "stored in login.password instead"
fi

echo "── R3: type-specific default on update (secure note) ──"
mk_item "$(item_json "Regr Note" 2)" >/dev/null
GOT=$(SS get regr_note) || true
[ "$GOT" = "old-note-value" ] || echo "  (pre-check unexpected: get returned '$GOT')"
SS set regr_note new-note-value >/dev/null
GOT=$(SS get regr_note) || true
if [ "$GOT" = "new-note-value" ]; then
  report R3 "set targets the same default field the getter reads" 1
else
  report R3 "set wrote a password field; get still returns '$GOT'" 0
fi

echo "── R4: case-insensitive field matching on update ──"
mk_item "$(item_json "Regr Case Item" 1 '[{"name":"API_KEY","value":"old-value","type":1}]')" >/dev/null
GOT=$(SS get regr_case) || true
[ "$GOT" = "old-value" ] || echo "  (pre-check unexpected: get returned '$GOT')"
SS set regr_case new-value >/dev/null
GOT=$(SS get regr_case) || true
if [ "$GOT" = "new-value" ]; then
  report R4 "update matched the existing field case-insensitively" 1
else
  report R4 "update added a duplicate field; get still returns '$GOT'" 0
fi

echo
echo "Findings fixed: $FIXED · reproduced: $REPRODUCED"
[ "$REPRODUCED" -eq 0 ]
