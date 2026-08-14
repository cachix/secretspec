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
#
# Covered findings (bw.rs review round 2, 2026-07-30):
#   R5  P1  a read extracts from the first `--search` hit, so API_KEY can
#           answer with API_KEY_OLD
#   R6  P1  the addressed `?type=` never narrows a read, so a Card and a
#           same-named Login are indistinguishable
#   R7  P1  a write falls back to a substring match and overwrites an
#           unrelated item instead of creating the addressed one
#   R8  P1  an explicit Secure Note field that is absent falls through to the
#           legacy `value` field and then to the note body
#   R9  P1  creation does not recognise the built-in field aliases that
#           reading and updating do (card exp_month, identity first_name)
#   R10 P2  an unsupported `?type=` (and any unknown query key) is discarded
#           rather than reported
#   R11 P2  names fold with ASCII-only case rules, unlike the `bw` CLI
#   R12 P1  the integration suite adopts a same-named real vault item as a
#           mutable fixture and never restores it
set -uo pipefail

# See bitwarden_integration.sh: without a reason, `[project].require_reason`
# ("agents" by default) denies every get/set under a coding agent, and each
# finding below reports itself REPRODUCED on the strength of the denial alone.
export MONOSECRET_REASON="${MONOSECRET_REASON:-bw provider regression checks}"

: "${BW_SESSION:?BW_SESSION required (unlocked vault)}"
export BW_SESSION

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="${MONOSECRET_BIN:-$REPO_ROOT/target/debug/monosecret}"
[ -x "$BIN" ] || {
	echo "Build first: cargo build --bin monosecret" >&2
	exit 2
}

WORKDIR=$(mktemp -d)
CREATED_IDS=()
FIXED=0
REPRODUCED=0

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
	[ -n "$id" ] && [ "$id" != "null" ] || {
		echo "item creation failed" >&2
		return 1
	}
	CREATED_IDS+=("$id")
	echo "$id"
}

item_json() { # item_json <name> <type:1 login|2 note|3 card|4 identity> [fields-json]
	jq -n --arg name "$1" --argjson type "$2" --argjson fields "${3:-[]}" '
    {organizationId: null, collectionIds: null, folderId: null, type: $type,
     name: $name, notes: (if $type == 2 then "old-note-value" else null end),
     favorite: false, fields: $fields,
     login: (if $type == 1 then {username: null, password: "unused", totp: null} else null end),
     card: (if $type == 3 then {cardholderName: null, brand: null, number: null,
                                expMonth: null, expYear: null, code: null} else null end),
     identity: (if $type == 4 then {title: null, firstName: null, middleName: null,
                                    lastName: null, username: null, company: null,
                                    email: null, phone: null} else null end),
     secureNote: (if $type == 2 then {type: 0} else null end)}'
}

item_json_with() { # item_json_with <name> <type> <fields-json> <patch-json>
	item_json "$1" "$2" "$3" | jq --argjson patch "$4" '. * $patch'
}

require_item() { # require_item <name> <json> -> 0 once the CLI can see the item
	local name="$1" json="$2"

	if ! mk_item "$json" >/dev/null; then
		echo "  fixture '$name': the creation command itself failed" >&2
		return 1
	fi

	bw sync --nointeraction >/dev/null 2>&1 || true
	if bw list items --nointeraction 2>/dev/null |
		jq -e --arg n "$name" 'any(.[]; .name == $n)' >/dev/null; then
		return 0
	fi

	# Created, but not listable under the name we asked for. Print what did land,
	# with bytes for anything non-ASCII: that is what separates "the name was
	# mangled on the way in" (e.g. NFC arriving as NFD) from "nothing was
	# created", which a bare absence cannot.
	echo "  fixture '$name': not listable under that exact name. Vault contains:" >&2
	bw list items --nointeraction 2>/dev/null | jq -r '.[].name' |
		while IFS= read -r listed; do
			if LC_ALL=C printf '%s' "$listed" | grep -q '[^ -~]'; then
				printf '    %s  (bytes: %s)\n' "$listed" \
					"$(printf '%s' "$listed" | od -An -tx1 | tr -s ' ' | tr -d '\n')" >&2
			else
				printf '    %s\n' "$listed" >&2
			fi
		done
	return 1
}

report() { # report <id> <desc> <fixed:0|1> [detail]
	if [ "$3" = "1" ]; then
		FIXED=$((FIXED + 1))
		printf '  \033[0;32mFIXED\033[0m      %s — %s\n' "$1" "$2"
	else
		REPRODUCED=$((REPRODUCED + 1))
		printf '  \033[0;31mREPRODUCED\033[0m %s — %s%s\n' "$1" "$2" "${4:+ ($4)}"
	fi
}

cat >"$WORKDIR/monosecret.toml" <<'EOF'
[project]
name = "bw-regression"
revision = "1.0"

[profiles.default]
regr_canary = { required = false, description = "R1 canary write", ref = { item = "Regr Canary Login" } }
regr_new_api_key = { required = false, description = "R2 named field on create", ref = { item = "Regr New Login", field = "api_key" } }
regr_note = { required = false, description = "R3 secure note default", ref = { item = "Regr Note" } }
regr_case = { required = false, description = "R4 case-insensitive update", ref = { item = "Regr Case Item", field = "api_key" } }

# Round 2 (2026-07-30)
regr_exact = { required = false, description = "R5 exact item match on read", ref = { item = "RegrExactKey" } }
regr_typed = { required = false, description = "R6 type filter on read", ref = { item = "RegrTyped" } }
regr_clobber = { required = false, description = "R7 no substring update target", ref = { item = "RegrApiKey" } }
regr_absent = { required = false, description = "R8 explicit field miss", ref = { item = "Regr Absent Note", field = "absent_field" } }
regr_expmonth = { required = false, description = "R9 built-in field on create", ref = { item = "RegrCardCreate", field = "exp_month" } }
regr_umlaut = { required = false, description = "R11 non-ASCII case folding", ref = { item = "überblick" } }
EOF
cd "$WORKDIR" || exit 2

MS() { "$BIN" "$@" --provider bw:// 2>&1; }
MSP() {
	local prov="$1"
	shift
	"$BIN" "$@" --provider "$prov" 2>&1
}
item_name_exists() { bw list items 2>/dev/null | jq -e --arg n "$1" 'any(.[]; .name == $n)' >/dev/null; }

echo "── R1: linked custom field (type 3) poisons unrelated writes ──"
LINKED_ID=$(mk_item "$(item_json "Regr Linked Item" 1 '[{"name":"linked_username","value":null,"type":3,"linkedId":100}]')")
OUT=$(MS set regr_canary canary-value)
RC=$?
if [ $RC -eq 0 ] && ! grep -qi "unknown field type" <<<"$OUT"; then
	report R1 "write succeeds with a linked field present in the vault" 1
else
	report R1 "any write aborts while a linked field exists" 0 "$(grep -oi 'unknown field type[^\"]*' <<<"$OUT" | head -1)"
fi
bw delete item "$LINKED_ID" >/dev/null 2>&1 && CREATED_IDS=(${CREATED_IDS[@]+"${CREATED_IDS[@]/$LINKED_ID/}"})
bw sync >/dev/null 2>&1

echo "── R2: named custom field preserved when creating a new item ──"
MS set regr_new_api_key sk_regr_12345 >/dev/null
NEW_ID=$(bw get item "Regr New Login" 2>/dev/null | jq -r '.id' || true)
[ -n "$NEW_ID" ] && [ "$NEW_ID" != "null" ] && CREATED_IDS+=("$NEW_ID")
GOT=$(MS get regr_new_api_key) || true
if [ "$GOT" = "sk_regr_12345" ]; then
	report R2 "get returns the value through the declared custom field" 1
else
	report R2 "value not readable via field=api_key after create" 0 "stored in login.password instead"
fi

echo "── R3: type-specific default on update (secure note) ──"
mk_item "$(item_json "Regr Note" 2)" >/dev/null
GOT=$(MS get regr_note) || true
[ "$GOT" = "old-note-value" ] || echo "  (pre-check unexpected: get returned '$GOT')"
MS set regr_note new-note-value >/dev/null
GOT=$(MS get regr_note) || true
if [ "$GOT" = "new-note-value" ]; then
	report R3 "set targets the same default field the getter reads" 1
else
	report R3 "set wrote a password field; get still returns '$GOT'" 0
fi

echo "── R4: case-insensitive field matching on update ──"
mk_item "$(item_json "Regr Case Item" 1 '[{"name":"API_KEY","value":"old-value","type":1}]')" >/dev/null
GOT=$(MS get regr_case) || true
[ "$GOT" = "old-value" ] || echo "  (pre-check unexpected: get returned '$GOT')"
MS set regr_case new-value >/dev/null
GOT=$(MS get regr_case) || true
if [ "$GOT" = "new-value" ]; then
	report R4 "update matched the existing field case-insensitively" 1
else
	report R4 "update added a duplicate field; get still returns '$GOT'" 0
fi

echo "── R5: a read resolves the exactly named item ──"
# `bw list --search RegrExactKey` returns both, and the order is not specified.
if ! require_item "RegrExactKeyOld" \
	"$(item_json_with "RegrExactKeyOld" 1 '[]' '{"login":{"password":"wrong-old-value"}}')" ||
	! require_item "RegrExactKey" \
		"$(item_json_with "RegrExactKey" 1 '[]' '{"login":{"password":"right-value"}}')"; then
	report R5 "fixtures never reached the vault" 0 "a fixture problem, not a provider result"
else
	GOT=$(MS get regr_exact) || true
	if [ "$GOT" = "right-value" ]; then
		report R5 "read returned the exactly named item" 1
	else
		report R5 "read returned a similarly named item instead" 0 "got '$GOT'"
	fi
fi

echo "── R6: an addressed type disambiguates same-named items ──"
if ! require_item "RegrTyped" \
	"$(item_json_with "RegrTyped" 1 '[]' '{"login":{"password":"the-login"}}')" ||
	! require_item "RegrTyped" \
		"$(item_json_with "RegrTyped" 3 '[]' '{"card":{"number":"the-card"}}')"; then
	report R6 "fixtures never reached the vault" 0 "a fixture problem, not a provider result"
else
	GOT=$(MSP 'bw://?type=card' get regr_typed) || true
	if [ "$GOT" = "the-card" ]; then
		report R6 "?type=card selected the Card over the same-named Login" 1
	else
		report R6 "?type=card did not select by type" 0 "got '$GOT'"
	fi
fi

echo "── R7: a write never adopts a substring match ──"
# "old_regrapikey" contains "regrapikey", which is what used to make this an
# update target. Nothing named RegrApiKey exists yet, so `set` must create one.
OLD_ID=$(mk_item "$(item_json_with "OLD_RegrApiKey" 1 '[]' '{"login":{"password":"must-not-change"}}')")
if [ -z "$OLD_ID" ]; then
	report R7 "the OLD_RegrApiKey fixture was never created" 0 \
		"a fixture problem, not a provider result"
	OLD_ID=""
fi
MS set regr_clobber brand-new-value >/dev/null
bw sync >/dev/null 2>&1
if [ -n "$OLD_ID" ]; then
	SURVIVED=$(bw get item "$OLD_ID" 2>/dev/null | jq -r '.login.password')
	if [ "$SURVIVED" = "must-not-change" ] && item_name_exists "RegrApiKey"; then
		report R7 "set created RegrApiKey and left OLD_RegrApiKey intact" 1
	else
		report R7 "set overwrote the unrelated OLD_RegrApiKey" 0 "its password is now '$SURVIVED'"
	fi
fi

echo "── R8: an absent explicit field returns nothing, not another secret ──"
mk_item "$(item_json "Regr Absent Note" 2 '[{"name":"value","value":"the-value-field","type":1}]')" >/dev/null
GOT=$(MS get regr_absent) || true
if [ "$GOT" = "the-value-field" ]; then
	report R8 "field=absent_field fell through to the legacy value field" 0
else
	report R8 "an explicit field that is missing resolves to nothing" 1
fi

echo "── R9: a built-in field named on create is readable back ──"
MSP 'bw://?type=card' set regr_expmonth "07" >/dev/null
bw sync >/dev/null 2>&1
GOT=$(MSP 'bw://?type=card' get regr_expmonth) || true
CARD_ID=$(bw list items 2>/dev/null | jq -r '.[] | select(.name == "RegrCardCreate") | .id' | head -1)
[ -n "$CARD_ID" ] && [ "$CARD_ID" != "null" ] && CREATED_IDS+=("$CARD_ID")
if [ "$GOT" = "07" ]; then
	report R9 "set --field exp_month round-trips through the card's built-in" 1
else
	report R9 "exp_month was stored where the getter does not look" 0 "get returned '$GOT'"
fi

echo "── R10: a misspelled address is rejected ──"
OUT=$(MSP 'bw://?type=sshkee' get regr_exact)
RC=$?
OUT2=$(MSP 'bw://?feild=api_key' get regr_exact)
RC2=$?
if [ $RC -ne 0 ] && [ $RC2 -ne 0 ]; then
	report R10 "?type=sshkee and ?feild= are both rejected" 1
elif [ $RC -ne 0 ]; then
	report R10 "?type=sshkee is rejected but ?feild= is silently ignored" 0 \
		"$(head -1 <<<"$OUT2")"
else
	report R10 "a misspelled ?type= silently fell back to Login" 0 "$(head -1 <<<"$OUT")"
fi

echo "── R11: names fold case beyond ASCII ──"
# The only non-ASCII value in this file, so the only one whose *fixture* can
# fail where the others' cannot -- it passes through jq and `bw encode` on the
# way in. Creation used to be unchecked here, which made a failed fixture and a
# failed lookup produce the same "got ''" and left a third-party report
# impossible to diagnose.
if ! require_item "Überblick" \
	"$(item_json_with "Überblick" 1 '[]' '{"login":{"password":"umlaut-value"}}')"; then
	report R11 "the Überblick fixture never reached the vault under that name" 0 \
		"a fixture problem, not a provider result -- see the listing above"
else
	GOT=$(MS get regr_umlaut) || true
	if [ "$GOT" = "umlaut-value" ]; then
		report R11 "an item named Überblick is addressable as überblick" 1
	else
		report R11 "a non-ASCII name is unreachable in lower case" 0 "got '$GOT'"
	fi
fi

echo "── R12: the integration suite refuses a pre-existing fixture ──"
# The data-loss path: the suite used to adopt a same-named vault item as a
# mutable fixture and then overwrite its password, without recording it for
# cleanup. Planting one must abort the run and leave the item untouched.
SQUATTER_NAME="monosecret-it Test Database"
SQUATTER_ID=$(mk_item "$(item_json_with "$SQUATTER_NAME" 1 '[]' '{"login":{"password":"precious"}}')")
bw sync >/dev/null 2>&1
if [ -z "$SQUATTER_ID" ]; then
	report R12 "the squatting fixture was never created" 0 \
		"a fixture problem, not a provider result"
	SUITE_RC=0
else
	(cd "$REPO_ROOT" && bash tests/bitwarden_integration.sh "$BW_SESSION" </dev/null) >/dev/null 2>&1
	SUITE_RC=$?
fi
bw sync >/dev/null 2>&1
if [ -n "$SQUATTER_ID" ]; then
	STILL=$(bw get item "$SQUATTER_ID" 2>/dev/null | jq -r '.login.password')
	if [ $SUITE_RC -ne 0 ] && [ "$STILL" = "precious" ]; then
		report R12 "the suite aborted and left the pre-existing item alone" 1
	else
		report R12 "the suite adopted a real vault item as a fixture" 0 "exit $SUITE_RC, password now '$STILL'"
	fi
fi

echo
echo "Findings fixed: $FIXED · reproduced: $REPRODUCED"
[ "$REPRODUCED" -eq 0 ]
