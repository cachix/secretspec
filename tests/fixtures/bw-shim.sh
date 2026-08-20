#!/usr/bin/env bash
# Test-only fake `bw` CLI for the Bitwarden provider's unit tests
# (ashebanow/secretspec#5).
#
# A real `bw` on PATH would talk to the developer's own vault: reads would
# answer with real account data and writes would mutate it. This one answers
# fixture files from a per-test directory and records every invocation, so
# unit tests can drive the full get/set/scope flows and the subprocess error
# paths without ever touching a real CLI or account.
#
# Fixtures (JSON) read from the script's own directory (the harness installs
# the shim as `<dir>/bw` and puts `<dir>` on PATH); each defaults to a
# sensible empty answer when absent:
#   status.json        - `bw status` output (default: unlocked, cloud server)
#   organizations.json - `bw list organizations` output (default: [])
#   collections.json   - `bw list collections` output (default: [])
#   items.json         - `bw list items` / `bw get item` source (default: [])
#   stateful            - when present, persist create/edit calls to items.json
#
# Every invocation is appended to $BW_SHIM_DIR/invocations.log as:
#   argv: <--nointeraction> <status> ...     (one per call)
#   stdin=<base64>                            (only when JSON was piped at it)
# Tests read the log to assert what the provider asked for.
#
# Failure injection:
#   $BW_SHIM_DIR/fail.env  - three lines: exit code, stdout, stderr. When
#                            present every call exits with that code and
#                            prints those streams, driving the provider's
#                            error paths (missing login, locked vault,
#                            generic failure, malformed output).
#   $BW_SHIM_DIR/garbage.bin - raw bytes echoed verbatim with exit 0, for
#                            output that is not valid UTF-8. (fail.env cannot
#                            express non-UTF-8 because it is line-delimited.)
#
# Not modelled (deliberately): bw's own fuzzy --search matching, scope
# filtering, item templates, and login/unlock state. The provider re-matches
# names itself and builds templates itself; the shim only needs to be a
# plausible vault, not a real one.
set -euo pipefail

# The fixture directory is the script's own directory: the harness installs
# the shim as `<dir>/bw` and puts that directory on PATH, so no extra
# environment variable is needed to find the fixtures.
DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LOG="$DIR/invocations.log"

# Record the call before anything else, so even a failing invocation is
# visible in the log.
{
  printf 'argv:'
  for arg in "$@"; do printf ' <%s>' "$arg"; done
  printf '\n'
} >> "$LOG"

# Forced-failure mode: exit with a fixed code and fixed streams. An optional
# fourth line limits the failure to invocations whose argv contains that
# substring, so one listing can fail while a sibling listing succeeds.
if [ -f "$DIR/fail.env" ]; then
  {
    read -r fail_code || true
    read -r fail_out || true
    read -r fail_err || true
    read -r fail_match || true
  } < "$DIR/fail.env"
  if [ -z "$fail_match" ] || [[ "$*" == *"$fail_match"* ]]; then
    [ -n "$fail_out" ] && printf '%s' "$fail_out"
    [ -n "$fail_err" ] && printf '%s' "$fail_err" >&2
    exit "${fail_code:-1}"
  fi
fi

# Non-UTF-8 output mode (see header).
if [ -f "$DIR/garbage.bin" ]; then
  cat "$DIR/garbage.bin"
  exit 0
fi

read_fixture() { # $1 = file name, answer "[]" when absent
  local file="$DIR/$1"
  if [ -f "$file" ]; then cat "$file"; else printf '[]'; fi
}

# Pipes one base64-encoded JSON payload on stdin, appending the raw base64 to
# the log so tests can verify exactly what was sent.
log_and_decode_stdin() {
  local raw
  raw=$(cat)
  printf ' stdin=%s\n' "$raw" >> "$LOG"
  # jq decodes base64 without depending on the platform's base64(1).
  printf '%s' "$raw" | jq -Rr '@base64d'
}

# The provider always sends --nointeraction first.
if [ "${1:-}" = "--nointeraction" ]; then
  shift
fi

sub="${1:-}"
shift || true

case "$sub" in
  status)
    if [ -f "$DIR/status.json" ]; then cat "$DIR/status.json"; else
      printf '{"serverUrl":null,"status":"unlocked","authenticated":true}'
    fi
    ;;

  list)
    target="${1:-}"
    case "$target" in
      organizations)
        read_fixture organizations.json
        ;;
      collections)
        read_fixture collections.json
        ;;
      items)
        # A naive name-substring --search so the provider's empty-result
        # fall-back is exercisable. Scope flags are ignored: the provider
        # resolves names itself and matches them itself.
        term=""
        while [ "$#" -gt 0 ]; do
          if [ "$1" = "--search" ] && [ "$#" -ge 2 ]; then term="$2"; fi
          shift
        done
        items="$(read_fixture items.json)"
        if [ -n "$term" ]; then
          printf '%s' "$items" | jq -c --arg t "$term" \
            '[.[] | select((.name // "") | contains($t))]'
        else
          printf '%s' "$items"
        fi
        ;;
      *)
        printf 'shim: unknown list target: %s\n' "$target" >&2
        exit 1
        ;;
    esac
    ;;

  get)
    # get item <id> [--organizationid X]
    [ "${1:-}" = "item" ] || { printf 'shim: unsupported get: %s\n' "$1" >&2; exit 1; }
    id="${2:-}"
    found="$(read_fixture items.json | jq -c --arg id "$id" '.[] | select(.id == $id)')"
    if [ -z "$found" ]; then
      printf 'Not found.\n' >&2
      exit 1
    fi
    printf '%s\n' "$found"
    ;;

  create)
    # create item [--organizationid X]; the item arrives base64 on stdin.
    [ "${1:-}" = "item" ] || { printf 'shim: unsupported create: %s\n' "$1" >&2; exit 1; }
    if [ -f "$DIR/stateful" ]; then
      current="$(read_fixture items.json)"
      next_id="shim-created-$(printf '%s' "$current" | jq 'length')"
      created="$(log_and_decode_stdin | jq -c --arg id "$next_id" '. + {id: $id}')"
      tmp="$DIR/items.json.tmp"
      printf '%s' "$current" | jq -c --argjson item "$created" '. + [$item]' > "$tmp"
      mv "$tmp" "$DIR/items.json"
      printf '%s\n' "$created"
    else
      log_and_decode_stdin | jq -c '. + {id: "shim-created"}'
    fi
    ;;

  edit)
    # edit item <id> [--organizationid X]; the item arrives base64 on stdin.
    [ "${1:-}" = "item" ] || { printf 'shim: unsupported edit: %s\n' "$1" >&2; exit 1; }
    if [ -f "$DIR/stateful" ]; then
      id="${2:-shim-edited}"
      edited="$(log_and_decode_stdin | jq -c --arg id "$id" '. + {id: $id}')"
      tmp="$DIR/items.json.tmp"
      read_fixture items.json | jq -c --arg id "$id" --argjson item "$edited" \
        'map(if .id == $id then $item else . end)' > "$tmp"
      mv "$tmp" "$DIR/items.json"
      printf '%s\n' "$edited"
    else
      log_and_decode_stdin | jq -c --arg id "${2:-shim-edited}" '. + {id: $id}'
    fi
    ;;

  *)
    printf 'shim: unexpected bw subcommand: %s\n' "$sub" >&2
    exit 1
    ;;
esac
