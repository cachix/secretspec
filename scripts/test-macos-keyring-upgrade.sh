#!/usr/bin/env bash
# Exercise access to a disposable legacy macOS keychain item from SecretSpec.
# Usage: scripts/test-macos-keyring-upgrade.sh [path/to/patched/secretspec]
set -euo pipefail

if [[ $(uname -s) != Darwin ]]; then
  echo "This test must run on macOS." >&2
  exit 1
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
binary=${1:-"$repo_root/target/debug/secretspec"}
if [[ $binary != /* ]]; then
  binary="$PWD/$binary"
fi
if [[ ! -x $binary ]]; then
  echo "Build the patched CLI first, then pass its path: $binary" >&2
  exit 1
fi

test_dir=$(mktemp -d "${TMPDIR:-/tmp}/secretspec-keyring.XXXXXX")
service="secretspec-keyring-${test_dir##*/}"
account=$(id -un)

cat > "$test_dir/secretspec.toml" <<EOF
[project]
name = "keyring-repro"
revision = "1.0"

[providers]
local = "keyring://"

[profiles.default]
PROBE = { description = "Disposable keychain test", providers = ["local"], ref = { item = "$service", field = "$account" } }
EOF

echo "Test directory: $test_dir"
echo "Keychain service: $service"
echo "Binary: $binary"
echo "The test item is left in place for inspection. Remove it afterward with:"
printf '  security delete-generic-password -s %q -a %q\n' "$service" "$account"
echo

cd "$test_dir"
security add-generic-password -s "$service" -a "$account" -w initial

echo "1. First read: choose Allow if macOS asks for keychain access."
read -r -p "Press Enter to run it... " _
"$binary" get PROBE

echo "2. Second read: the dialog should return. Choose Always Allow."
read -r -p "Press Enter to run it... " _
"$binary" get PROBE

echo "3. Third read: there should be no dialog."
read -r -p "Press Enter to run it... " _
"$binary" get PROBE
read -r -p "Was the third read dialog-free? [y/N] " reply
if [[ $reply != [yY] && $reply != [yY][eE][sS] ]]; then
  echo "FAIL: repeated reads still prompt after Always Allow." >&2
  exit 1
fi

stored=$(security find-generic-password -s "$service" -a "$account" -w)
if [[ $stored != initial ]]; then
  echo "FAIL: reads changed or removed the original keychain value." >&2
  exit 1
fi

echo "4. Write over the item. Choose Always Allow if macOS asks again."
read -r -p "Press Enter to run it... " _
if "$binary" set PROBE updated; then
  stored=$(security find-generic-password -s "$service" -a "$account" -w)
  if [[ $stored != updated ]]; then
    echo "FAIL: the write reported success but the keychain value is '$stored'." >&2
    exit 1
  fi
  echo "PASS: repeated reads stopped prompting and the write updated the item."
else
  stored=$(security find-generic-password -s "$service" -a "$account" -w)
  if [[ $stored == initial ]]; then
    echo "FAIL: the write was refused, but the original value was preserved." >&2
  else
    echo "FAIL: the write was refused and the original value changed." >&2
  fi
  exit 1
fi
