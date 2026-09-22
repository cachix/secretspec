#!/usr/bin/env bash
# Exercise access to a disposable legacy macOS keychain item from SecretSpec.
# Usage: scripts/test-macos-keyring-upgrade.sh [path/to/patched/secretspec]
set -euo pipefail

if [[ $(uname -s) != Darwin ]]; then
  echo "This test must run on macOS." >&2
  exit 1
fi

repo_root=$(cd "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/.." && pwd)
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

echo "Read 1..."
"$binary" get PROBE

echo "Read 2..."
"$binary" get PROBE

echo "Read 3 (10-second limit)..."
if ! perl -e 'alarm 10; exec @ARGV or die "exec: $!"' "$binary" get PROBE; then
  echo "FAIL: third read failed or waited too long for keychain access." >&2
  exit 1
fi

stored=$(security find-generic-password -s "$service" -a "$account" -w)
if [[ $stored != initial ]]; then
  echo "FAIL: reads changed or removed the original keychain value." >&2
  exit 1
fi

echo "Write..."
if "$binary" set PROBE updated; then
  stored=$(security find-generic-password -s "$service" -a "$account" -w)
  if [[ $stored != updated ]]; then
    echo "FAIL: the write reported success but the keychain value is '$stored'." >&2
    exit 1
  fi
  echo "PASS: three reads preserved the item and the write updated it."
else
  stored=$(security find-generic-password -s "$service" -a "$account" -w)
  if [[ $stored == initial ]]; then
    echo "FAIL: the write was refused, but the original value was preserved." >&2
  else
    echo "FAIL: the write was refused and the original value changed." >&2
  fi
  exit 1
fi
