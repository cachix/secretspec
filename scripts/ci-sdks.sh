#!/usr/bin/env bash
#
# Run every language SDK's full test suite (unit + conformance + the
# schema/quicktype pipeline) against one freshly built cdylib. Run inside the
# project devenv shell:
#
#     devenv shell -- bash scripts/ci-sdks.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

echo "==> Building cdylib + CLI"
cargo build -p secretspec-ffi -p secretspec

target_dir="$(cargo metadata --no-deps --format-version 1 \
  | grep -o '"target_directory":"[^"]*"' | head -1 | sed 's/.*:"\(.*\)"/\1/')"
case "$(uname -s)" in
  Darwin) lib_name="libsecretspec_ffi.dylib" ;;
  *)      lib_name="libsecretspec_ffi.so" ;;
esac
export SECRETSPEC_FFI_LIB="$target_dir/debug/$lib_name"
export SECRETSPEC_BIN="$target_dir/debug/secretspec"
echo "==> SECRETSPEC_FFI_LIB=$SECRETSPEC_FFI_LIB"

echo "==> Python"
( cd secretspec-py && python -m pytest -q )

echo "==> Go"
( cd secretspec-go && go test ./... )

echo "==> Ruby"
( cd secretspec-rb && ruby -e 'Dir["test/test_*.rb"].sort.each { |f| require File.expand_path(f) }' )

echo "==> Node"
# The Node SDK uses a napi-rs addon (built by its test harness), not the cdylib,
# and has no npm dependencies.
( cd secretspec-node && node --test )

echo "==> All SDK suites passed"
