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
# The Node SDK uses a napi-rs addon (not the cdylib) and has no npm
# dependencies. Build the addon once up front: the test files each ensure it
# exists and would otherwise race to build it in parallel processes.
bash secretspec-node/scripts/build-addon.sh
( cd secretspec-node && node --test )

echo "==> Haskell"
# The Haskell SDK links the cdylib at build time, so its directory goes on both
# the linker path (--extra-lib-dirs) and the runtime loader path.
(
  cd secretspec-hs
  hs_lib_dir="$(dirname "$SECRETSPEC_FFI_LIB")"
  cabal update
  # --write-ghc-environment-files lets the codegen test's runghc see aeson and
  # the quicktype-generated module's transitive imports; SECRETSPEC_BIN (set
  # above) lets it run `secretspec schema`.
  LD_LIBRARY_PATH="$hs_lib_dir:${LD_LIBRARY_PATH:-}" \
    cabal test --extra-lib-dirs="$hs_lib_dir" --write-ghc-environment-files=always
)

echo "==> All SDK suites passed"
