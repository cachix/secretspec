#!/usr/bin/env bash
#
# Aggregate cross-language conformance runner.
#
# Builds the secretspec-ffi cdylib once, then runs every SDK's conformance suite
# against the shared fixtures and reports a combined result. Run inside the
# project devenv shell (which provides cargo, python, go, ruby, node):
#
#     devenv shell -- bash conformance/run.sh
#
# Exits non-zero if any language's conformance suite fails. A language whose
# toolchain is missing is reported as SKIP and does not fail the run.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

echo "==> Building secretspec-ffi cdylib"
cargo build -p secretspec-ffi || exit 1

target_dir="$(cargo metadata --no-deps --format-version 1 \
  | grep -o '"target_directory":"[^"]*"' | head -1 | sed 's/.*:"\(.*\)"/\1/')"
case "$(uname -s)" in
  Darwin)                lib_name="libsecretspec_ffi.dylib" ;;
  MINGW*|MSYS*|CYGWIN*)  lib_name="secretspec_ffi.dll" ;;
  *)                     lib_name="libsecretspec_ffi.so" ;;
esac
export SECRETSPEC_FFI_LIB="$target_dir/debug/$lib_name"
echo "==> SECRETSPEC_FFI_LIB=$SECRETSPEC_FFI_LIB"

names=()
statuses=()

run() {
  local name="$1" tool="$2" fn="$3"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "==> SKIP $name ($tool not found)"
    names+=("$name"); statuses+=("SKIP")
    return
  fi
  echo "==> $name conformance"
  if "$fn"; then
    names+=("$name"); statuses+=("PASS")
  else
    names+=("$name"); statuses+=("FAIL")
  fi
}

run_python() { ( cd secretspec-py && python -m pytest tests/test_conformance.py -q ); }
run_go()     { ( cd secretspec-go && go test -run TestConformance ./... ); }
run_ruby()   { ( cd secretspec-rb && ruby test/test_resolve.rb -n "/conformance/" ); }
run_node()   { (
  cd secretspec-node
  [ -d node_modules ] || npm install --no-audit --no-fund >/dev/null
  node --test test/conformance.test.js
); }
run_haskell() { (
  cd secretspec-hs
  # The Haskell SDK links the cdylib at build time, so its directory must be on
  # both the linker path (--extra-lib-dirs) and the runtime loader path.
  lib_dir="$(dirname "$SECRETSPEC_FFI_LIB")"
  export LD_LIBRARY_PATH="$lib_dir:${LD_LIBRARY_PATH:-}"
  cabal test --extra-lib-dirs="$lib_dir" --test-show-details=streaming
); }

run "Python"  python run_python
run "Go"      go     run_go
run "Ruby"    ruby   run_ruby
run "Node"    node   run_node
run "Haskell" cabal  run_haskell

echo
echo "==> Conformance summary"
overall=0
for i in "${!names[@]}"; do
  printf "    %-8s %s\n" "${names[$i]}" "${statuses[$i]}"
  [ "${statuses[$i]}" = "FAIL" ] && overall=1
done
exit "$overall"
