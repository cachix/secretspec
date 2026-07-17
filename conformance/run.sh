#!/usr/bin/env bash
#
# Aggregate cross-language conformance runner.
#
# Builds the secretspec-ffi cdylib once, then runs every SDK's conformance suite
# against the shared fixtures and reports a combined result. Run inside the
# project devenv shell (which provides cargo, python, go, ruby, node, dotnet):
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
# Static-link contract (see scripts/ci-sdks.sh): the .a plus the archive's
# transitive native deps, for SDKs that link statically instead of dlopening.
export SECRETSPEC_FFI_STATICLIB="$target_dir/debug/libsecretspec_ffi.a"
export SECRETSPEC_FFI_INCLUDE="$repo_root/secretspec-ffi/include"
SECRETSPEC_FFI_NATIVE_LIBS="$(cargo rustc -q -p secretspec-ffi --crate-type staticlib -- \
  --print native-static-libs 2>&1 | sed -n 's/^note: native-static-libs: //p' | tail -1)"
export SECRETSPEC_FFI_NATIVE_LIBS
echo "==> SECRETSPEC_FFI_LIB=$SECRETSPEC_FFI_LIB"
echo "==> SECRETSPEC_FFI_STATICLIB=$SECRETSPEC_FFI_STATICLIB"

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
  # The Haskell SDK statically links the secretspec-ffi archive at build time, so
  # there is no runtime loader path. Stage the .a alone (target/debug also holds
  # the .so) and pass its transitive native deps as linker options.
  hs_lib_dir="$(mktemp -d)"
  cp "$SECRETSPEC_FFI_STATICLIB" "$hs_lib_dir/"
  ghc_optl=()
  for l in $SECRETSPEC_FFI_NATIVE_LIBS; do ghc_optl+=("--ghc-options=-optl$l"); done
  cabal test --extra-lib-dirs="$hs_lib_dir" "${ghc_optl[@]}" --test-show-details=streaming
); }
run_php() { (
  # The PHP SDK dlopens the cdylib via ext-ffi at runtime, located through
  # SECRETSPEC_FFI_LIB exported above. The Composer manifest is at the repo root;
  # vendor-dir points into secretspec-php/, so phpunit runs from there.
  [ -d secretspec-php/vendor ] || composer install --no-interaction --no-progress >/dev/null
  cd secretspec-php && ./vendor/bin/phpunit tests/ConformanceTest.php
); }
run_dotnet() { (
  cd secretspec-dotnet
  dotnet run --project tests/SecretSpec.Tests --configuration Release
); }

run "Python"  python run_python
run "Go"      go     run_go
run "Ruby"    ruby   run_ruby
run "Node"    node   run_node
run "Haskell" cabal  run_haskell
run "C#"      dotnet run_dotnet
run "PHP"     php    run_php

echo
echo "==> Conformance summary"
overall=0
for i in "${!names[@]}"; do
  printf "    %-8s %s\n" "${names[$i]}" "${statuses[$i]}"
  [ "${statuses[$i]}" = "FAIL" ] && overall=1
done
exit "$overall"
