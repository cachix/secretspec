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

# Static-link consumers otherwise spend minutes processing a ~1.4 GB archive
# whose size is mostly debug information. Keep dev's unoptimized code but omit
# symbols: these suites validate SDK behavior and linking, not Rust backtraces.
export CARGO_PROFILE_DEV_DEBUG=0

echo "==> Building shared Rust SDK artifacts"
# Build every Rust-backed SDK in one Cargo invocation. Cargo can then unify the
# resolver dependency graph instead of serially rebuilding it for the FFI,
# Node, and PHP packages after the language suites have started.
cargo build \
  -p libsecretspec \
  -p secretspec \
  -p secretspec-node-native \
  -p secretspec-php-native

target_dir="$(cargo metadata --no-deps --format-version 1 \
  | grep -o '"target_directory":"[^"]*"' | head -1 | sed 's/.*:"\(.*\)"/\1/')"
case "$(uname -s)" in
  Darwin)
    lib_name="libsecretspec.dylib"
    node_native_name="libsecretspec_node_native.dylib"
    php_native_name="libsecretspec_php_native.dylib"
    ;;
  *)
    lib_name="libsecretspec.so"
    node_native_name="libsecretspec_node_native.so"
    php_native_name="libsecretspec_php_native.so"
    ;;
esac
# Runtime-dlopen contract (SDKs not yet migrated to static linking still use it).
export SECRETSPEC_FFI_LIB="$target_dir/debug/$lib_name"
export SECRETSPEC_BIN="$target_dir/debug/secretspec"

# Raw linker flags for the legs that do not call pkg-config. A Rust staticlib
# does not carry its own native dependency closure; NEVER hardcode this list --
# it drifts as providers change.
SECRETSPEC_FFI_NATIVE_LIBS="$(cargo rustc -q -p libsecretspec --crate-type staticlib -- \
  --print native-static-libs 2>&1 | sed -n 's/^note: native-static-libs: //p' | tail -1)"
export SECRETSPEC_FFI_NATIVE_LIBS

# Static-link contract: SDKs link libsecretspec.a (the resolver compiled in)
# instead of dlopening the cdylib. Stage the artifacts Cargo already built into
# a test-only prefix. Using cargo-c here would compile the full dependency graph
# again under target/<host-triple>, adding several minutes without adding test
# coverage; release/install workflows still exercise cargo-c itself.
echo "==> Staging staticlib + header + pkg-config file"
SECRETSPEC_FFI_PREFIX="$target_dir/ci-sdk-prefix"
export SECRETSPEC_FFI_PREFIX
mkdir -p \
  "$SECRETSPEC_FFI_PREFIX/lib/pkgconfig" \
  "$SECRETSPEC_FFI_PREFIX/include"
ln -sfn "$target_dir/debug/libsecretspec.a" \
  "$SECRETSPEC_FFI_PREFIX/lib/libsecretspec.a"
ln -sfn "$repo_root/libsecretspec/include/secretspec.h" \
  "$SECRETSPEC_FFI_PREFIX/include/secretspec.h"

ffi_version="$(cargo pkgid -p libsecretspec)"
ffi_version="${ffi_version##*#}"
{
  printf 'prefix=%s\n' "$SECRETSPEC_FFI_PREFIX"
  printf '%s\n' \
    'exec_prefix=${prefix}' \
    'libdir=${prefix}/lib' \
    'includedir=${prefix}/include' \
    '' \
    'Name: libsecretspec' \
    'Description: C ABI for SecretSpec: resolve secrets from any language'
  printf 'Version: %s\n' "$ffi_version"
  printf 'Libs: -L${libdir} -lsecretspec %s\n' "$SECRETSPEC_FFI_NATIVE_LIBS"
  printf 'Cflags: -I${includedir}\n'
  printf 'Libs.private: %s\n' "$SECRETSPEC_FFI_NATIVE_LIBS"
} > "$SECRETSPEC_FFI_PREFIX/lib/pkgconfig/libsecretspec.pc"

export PKG_CONFIG_PATH="$SECRETSPEC_FFI_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
pkg-config --print-errors --exists libsecretspec
export SECRETSPEC_FFI_STATICLIB="$SECRETSPEC_FFI_PREFIX/lib/libsecretspec.a"
export SECRETSPEC_FFI_INCLUDE="$SECRETSPEC_FFI_PREFIX/include"
echo "==> SECRETSPEC_FFI_LIB=$SECRETSPEC_FFI_LIB"
echo "==> SECRETSPEC_FFI_PREFIX=$SECRETSPEC_FFI_PREFIX"
echo "==> SECRETSPEC_FFI_NATIVE_LIBS=$SECRETSPEC_FFI_NATIVE_LIBS"

run_python() {
  echo "==> Python"
  ( cd secretspec-py && python -m pytest -q )
  ( cd secretspec-py && python -m compileall -q examples )
}

run_go() {
  # cgo's build cache does not track changes in pkg-config's emitted -L path.
  # Use an isolated cache so the pkg-config leg can never reuse an object that
  # points at a temporary prefix from an earlier local run.
  export GOCACHE="$suite_log_dir/go-build-cache"

  echo "==> Go (default purego/dlopen path)"
  ( cd secretspec-go && go test ./... )

  echo "==> Go (-tags static: cgo links the archive in)"
  # Stage the debug archive + header + generated cgo LDFLAGS, then exercise the
  # static binding. This is the glibc self-contained build; the fully-static musl
  # binary is built in the go-static.yml artifact workflow.
  ( cd secretspec-go && SECRETSPEC_FFI_PROFILE=debug bash scripts/stage-staticlib.sh )
  ( cd secretspec-go && CGO_ENABLED=1 go test -tags static ./... )

  echo "==> Go (-tags pkgconfig: link inputs from libsecretspec.pc)"
  ( cd secretspec-go && CGO_ENABLED=1 go test -tags pkgconfig ./... )
}

run_ruby() {
  echo "==> Ruby"
  # The Ruby SDK compiles an mkmf C extension that statically links the archive
  # (using the SECRETSPEC_FFI_* contract above); build it once up front.
  bash secretspec-rb/scripts/build-ext.sh
  ( cd secretspec-rb && ruby -e 'Dir["test/test_*.rb"].sort.each { |f| require File.expand_path(f) }' )
  ( cd secretspec-rb && find examples -name '*.rb' -exec ruby -c {} \; )

  echo "==> Ruby (pkg-config discovery)"
  # The same link inputs read from libsecretspec.pc in the installed prefix
  # (PKG_CONFIG_PATH above); rebuild the extension and rerun the resolver plus
  # conformance contract. Codegen and cleanup behavior are independent of link
  # discovery and already ran above; repeating codegen would reinstall its
  # temporary Ruby dependencies on every cold CI run.
  bash secretspec-rb/scripts/build-ext.sh --enable-pkg-config
  ( cd secretspec-rb && ruby test/test_resolve.rb )
}

run_node() {
  echo "==> Node"
  # The shared Cargo invocation already built the napi-rs addon. Stage it under
  # Node's required .node suffix after installing the JS test dependencies.
  ( cd secretspec-node && npm ci )
  cp "$target_dir/debug/$node_native_name" secretspec-node/secretspec.node.tmp.$$
  mv -f secretspec-node/secretspec.node.tmp.$$ secretspec-node/secretspec.node
  ( cd secretspec-node && node --test )
  ( cd secretspec-node && find examples -type f \( -name '*.js' -o -name '*.ts' \) -exec node --check {} \; )
}

run_haskell() {
  echo "==> Haskell"
  # The Haskell SDK statically links the libsecretspec archive at build time: the
  # Rust resolver is embedded in the test binary, so there is NO runtime loader path
  # (no LD_LIBRARY_PATH). Stage libsecretspec.a alone into an isolated dir so
  # -lsecretspec resolves to the archive (target/debug also holds the .so), and
  # pass the archive's transitive native deps as linker options.
  (
    cd secretspec-hs
    # Cabal leaves this generated file behind. Remove an environment from a
    # previous checkout before asking Cabal to write the current package IDs.
    rm -f .ghc.environment.*
    hs_lib_dir="$(mktemp -d)"
    cp "$SECRETSPEC_FFI_STATICLIB" "$hs_lib_dir/"
    cabal update
    # --write-ghc-environment-files lets the codegen test's runghc see aeson and
    # the quicktype-generated module's transitive imports; SECRETSPEC_BIN (set
    # above) lets it run `secretspec schema`. All -optl flags go in ONE
    # --ghc-options occurrence: cabal reverses the order of repeated occurrences,
    # which breaks two-token `-framework X` pairs on macOS.
    cabal test --extra-lib-dirs="$hs_lib_dir" \
      --ghc-options="-optl${SECRETSPEC_FFI_NATIVE_LIBS// / -optl}" \
      --write-ghc-environment-files=always
    cabal build exe:secretspec-quick-start-example \
      exe:secretspec-scopes-example \
      exe:secretspec-report-example \
      --extra-lib-dirs="$hs_lib_dir" \
      --ghc-options="-optl${SECRETSPEC_FFI_NATIVE_LIBS// / -optl}"
  )

  echo "==> Haskell (pkg-config discovery)"
  ( cd secretspec-hs && cabal test -f use-pkg-config --write-ghc-environment-files=always )
}

run_dotnet() {
  echo "==> C# / .NET"
  ( cd secretspec-dotnet && dotnet run --project tests/SecretSpec.Tests --configuration Release )
  ( cd secretspec-dotnet && find examples -name '*.csproj' -exec dotnet build {} \; )
}

run_jvm() {
  echo "==> JVM"
  ( cd secretspec-jvm && ./gradlew build )
}

run_elixir() {
  echo "==> Elixir"
  ( cd secretspec-ex && SECRETSPEC_EX_BUILD=1 mix test )
}

run_php() {
  echo "==> PHP"
  # The PHP SDK has two native backends over the same resolver; exercise both.
  # The Composer manifest is at the repo root (so Packagist can read it from the
  # monorepo); vendor-dir points into secretspec-php/, so phpunit still runs there.
  composer validate --no-check-lock --no-check-publish
  composer install --no-interaction --no-progress

  echo "==> PHP (ext-ffi fallback, dlopens the cdylib via SECRETSPEC_FFI_LIB)"
  ( cd secretspec-php && php ./vendor/bin/phpunit )
  ( cd secretspec-php && find examples -name '*.php' -exec php -l {} \; )

  echo "==> PHP (secretspec-php-native extension, ext-php-rs)"
  # The shared Cargo invocation already built the ext-php-rs extension. Stage
  # it where the PHP client expects it and prove it registers its functions.
  mkdir -p secretspec-php/lib
  cp "$target_dir/debug/$php_native_name" secretspec-php/lib/secretspec.so
  ( cd secretspec-php && php -d extension="$PWD/lib/secretspec.so" ./vendor/bin/phpunit )
}

# Each language owns its source/build directories. Run the suites concurrently
# after the shared resolver artifacts are ready, but buffer each suite's output
# so GitHub log groups remain readable and failures retain their full context.
suite_log_dir="$(mktemp -d)"
trap 'rm -rf "$suite_log_dir"' EXIT
suite_names=()
suite_logs=()
suite_pids=()

start_suite() {
  local name="$1"
  local function_name="$2"
  local index="${#suite_pids[@]}"
  local log="$suite_log_dir/$index.log"
  suite_names+=("$name")
  suite_logs+=("$log")
  (
    start_seconds="$SECONDS"
    "$function_name"
    printf '==> %s SDK completed in %ss\n' "$name" "$((SECONDS - start_seconds))"
  ) >"$log" 2>&1 &
  suite_pids+=("$!")
}

start_suite Python run_python
start_suite Go run_go
start_suite Ruby run_ruby
start_suite Node run_node
start_suite Haskell run_haskell
start_suite .NET run_dotnet
start_suite JVM run_jvm
start_suite PHP run_php
start_suite Elixir run_elixir

failed_suites=()
for index in "${!suite_pids[@]}"; do
  if ! wait "${suite_pids[$index]}"; then
    failed_suites+=("${suite_names[$index]}")
  fi
done

for index in "${!suite_logs[@]}"; do
  echo "::group::${suite_names[$index]} SDK"
  cat "${suite_logs[$index]}"
  echo "::endgroup::"
done

if [ "${#failed_suites[@]}" -ne 0 ]; then
  printf 'SDK suites failed: %s\n' "${failed_suites[*]}" >&2
  exit 1
fi

echo "==> All SDK suites passed"
