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

echo "==> Building cdylib + staticlib + CLI"
cargo build -p secretspec-ffi -p secretspec

target_dir="$(cargo metadata --no-deps --format-version 1 \
  | grep -o '"target_directory":"[^"]*"' | head -1 | sed 's/.*:"\(.*\)"/\1/')"
case "$(uname -s)" in
  Darwin) lib_name="libsecretspec_ffi.dylib" ;;
  *)      lib_name="libsecretspec_ffi.so" ;;
esac
# Runtime-dlopen contract (SDKs not yet migrated to static linking still use it).
export SECRETSPEC_FFI_LIB="$target_dir/debug/$lib_name"
export SECRETSPEC_BIN="$target_dir/debug/secretspec"

# Static-link contract: SDKs link libsecretspec_ffi.a (the resolver compiled in)
# instead of dlopening the cdylib. A Rust staticlib does not carry its own native
# dependency closure, so capture the transitive system libs the archive needs and
# hand them to every consumer's linker. NEVER hardcode this list -- it drifts as
# providers change (today: -ldbus-1 -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc).
export SECRETSPEC_FFI_STATICLIB="$target_dir/debug/libsecretspec_ffi.a"
export SECRETSPEC_FFI_INCLUDE="$repo_root/secretspec-ffi/include"
SECRETSPEC_FFI_NATIVE_LIBS="$(cargo rustc -q -p secretspec-ffi --crate-type staticlib -- \
  --print native-static-libs 2>&1 | sed -n 's/^note: native-static-libs: //p' | tail -1)"
export SECRETSPEC_FFI_NATIVE_LIBS
echo "==> SECRETSPEC_FFI_LIB=$SECRETSPEC_FFI_LIB"
echo "==> SECRETSPEC_FFI_STATICLIB=$SECRETSPEC_FFI_STATICLIB"
echo "==> SECRETSPEC_FFI_NATIVE_LIBS=$SECRETSPEC_FFI_NATIVE_LIBS"

echo "==> Python"
( cd secretspec-py && python -m pytest -q )

echo "==> Go (default purego/dlopen path)"
( cd secretspec-go && go test ./... )

echo "==> Go (-tags static: cgo links the archive in)"
# Stage the debug archive + header + generated cgo LDFLAGS, then exercise the
# static binding. This is the glibc self-contained build; the fully-static musl
# binary is built in the go-static.yml artifact workflow.
( cd secretspec-go && SECRETSPEC_FFI_PROFILE=debug bash scripts/stage-staticlib.sh )
( cd secretspec-go && CGO_ENABLED=1 go test -tags static ./... )

echo "==> Ruby"
# The Ruby SDK compiles an mkmf C extension that statically links the archive
# (using the SECRETSPEC_FFI_* contract above); build it once up front.
bash secretspec-rb/scripts/build-ext.sh
( cd secretspec-rb && ruby -e 'Dir["test/test_*.rb"].sort.each { |f| require File.expand_path(f) }' )

echo "==> Node"
# The Node SDK uses a napi-rs addon (not the cdylib), built via the @napi-rs/cli
# devDependency. Install it and build the addon once up front: the test files
# each ensure it exists and would otherwise race to build it in parallel
# processes.
( cd secretspec-node && npm ci )
bash secretspec-node/scripts/build-addon.sh
( cd secretspec-node && node --test )

echo "==> Haskell"
# The Haskell SDK statically links the secretspec-ffi archive at build time: the
# Rust resolver is embedded in the test binary, so there is NO runtime loader path
# (no LD_LIBRARY_PATH). Stage libsecretspec_ffi.a alone into an isolated dir so
# -lsecretspec_ffi resolves to the archive (target/debug also holds the .so), and
# pass the archive's transitive native deps as linker options.
(
  cd secretspec-hs
  hs_lib_dir="$(mktemp -d)"
  cp "$SECRETSPEC_FFI_STATICLIB" "$hs_lib_dir/"
  ghc_optl=()
  for l in $SECRETSPEC_FFI_NATIVE_LIBS; do ghc_optl+=("--ghc-options=-optl$l"); done
  cabal update
  # --write-ghc-environment-files lets the codegen test's runghc see aeson and
  # the quicktype-generated module's transitive imports; SECRETSPEC_BIN (set
  # above) lets it run `secretspec schema`.
  cabal test --extra-lib-dirs="$hs_lib_dir" "${ghc_optl[@]}" \
    --write-ghc-environment-files=always
)

echo "==> PHP"
# The PHP SDK has two native backends over the same resolver; exercise both.
# The Composer manifest is at the repo root (so Packagist can read it from the
# monorepo); vendor-dir points into secretspec-php/, so phpunit still runs there.
composer validate --no-check-lock --no-check-publish
composer install --no-interaction --no-progress

echo "==> PHP (ext-ffi fallback, dlopens the cdylib via SECRETSPEC_FFI_LIB)"
( cd secretspec-php && php ./vendor/bin/phpunit )

echo "==> PHP (secretspec-php-native extension, ext-php-rs)"
# Build the extension in debug and load it directly; when it is present the SDK
# prefers it over ext-ffi. This also proves the extension registers its functions.
cargo build -p secretspec-php-native
case "$(uname -s)" in
  Darwin) php_ext="$target_dir/debug/libsecretspec_php_native.dylib" ;;
  *)      php_ext="$target_dir/debug/libsecretspec_php_native.so" ;;
esac
( cd secretspec-php && php -d extension="$php_ext" ./vendor/bin/phpunit )

echo "==> All SDK suites passed"
