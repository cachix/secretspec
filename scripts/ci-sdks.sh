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
# instead of dlopening the cdylib. Every leg resolves the archive, its header,
# and its secretspec_ffi.pc from this one installed prefix.
echo "==> Installing staticlib + header + pkg-config file"
SECRETSPEC_FFI_PREFIX="$(mktemp -d)"
export SECRETSPEC_FFI_PREFIX
bash secretspec-ffi/scripts/cinstall.sh "$SECRETSPEC_FFI_PREFIX" static
export PKG_CONFIG_PATH="$SECRETSPEC_FFI_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
pkg-config --print-errors --exists secretspec_ffi
export SECRETSPEC_FFI_STATICLIB="$SECRETSPEC_FFI_PREFIX/lib/libsecretspec_ffi.a"
export SECRETSPEC_FFI_INCLUDE="$SECRETSPEC_FFI_PREFIX/include"
# Raw linker flags for the legs that do not call pkg-config. A Rust staticlib
# does not carry its own native dependency closure; NEVER hardcode this list --
# it drifts as providers change.
SECRETSPEC_FFI_NATIVE_LIBS="$(cargo rustc -q -p secretspec-ffi --crate-type staticlib -- \
  --print native-static-libs 2>&1 | sed -n 's/^note: native-static-libs: //p' | tail -1)"
export SECRETSPEC_FFI_NATIVE_LIBS
echo "==> SECRETSPEC_FFI_LIB=$SECRETSPEC_FFI_LIB"
echo "==> SECRETSPEC_FFI_PREFIX=$SECRETSPEC_FFI_PREFIX"
echo "==> SECRETSPEC_FFI_NATIVE_LIBS=$SECRETSPEC_FFI_NATIVE_LIBS"

echo "==> Python"
( cd secretspec-py && python -m pytest -q )
( cd secretspec-py && python -m compileall -q examples )

echo "==> Go (default purego/dlopen path)"
( cd secretspec-go && go test ./... )

echo "==> Go (-tags static: cgo links the archive in)"
# Stage the debug archive + header + generated cgo LDFLAGS, then exercise the
# static binding. This is the glibc self-contained build; the fully-static musl
# binary is built in the go-static.yml artifact workflow.
( cd secretspec-go && SECRETSPEC_FFI_PROFILE=debug bash scripts/stage-staticlib.sh )
( cd secretspec-go && CGO_ENABLED=1 go test -tags static ./... )

echo "==> Go (-tags pkgconfig: link inputs from secretspec_ffi.pc)"
( cd secretspec-go && CGO_ENABLED=1 go test -tags pkgconfig ./... )

echo "==> Ruby"
# The Ruby SDK compiles an mkmf C extension that statically links the archive
# (using the SECRETSPEC_FFI_* contract above); build it once up front.
bash secretspec-rb/scripts/build-ext.sh
( cd secretspec-rb && ruby -e 'Dir["test/test_*.rb"].sort.each { |f| require File.expand_path(f) }' )
( cd secretspec-rb && find examples -name '*.rb' -exec ruby -c {} \; )

echo "==> Ruby (pkg-config discovery)"
# The same link inputs read from secretspec_ffi.pc in the installed prefix
# (PKG_CONFIG_PATH above); rebuild the extension and rerun the tests.
bash secretspec-rb/scripts/build-ext.sh --enable-pkg-config
( cd secretspec-rb && ruby -e 'Dir["test/test_*.rb"].sort.each { |f| require File.expand_path(f) }' )

echo "==> Ruby (Bundler 4 Linux platforms)"
# Ruby in the pinned Nix environment may predate Ruby 4, so exercise the
# published gem with pinned Ruby 4 glibc and musl containers. The integration
# test includes a working glibc control and asserts both known packaging
# failures: the generic Linux gem loading on musl, and the missing `ruby`
# platform fallback.
bash secretspec-rb/repro/bundler-4-platforms/run.sh

echo "==> Node"
# The Node SDK uses a napi-rs addon (not the cdylib), built via the @napi-rs/cli
# devDependency. Install it and build the addon once up front: the test files
# each ensure it exists and would otherwise race to build it in parallel
# processes.
( cd secretspec-node && npm ci )
bash secretspec-node/scripts/build-addon.sh
( cd secretspec-node && node --test )
( cd secretspec-node && find examples -type f \( -name '*.js' -o -name '*.ts' \) -exec node --check {} \; )

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
(
  cd secretspec-hs
  cabal test -f use-pkg-config --write-ghc-environment-files=always
)

echo "==> C# / .NET"
( cd secretspec-dotnet && dotnet run --project tests/SecretSpec.Tests --configuration Release )
( cd secretspec-dotnet && find examples -name '*.csproj' -exec dotnet build {} \; )

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
# Build the extension in debug and load it directly; when it is present the SDK
# prefers it over ext-ffi. This also proves the extension registers its functions.
CARGO_TARGET_DIR="$target_dir" SECRETSPEC_PHP_PROFILE=debug \
  bash secretspec-php/scripts/build-ext.sh
( cd secretspec-php && php -d extension="$PWD/lib/secretspec.so" ./vendor/bin/phpunit )

echo "==> All SDK suites passed"
