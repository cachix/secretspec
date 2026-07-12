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
cargo build -p monosecret_ffi -p monosecret

target_dir="$(cargo metadata --no-deps --format-version 1 |
	grep -o '"target_directory":"[^"]*"' | head -1 | sed 's/.*:"\(.*\)"/\1/')"
case "$(uname -s)" in
Darwin) lib_name="libmonosecret_ffi.dylib" ;;
*) lib_name="libmonosecret_ffi.so" ;;
esac
# Runtime-dlopen contract (SDKs not yet migrated to static linking still use it).
export MONOSECRET_FFI_LIB="$target_dir/debug/$lib_name"
export MONOSECRET_BIN="$target_dir/debug/monosecret"

# Static-link contract: SDKs link libmonosecret_ffi.a (the resolver compiled in)
# instead of dlopening the cdylib. A Rust staticlib does not carry its own native
# dependency closure, so capture the transitive system libs the archive needs and
# hand them to every consumer's linker. NEVER hardcode this list -- it drifts as
# providers change (today: -ldbus-1 -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc).
export MONOSECRET_FFI_STATICLIB="$target_dir/debug/libmonosecret_ffi.a"
export MONOSECRET_FFI_INCLUDE="$repo_root/crates/monosecret_ffi/include"
MONOSECRET_FFI_NATIVE_LIBS="$(cargo rustc -q -p monosecret_ffi --crate-type staticlib -- \
	--print native-static-libs 2>&1 | sed -n 's/^note: native-static-libs: //p' | tail -1)"
export MONOSECRET_FFI_NATIVE_LIBS
echo "==> MONOSECRET_FFI_LIB=$MONOSECRET_FFI_LIB"
echo "==> MONOSECRET_FFI_STATICLIB=$MONOSECRET_FFI_STATICLIB"
echo "==> MONOSECRET_FFI_NATIVE_LIBS=$MONOSECRET_FFI_NATIVE_LIBS"

echo "==> Dart"
melos exec --scope monosecret -- dart test

echo "==> Python"
python_venv="$(mktemp -d)"
cleanup_python_venv() {
	rm -rf "$python_venv"
}
trap cleanup_python_venv EXIT
python -m venv --system-site-packages "$python_venv"
(
	source "$python_venv/bin/activate"
	cd python/monosecret_py
	python -m pytest -q
)
cleanup_python_venv
trap - EXIT

echo "==> Go (default purego/dlopen path)"
(cd go/monosecret_go && go test ./...)

echo "==> Go (-tags monosecret_static: cgo links the archive in)"
# Stage the debug archive + header + generated cgo LDFLAGS, then exercise the
# static binding. This is the glibc self-contained build; the fully-static musl
# binary can be built later by the deferred publishing artifact workflow.
(cd go/monosecret_go && MONOSECRET_FFI_PROFILE=debug bash scripts/stage-staticlib.sh)
(cd go/monosecret_go && CGO_ENABLED=1 go test -tags monosecret_static ./...)

echo "==> Ruby"
# The Ruby SDK compiles an mkmf C extension that statically links the archive
# (using the MONOSECRET_FFI_* contract above); build it once up front.
bash ruby/monosecret_rb/scripts/build-ext.sh
(cd ruby/monosecret_rb && ruby -e 'Dir["test/test_*.rb"].sort.each { |f| require File.expand_path(f) }')

echo "==> Node"
# The Node SDK uses a napi-rs addon (not the cdylib), built via the @napi-rs/cli
# devDependency. Install it and build the addon once up front: the test files
# each ensure it exists and would otherwise race to build it in parallel
# processes.
pnpm install --frozen-lockfile
pnpm --filter @monosecret/client run build:native
pnpm --filter @monosecret/client run test

echo "==> Haskell"
# The Haskell SDK statically links the monosecret_ffi archive at build time: the
# Rust resolver is embedded in the test binary, so there is NO runtime loader path
# (no LD_LIBRARY_PATH). Stage libmonosecret_ffi.a alone into an isolated dir so
# -lmonosecret_ffi resolves to the archive (target/debug also holds the .so), and
# pass the archive's transitive native deps as linker options.
(
	cd haskell/monosecret_hs
	hs_lib_dir="$(mktemp -d)"
	cp "$MONOSECRET_FFI_STATICLIB" "$hs_lib_dir/"
	ghc_optl=()
	read -r -a native_libs <<<"$MONOSECRET_FFI_NATIVE_LIBS"
	for ((i = 0; i < ${#native_libs[@]}; i++)); do
		lib="${native_libs[$i]}"
		if [[ "$lib" == "-framework" ]]; then
			((i += 1))
			ghc_optl+=("--ghc-options=-optl-Wl,-framework,${native_libs[$i]}")
		else
			ghc_optl+=("--ghc-options=-optl$lib")
		fi
	done
	cabal update
	# --write-ghc-environment-files lets the codegen test's runghc see aeson and
	# the quicktype-generated module's transitive imports; MONOSECRET_BIN (set
	# above) lets it run `monosecret schema`.
	cabal test --extra-lib-dirs="$hs_lib_dir" "${ghc_optl[@]}" \
		--write-ghc-environment-files=always
)

echo "==> All SDK suites passed"
