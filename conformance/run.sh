#!/usr/bin/env bash
#
# Aggregate cross-language conformance runner.
#
# Builds the monosecret_ffi cdylib once, then runs every SDK's conformance suite
# against the shared fixtures and reports a combined result. Run inside the
# project devenv shell (which provides all nine SDK toolchains):
#
#     devenv shell -- bash conformance/run.sh
#
# Exits non-zero if any language's conformance suite fails. A language whose
# toolchain is missing is reported as SKIP and does not fail the run.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

echo "==> Building monosecret_ffi cdylib"
cargo build -p monosecret_ffi || exit 1

target_dir="$(cargo metadata --no-deps --format-version 1 |
	grep -o '"target_directory":"[^"]*"' | head -1 | sed 's/.*:"\(.*\)"/\1/')"
case "$(uname -s)" in
Darwin) lib_name="libmonosecret_ffi.dylib" ;;
MINGW* | MSYS* | CYGWIN*) lib_name="monosecret_ffi.dll" ;;
*) lib_name="libmonosecret_ffi.so" ;;
esac
export MONOSECRET_FFI_LIB="$target_dir/debug/$lib_name"
# Static-link contract (see scripts/ci-sdks.sh): the .a plus the archive's
# transitive native deps, for SDKs that link statically instead of dlopening.
export MONOSECRET_FFI_STATICLIB="$target_dir/debug/libmonosecret_ffi.a"
export MONOSECRET_FFI_INCLUDE="$repo_root/crates/monosecret_ffi/include"
MONOSECRET_FFI_NATIVE_LIBS="$(cargo rustc -q -p monosecret_ffi --crate-type staticlib -- \
	--print native-static-libs 2>&1 | sed -n 's/^note: native-static-libs: //p' | tail -1)"
export MONOSECRET_FFI_NATIVE_LIBS
echo "==> MONOSECRET_FFI_LIB=$MONOSECRET_FFI_LIB"
echo "==> MONOSECRET_FFI_STATICLIB=$MONOSECRET_FFI_STATICLIB"

names=()
statuses=()

run() {
	local name="$1" tool="$2" fn="$3"
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "==> SKIP $name ($tool not found)"
		names+=("$name")
		statuses+=("SKIP")
		return
	fi
	echo "==> $name conformance"
	if "$fn"; then
		names+=("$name")
		statuses+=("PASS")
	else
		names+=("$name")
		statuses+=("FAIL")
	fi
}

run_dart() { melos exec --scope monosecret -- dart test test/conformance_test.dart; }
run_python() { (
	python_venv="$(mktemp -d)"
	trap 'rm -rf "$python_venv"' EXIT
	python -m venv --system-site-packages "$python_venv"
	source "$python_venv/bin/activate"
	cd python/monosecret_py
	python -m pytest tests/test_conformance.py -q
); }
run_go() { (cd go/monosecret_go && go test -run 'Test(Conformance|ConstraintViolations)' ./...); }
run_ruby() { (cd ruby/monosecret_rb && ruby test/test_resolve.rb -n "/conformance/"); }
run_node() {
	pnpm --filter @monosecret/client run build:native &&
		pnpm --filter @monosecret/client run test
}
run_php() {
	composer install --no-interaction --no-progress &&
		(cd php/monosecret_php && ./vendor/bin/phpunit -c phpunit.xml.dist tests/ConformanceTest.php)
}
run_dotnet() {
	dotnet run --project dotnet/monosecret_dotnet/tests/Monosecret.Tests/Monosecret.Tests.csproj
}
run_swift() { (
	xcode_developer_dir="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
	if [[ ! -d "$xcode_developer_dir" ]]; then
		xcode_developer_dir="$(/usr/bin/xcode-select -p)"
	fi
	xcode_sdk="$xcode_developer_dir/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
	xcode_swift="$xcode_developer_dir/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift"
	DEVELOPER_DIR="$xcode_developer_dir" SDKROOT="$xcode_sdk" \
		bash swift/monosecret_swift/scripts/stage-local-xcframework.sh
	# Package.swift selects the local binary by file existence; bypass a cached
	# pre-staging manifest that may still point at the deferred release artifact.
	DEVELOPER_DIR="$xcode_developer_dir" SDKROOT="$xcode_sdk" \
		"$xcode_swift" test --manifest-cache none
); }
run_haskell() { (
	cd haskell/monosecret_hs
	# The Haskell SDK statically links the monosecret_ffi archive at build time, so
	# there is no runtime loader path. Stage the .a alone (target/debug also holds
	# the .so) and pass its transitive native deps as linker options.
	hs_lib_dir="$(mktemp -d)"
	trap 'rm -rf "$hs_lib_dir"' EXIT
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
	cabal test --extra-lib-dirs="$hs_lib_dir" "${ghc_optl[@]}" --test-show-details=streaming
); }
run "Dart" dart run_dart
run "Python" python run_python
run "Go" go run_go
run "Ruby" ruby run_ruby
run "Node" node run_node
run "Haskell" cabal run_haskell
run "PHP" composer run_php
run ".NET" dotnet run_dotnet
if [[ "$(uname -s)" == "Darwin" ]]; then
	run "Swift" swift run_swift
else
	echo "==> SKIP Swift (macOS-only SDK)"
	names+=("Swift")
	statuses+=("SKIP")
fi

echo
echo "==> Conformance summary"
overall=0
for i in "${!names[@]}"; do
	printf "    %-8s %s\n" "${names[$i]}" "${statuses[$i]}"
	[ "${statuses[$i]}" = "FAIL" ] && overall=1
done
exit "$overall"
