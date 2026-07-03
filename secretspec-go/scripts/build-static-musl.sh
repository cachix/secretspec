#!/usr/bin/env bash
#
# Build a fully-static (musl) Go binary that links the secretspec-ffi archive in
# via cgo. Run inside the project devenv shell, which provides the musl C
# cross-toolchain and static libdbus/libunwind via MUSL_CC / MUSL_STATIC_LDFLAGS
# (and the CC_/linker env so cargo compiles the C deps against musl):
#
#     devenv shell -- bash secretspec-go/scripts/build-static-musl.sh <pkg-or-dir> [out]
#
# With no argument it builds the SDK's own packages (a compile/link check);
# `file <out>` on a produced binary reports "statically linked".
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${MUSL_CC:?set by devenv; run inside 'devenv shell'}"
: "${MUSL_STATIC_LDFLAGS:?set by devenv; run inside 'devenv shell'}"

target="${SECRETSPEC_FFI_TARGET:-x86_64-unknown-linux-musl}"
profile="${SECRETSPEC_FFI_PROFILE:-release}"

# Stage the musl archive + header + generated cgo LDFLAGS (cargo uses the musl cc
# from the CC_/linker env for the C deps).
SECRETSPEC_FFI_TARGET="$target" SECRETSPEC_FFI_PROFILE="$profile" \
  bash "$pkg_dir/scripts/stage-staticlib.sh"

what="${1:-./...}"
out="${2:-}"
build=(go build -buildvcs=false -tags static
  -ldflags '-linkmode external -extldflags "-static"')
[ -n "$out" ] && build+=(-o "$out")

cd "$pkg_dir"
CGO_ENABLED=1 CC="$MUSL_CC" CGO_LDFLAGS="$MUSL_STATIC_LDFLAGS" "${build[@]}" "$what"
echo "built fully-static ($target): ${out:-$what}"
