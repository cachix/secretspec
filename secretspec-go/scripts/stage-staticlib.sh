#!/usr/bin/env bash
#
# Stage the secretspec-ffi staticlib for the `-tags static` cgo build: the
# per-platform archive (lib/), the C header (include/), and a generated
# cgo_ldflags_<os>_<arch>.go carrying the archive path + its transitive native
# deps (captured from `rustc --print native-static-libs`, never hardcoded).
#
# Honors:
#   SECRETSPEC_FFI_PROFILE  release|debug   (default: debug)
#   SECRETSPEC_FFI_TARGET   a rust target triple, e.g. x86_64-unknown-linux-musl
#                           (default: host; required for a fully-static binary)
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$pkg_dir/.." && pwd)"

goos="$(go env GOOS)"
goarch="$(go env GOARCH)"
profile="${SECRETSPEC_FFI_PROFILE:-debug}"
target="${SECRETSPEC_FFI_TARGET:-}"

build=(-p secretspec-ffi --manifest-path "$repo_root/Cargo.toml")
[ "$profile" = release ] && build+=(--release)
[ -n "$target" ] && build+=(--target "$target")
cargo build "${build[@]}"

native_libs="$(cargo rustc -q "${build[@]}" --crate-type staticlib -- \
  --print native-static-libs 2>&1 | sed -n 's/^note: native-static-libs: //p' | tail -1)"

tdir="$(cargo metadata --no-deps --format-version 1 --manifest-path "$repo_root/Cargo.toml" \
  | grep -o '"target_directory":"[^"]*"' | head -1 | sed 's/.*:"\(.*\)"/\1/')"
a_path="$tdir/${target:+$target/}$profile/libsecretspec_ffi.a"

mkdir -p "$pkg_dir/lib" "$pkg_dir/include"
cp "$a_path" "$pkg_dir/lib/libsecretspec_ffi_${goos}_${goarch}.a"
cp "$repo_root/secretspec-ffi/include/secretspec.h" "$pkg_dir/include/secretspec.h"

# The cgo LDFLAGS live in a generated per-platform file (the wasmtime-go pattern):
# the archive is pulled for the referenced symbols, then its native deps follow.
cat > "$pkg_dir/cgo_ldflags_${goos}_${goarch}.go" <<EOF
//go:build static && $goos && $goarch

package secretspec

/*
#cgo LDFLAGS: \${SRCDIR}/lib/libsecretspec_ffi_${goos}_${goarch}.a $native_libs
*/
import "C"
EOF

echo "staged lib/libsecretspec_ffi_${goos}_${goarch}.a + include/secretspec.h + cgo_ldflags_${goos}_${goarch}.go"
