#!/usr/bin/env bash
#
# Build the monosecret_ffi cdylib (release) and stage it into lib/ under the
# build-tagged name the embedded_<os>_<arch>.go files reference, so `go build`
# embeds it. Run before building/releasing the Go module.
#
# NOTE: the embedded libraries are large (tens of MB each) and are gitignored —
# do not commit them, in plain git or git-LFS. The module proxy does not run LFS
# smudge filters, so an LFS-committed lib reaches `go get` consumers as pointer
# text, not a library. Stage them at build time for a self-contained `-tags
# monosecret_embed` build, or attach the per-platform libs to the GitHub release.
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$pkg_dir/../.." && pwd)"

cargo build -p monosecret_ffi --release --manifest-path "$repo_root/Cargo.toml"

target_dir="$(cargo metadata --no-deps --format-version 1 --manifest-path "$repo_root/Cargo.toml" |
	grep -o '"target_directory":"[^"]*"' | head -1 | sed 's/.*:"\(.*\)"/\1/')"

goos="$(go env GOOS)"
goarch="$(go env GOARCH)"
case "$goos" in
darwin)
	src="libmonosecret_ffi.dylib"
	ext="dylib"
	;;
windows)
	src="monosecret_ffi.dll"
	ext="dll"
	;;
*)
	src="libmonosecret_ffi.so"
	ext="so"
	;;
esac

mkdir -p "$pkg_dir/lib"
cp "$target_dir/release/$src" "$pkg_dir/lib/monosecret_ffi_${goos}_${goarch}.${ext}"
echo "staged monosecret_ffi_${goos}_${goarch}.${ext} into lib/"
