#!/usr/bin/env bash
#
# Build the secretspec-ffi cdylib (release) and stage it into lib/ under the
# build-tagged name the embedded_<os>_<arch>.go files reference, so `go build`
# embeds it. Run before building/releasing the Go module.
#
# NOTE: the embedded libraries are large (tens of MB each); a release should
# commit them via git-LFS (or stage them into a release tag) rather than plain
# git. They are gitignored here.
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$pkg_dir/.." && pwd)"

cargo build -p secretspec-ffi --release --manifest-path "$repo_root/Cargo.toml"

target_dir="$(cargo metadata --no-deps --format-version 1 --manifest-path "$repo_root/Cargo.toml" \
  | grep -o '"target_directory":"[^"]*"' | head -1 | sed 's/.*:"\(.*\)"/\1/')"

goos="$(go env GOOS)"
goarch="$(go env GOARCH)"
case "$goos" in
  darwin)  src="libsecretspec_ffi.dylib"; ext="dylib" ;;
  windows) src="secretspec_ffi.dll";      ext="dll" ;;
  *)       src="libsecretspec_ffi.so";    ext="so" ;;
esac

mkdir -p "$pkg_dir/lib"
cp "$target_dir/release/$src" "$pkg_dir/lib/secretspec_ffi_${goos}_${goarch}.${ext}"
echo "staged secretspec_ffi_${goos}_${goarch}.${ext} into lib/"
