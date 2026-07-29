#!/usr/bin/env bash
#
# Build the secretspec-ffi cdylib (release) and stage it into lib/ under the
# build-tagged name the embedded_<os>_<arch>.go files reference, so `go build`
# embeds it. Run before building/releasing the Go module.
#
# NOTE: the embedded libraries are large (tens of MB each) and are gitignored —
# do not commit them, in plain git or git-LFS. The module proxy does not run LFS
# smudge filters, so an LFS-committed lib reaches `go get` consumers as pointer
# text, not a library. Stage them at build time for a self-contained `-tags
# embed_lib` build, or attach the per-platform libs to the GitHub release.
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$pkg_dir/.." && pwd)"

goos="$(go env GOOS)"
goarch="$(go env GOARCH)"

build_args=(
  -p secretspec-ffi
  --release
  --manifest-path "$repo_root/Cargo.toml"
)
# The staged library is a distributable artifact, not a development build.
# Linux consumers cannot be expected to provide the exact libdbus soname from
# the build host (notably on NixOS), so compile libdbus into the cdylib.
if [[ "$goos" == "linux" ]]; then
  build_args+=(--features vendored-dbus)
fi
cargo build "${build_args[@]}"

target_dir="$(cargo metadata --no-deps --format-version 1 --manifest-path "$repo_root/Cargo.toml" \
  | grep -o '"target_directory":"[^"]*"' | head -1 | sed 's/.*:"\(.*\)"/\1/')"

case "$goos" in
  darwin)  src="libsecretspec_ffi.dylib"; ext="dylib" ;;
  windows) src="secretspec_ffi.dll";      ext="dll" ;;
  *)       src="libsecretspec_ffi.so";    ext="so" ;;
esac

mkdir -p "$pkg_dir/lib"
cp "$target_dir/release/$src" "$pkg_dir/lib/secretspec_ffi_${goos}_${goarch}.${ext}"
echo "staged secretspec_ffi_${goos}_${goarch}.${ext} into lib/"
