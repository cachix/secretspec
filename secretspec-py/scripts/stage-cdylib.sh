#!/usr/bin/env bash
#
# Build the secretspec-ffi cdylib (release) and stage it into
# secretspec/_lib/ so a wheel build bundles it. Run before building the wheel.
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$pkg_dir/.." && pwd)"

cargo build -p secretspec-ffi --release --manifest-path "$repo_root/Cargo.toml"

target_dir="$(cargo metadata --no-deps --format-version 1 --manifest-path "$repo_root/Cargo.toml" \
  | grep -o '"target_directory":"[^"]*"' | head -1 | sed 's/.*:"\(.*\)"/\1/')"
case "$(uname -s)" in
  Darwin)                lib_name="libsecretspec_ffi.dylib" ;;
  MINGW* | MSYS* | CYGWIN*) lib_name="secretspec_ffi.dll" ;;
  *)                     lib_name="libsecretspec_ffi.so" ;;
esac

mkdir -p "$pkg_dir/secretspec/_lib"
cp "$target_dir/release/$lib_name" "$pkg_dir/secretspec/_lib/$lib_name"
echo "staged $lib_name into secretspec/_lib/"
