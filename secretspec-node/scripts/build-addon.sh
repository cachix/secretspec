#!/usr/bin/env bash
#
# Build the napi-rs addon (release) and place it as secretspec.node next to
# index.js. A napi cdylib is itself a valid Node addon, so this is just a
# cargo build plus a rename.
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$pkg_dir/.." && pwd)"

cargo build -p secretspec-node-native --release --manifest-path "$repo_root/Cargo.toml"

target_dir="$(cargo metadata --no-deps --format-version 1 --manifest-path "$repo_root/Cargo.toml" \
  | grep -o '"target_directory":"[^"]*"' | head -1 | sed 's/.*:"\(.*\)"/\1/')"
case "$(uname -s)" in
  Darwin)                  src="libsecretspec_node_native.dylib" ;;
  MINGW* | MSYS* | CYGWIN*) src="secretspec_node_native.dll" ;;
  *)                       src="libsecretspec_node_native.so" ;;
esac

cp "$target_dir/release/$src" "$pkg_dir/secretspec.node"
echo "built secretspec.node"
