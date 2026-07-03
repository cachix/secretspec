#!/usr/bin/env bash
#
# Stage the secretspec-ffi staticlib (release) into vendor/ so a platform gem
# build bundles it: the archive, the C header, and the archive's transitive
# native deps. `gem install` then compiles only the tiny C glue and links the
# bundled archive. Run before `gem build`.
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$pkg_dir/.." && pwd)"

cargo build -p secretspec-ffi --release --manifest-path "$repo_root/Cargo.toml"

target_dir="$(cargo metadata --no-deps --format-version 1 --manifest-path "$repo_root/Cargo.toml" \
  | grep -o '"target_directory":"[^"]*"' | head -1 | sed 's/.*:"\(.*\)"/\1/')"

mkdir -p "$pkg_dir/vendor"
cp "$target_dir/release/libsecretspec_ffi.a" "$pkg_dir/vendor/libsecretspec_ffi.a"
cp "$repo_root/secretspec-ffi/include/secretspec.h" "$pkg_dir/vendor/secretspec.h"
cargo rustc -q -p secretspec-ffi --release --manifest-path "$repo_root/Cargo.toml" \
  --crate-type staticlib -- --print native-static-libs 2>&1 \
  | sed -n 's/^note: native-static-libs: //p' | tail -1 > "$pkg_dir/vendor/native-static-libs.txt"
echo "staged libsecretspec_ffi.a + secretspec.h + native-static-libs.txt into vendor/"
