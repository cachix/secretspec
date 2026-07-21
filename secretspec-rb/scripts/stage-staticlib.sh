#!/usr/bin/env bash
#
# Stage the secretspec-ffi staticlib (release) into vendor/ so a platform gem
# build bundles it: the archive, the C header, and the archive's transitive
# native deps. `gem install` then compiles only the tiny C glue and links the
# bundled archive. Run before `gem build`.
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$pkg_dir/.." && pwd)"

# Crate-type override: the gem only ships the staticlib, so skip the crate's
# other types (on windows-gnu this avoids linking the unused cdylib entirely).
cargo rustc -p secretspec-ffi --release --manifest-path "$repo_root/Cargo.toml" \
  --crate-type staticlib

# The trailing sed unescapes the JSON-escaped backslashes a Windows target
# directory arrives with (D:\\a\\... -> D:/a/...); a no-op elsewhere.
target_dir="$(cargo metadata --no-deps --format-version 1 --manifest-path "$repo_root/Cargo.toml" \
  | grep -o '"target_directory":"[^"]*"' | head -1 | sed 's/.*:"\(.*\)"/\1/' | sed 's/\\\\/\//g')"

# When CARGO_BUILD_TARGET is set (the Windows gem builds the
# x86_64-pc-windows-gnu staticlib), cargo nests output under the triple.
out_dir="$target_dir/${CARGO_BUILD_TARGET:+$CARGO_BUILD_TARGET/}release"

mkdir -p "$pkg_dir/vendor"
cp "$out_dir/libsecretspec_ffi.a" "$pkg_dir/vendor/libsecretspec_ffi.a"
cp "$repo_root/secretspec-ffi/include/secretspec.h" "$pkg_dir/vendor/secretspec.h"
cargo rustc -q -p secretspec-ffi --release --manifest-path "$repo_root/Cargo.toml" \
  --crate-type staticlib -- --print native-static-libs 2>&1 \
  | sed -n 's/^note: native-static-libs: //p' | tail -1 > "$pkg_dir/vendor/native-static-libs.txt"

# The windows-gnu link line references import libraries that live inside cargo
# registry crates, not in the MinGW toolchain; a user installing the gem has no
# cargo registry, so bundle them (extconf.rb adds vendor/ to the search path).
if [[ "${CARGO_BUILD_TARGET:-}" == *-windows-gnu ]]; then
  bash "$repo_root/scripts/copy-mingw-import-libs.sh" \
    "$pkg_dir/vendor/native-static-libs.txt" "$pkg_dir/vendor"
fi

echo "staged libsecretspec_ffi.a + secretspec.h + native-static-libs.txt into vendor/"
