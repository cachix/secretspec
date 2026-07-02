#!/usr/bin/env bash
#
# Compile the secretspec native extension (statically linking
# libsecretspec_ffi.a) and place it on the SDK's load path for dev and tests.
# extconf.rb honors the SECRETSPEC_FFI_STATICLIB / SECRETSPEC_FFI_NATIVE_LIBS /
# SECRETSPEC_FFI_INCLUDE contract (exported by scripts/ci-sdks.sh); otherwise it
# builds and locates the debug archive from the Cargo target dir.
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$pkg_dir/.." && pwd)"

if [ -z "${SECRETSPEC_FFI_STATICLIB:-}" ]; then
  cargo build -p secretspec-ffi --manifest-path "$repo_root/Cargo.toml"
fi

ext_dir="$pkg_dir/ext/secretspec"
( cd "$ext_dir" && ruby extconf.rb && make --silent )

# The build output lands in ext_dir (target_prefix only affects the install dir);
# copy it onto the SDK's load path so `require "secretspec/secretspec_ext"` finds it.
mkdir -p "$pkg_dir/lib/secretspec"
built=""
for f in "$ext_dir/secretspec_ext.so" "$ext_dir/secretspec_ext.bundle"; do
  [ -f "$f" ] && built="$f" && break
done
[ -n "$built" ] || { echo "build-ext: no secretspec_ext.{so,bundle} produced" >&2; exit 1; }
cp "$built" "$pkg_dir/lib/secretspec/$(basename "$built")"
echo "built $(basename "$built") into lib/secretspec/"
