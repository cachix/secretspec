#!/usr/bin/env bash
#
# Compile the monosecret native extension (statically linking
# libmonosecret_ffi.a) and place it on the SDK's load path for dev and tests.
# extconf.rb honors the MONOSECRET_FFI_STATICLIB / MONOSECRET_FFI_NATIVE_LIBS /
# MONOSECRET_FFI_INCLUDE contract (exported by scripts/ci-sdks.sh); otherwise it
# builds and locates the debug archive from the Cargo target dir.
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$pkg_dir/../.." && pwd)"

if [ -z "${MONOSECRET_FFI_STATICLIB:-}" ]; then
	cargo build -p monosecret_ffi --manifest-path "$repo_root/Cargo.toml"
fi

ext_dir="$pkg_dir/ext/monosecret"
(cd "$ext_dir" && ruby extconf.rb && make --silent)

# The build output lands in ext_dir (target_prefix only affects the install dir);
# copy it onto the SDK's load path so `require "monosecret/monosecret_ext"` finds it.
mkdir -p "$pkg_dir/lib/monosecret"
built=""
for f in "$ext_dir/monosecret_ext.so" "$ext_dir/monosecret_ext.bundle"; do
	[ -f "$f" ] && built="$f" && break
done
[ -n "$built" ] || {
	echo "build-ext: no monosecret_ext.{so,bundle} produced" >&2
	exit 1
}
cp "$built" "$pkg_dir/lib/monosecret/$(basename "$built")"
echo "built $(basename "$built") into lib/monosecret/"
