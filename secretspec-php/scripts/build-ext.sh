#!/usr/bin/env bash
#
# Build the secretspec-php-native extension (an ext-php-rs PHP extension that
# embeds the resolver) and stage it as lib/secretspec.so, ready to load with
#
#     php -d extension="$(pwd)/lib/secretspec.so" ...
#
# or via `extension=` in php.ini. Set SECRETSPEC_PHP_PROFILE=debug for a faster
# unoptimized build (default: release).
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$pkg_dir/.." && pwd)"
profile="${SECRETSPEC_PHP_PROFILE:-release}"
target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"

case "$(uname -s)" in
  Darwin)               built="libsecretspec_php_native.dylib"; staged="secretspec.so" ;;
  MINGW*|MSYS*|CYGWIN*) built="secretspec_php_native.dll";       staged="secretspec.dll" ;;
  *)                    built="libsecretspec_php_native.so";     staged="secretspec.so" ;;
esac

build_flag=()
[ "$profile" = "release" ] && build_flag=(--release)
( cd "$repo_root" && cargo build "${build_flag[@]}" -p secretspec-php-native )

mkdir -p "$pkg_dir/lib"
# dlopen (which PHP uses to load extensions) resolves by path, not by suffix, so
# staging the macOS .dylib under a .so name loads fine.
cp -f "$target_dir/$profile/$built" "$pkg_dir/lib/$staged"
echo "built $pkg_dir/lib/$staged"
