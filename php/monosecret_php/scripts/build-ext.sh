#!/usr/bin/env bash
#
# Build the monosecret-php-native extension (an ext-php-rs PHP extension that
# embeds the resolver) and stage it as lib/monosecret.so, ready to load with
#
#     php -d extension="$(pwd)/lib/monosecret.so" ...
#
# or via `extension=` in php.ini. Set MONOSECRET_PHP_PROFILE=debug for a faster
# unoptimized build (default: release).
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$pkg_dir/../.." && pwd)"
profile="${MONOSECRET_PHP_PROFILE:-release}"
target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"

case "$(uname -s)" in
Darwin)
	built="libmonosecret_php_native.dylib"
	staged="monosecret.so"
	;;
MINGW* | MSYS* | CYGWIN*)
	built="monosecret_php_native.dll"
	staged="monosecret.dll"
	;;
*)
	built="libmonosecret_php_native.so"
	staged="monosecret.so"
	;;
esac

build_flag=()
[ "$profile" = "release" ] && build_flag=(--release)
(cd "$repo_root" && cargo build "${build_flag[@]}" -p monosecret-php-native)

mkdir -p "$pkg_dir/lib"
# dlopen (which PHP uses to load extensions) resolves by path, not by suffix, so
# staging the macOS .dylib under a .so name loads fine.
cp -f "$target_dir/$profile/$built" "$pkg_dir/lib/$staged"
echo "built $pkg_dir/lib/$staged"
