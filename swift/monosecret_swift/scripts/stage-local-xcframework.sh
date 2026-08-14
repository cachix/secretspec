#!/usr/bin/env bash
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$(cd "$pkg_dir/../.." && pwd)"
lib="${MONOSECRET_FFI_LIB:-$repo_root/target/debug/libmonosecret_ffi.dylib}"
out="$pkg_dir/Artifacts/CMonosecret.xcframework"
headers="$(mktemp -d)"
trap 'rm -rf "$headers"' EXIT

cp "$repo_root/crates/monosecret_ffi/include/monosecret.h" "$headers/monosecret.h"
cp "$pkg_dir/ffi/module.modulemap" "$headers/module.modulemap"
rm -rf "$out"
mkdir -p "$(dirname "$out")"
xcodebuild -create-xcframework -library "$lib" -headers "$headers" -output "$out"
