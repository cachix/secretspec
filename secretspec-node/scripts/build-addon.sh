#!/usr/bin/env bash
#
# Build the napi-rs addon (release) via `napi build` and place it as
# secretspec.node next to index.js.
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
napi_bin="$pkg_dir/node_modules/.bin/napi"

# --output-dir keeps napi build's generated .d.ts (which would otherwise
# clobber the hand-maintained index.d.ts) out of pkg_dir entirely.
tmp_out="$(mktemp -d)"
trap 'rm -rf "$tmp_out"' EXIT
( cd "$pkg_dir" && "$napi_bin" build --release --output-dir "$tmp_out" )

# Install atomically: node --test runs test files in parallel processes that
# may build concurrently, and overwriting in place SIGBUSes a process that has
# already mapped the addon. A rename keeps the old inode valid for them.
mv -f "$tmp_out/secretspec.node" "$pkg_dir/secretspec.node.tmp.$$"
mv -f "$pkg_dir/secretspec.node.tmp.$$" "$pkg_dir/secretspec.node"
echo "built secretspec.node"
