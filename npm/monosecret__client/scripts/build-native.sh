#!/usr/bin/env bash
#
# Build the napi-rs addon (release) via `napi build` and place it as
# monosecret.node next to index.js. Extra arguments are forwarded to
# `napi build`.
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
napi_bin="$pkg_dir/node_modules/.bin/napi"

# --output-dir keeps napi build's generated declarations out of the TypeScript
# build output.
tmp_out="$(mktemp -d)"
trap 'rm -rf "$tmp_out"' EXIT
(cd "$pkg_dir" && "$napi_bin" build --release --output-dir "$tmp_out" "$@")

# Install atomically: node --test runs test files in parallel processes that
# may build concurrently, and overwriting in place SIGBUSes a process that has
# already mapped the addon. A rename keeps the old inode valid for them.
mv -f "$tmp_out/monosecret-client.node" "$pkg_dir/monosecret-client.node.tmp.$$"
mv -f "$pkg_dir/monosecret-client.node.tmp.$$" "$pkg_dir/monosecret-client.node"
echo "built monosecret-client.node"
