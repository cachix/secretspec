#!/usr/bin/env bash
#
# Build the napi-rs addon via `napi build` and place it as secretspec.node next
# to index.js. Set SECRETSPEC_NODE_PROFILE=debug for a faster unoptimized build
# (default: release). Extra arguments are forwarded to `napi build`.
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
napi_bin="$pkg_dir/node_modules/.bin/napi"
profile="${SECRETSPEC_NODE_PROFILE:-release}"

case "$profile" in
  release) profile_args=(--release) ;;
  debug) profile_args=() ;;
  *)
    echo "error: SECRETSPEC_NODE_PROFILE must be 'release' or 'debug'" >&2
    exit 2
    ;;
esac

# --output-dir keeps napi build's generated .d.ts (which would otherwise
# clobber the hand-maintained index.d.ts) out of pkg_dir entirely.
tmp_out="$(mktemp -d)"
trap 'rm -rf "$tmp_out"' EXIT
( cd "$pkg_dir" && "$napi_bin" build "${profile_args[@]}" --output-dir "$tmp_out" "$@" )

# Install atomically: node --test runs test files in parallel processes that
# may build concurrently, and overwriting in place SIGBUSes a process that has
# already mapped the addon. A rename keeps the old inode valid for them.
mv -f "$tmp_out/secretspec.node" "$pkg_dir/secretspec.node.tmp.$$"
mv -f "$pkg_dir/secretspec.node.tmp.$$" "$pkg_dir/secretspec.node"
echo "built secretspec.node"
