#!/usr/bin/env bash
#
# Install the SecretSpec C ABI into a predictable prefix layout. cargo-c uses
# lib/<host-triplet> on Debian-like hosts by default, so keep the library and
# pkg-config directories stable for SDK consumers on every platform.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 PREFIX" >&2
  exit 2
fi

prefix="$1"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cargo cinstall -p secretspec-ffi --manifest-path "$repo_root/Cargo.toml" \
  --library-type staticlib \
  --prefix "$prefix" \
  --libdir lib \
  --pkgconfigdir lib/pkgconfig
