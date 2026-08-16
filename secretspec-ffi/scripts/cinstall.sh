#!/usr/bin/env bash
#
# Install one form of the SecretSpec C ABI into a predictable prefix layout.
# cargo-c uses lib/<host-triplet> on Debian-like hosts by default, so keep the
# library and pkg-config directories stable for SDK consumers on every platform.
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
  echo "usage: $0 PREFIX [static|shared] [release|debug]" >&2
  exit 2
fi

prefix="$1"
mode="${2:-static}"
profile="${3:-release}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

case "$mode" in
  static) library_type="staticlib" ;;
  shared) library_type="cdylib" ;;
  *)
    echo "error: library type must be 'static' or 'shared'" >&2
    exit 2
    ;;
esac

case "$profile" in
  release) profile_args=() ;;
  debug) profile_args=(--debug) ;;
  *)
    echo "error: profile must be 'release' or 'debug'" >&2
    exit 2
    ;;
esac

cargo cinstall -p secretspec-ffi --manifest-path "$repo_root/Cargo.toml" \
  --library-type "$library_type" \
  --prefix "$prefix" \
  --bindir lib \
  --libdir lib \
  --pkgconfigdir lib/pkgconfig \
  "${profile_args[@]}"
