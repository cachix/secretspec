#!/usr/bin/env bash
#
# Verify a Linux native library built in the musllinux_1_2 container links
# against musl and carries no system libdbus dependency.
#
#     check-musl-portability.sh <library> [arch]
#
# `arch` names the musl libc the library must use, as `uname -m` spells it, and
# defaults to the host. Pass it for a cross-compiled library.
#
# Read the dynamic dependencies (readelf -d), not symbol versions. On ARM musl
# the libgcc_s library exports a compatibility symbol version named GLIBC_2.0.
# A symbol scan therefore reports a glibc need on a library that has none.
set -euo pipefail

library="${1:?usage: check-musl-portability.sh <library> [arch]}"
arch="${2:-$(uname -m)}"

case "$arch" in
  x86_64 | amd64) expected_libc=libc.musl-x86_64.so.1 ;;
  aarch64 | arm64) expected_libc=libc.musl-aarch64.so.1 ;;
  *)
    echo "unsupported musl architecture: $arch" >&2
    exit 2
    ;;
esac

needed=$(readelf -d "$library" | grep NEEDED)

if grep -q '\[libc\.so\.6\]' <<<"$needed"; then
  echo "$library links glibc instead of musl:" >&2
  echo "$needed" >&2
  exit 1
fi
if ! grep -Fq "[$expected_libc]" <<<"$needed"; then
  echo "$library does not link $expected_libc:" >&2
  echo "$needed" >&2
  exit 1
fi
if grep -q dbus <<<"$needed"; then
  echo "$library unexpectedly links libdbus dynamically:" >&2
  echo "$needed" >&2
  exit 1
fi
