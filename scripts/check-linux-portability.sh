#!/usr/bin/env bash
#
# Verify a Linux native library built in the manylinux_2_28 container stays
# loadable on older supported glibc distributions with no system libdbus
# dependency (issue #136: an unverified build once shipped a broken addon).
#
#     check-linux-portability.sh <library>
#
# Read the version-reference table (objdump -p), not per-symbol version tags
# (objdump -T): file-level ABI markers such as GLIBC_ABI_DT_RELR (needs
# glibc >= 2.36) are attached to no symbol, so a symbol scan stays green on a
# binary older loaders reject. Numeric needs above GLIBC_2.28 fail, and so
# does any GLIBC_* version need that is not plain numeric.
set -euo pipefail

library="${1:?usage: check-linux-portability.sh <library>}"

headers=$(objdump -p "$library")
too_new=$(grep -oE 'GLIBC_[A-Za-z0-9_.]+' <<<"$headers" \
  | sort -u \
  | awk -F. '/^GLIBC_2\.[0-9]+(\.[0-9]+)?$/ { if ($2 + 0 > 28) print; next } { print }')
if [ -n "$too_new" ]; then
  echo "$library requires glibc version needs newer than the 2.28 baseline:" >&2
  echo "$too_new" >&2
  exit 1
fi
if grep NEEDED <<<"$headers" | grep -q dbus; then
  echo "$library links libdbus dynamically; vendored-dbus regressed:" >&2
  grep NEEDED <<<"$headers" >&2
  exit 1
fi
