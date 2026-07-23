#!/usr/bin/env bash
#
# Copy the MinGW import libraries a windows-gnu staticlib's link line needs out
# of the cargo registry. rustc's native-static-libs note names them like system
# libraries (-lwindows.0.52.0, -lwinapi_advapi32), but they ship inside the
# windows-sys/winapi support crates -- a MinGW toolchain does not provide them,
# so a consumer linking the staticlib outside cargo (mkmf, GHC) needs a copy in
# its library search path. System libraries in the note (kernel32, ws2_32, ...)
# are skipped: every MinGW distribution provides those.
#
# Usage: copy-mingw-import-libs.sh <native-static-libs-file> <dest-dir>
set -euo pipefail

note_file="$1"
dest="$2"

# In an MSYS2 shell HOME is the MSYS home, but rustup's registry lives under
# the Windows profile; prefer CARGO_HOME, then the profile, then POSIX HOME.
cargo_home="${CARGO_HOME:-}"
if [ -z "$cargo_home" ]; then
  if [ -n "${USERPROFILE:-}" ] && [ -d "$USERPROFILE/.cargo" ]; then
    cargo_home="$USERPROFILE/.cargo"
  else
    cargo_home="$HOME/.cargo"
  fi
fi
if command -v cygpath >/dev/null 2>&1; then
  cargo_home="$(cygpath -u "$cargo_home")"
fi

mkdir -p "$dest"
while read -r name; do
  for dir in "$cargo_home"/registry/src/*/windows_x86_64_gnu-*/lib \
             "$cargo_home"/registry/src/*/winapi-x86_64-pc-windows-gnu-*/lib; do
    if [ -f "$dir/lib$name.a" ]; then
      cp -f "$dir/lib$name.a" "$dest/"
      echo "bundled lib$name.a (cargo registry import library)"
      break
    fi
  done
done < <(tr ' ' '\n' < "$note_file" | sed -n 's/^-l//p')
