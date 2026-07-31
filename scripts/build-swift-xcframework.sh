#!/usr/bin/env bash
#
# Package one or more macOS secretspec-ffi cdylibs as the CSecretSpec
# XCFramework imported by the Swift SDK. Pass one native library per
# architecture; multiple inputs are merged into one universal Mach-O because
# xcodebuild rejects separate library definitions for the same platform.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "$#" -lt 2 ]]; then
  echo "usage: $0 OUTPUT.xcframework LIBSECRETSPEC_FFI.dylib [...]" >&2
  exit 2
fi

output="$1"
shift

if [[ "$output" != *.xcframework || "$output" == "/" ]]; then
  echo "output must be a specific .xcframework path: $output" >&2
  exit 2
fi
if [[ -e "$output" ]]; then
  echo "output already exists: $output" >&2
  exit 2
fi
if ! command -v xcodebuild >/dev/null 2>&1; then
  echo "xcodebuild is required (run this script on macOS with Xcode)" >&2
  exit 1
fi

staging="$(mktemp -d "${TMPDIR:-/tmp}/secretspec-swift.XXXXXX")"
trap 'rm -rf "$staging"' EXIT

seen_arches=""

for library in "$@"; do
  if [[ ! -f "$library" ]]; then
    echo "native library does not exist: $library" >&2
    exit 2
  fi

  arches="$(xcrun lipo -archs "$library")"
  if [[ -z "$arches" ]]; then
    echo "could not determine Mach-O architecture: $library" >&2
    exit 1
  fi
  for arch in $arches; do
    if [[ " $seen_arches " == *" $arch "* ]]; then
      echo "duplicate architecture $arch in $library" >&2
      exit 2
    fi
    seen_arches="$seen_arches $arch"
  done

done

slice="$staging/macos"
headers="$slice/Headers"
mkdir -p "$headers"
staged_library="$slice/libCSecretSpec.dylib"
if [[ "$#" -eq 1 ]]; then
  cp "$1" "$staged_library"
else
  xcrun lipo -create "$@" -output "$staged_library"
fi
cp "$repo_root/secretspec-ffi/include/secretspec.h" "$headers/"
cp "$repo_root/secretspec-swift/ffi/module.modulemap" "$headers/"

# A SwiftPM binary target embeds this dylib beside the consumer and supplies
# an @rpath. Do not retain Cargo's absolute/target-local install name. The
# edit invalidates Cargo/linker's existing signature on Apple silicon, so
# replace it with a deterministic ad-hoc signature for local SwiftPM loads;
# application distribution can sign the embedded dylib with its own identity.
install_name_tool -id "@rpath/libCSecretSpec.dylib" "$staged_library"
codesign --force --sign - --timestamp=none "$staged_library"

mkdir -p "$(dirname "$output")"
xcodebuild -create-xcframework \
  -library "$staged_library" \
  -headers "$headers" \
  -output "$output"
