#!/usr/bin/env bash
#
# Install a pinned yyjson for the CI runners that build libsecretspec-resolver
# without Nix. The devenv shell gets yyjson from nixpkgs instead.
#
#     install-yyjson.sh [prefix]
#
# Distribution packaging cannot cover all three runners: Ubuntu 24.04 has no
# libyyjson-dev at all, and Homebrew and vcpkg track the version independently.
# Building the pinned tag keeps every platform on the same yyjson the C client
# is tested against.
#
# Writes the discovery variables the build systems read to $GITHUB_ENV when it
# is set: PKG_CONFIG_PATH and CMAKE_PREFIX_PATH for Meson, CMake, and the
# pkg-config probe in the conformance build script, plus YYJSON_INCLUDE_DIR and
# YYJSON_LIB_DIR for runners with no pkg-config (Windows).
set -euo pipefail

# Keep the version in sync with libsecretspec-resolver/README.md. When bumping
# it, take the digest from the release tarball itself:
#   curl -fsSL https://github.com/ibireme/yyjson/archive/refs/tags/<tag>.tar.gz \
#     | sha256sum
yyjson_version="0.12.0"
yyjson_sha256="b16246f617b2a136c78d73e5e2647c6f1de1313e46678062985bdcf1f40bb75d"

prefix="${1:-${RUNNER_TEMP:-/tmp}/yyjson}"
# GitHub's Windows runners hand out backslash paths that CMake cannot consume
# through a bash string.
if command -v cygpath >/dev/null 2>&1; then
  prefix="$(cygpath -m "$prefix")"
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

archive="$workdir/yyjson.tar.gz"
curl --fail --location --silent --show-error \
  "https://github.com/ibireme/yyjson/archive/refs/tags/${yyjson_version}.tar.gz" \
  --output "$archive"

if command -v sha256sum >/dev/null 2>&1; then
  observed="$(sha256sum "$archive" | cut -d' ' -f1)"
else
  observed="$(shasum -a 256 "$archive" | cut -d' ' -f1)"
fi
if [[ "$observed" != "$yyjson_sha256" ]]; then
  echo "yyjson ${yyjson_version} digest mismatch" >&2
  echo "  expected $yyjson_sha256" >&2
  echo "  observed $observed" >&2
  exit 1
fi

tar -xzf "$archive" -C "$workdir"

cmake -S "$workdir/yyjson-${yyjson_version}" -B "$workdir/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DCMAKE_INSTALL_PREFIX="$prefix"
cmake --build "$workdir/build" --config Release
cmake --install "$workdir/build" --config Release

# GNUInstallDirs picks lib or lib64 per distribution, so read the libdir back
# from the install tree rather than assuming. MSVC puts its import library
# there too, so one pair of variables covers every runner.
libdir="$(dirname "$(find "$prefix" -name 'yyjson.pc' -print -quit)")"
libdir="$(dirname "$libdir")"

if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    echo "PKG_CONFIG_PATH=${libdir}/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
    echo "CMAKE_PREFIX_PATH=${prefix}${CMAKE_PREFIX_PATH:+:${CMAKE_PREFIX_PATH}}"
    echo "YYJSON_INCLUDE_DIR=${prefix}/include"
    echo "YYJSON_LIB_DIR=${libdir}"
  } >>"$GITHUB_ENV"
fi

echo "installed yyjson ${yyjson_version} to ${prefix}"
