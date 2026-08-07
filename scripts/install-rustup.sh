#!/usr/bin/env bash
#
# Install a pinned rustup bootstrap in Linux build containers that do not ship
# Rust. The compiler toolchain remains pinned separately by rust-toolchain.toml.
set -euo pipefail

# When updating, verify each digest against the matching rustup-init.sha256 at
# https://static.rust-lang.org/rustup/archive/<version>/<target>/.
rustup_version="1.29.0"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "install-rustup.sh only supports Linux build containers" >&2
  exit 2
fi

case "$(uname -m)" in
  x86_64 | amd64)
    rustup_arch="x86_64"
    ;;
  aarch64 | arm64)
    rustup_arch="aarch64"
    ;;
  *)
    echo "unsupported rustup architecture: $(uname -m)" >&2
    exit 2
    ;;
esac

rustup_libc="gnu"
ldd_version="$(ldd --version 2>&1 || true)"
if [[ "$ldd_version" == *musl* ]]; then
  rustup_libc="musl"
fi
rustup_target="${rustup_arch}-unknown-linux-${rustup_libc}"

case "$rustup_target" in
  x86_64-unknown-linux-gnu)
    expected_sha256="4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10"
    ;;
  aarch64-unknown-linux-gnu)
    expected_sha256="9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792"
    ;;
  x86_64-unknown-linux-musl)
    expected_sha256="9cd3fda5fd293890e36ab271af6a786ee22084b5f6c2b83fd8323cec6f0992c1"
    ;;
  aarch64-unknown-linux-musl)
    expected_sha256="88761caacddb92cd79b0b1f939f3990ba1997d701a38b3e8dd6746a562f2a759"
    ;;
esac

rustup_init="$(mktemp "${TMPDIR:-/tmp}/rustup-init.XXXXXX")"
trap 'rm -f "$rustup_init"' EXIT
rustup_url="https://static.rust-lang.org/rustup/archive/${rustup_version}/${rustup_target}/rustup-init"

curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  "$rustup_url" --output "$rustup_init"

if command -v sha256sum >/dev/null; then
  actual_sha256="$(sha256sum "$rustup_init" | awk '{ print $1 }')"
elif command -v shasum >/dev/null; then
  actual_sha256="$(shasum -a 256 "$rustup_init" | awk '{ print $1 }')"
else
  echo "sha256sum or shasum is required to verify rustup-init" >&2
  exit 1
fi

if [[ "$actual_sha256" != "$expected_sha256" ]]; then
  echo "rustup-init checksum mismatch for $rustup_target" >&2
  echo "expected: $expected_sha256" >&2
  echo "actual:   $actual_sha256" >&2
  exit 1
fi

chmod +x "$rustup_init"
"$rustup_init" -y --default-toolchain none
