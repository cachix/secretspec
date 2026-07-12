#!/usr/bin/env bash
set -euo pipefail

asset_dir="${1:?usage: verify-ffi-assets.sh <asset-dir> <release-tag>}"
release_tag="${2:?usage: verify-ffi-assets.sh <asset-dir> <release-tag>}"

targets=(
	"x86_64-unknown-linux-gnu:so"
	"aarch64-unknown-linux-gnu:so"
	"x86_64-apple-darwin:dylib"
	"aarch64-apple-darwin:dylib"
	"x86_64-pc-windows-msvc:dll"
	"aarch64-pc-windows-msvc:dll"
)

for specification in "${targets[@]}"; do
	target="${specification%%:*}"
	extension="${specification##*:}"
	stem="monosecret-ffi-${target}-${release_tag}"
	payload="${stem}.${extension}"

	for file in "$payload" "${stem}.sha256" "${stem}.sha512"; do
		if [[ ! -f "$asset_dir/$file" ]]; then
			echo "Missing Monosecret FFI release asset: $file" >&2
			exit 1
		fi
	done

	(
		cd "$asset_dir"
		sha256sum --check "${stem}.sha256"
		sha512sum --check "${stem}.sha512"
	)
done
