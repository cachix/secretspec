#!/usr/bin/env bash
#
# Attach release assets (each with a sha256 sidecar) to the GitHub Release for
# a tag:
#
#     upload-release-asset.sh <tag> <asset> [asset...]
#
# cargo-dist's v-release.yml creates the release for the same tag concurrently,
# so wait for it to exist, then upload with --clobber (either workflow may
# retry). Needs GH_TOKEN with contents: write.
set -euo pipefail

if (( $# < 2 )); then
  echo "usage: upload-release-asset.sh <tag> <asset> [asset...]" >&2
  exit 2
fi

tag="$1"
shift

# Release publication uses version tags. Reject malformed input before it is
# passed to gh, while allowing SemVer prerelease and build suffixes.
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z][0-9A-Za-z.+-]*)?$ ]]; then
  echo "invalid release tag: $tag" >&2
  exit 2
fi

files=()
for asset in "$@"; do
  # Record only the basename so `sha256sum -c` works after users download the
  # asset and sidecar into the same directory, regardless of the runner path.
  asset_name="$(basename "$asset")"
  if command -v sha256sum >/dev/null; then
    digest="$(sha256sum "$asset" | awk '{ print $1 }')"
  else
    digest="$(shasum -a 256 "$asset" | awk '{ print $1 }')"
  fi
  printf '%s  %s\n' "$digest" "$asset_name" > "$asset.sha256"
  files+=("$asset" "$asset.sha256")
done

# Wait for cargo-dist to create the release (concurrent workflow). Building the
# full five-platform CLI matrix can take well over ten minutes on uncached
# runners, so allow an hour before treating the release as missing.
for _ in $(seq 1 180); do
  if gh release view "$tag" >/dev/null 2>&1; then
    break
  fi
  sleep 20
done
if ! gh release view "$tag" >/dev/null 2>&1; then
  echo "GitHub Release $tag was not created within one hour" >&2
  exit 1
fi
gh release upload "$tag" "${files[@]}" --clobber
