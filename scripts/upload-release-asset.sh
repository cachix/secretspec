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

tag="$1"
shift

files=()
for asset in "$@"; do
  # sha256 sidecar (BSD shasum on macOS, GNU sha256sum on Linux; both here).
  if command -v sha256sum >/dev/null; then sha256sum "$asset" > "$asset.sha256"
  else shasum -a 256 "$asset" > "$asset.sha256"; fi
  files+=("$asset" "$asset.sha256")
done

# Wait for cargo-dist to create the release (concurrent workflow). Building the
# full five-platform CLI matrix can take well over ten minutes on uncached
# runners, so allow an hour before treating the release as missing.
for _ in $(seq 1 180); do
  gh release view "$tag" >/dev/null 2>&1 && break || sleep 20
done
if ! gh release view "$tag" >/dev/null 2>&1; then
  echo "GitHub Release $tag was not created within one hour" >&2
  exit 1
fi
gh release upload "$tag" "${files[@]}" --clobber
