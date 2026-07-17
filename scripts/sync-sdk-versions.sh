#!/usr/bin/env bash
#
# Keep package-manager metadata for non-Rust SDKs in lockstep with the Cargo
# workspace version. Release workflows run this before building artifacts so a
# single Cargo.toml bump drives every SDK package version.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

workspace_version="$(
  awk '
    /^\[workspace\.package\][[:space:]]*$/ { in_workspace_package = 1; next }
    /^\[/ { in_workspace_package = 0 }
    in_workspace_package && /^[[:space:]]*version[[:space:]]*=/ {
      line = $0
      sub(/^[^"]*"/, "", line)
      sub(/".*$/, "", line)
      print line
      exit
    }
  ' Cargo.toml
)"

if [[ -z "$workspace_version" ]]; then
  echo "could not find [workspace.package].version in Cargo.toml" >&2
  exit 1
fi

if [[ ! "$workspace_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "workspace version is not valid semver: $workspace_version" >&2
  exit 1
fi

tag_version=""
if [[ "${GITHUB_REF_TYPE:-}" == "tag" && -n "${GITHUB_REF_NAME:-}" ]]; then
  tag_version="${GITHUB_REF_NAME#v}"
elif [[ "${GITHUB_REF:-}" == refs/tags/* ]]; then
  tag_name="${GITHUB_REF#refs/tags/}"
  tag_version="${tag_name#v}"
fi

if [[ -n "$tag_version" && "$tag_version" != "$workspace_version" ]]; then
  echo "tag version ($tag_version) does not match Cargo workspace version ($workspace_version)" >&2
  exit 1
fi

update_file() {
  local file="$1"
  local kind="$2"
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/sync-sdk-version.XXXXXX")"

  case "$kind" in
    pyproject)
      awk -v version="$workspace_version" '
        /^\[project\][[:space:]]*$/ { in_project = 1 }
        /^\[/ && $0 !~ /^\[project\][[:space:]]*$/ { in_project = 0 }
        in_project && /^[[:space:]]*version[[:space:]]*=/ {
          print "version = \"" version "\""
          changed = 1
          next
        }
        { print }
        END { if (!changed) exit 1 }
      ' "$file" > "$tmp"
      ;;
    gemspec)
      awk -v version="$workspace_version" '
        !changed && /^[[:space:]]*spec\.version[[:space:]]*=/ {
          sub(/"[^"]+"/, "\"" version "\"")
          changed = 1
        }
        { print }
        END { if (!changed) exit 1 }
      ' "$file" > "$tmp"
      ;;
    cabal)
      # Cabal's version: field is PVP — dot-separated integers only — and rejects
      # the semver prerelease/build suffixes the validation above accepts (e.g.
      # v0.13.0-rc.1). Strip the suffix so a prerelease tag still produces a cabal
      # file that builds; the X.Y.Z prefix is what PVP cares about.
      local cabal_version="${workspace_version%%[-+]*}"
      if [[ "$cabal_version" != "$workspace_version" ]]; then
        echo "stripping semver suffix for cabal version: $workspace_version -> $cabal_version" >&2
      fi
      awk -v version="$cabal_version" '
        !changed && /^version:[[:space:]]*/ {
          print "version:            " version
          changed = 1
          next
        }
        { print }
        END { if (!changed) exit 1 }
      ' "$file" > "$tmp"
      ;;
    package-json)
      awk -v version="$workspace_version" '
        !changed && /^[[:space:]]*"version"[[:space:]]*:/ {
          sub(/"version"[[:space:]]*:[[:space:]]*"[^"]+"/, "\"version\": \"" version "\"")
          changed = 1
        }
        { print }
        END { if (!changed) exit 1 }
      ' "$file" > "$tmp"
      ;;
    csproj)
      awk -v version="$workspace_version" '
        !changed && /<Version>[^<]+<\/Version>/ {
          sub(/<Version>[^<]+<\/Version>/, "<Version>" version "</Version>")
          changed = 1
        }
        { print }
        END { if (!changed) exit 1 }
      ' "$file" > "$tmp"
      ;;
    *)
      echo "unknown manifest kind: $kind" >&2
      rm -f "$tmp"
      exit 1
      ;;
  esac

  mv "$tmp" "$file"
}

update_file secretspec-py/pyproject.toml pyproject
update_file secretspec-rb/secretspec.gemspec gemspec
update_file secretspec-hs/secretspec.cabal cabal
update_file secretspec-node/package.json package-json
update_file secretspec-dotnet/src/SecretSpec/SecretSpec.csproj csproj

echo "synced SDK package versions to $workspace_version"
