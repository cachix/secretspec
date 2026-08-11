#!/usr/bin/env bash
set -euo pipefail

repro_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

run_case() {
  local label="$1"
  local image="$2"
  local repro_case="$3"

  echo
  echo "==> $label"
  docker run --rm \
    --env "REPRO_CASE=$repro_case" \
    --volume "$repro_dir:/repro:ro" \
    "$image" \
    sh /repro/run-case.sh
}

# Pin Ruby's patch version so the reproduction does not silently move to a
# future Ruby/Bundler release. run-case.sh also verifies Bundler's major version.
run_case "glibc control" "ruby:4.0.6-slim" "gnu"
run_case "musl platform mismatch" "ruby:4.0.6-alpine" "musl"
run_case "missing ruby-platform fallback" "ruby:4.0.6-slim" "force-ruby"
