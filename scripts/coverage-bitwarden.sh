#!/usr/bin/env bash
#
# Reproducible code-coverage measurement for the Bitwarden provider (bw.rs),
# for cachix/secretspec PR #166. Measures:
#
#   unit        in-file bw.rs unit tests + the bw URI tests in provider/tests.rs
#   integration tests/bitwarden_integration.sh (via the vaultwarden harness)
#   collection  tests/bitwarden_collection_addressing.sh
#   regressions tests/bitwarden_regression_findings.sh (RUN_REGRESSIONS=1)
#
# Reports function / line / branch coverage per source file for bw.rs,
# provider/mod.rs and provider/tests.rs, and appends a dated, git-rev-stamped
# entry to scripts/coverage-bitwarden.md.
#
# Instrumentation notes:
#   - RUSTFLAGS="-C instrument-coverage" only. `-C link-dead-code` would make
#     function coverage complete, but it also forces dead objc2/core-foundation
#     paths to be linked, and those reference macOS 15 CoreFoundation symbols
#     (CFAllocatorAllocateBytes et al.) that are absent from an SDK 14.4
#     toolchain, so the bin fails to link. Consequence: functions a normal
#     build fully dead-strips never appear in the report (they cannot be
#     counted as uncovered). For bw.rs this is limited to unreferenced helpers.
#
# Run inside the project's devenv shell (pinned toolchain, nix bw CLI, docker
# client), with a container runtime up (podman in docker-compat mode works):
#
#   devenv shell -- scripts/coverage-bitwarden.sh
#
# The instrumented build and all raw profiles live under target/coverage/
# (gitignored). No upstream build/CI files are touched; the only committed
# change this relies on is the SECRETSPEC_BIN hook in the three bw test
# scripts (skip the local `cargo build` and run a caller-supplied binary).
#
# Flags:
#   --no-build      reuse an existing instrumented build under target/coverage/build
#   --no-unit       skip the unit-test runs (keep existing raw profiles)
#   --suites X      which harness suites to run: all|integration|collection|regressions|none
#   --report-only   skip build/unit/suites; merge existing raw profiles and report
#   --clean         wipe raw/merged/reports before running
#   --no-history    do not append to the history .md
#   --worst [N]     after reporting, print the N worst-covered functions of bw.rs
#                   under the unit profile (N defaults to ${WORST_N:-20}; set
#                   WORST_SCENARIO=unit+all to use the full profile, and
#                   WORST_SORT=missed to sort by uncovered-line count)
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT"

COV_ROOT="${COV_ROOT:-$REPO_ROOT/target/coverage}"
BUILD_DIR="$COV_ROOT/build"
RAW_DIR="$COV_ROOT/raw"
MERGED_DIR="$COV_ROOT/merged"
REPORT_DIR="$COV_ROOT/reports"
HISTORY_FILE="${HISTORY_FILE:-$REPO_ROOT/scripts/coverage-bitwarden.md}"

# Source files to measure (whole-file coverage; only the added lines of
# mod.rs/tests.rs are the PR's, bw.rs is entirely the PR's).
SOURCES=(
  "$REPO_ROOT/secretspec/src/provider/bw.rs"
  "$REPO_ROOT/secretspec/src/provider/mod.rs"
  "$REPO_ROOT/secretspec/src/provider/tests.rs"
)

LLVM_COV="${LLVM_COV:-}"
LLVM_PROFDATA="${LLVM_PROFDATA:-}"
[ -z "$LLVM_COV" ] && LLVM_COV="$(command -v llvm-cov || echo /opt/homebrew/opt/llvm/bin/llvm-cov)"
[ -z "$LLVM_PROFDATA" ] && LLVM_PROFDATA="$(command -v llvm-profdata || echo /opt/homebrew/opt/llvm/bin/llvm-profdata)"

SUITES="all"
DO_BUILD=1
DO_UNIT=1
DO_REPORT=1
DO_HISTORY=1
DO_WORST=0
WORST_N="${WORST_N:-20}"
CLEAN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --no-build)     DO_BUILD=0 ;;
    --no-unit)      DO_UNIT=0 ;;
    --suites)       SUITES="$2"; shift ;;
    --report-only)  DO_BUILD=0; DO_UNIT=0; SUITES="none" ;;
    --clean)        CLEAN=1 ;;
    --no-history)   DO_HISTORY=0 ;;
    --worst)
      DO_WORST=1
      # optional numeric value: --worst 30 or --worst (defaults to $WORST_N)
      if [ $# -gt 1 ] && [[ "$2" =~ ^[0-9]+$ ]]; then WORST_N="$2"; shift; fi
      ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done

# Any get/set under a coding agent is denied unless a reason is supplied
# (secretspec's default require_reason is "agents"). Harmless for the suites.
export SECRETSPEC_REASON="${SECRETSPEC_REASON:-coverage measurement}"

say() { printf '%s\n' "$*"; }

check_deps() {
  for d in cargo rustc docker bw jq python3; do
    command -v "$d" >/dev/null || { echo "missing dependency: $d (run inside: devenv shell)" >&2; exit 1; }
  done
  [ -x "$LLVM_PROFDATA" ] || { echo "llvm-profdata not found at $LLVM_PROFDATA" >&2; exit 1; }
  [ -x "$LLVM_COV" ] || { echo "llvm-cov not found at $LLVM_COV" >&2; exit 1; }
}

# -- build ---------------------------------------------------------------

cmd_build() {
  say "== build: instrumented secretspec binary =="
  RUSTFLAGS="-C instrument-coverage" \
  CARGO_TARGET_DIR="$BUILD_DIR" \
    cargo build --bin secretspec --quiet
}

# -- unit tests -----------------------------------------------------------

cmd_unit() {
  say "== unit: bw.rs tests + bw URI tests (raw -> $RAW_DIR/unit) =="
  mkdir -p "$RAW_DIR/unit"
  local pf="$RAW_DIR/unit/unit-%p-%m.profraw"
  # 'provider::bw::' (trailing ::) matches bw.rs's tests but not bws.rs's.
  # tests.rs nests its bw URI tests under provider::tests::integration_tests.
  RUSTFLAGS="-C instrument-coverage" \
  CARGO_TARGET_DIR="$BUILD_DIR" \
  LLVM_PROFILE_FILE="$pf" \
    cargo test --lib 'provider::bw::' 2>&1 | tail -8
  RUSTFLAGS="-C instrument-coverage" \
  CARGO_TARGET_DIR="$BUILD_DIR" \
  LLVM_PROFILE_FILE="$pf" \
    cargo test --lib 'provider::tests::integration_tests::test_bw_' 2>&1 | tail -8
}

# -- harness suites --------------------------------------------------------

cmd_suite() {
  local name="$1"; shift
  local extra=("$@")
  say "== suite: $name =="
  mkdir -p "$RAW_DIR/suite-$name"
  local rc=0
  env "${extra[@]}" \
    LLVM_PROFILE_FILE="$RAW_DIR/suite-$name/suite-$name-%p-%m.profraw" \
    SECRETSPEC_BIN="$BUILD_DIR/debug/secretspec" \
    bash tests/vaultwarden_harness.sh || rc=$?
  say "suite $name finished (exit $rc)"
  [ "$rc" -eq 0 ] || say "!! suite $name failed — coverage profiles were still captured"
}

cmd_suites() {
  case "$SUITES" in
    none) say "== suites: skipped ==" ;;
    all)
      cmd_suite integration  SKIP_ORG_FIXTURE=1
      cmd_suite collection   SKIP_ORG_FIXTURE=0
      cmd_suite regressions  RUN_REGRESSIONS=1
      ;;
    integration) cmd_suite integration SKIP_ORG_FIXTURE=1 ;;
    collection)  cmd_suite collection  SKIP_ORG_FIXTURE=0 ;;
    regressions) cmd_suite regressions RUN_REGRESSIONS=1 ;;
    *) echo "unknown --suites value: $SUITES" >&2; exit 2 ;;
  esac
}

# -- merge ----------------------------------------------------------------

# scenario -> list of raw dirs
raw_dirs_for() {
  case "$1" in
    unit)                       echo "$RAW_DIR/unit" ;;
    unit+integration)           echo "$RAW_DIR/unit $RAW_DIR/suite-integration" ;;
    unit+all)                   echo "$RAW_DIR/unit $RAW_DIR/suite-integration $RAW_DIR/suite-collection $RAW_DIR/suite-regressions" ;;
  esac
}

cmd_merge() {
  mkdir -p "$MERGED_DIR"
  for scenario in unit unit+integration unit+all; do
    local dirs; dirs=$(raw_dirs_for "$scenario")
    local profs=()
    for d in $dirs; do [ -d "$d" ] && profs+=("$d"/*.profraw); done
    if [ ${#profs[@]} -gt 0 ]; then
      say "== merge: $scenario (${#profs[@]} profraw files) =="
      "$LLVM_PROFDATA" merge -sparse "${profs[@]}" -o "$MERGED_DIR/$scenario.profdata"
    else
      say "== merge: $scenario — no profiles, skipped =="
    fi
  done
}

# -- report ----------------------------------------------------------------

find_test_bin() {
  ls "$BUILD_DIR/debug/deps"/secretspec-* 2>/dev/null \
    | grep -E '/secretspec-[0-9a-f]+$' | head -1 || true
}

BRANCH_FLAG=""
pick_branch_flag() {
  if "$LLVM_COV" report --help 2>&1 | grep -q -- '--show-branch-counts'; then
    BRANCH_FLAG="--show-branch-counts"
  else
    BRANCH_FLAG="--show-branch-summary"
  fi
}

cmd_report() {
  local bin="$BUILD_DIR/debug/secretspec"
  local testbin; testbin=$(find_test_bin)
  [ -x "$bin" ] || { echo "instrumented binary missing: $bin" >&2; exit 1; }
  [ -n "$testbin" ] || { echo "instrumented lib test binary not found under $BUILD_DIR/debug/deps" >&2; exit 1; }
  pick_branch_flag
  say "== report (branch flag: $BRANCH_FLAG; objects: $bin, $testbin) =="
  mkdir -p "$REPORT_DIR"
  local src_args=()
  for s in "${SOURCES[@]}"; do src_args+=(-sources "$s"); done
  for scenario in unit unit+integration unit+all; do
    [ -f "$MERGED_DIR/$scenario.profdata" ] || { say "no merged profile for $scenario"; continue; }
    "$LLVM_COV" report \
      --instr-profile="$MERGED_DIR/$scenario.profdata" \
      --object="$bin" --object="$testbin" \
      "$BRANCH_FLAG" "${src_args[@]}" \
      > "$REPORT_DIR/report-$scenario.txt" 2>&1 || true
    "$LLVM_COV" export \
      --instr-profile="$MERGED_DIR/$scenario.profdata" \
      --object="$bin" --object="$testbin" \
      "${src_args[@]}" \
      > "$REPORT_DIR/export-$scenario.json" 2>&1 || true
    say "--- report-$scenario.txt ---"
    cat "$REPORT_DIR/report-$scenario.txt"
  done
}

# -- added-lines coverage -------------------------------------------------------
# For files the PR only partially added to (tests.rs, mod.rs), whole-file %
# understates what the PR's own lines do. Compute coverage of exactly the
# lines the branch adds vs upstream/main, from the same merged profile.

# new_line_numbers_of_additions <file> — echoes the new-file line number of
# every line the branch adds vs upstream/main (git diff -U0, additions only).
new_line_numbers_of_additions() {
  local rel="$1"
  local new_line=0 s=""
  git diff upstream/main...HEAD -U0 -- "$rel" 2>/dev/null | while IFS= read -r l; do
    case "$l" in
      @@*) # @@ -a[,b] +c[,d] @@ [context] — new-file hunk starts at c.
        s=$(printf '%s' "$l" | sed -E 's/@@ -[0-9]+(,[0-9]+)? \+([0-9]+)(,[0-9]+)? @@.*/\2/')
        [ -n "$s" ] && new_line=$s
        ;;
      +++) : ;;              # +++ header line, not an added line
      +*)  # added line
        [ "$new_line" -gt 0 ] && echo "$new_line"
        new_line=$((new_line + 1))
        ;;
      ' '*) new_line=$((new_line + 1)) ;;  # context (absent with -U0)
      -*) : ;;                             # removed line
    esac
  done
}

# added_lines_report <profile> — appends a per-file table row for each of the
# PR's partially-added Rust files: of the added lines that carry coverage
# instrumentation, how many executed (unit+all scenario).
added_lines_report() {
  local prof="$1"
  local bin="$BUILD_DIR/debug/secretspec"
  local testbin; testbin=$(find_test_bin)
  echo
  echo "### PR-added lines executed (unit+all profile, added vs upstream/main)"
  echo
  echo "| file | added instrumented lines | executed | % |"
  echo "|---|---|---|---|"
  local rel src l
  for rel in secretspec/src/provider/tests.rs secretspec/src/provider/mod.rs; do
    src="$REPO_ROOT/$rel"
    # line -> covered map from llvm-cov show (only lines with a numeric count)
    local tmp; tmp=$(mktemp)
    "$LLVM_COV" show --instr-profile="$prof" --object="$bin" --object="$testbin" \
      -sources "$src" 2>/dev/null \
      | awk -F'|' '/^[ ]*[0-9]+\|/ {
           gsub(/ /, "", $1); gsub(/ /, "", $2);
           if ($2 ~ /^[0-9.]+[kMG]?$/) print $1, ($2 + 0 > 0 ? 1 : 0)
         }' > "$tmp"
    local total=0 executed=0 n hit
    local added; added=$(mktemp)
    new_line_numbers_of_additions "$rel" | sort -n | uniq > "$added"
    while read -r n hit; do
      # only count lines the branch actually added
      if grep -qx "$n" "$added"; then
        total=$((total + 1))
        [ "$hit" = "1" ] && executed=$((executed + 1))
      fi
    done < "$tmp"
    rm -f "$tmp" "$added"
    if [ "$total" -eq 0 ]; then
      echo "| \`$rel\` | 0 (declarations/doc only) | — | n/a |"
    else
      local pct; pct=$(awk "BEGIN{printf \"%.1f%%\", $executed * 100.0 / $total}")
      echo "| \`$rel\` | $total | $executed | $pct |"
    fi
  done
  echo "- bw.rs is entirely added by this PR: whole-file numbers in the table above apply."
}

# -- worst functions ---------------------------------------------------------

cmd_worst() {
  local bin="$BUILD_DIR/debug/secretspec"
  local testbin; testbin=$(find_test_bin)
  local prof="$MERGED_DIR/${WORST_SCENARIO:-unit}.profdata"
  [ -f "$prof" ] || { say "no profile $prof — run the pipeline first"; return 0; }
  say "== worst ${WORST_N} functions (${WORST_SCENARIO:-unit}) =="
  python3 "$REPO_ROOT/scripts/worst-functions.py" "$prof" \
    --objects "$bin" "$testbin" --n "$WORST_N" --short \
    ${WORST_SORT:+--sort "$WORST_SORT"}
}

# -- history ----------------------------------------------------------------

cmd_history() {
  local rev; rev=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
  local date; date=$(date +%Y-%m-%d)
  local src_dirs; src_dirs=$(ls -d "$RAW_DIR"/unit "$RAW_DIR"/suite-* 2>/dev/null \
    | while read -r d; do [ "$(ls "$d"/*.profraw 2>/dev/null | wc -l | tr -d ' ')" -gt 0 ] && basename "$d"; done \
    | tr '\n' ',' | sed 's/,$//')
  if [ ! -f "$HISTORY_FILE" ]; then
    {
      echo "# SecretSpec Bitwarden provider (bw.rs) — coverage history"
      echo
      echo "Measured with \`scripts/coverage-bitwarden.sh\` (run inside \`devenv shell\`)."
      echo "Scenario meaning: \`unit\` = bw.rs in-file tests + the bw URI tests in"
      echo "provider/tests.rs; \`unit+integration\` adds tests/bitwarden_integration.sh;";
      echo "\`unit+all\` adds the collection-addressing and regression-finding suites"
      echo "(all driven by the vaultwarden harness)."
      echo
    } > "$HISTORY_FILE"
  fi
  {
    echo
    echo "## Run $date ($rev)"
    echo
    echo "- toolchain: $(rustc --version), bw $(bw --version 2>/dev/null || echo '?'), suites run: $src_dirs"
    echo "- branch coverage: stable rustc \`-C instrument-coverage\` does not emit branch"
    echo "  mappings; the regions column is llvm-cov's decision-point metric (closest"
    echo "  stable proxy). True branch coverage would need nightly \`-Z coverage-options=branch\`."
    echo
    echo "### Whole-file coverage (functions / lines / regions)"
    echo
    echo "| scenario | file | functions | lines | regions |"
    echo "|---|---|---|---|---|"
    # report columns: 1=Filename 2=Regions 3=Missed 4=Cover% 5=Functions 6=Missed 7=Executed%
    #                 8=Lines 9=Missed 10=Cover% 11=Branches 12=Missed 13=Cover%
    for scenario in unit unit+integration unit+all; do
      [ -f "$REPORT_DIR/report-$scenario.txt" ] || continue
      awk -v sc="$scenario" \
        '$1 ~ /^(bw|mod|tests)\.rs$/ {
           printf "| %s | %s | %s | %s | %s |\n", sc, $1, $7, $10, $4
         }' "$REPORT_DIR/report-$scenario.txt" >> "$HISTORY_FILE"
    done
    added_lines_report "$MERGED_DIR/unit+all.profdata" >> "$HISTORY_FILE"
    echo "- raw reports: \`$REPORT_DIR\`"
  } >> "$HISTORY_FILE"
  say "history appended to $HISTORY_FILE"
}

# -- main -------------------------------------------------------------------

main() {
  check_deps
  [ "$CLEAN" = 1 ] && rm -rf "$RAW_DIR" "$MERGED_DIR" "$REPORT_DIR"
  mkdir -p "$RAW_DIR" "$REPORT_DIR"
  # Instrumented processes that somehow run without LLVM_PROFILE_FILE drop
  # default_*.profraw into the cwd (repo root); tidy them so they never
  # pollute `git status`.
  rm -f "$REPO_ROOT"/default_*.profraw
  trap 'rm -f "$REPO_ROOT"/default_*.profraw' EXIT
  [ "$DO_BUILD" = 1 ] && cmd_build
  [ "$DO_UNIT" = 1 ] && cmd_unit
  cmd_suites
  cmd_merge
  cmd_report
  [ "$DO_WORST" = 1 ] && cmd_worst
  [ "$DO_HISTORY" = 1 ] && cmd_history
  say "done. reports in $REPORT_DIR; history: $HISTORY_FILE"
}

main
