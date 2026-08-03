# SecretSpec Bitwarden provider (bw.rs) — coverage history

Measured with `scripts/coverage-bitwarden.sh` (run inside `devenv shell`).
Scenario meaning: `unit` = bw.rs in-file tests + the bw URI tests in
provider/tests.rs; `integration` = tests/bitwarden_integration.sh;
`collection` = tests/bitwarden_collection_addressing.sh; `regressions` =
tests/bitwarden_regression_findings.sh (all driven by the vaultwarden harness).


## Run 2026-08-02 (c6c32d9)

- toolchain: rustc 1.92.0 (ded5c06cf 2025-12-08), bw 2025.11.0, suites run: suite-collection,suite-integration,suite-regressions,unit
- branch coverage: stable rustc `-C instrument-coverage` does not emit branch
  mappings; the regions column is llvm-cov's decision-point metric (closest
  stable proxy). True branch coverage would need nightly `-Z coverage-options=branch`.

### Whole-file coverage (functions / lines / regions)

| scenario | file | functions | lines | regions |
|---|---|---|---|---|
| unit | bw.rs | 75.11% | 75.23% | 72.57% |
| unit | mod.rs | 11.11% | 11.41% | 11.56% |
| unit | tests.rs | 2.63% | 1.75% | 2.35% |
| unit+integration | bw.rs | 88.41% | 85.24% | 85.02% |
| unit+integration | mod.rs | 15.28% | 16.55% | 15.94% |
| unit+integration | tests.rs | 2.63% | 1.75% | 2.35% |
| unit+integration+collection | bw.rs | 88.41% | 85.96% | 85.99% |
| unit+integration+collection | mod.rs | 15.28% | 16.55% | 15.94% |
| unit+integration+collection | tests.rs | 2.63% | 1.75% | 2.35% |
| unit+all | bw.rs | 89.70% | 86.50% | 86.78% |
| unit+all | mod.rs | 15.28% | 16.55% | 15.94% |
| unit+all | tests.rs | 2.63% | 1.75% | 2.35% |

### PR-added lines executed (unit+all profile, added vs upstream/main)

| file | added instrumented lines | executed | % |
|---|---|---|---|
| `secretspec/src/provider/tests.rs` | 21 | 21 | 100.0% |
| `secretspec/src/provider/mod.rs` | 0 (declarations/doc only) | — | n/a |
- bw.rs is entirely added by this PR: whole-file numbers in the table above apply.
- raw reports: `/Users/ashebanow/Development/nix/secretspec/main.bitwarden-provider/target/coverage/reports`
