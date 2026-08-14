# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1](https://github.com/ifiokjr/monosecret/releases/tag/v0.2.1) (2026-08-14)

### Changed

- No package-specific changes were recorded; `monosecret` was updated to 0.2.1 as part of group `monosecret`.

## [0.2.0](https://github.com/ifiokjr/monosecret/releases/tag/v0.2.0) (2026-08-13)

### Documentation

#### Fix the `depends_on` docs example and validate docs snippets

The `depends_on` example in the configuration reference used a
`service_token = { secret = "..." }` shape that did not deserialize into
`ProviderDependency`, so anyone copying it hit a parse error. Use the correct
`secret = "..."` form, make the example a complete copy-pasteable config, and
document the optional `as` field for injecting a dependency under a different
env-var name.

Add an integration test (`docs_snippets`) that scans the docs for TOML snippets
marked with an invisible `<!-- monosecret-test: ... -->` marker and parses /
validates them against the `Config`, `GlobalConfig`, and `Project` schemas, so
reference examples can't silently drift from the schema again. The harness is
opt-in (no false positives on partial snippets) and a no-op when the docs tree
isn't present.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #27](https://github.com/ifiokjr/monosecret/pull/27)

#### Repair stale documentation links and installation guidance

Point historical issue references to the original `cachix/secretspec` repository, restore the original SecretSpec announcement and devenv integration URLs, and replace the unavailable custom installer with the published `@monosecret/cli` npm package.

_Owner:_ Ifiok Jr. · _Review:_ [PR #29](https://github.com/ifiokjr/monosecret/pull/29) · _Related issues:_ [#23](https://github.com/ifiokjr/monosecret/issues/23), [#27](https://github.com/ifiokjr/monosecret/issues/27), [#28](https://github.com/ifiokjr/monosecret/issues/28)

## [0.1.0](https://github.com/ifiokjr/monosecret/releases/tag/v0.1.0) (2026-07-05)

### Features

- Port upstream audit log support

#### `monosecret env`: load secrets into any shell

Add `monosecret env` (alias `load-env`) to load resolved secrets into the
surrounding shell or a CI environment with one command. A `--shell` flag
selects the output format:

- `bash`/`sh`/`zsh` — `export KEY='value';` (apply with `eval "$(...)"`)
- `fish` — `set -gx KEY 'value';` (apply with `| source`)
- `powershell`/`pwsh` — `$env:KEY='value';` (apply with `| iex`)
- `nushell`/`nu` — `load-env { KEY: "value" }`
- `github` — appends `KEY<<DELIM` heredoc blocks to `$GITHUB_ENV` and prints
  `::add-mask::` so values are masked in the run log
- `gitlab`/`dotenv` — portable `KEY="value"` for `artifacts:reports:dotenv`

Values are escaped per the target shell's rules. Reuses the same secret
resolution path and `require_reason` policy as `monosecret run`, and supports
`--include`/`--group` filtering and `--output` to write to a file.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #14](https://github.com/ifiokjr/monosecret/pull/14)

- Add a secret-value-free manifest command for SDK code generation, introduce a build_runner-based Dart typed SDK generator, reorganize source by ecosystem into `crates/`, `npm/`, and `dart/`, and wire Rust, Dart, and npm coverage reports with package-level Codecov flags.

#### Sync upstream secretspec 0.12.2 support

Merge upstream/main through 0.12.2.

- Restore the `monosecret audit` CLI command (`show_audit_log`,
  `filter_audit_entries`, `sanitize_field`, `format_audit_line`) that was
  dropped during the rebrand merge, plus the `audit` field on `GlobalConfig`
  so the log path can be resolved from the user-global `[audit]` config.
- port the `pass` provider `store_dir` query parameter
  (`PASSWORD_STORE_DIR` scoped per invocation) and the shared
  `query_value` / `encode_query` / `QUERY_ENCODE_SET` helpers so query
  values round-trip through form-urlencoded parsing (awssm `prefix` too).

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #13](https://github.com/ifiokjr/monosecret/pull/13)

### Fixes

- Update Monosecret documentation and CLI website links to the GitHub Pages site.
