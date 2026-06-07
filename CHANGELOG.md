# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `--reason` CLI flag (and `SECRETSPEC_REASON` env var) records a human-readable
  reason for a session's secret access, forwarded to providers that support audit
  logging. `SECRETSPEC_REASON` is honored across the SDK/library too: it is resolved
  by `Secrets::load`/`load_from` (so `secretspec-derive`-generated code and other
  library callers can satisfy the `require_reason` policy and supply an audit reason
  without code changes), and `Secrets::with_reason(...)` sets it explicitly, taking
  precedence. Blank or whitespace-only reasons are ignored so they cannot satisfy the
  policy. Backed by a new `Provider::set_reason` trait method (default no-op).
- `[project] require_reason` policy in `secretspec.toml`, controlling when secret
  access must supply an explicit reason. Accepts `"agents"` (the default — require
  a reason only when an AI agent is detected), `true` (require it from every
  caller), or `false` (never). Agent detection is delegated to the
  `detect-coding-agent` crate (Claude Code, Cursor, Codex, Gemini CLI, Copilot,
  ...), plus a `SECRETSPEC_AGENT` opt-in for harnesses it does not recognize.
  Because the tool enforces it and it is checked into the repo, the policy applies
  uniformly and cannot be bypassed by an individual tool's configuration. An invalid
  `require_reason` value is rejected at config-parse time rather than silently
  falling back to the default. The policy is inherited through `extends`: a shared
  base config's `require_reason` applies to every config that extends it, unless the
  child sets its own.
  **Note:** the default `"agents"` means AI agents must now pass a reason out of
  the box.
- `bws` provider now accepts an optional server base in the URI
  (`bws://[server-base@]project-uuid`) to target EU cloud or self hosted
  Bitwarden instances. When set, the identity and API endpoints are derived as
  `https://<server-base>/identity` and `https://<server-base>/api`; omitting it
  keeps the `bitwarden.com` US cloud default.

### Fixed
- Proton Pass provider now works with `pass-cli` >= 2.1.0 agent sessions. Since
  2.1.0, audited item operations (`item view`, `item create`, `item delete`)
  fail unless `PROTON_PASS_AGENT_REASON` is set, which made existing secrets
  appear missing under an agent session. The provider now sets this variable on
  every `pass-cli` invocation. The reason is resolved as `--reason`/`with_reason`,
  then `PROTON_PASS_AGENT_REASON`, then a secretspec-versioned default
  (`secretspec/<version> (https://secretspec.dev)`); each source is normalized first,
  so a blank reason falls through to the next rather than masking it. It is ignored by
  older releases and non-agent sessions.

### Changed
- Minimum supported Rust version raised to 1.92 (required by the
  `detect-coding-agent` dependency). The devenv toolchain is pinned accordingly.

### Internal
- Expanded test coverage for previously untested logic: CLI argument parsing
  and `init` TOML generation, the config/secret validation guards
  (`Config::validate`, `Secret::validate`, identifier checks), the
  `ValidationErrors` display/`has_errors` behavior, `ProviderUrl`
  encode/decode and `ProviderInfo` display, and the no-network parsing and
  path-building logic of the keyring, pass, and OnePassword providers
  (`TryFrom<&ProviderUrl>`, path/item-name builders, and `uri()` round-trips),
  and the `Secrets` public surface (`check()` present/missing paths,
  `run_command` child exit-code propagation, and the `InvalidProfile` error).

### Fixed
- `secretspec init` now serializes the generated `secretspec.toml` with
  `toml_edit` instead of hand-interpolating strings. This fixes several cases
  that previously produced TOML that could not be parsed back: a project name,
  secret description, or default value containing a double-quote, backslash,
  control character (including U+007F), or newline; a secret name containing a
  dot (e.g. `FOO.BAR`, which dotenvy accepts and which silently collapsed to a
  nested key); and a configured `project.extends`, which was dropped entirely.
  Output is now also deterministically ordered.
- `secretspec init` no longer defines a conflicting `-f` short flag for
  `--from`; `-f` is reserved for the global `--file` option. The duplicate
  short flag made `secretspec init` panic in debug builds and was ambiguous in
  release builds.

## [0.11.0] - 2026-05-22

### Added
- AWS Secrets Manager (`awssm`) provider: support for a `?prefix=` query
  parameter in the provider URI (e.g., `awssm://us-east-1?prefix=myteam`).
  The prefix is prepended to all secret names
  (`myteam/secretspec/{project}/{profile}/{key}`). Closes
  [#92](https://github.com/cachix/secretspec/issues/92).
- Provider aliases can now be declared at the project level in a top-level
  `[providers]` table of `secretspec.toml`. Aliases declared there are visible
  to per-secret `providers = [...]` lists and to `--provider`/`SECRETSPEC_PROVIDER`,
  and are merged with the existing user-level `[defaults.providers]` map in
  `~/.config/secretspec/config.toml`. On name conflicts the project entry wins,
  so a team's checked-in mapping cannot be silently shadowed by a stale local
  config. Closes [#79](https://github.com/cachix/secretspec/issues/79) and
  addresses the "share aliases via VCS" half of
  [#90](https://github.com/cachix/secretspec/issues/90).

### Fixed
- Profile-not-found errors no longer surface as the confusing
  `Secret 'Profile 'X' not found' not found`. They now use the dedicated
  `InvalidProfile` variant and include the list of profiles defined in
  `secretspec.toml`, e.g.
  `Invalid profile: 'production' is not defined in secretspec.toml. Available profiles: default, dev`.
  Affects `check`, `run`, `get`, `set`, and `import`. Surfaced via
  [#79](https://github.com/cachix/secretspec/issues/79).

## [0.10.1] - 2026-05-11

### Fixed
- `secretspec check`: optional secrets that aren't set no longer render with a
  green `✓` and aren't counted as "found" in the trailing summary. They now
  display with the same blue `○ (optional)` styling already used in the
  missing-required path, and the summary appends `, N optional` whenever
  optional secrets are absent (e.g. `Summary: 4 found, 0 missing, 1 optional`).
  If every optional secret is set, the summary line stays in its previous
  `X found, Y missing` form. Fixes
  [#72](https://github.com/cachix/secretspec/issues/72).

## [0.10.0] - 2026-05-11

### Added
- Proton Pass provider that stores secrets in a Proton Pass vault via the
  `proton-pass` CLI. Configured as `protonpass://<vault>`; items are
  organized per project / profile and read / write both go through the
  CLI.

### Fixed
- OnePassword provider: the auth preflight now probes `op vault list` instead
  of `op whoami`. Under the 1Password desktop app's delegated-session
  integration, `op whoami` reports `account is not signed in` even when
  `op item get` / `op vault list` work fine — so every secret read or write
  failed at preflight with a misleading "not signed in" error. `op vault
  list` exercises the actual access path and succeeds when the desktop app
  can serve secrets. Additionally, `OP_SESSION_*` environment variables
  (left over from `eval $(op signin)`) are now stripped before spawning
  `op` so a stale shell session can't shadow the desktop integration. Auth
  failure and install hints now point users at desktop integration as the
  primary local-dev path. Fixes
  [#80](https://github.com/cachix/secretspec/issues/80).
- Vault / OpenBao provider: HTTPS requests now trust certificates from the
  operating system trust store (and honor `SSL_CERT_FILE` / `SSL_CERT_DIR`),
  so servers fronted by a private / internal CA work without modification.
  Previously the bundled `webpki-roots` set was the only trust anchor and any
  non-public CA produced `Failed to connect to Vault ... error sending
  request`. Switches the `reqwest` workspace dependency from `rustls-tls` to
  `rustls-tls-native-roots`. Fixes
  [#85](https://github.com/cachix/secretspec/issues/85).

## [0.9.1] - 2026-05-07

### Changed
- Dropped the `serde-envfile` dependency in favor of a small in-tree
  `.env` serializer. The previous git-pinned fork blocked publishing to
  crates.io; the new serializer applies the same escapes (backslash,
  double quote, dollar, newline) that the fork added and emits keys in
  sorted order for stable diffs.

## [0.9.0] - 2026-05-07

### Fixed
- The `--provider` CLI flag now correctly takes precedence over the
  `SECRETSPEC_PROVIDER` environment variable. Previously the env var was
  consulted before the value forwarded from `--provider` (via `set_provider`),
  so users could not temporarily override the provider on the command line
  while the env var was set. Fixes
  [#77](https://github.com/cachix/secretspec/issues/77).
- Per-secret `providers = [...]` chains now behave as a true fallback chain
  when an upstream provider errors (e.g. a 403 from a vault the current user
  cannot access). Previously the first provider's error short-circuited the
  whole operation; now the error is logged as a warning and the next provider
  in the chain is tried. The original error is only surfaced if every
  provider in the chain failed (so genuine outages still bubble up), or if
  the secret has no alternative to fall back to. Fixes
  [#83](https://github.com/cachix/secretspec/issues/83).
- `secretspec run` now removes the temporary files it creates for
  `as_path = true` secrets after the child process exits. Previously the
  files were leaked under `/tmp` because `std::process::exit` skipped the
  destructors that own them. Fixes
  [#71](https://github.com/cachix/secretspec/issues/71).
- Provider URIs now support spaces and special characters in names
  (e.g., `onepassword://Home Lab`). All providers receive automatically
  percent-decoded values via a new `ProviderUrl` wrapper type.
- dotenv provider: setting a secret no longer corrupts neighboring values
  that contain double quotes, backslashes, dollar signs, or newlines
  (e.g. JSON values). The underlying `serde-envfile` serializer did not
  escape these characters; fix is pinned via a fork until
  [lucagoslar/serde-envfile#6](https://github.com/lucagoslar/serde-envfile/pull/6)
  lands upstream. Fixes [#74](https://github.com/cachix/secretspec/issues/74).
- `--provider` (and `SECRETSPEC_PROVIDER`) is now honored on every command
  even when a `providers = [...]` chain is configured for the secret or
  profile. Previously `set`, `get`, `check`, `import`, and `run` silently
  used the first provider in the chain and ignored the explicit override,
  making `secretspec set --provider <alias>` a no-op against the requested
  target. The flag now consistently takes precedence: `set`/`import`/
  generation write only to the chosen provider, and `get`/`validate` read
  only from it (no chain fallback). Provider aliases declared in
  `~/.config/secretspec/config.toml` can now be passed directly to
  `--provider`. Fixes [#81](https://github.com/cachix/secretspec/issues/81).

### Added
- BWS (Bitwarden Secrets Manager) provider with async SDK integration, secret caching, and full read-write support (requires `--features bws`)

### Changed
- `secretspec-derive` now depends on `secretspec` with `default-features = false`, avoiding pulling in CLI and provider features when only the derive macro is used.

## [0.8.2] - 2026-03-19

### Changed
- All provider features (`gcsm`, `awssm`, `vault`) are now enabled by default
- AWS Secrets Manager (`awssm`) provider: batch fetching via `BatchGetSecretValue` API,
  reducing N sequential API calls to ceil(N/20) batched calls. For 30 secrets this means
  2 API calls instead of 30. **Note:** requires the `secretsmanager:BatchGetSecretValue`
  IAM permission in addition to existing permissions.

## [0.8.1] - 2026-03-15

### Added
- `rsa_private_key` secret generation type: generates RSA private keys in PKCS1 PEM format,
  defaults to 2048 bits, configurable via `generate = { bits = 4096 }`

### Fixed
- Check provider authentication (e.g. OnePassword, LastPass) before prompting
  user for secrets, via a `PreflightGuard` that runs the check exactly once
  per provider instance

## [0.8.0] - 2026-03-11

### Added
- HashiCorp Vault / OpenBao (`vault`) provider for Vault KV v1/v2 secret storage, with support
  for namespaces, TLS configuration, and OpenBao compatibility (requires `--features vault`)
- AWS Secrets Manager (`awssm`) provider for AWS secret storage integration (requires `--features awssm`)
- Support running secretspec from subdirectories: the CLI now walks up the directory tree to find the nearest `secretspec.toml`, similar to `cargo` and `git`. Also adds a `-f`/`--file` flag (and `SECRETSPEC_FILE` env var) to explicitly specify the config file path (#59)

### Changed
- Extract shared `block_on` async helper from AWSSM and GCSM providers into `provider::block_on`

### Fixed
- GCSM provider no longer panics when called from within an existing tokio runtime

## [0.7.2] - 2026-02-24

### Added
- Keyring and pass providers now support `folder_prefix` via URI (e.g., `keyring://secretspec/shared/{profile}/{key}`)
  to share secrets across projects, matching the existing OnePassword and LastPass behavior

### Changed
- Support `XDG_CONFIG_HOME` on macOS by switching from `directories` to `etcetera` crate.
  Existing macOS configs at `~/Library/Application Support/secretspec/` are automatically
  migrated to `~/.config/secretspec/` (#28)

### Fixed
- Reject empty values when setting a secret

## [0.7.1] - 2026-02-08

### Changed
- Improved interactive prompt for missing secrets: lists all missing secrets upfront with descriptions, adds step counter (`[1/3]`), and uses `inquire::Password` for consistent masked input. Removed `rpassword` dependency.

### Fixed
- Use a fork of inquire to support setting multi-line secrets (#32)

## [0.7.0] - 2026-02-08

### Added
- Declarative secret generation: secrets can now be auto-generated when missing by adding
  `type` and `generate` fields to secret config. Supported types: `password`, `hex`, `base64`,
  `uuid`, and `command` (for arbitrary shell commands). Generation triggers during `check`/`run`
  when a secret is missing, and the generated value is stored via the configured provider.

### Changed
- OnePassword provider: Significant performance improvement by caching authentication status
  and using batch fetching with parallel threads. Reduces CLI calls from 2N sequential to
  ~2 sequential + N parallel for N secrets.

## [0.6.2] - 2026-01-27

### Added
- CLI: Add `--no-prompt` (`-n`) flag to `secretspec check` command for non-interactive mode.
  When used, the command exits with non-zero status if secrets are missing instead of prompting for values.
  Useful for CI/CD pipelines, scripts, and automation. (#55)

## [0.6.1] - 2026-01-15

### Fixed
- OnePassword provider: Fix duplicate item creation when existing item has no extractable value.
  Now uses `op item list` for existence checks and updates by item ID to avoid ambiguity.
- OnePassword provider: Handle "More than one item matches" error gracefully by falling back to ID-based lookup.

## [0.6.0] - 2026-01-12

### Added
- Google Cloud Secret Manager (GCSM) provider for GCP secret storage integration (#53)

### Fixed
- LastPass provider: Fix creating new secrets by using correct `lpass add` command instead of non-existent `lpass set` (#54)

## [0.5.1] - 2026-01-02

### Changed
- CI: Updated macOS runners from deprecated macos-13 to macos-15 (Intel) and macos-latest (ARM)

## [0.5.0] - 2026-01-02

### Added
- Pass (password-store) provider for Unix password manager integration
- `ensure_secrets()` method is now public in the Rust SDK
- Support specifying full file paths (ending in `.toml`) in `extends` field, in addition to directory paths

### Changed
- Performance: avoid double validation in `check()` for happy path

### Fixed
- Display correct error message when extended config file is not found, instead of the misleading "No secretspec.toml found in current directory" error

## [0.4.1] - 2025-11-27

### Added
- OnePassword provider: Support for `SECRETSPEC_OPCLI_PATH` environment variable to specify custom path to the OnePassword CLI
- OnePassword provider: Automatic detection of Windows Subsystem for Linux 2 (WSL2) and use of `op.exe` on that platform
- Documentation for `as_path` option in configuration reference, Rust SDK docs, and landing page
- Documentation for per-secret providers with fallback chains on landing page

### Changed
- OnePassword provider: Use stdin instead of temporary files when creating items for WSL2 compatibility (WSL paths are invalid when passed to Windows executables)

### Fixed
- Output status/progress messages to stderr instead of stdout, fixing direnv integration where stdout was evaluated as shell code

## [0.4.0] - 2025-11-24

### Added
- Profile-level default configuration: `profiles.<name>.defaults` section for shared settings across secrets in a profile
- Default providers for profiles: define common providers once and have all secrets use them unless overridden
- Default values and required settings can now be specified at profile level to reduce repetition
- `as_path` option for secrets: write secret values to temporary files and return the file path instead of the value. Temporary files are automatically cleaned up when the resolved secrets are dropped in Rust SDK usage. For CLI commands (`get` and `check`), temporary files are persisted and NOT deleted after the command exits. In the Rust SDK, fields with `as_path = true` are generated as `PathBuf` or `Option<PathBuf>` instead of `String`

### Changed
- Secret `required` field is now `Option<bool>` to allow profile-level defaults to apply when not explicitly set
- Secret `default` field can now inherit from profile-level defaults if not specified per-secret
- Secret `providers` field can now inherit from profile-level defaults if not specified per-secret
- Profile defaults only apply to secrets that don't explicitly set these fields

## [0.3.4] - 2025-11-09

### Changed
- `Secrets::check()` now returns `Result<ValidatedSecrets>` instead of `Result<()>`, allowing callers to access the validated secrets

## [0.3.3] - 2025-09-10

### Fixed
- CLI: Count optional secrets as "found" in the summary

## [0.3.2] - 2025-09-10

### Added
- Support for piping multi-line secrets via stdin

### Fixed
- Import command now resolves secrets from all profiles, not just the active profile (fixes issue #36)
- Fix incorrect stats in the summary for certain configurations

## [0.3.1] - 2025-07-28

### Fixed
- Installers for arm/linux

## [0.3.0] - 2025-07-25

### Added
- Integrate `secrecy` crate for secure secret handling with automatic memory zeroing
- Add `reflect()` method to Provider trait for provider introspection
- Export `Provider` trait from secretspec crate for use in derived code

### Changed
- Made keyring provider optional via `keyring` feature flag (enabled by default)
- Unified provider parsing logic in init command to support all provider formats consistently
- Downgraded keyring dependency to 3.6.2
- Updated `with_provider` in derive macro to accept `TryInto<Box<dyn Provider>>` for consistent provider handling

### Fixed
- Fixed secret optionality logic: having a default value no longer makes a secret optional in generated types

## [0.2.0] - 2025-07-17

### Changed
- SDK: Added `set_provider()` and `set_profile()` methods for configuration
- SDK: Removed provider/profile parameters from `set()`, `get()`, `check()`, `validate()`, and `run()` methods
- SDK: Embedded Resolved inside ValidatedSecrets

### Fixed
- Fix stdin handling for piped input in set/check commands
- Fix SECRETSPEC_PROFILE and SECRETSPEC_PROVIDER environment variable resolution
- Ensure CLI arguments take precedence over environment variables
- add CLI integration tests
- Update test script to handle non-TTY environments correctly

## [0.1.2] - 2025-01-17

### Fixed
- SDK: Hide internal functions

## [0.1.1] - 2025-07-16

### Added
- `secretspec --version`

### Fixed
- Profile inheritance: fields are merged with current profile taking precedence

## [0.1.0] - 2025-07-16

Initial release of SecretSpec - a declarative secrets manager for development workflows.
