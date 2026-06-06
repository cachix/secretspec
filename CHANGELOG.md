# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `--reason` CLI flag (and `MONOSECRET_REASON` env var) records a human-readable
  reason for a session's secret access, forwarded to providers that support audit
  logging. `MONOSECRET_REASON` is honored across the SDK/library too: it is resolved
  by `Secrets::load`/`load_from` (so `monosecret_derive`-generated code and other
  library callers can satisfy the `require_reason` policy and supply an audit reason
  without code changes), and `Secrets::with_reason(...)` sets it explicitly, taking
  precedence. Blank or whitespace-only reasons are ignored so they cannot satisfy the
  policy. Backed by a new `Provider::set_reason` trait method (default no-op).
- `[project] require_reason` policy in `monosecret.toml`, controlling when secret
  access must supply an explicit reason. Accepts `"agents"` (the default — require
  a reason only when an AI agent is detected), `true` (require it from every
  caller), or `false` (never). Agent detection is delegated to the
  `detect-coding-agent` crate (Claude Code, Cursor, Codex, Gemini CLI, Copilot,
  ...), plus a `MONOSECRET_AGENT` opt-in for harnesses it does not recognize.
  Because the tool enforces it and it is checked into the repo, the policy applies
  uniformly and cannot be bypassed by an individual tool's configuration. An invalid
  `require_reason` value is rejected at config-parse time rather than silently
  falling back to the default. The policy is inherited through `extends`: a shared
  base config's `require_reason` applies to every config that extends it, unless the
  child sets its own.
  **Note:** the default `"agents"` means AI agents must now pass a reason out of
  the box.

### Fixed

- Cargo workspace metadata now keeps `monosecret_derive` on the workspace `monosecret`
  dependency with default features disabled during package validation.
- Proton Pass provider now works with `pass-cli` >= 2.1.0 agent sessions. Since
  2.1.0, audited item operations (`item view`, `item create`, `item delete`)
  fail unless `PROTON_PASS_AGENT_REASON` is set, which made existing secrets
  appear missing under an agent session. The provider now sets this variable on
  every `pass-cli` invocation. The reason is resolved as `--reason`/`with_reason`,
  then `PROTON_PASS_AGENT_REASON`, then a secretspec-versioned default
  (`monosecret/<version> (https://monosecret.dev)`); each source is normalized first,
  so a blank reason falls through to the next rather than masking it. It is ignored by
  older releases and non-agent sessions.

### Changed

- Minimum supported Rust version raised to 1.92 (required by the
  `detect-coding-agent` dependency). The devenv toolchain is pinned accordingly.

### Motivation

Currently, Monosecret stores every secret as a separate 1Password item
(`monosecret/{project}/{profile}/{KEY}`). This creates item sprawl — a
project with 20 secrets creates 20 items, making the vault noisy and the
structure harder to reason about.

This release adds two related features:

1. **Provider-relative secret locations** — multiple secrets can live inside a
   single provider "root" (one 1Password item per project/profile, with
   sections for different services and fields for individual keys).
2. **Provider dependency declarations** — providers that need auth tokens (like
   1Password service accounts) can declare those requirements in the config,
   making dependencies explicit rather than relying on ambient environment
   variables.

Both features are purely additive at the TOML level — every existing
`monosecret.toml` file parses identically after this change.

### Added

- Added platform-specific npm binary packages for `@monosecret/cli-*`, moved the Dart SDK into the root `packages/` workspace, and updated repository references for `ifiokjr/monosecret`.

- Rebranded the project to Monosecret, reset package versions to 0.0.0, added monochange release metadata and lint inheritance, npm packages, and a functional Dart SDK while keeping compatibility fallbacks for `monosecret.toml`, legacy `secretspec.toml`, and `SECRETSPEC_*`.

- **Native 1Password reference schemes.** Added `op://` and `op+token://` provider URI schemes for native 1Password references such as `op://Development/dotfiles/forges/GITHUB_TOKEN`, while preserving `onepassword://` and `onepassword+token://` as legacy Monosecret-owned storage. Native references are read with `op read`; `monosecret set` can edit existing native references but will not create missing native items, sections, or fields.

- **Filtered `monosecret run` injection.** `monosecret run` now accepts repeatable, comma-aware `--include <SECRET>` and `--group <GROUP>` filters so commands can receive only the selected secrets. Group filters use declared top-level `[groups]`; profile-specific `groups = [...]` replaces inherited default groups when set, and filtered runs only validate/resolve selected secrets plus any provider dependencies they require.

- **Provider-relative secret locations.** Secrets in `providers` lists now
  accept detailed references with optional `path` and `key` fields:

### Internal

- Reworked GitHub Actions and devenv scripts around the monochange release flow,
  shared setup, Rust binary asset publishing, package checks, changeset policy,
  nightly Rust tooling, and Dart SDK coverage reporting.

- Expanded Dart SDK coverage for CLI argument construction, environment loading,
  process configuration, and error reporting.

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

- Fixed CI by running Dart steps from the repository root under `devenv shell`, disabling nightly-only coverage cfg for Rust dependency coverage, and applying rustfmt output.

- `monosecret init` now serializes the generated `monosecret.toml` with
  `toml_edit` instead of hand-interpolating strings. This fixes several cases
  that previously produced TOML that could not be parsed back: a project name,
  secret description, or default value containing a double-quote, backslash,
  control character (including U+007F), or newline; a secret name containing a
  dot (e.g. `FOO.BAR`, which dotenvy accepts and which silently collapsed to a
  nested key); and a configured `project.extends`, which was dropped entirely.
  Output is now also deterministically ordered.
- `monosecret init` no longer defines a conflicting `-f` short flag for
  `--from`; `-f` is reserved for the global `--file` option. The duplicate
  short flag made `monosecret init` panic in debug builds and was ambiguous in
  release builds.
  ```toml
  GITHUB_TOKEN = {
    description = "GitHub token",
    providers = [
      { provider = "op-dev", path = ["GitHub"], key = "token" }
    ]
  }
  ```
  A single 1Password item (title `monosecret/{project}/{profile}`) can now
  serve many secrets at different paths within it. `key` defaults to the
  Monosecret secret name when omitted. Bare strings (`["env"]`) continue to
  work as before — they deserialize as `ProviderRef::Alias` transparently.

- **Structured provider configs.** `[providers]` entries can now be tables
  with an optional `depends_on` section to declare auth dependencies:
  ```toml
  [providers.op-dev]
  uri = "onepassword://Development"
  [[providers.op-dev.depends_on]]
  service_token = { secret = "OP_SERVICE_ACCOUNT_TOKEN" }
  ```
  This makes a provider's auth requirements explicit in the config rather
  than relying on an ambient `OP_SERVICE_ACCOUNT_TOKEN` env var that may or
  may not be set. The required secret is itself a normal Monosecret secret
  that can come from any provider (keyring, env, dotenv, etc.). Plain string
  aliases (`keyring = "keyring://"`) remain fully supported.

- **`Provider::get_with_request`.** New default trait method that receives a
  `SecretRequest` (carrying `path` and `key`). The default implementation
  delegates to `get()`, so existing providers don't need changes. The
  1Password provider overrides this to navigate to the correct section and
  field within a shared project item.
- **`Provider::configure_dependency_secrets`.** New default trait method for
  providers to receive resolved `depends_on` secrets in provider-local state.
  Command-line providers pass supported values directly to child commands with
  `Command::env(...)` instead of mutating the Monosecret process environment.

- **`Secrets::resolve_provider_requirements`.** Resolves the `requires`
  declarations for a provider alias, looking up each required secret through
  the normal resolution pipeline and returning the resolved values.

- **New public types:** `ProviderConfig`, `ProviderRef`, `ProviderRefDetail`,
  `SecretRequest`, `ProviderDependency`, `ProviderConfigStructured`. All
  exported from the crate root — additive only.
- **1Password Environments provider.** New `onepassword+env` provider for
  [1Password Environments](https://www.1password.dev/environments) (beta):
  ```toml
  [providers]
  prod-env = "onepassword+env://blgexucrwfr2dtsxe2q4uu7dp4"
  ci-env = "onepassword+env+token://ops_abc123@xyz789"
  ```
  Uses `op environment read` to fetch all variables in one call — simpler
  and faster than the item-based provider. Read-only. Supports desktop app
  auth (`onepassword+env://`) and service account tokens
  (`onepassword+env+token://`). Requires 1Password CLI 2.33.0-beta.02+.

### Changed

- Native `op://` / `op+token://` batch reads now fetch references with bounded parallelism, sharing the 1Password provider's batch worker path while keeping legacy `onepassword://` storage semantics unchanged.
- Reduced release CLI binary size by stripping symbols in the `dist` profile, using fat LTO
  with a single codegen unit, and replacing `tracing-subscriber` with a small stderr
  subscriber that preserves `-v`/`--verbose`, `RUST_LOG=verbose`, `RUST_LOG=quiet`, and
  simple `RUST_LOG` level/target filters.
- **Breaking (serde):** `Secret.providers` is now `Option<Vec<ProviderRef>>`
  instead of `Option<Vec<String>>` for structured references.
  Backward-compatible at the TOML level (bare strings deserialize as
  `ProviderRef::Alias`).
- **Breaking (serde):** `Config.providers` is now
  `Option<HashMap<String, ProviderConfig>>` instead of
  `Option<HashMap<String, String>>` to support structured provider entries.
  TOML backwards compatibility is preserved via `#[serde(untagged)]`.
- **Breaking (Rust API):** Code that constructs `Config` or `Secret` structs
  directly (not via TOML deserialization) must wrap provider values in the
  new enum types:
  ```rust
  // Before (no longer compiles)
  Secret { providers: Some(vec!["keyring".into()]), .. }
  Config { providers: Some(HashMap::from([("k".into(), "keyring://".into())])), .. }

  // After
  Secret { providers: Some(vec![ProviderRef::from("keyring")]), .. }
  Config { providers: Some(HashMap::from([("k".into(), ProviderConfig::Alias("keyring://".into()))])), .. }
  ```
  This only affects the Rust SDK; TOML files, profile-level `providers`
  (`Vec<String>`), and user-global `[defaults.providers]`
  (`HashMap<String, String>`) are unchanged.

### Backward Compatibility

- **TOML files:** fully backward compatible. `[providers]` bare strings
  (`keyring = "keyring://"`) → `ProviderConfig::Alias`. Per-secret list
  entries (`["env"]`) → `ProviderRef::Alias`. Roundtrip through
  serialize → deserialize is lossless.
- **Provider trait:** `get_with_request` is a defaulted method (delegates
  to `get`). No changes required in existing provider implementations.
- **Profile/global config:** `ProfileDefaults.providers` stays
  `Vec<String>`; `GlobalDefaults.providers` stays `HashMap<String, String>`.
- **Public API:** new types (`ProviderConfig`, `ProviderRef`,
  `ProviderRefDetail`, `SecretRequest`, `ProviderDependency`,
  `ProviderConfigStructured`) are additive only. No existing public types
  or methods were removed or renamed.

### Fixed

- Provider `depends_on` secrets are now injected into provider instances before
  use. The 1Password item and Environments providers pass
  `OP_SERVICE_ACCOUNT_TOKEN` directly to each `op` child command, avoiding
  process-global environment mutation while still supporting repeated command
  invocations and preflight checks.
- `monosecret check` now resolves object-form per-secret provider refs with
  `path`/`key` hints during validation instead of batching them by provider URI
  and checking the Monosecret variable name.
- 1Password object-form provider refs now treat `path = ["item", "section"]`
  as a lookup for `section` inside the shared item `item`, matching provider-relative
  paths used by checked-in `monosecret.toml` files.
- 1Password provider URI paths such as `onepassword+token://Development/dotfiles`
  now act as provider-relative item roots, so `{ provider = "op-token", path = ["forges"] }`
  reads section `forges` from item `dotfiles` instead of the default
  `monosecret/{project}/{profile}` item.
- Added verbose provider/1Password lookup tracing via `-v`/`--verbose`, `-vv`,
  or `RUST_LOG=verbose` to make provider selection and `op` CLI failures visible.
- 1Password tracing now emits failed `op` commands and missing requested fields
  at warning level, and authentication failures at error level, instead of
  reporting every diagnostic as debug.
- Profile-not-found errors no longer surface as the confusing
  `Secret 'Profile 'X' not found' not found`. They now use the dedicated
  `InvalidProfile` variant and include the list of profiles defined in
  `monosecret.toml`, e.g.
  `Invalid profile: 'production' is not defined in monosecret.toml. Available profiles: default, dev`.
  Affects `check`, `run`, `get`, `set`, and `import`. Surfaced via
  [#79](https://github.com/ifiokjr/monosecret/issues/79).

## [0.11.0] - 2026-05-22

### Added

- AWS Secrets Manager (`awssm`) provider: support for a `?prefix=` query
  parameter in the provider URI (e.g., `awssm://us-east-1?prefix=myteam`).
  The prefix is prepended to all secret names
  (`myteam/monosecret/{project}/{profile}/{key}`). Closes
  [#92](https://github.com/ifiokjr/monosecret/issues/92).
- Provider aliases can now be declared at the project level in a top-level
  `[providers]` table of `monosecret.toml`. Aliases declared there are visible
  to per-secret `providers = [...]` lists and to `--provider`/`MONOSECRET_PROVIDER`,
  and are merged with the existing user-level `[defaults.providers]` map in
  `~/.config/monosecret/config.toml`. On name conflicts the project entry wins,
  so a team's checked-in mapping cannot be silently shadowed by a stale local
  config. Closes [#79](https://github.com/ifiokjr/monosecret/issues/79) and
  addresses the "share aliases via VCS" half of
  [#90](https://github.com/ifiokjr/monosecret/issues/90).

### Fixed

- Profile-not-found errors no longer surface as the confusing
  `Secret 'Profile 'X' not found' not found`. They now use the dedicated
  `InvalidProfile` variant and include the list of profiles defined in
  `monosecret.toml`, e.g.
  `Invalid profile: 'production' is not defined in monosecret.toml. Available profiles: default, dev`.
  Affects `check`, `run`, `get`, `set`, and `import`. Surfaced via
  [#79](https://github.com/ifiokjr/monosecret/issues/79).

## [0.10.1] - 2026-05-11

### Fixed

- `monosecret check`: optional secrets that aren't set no longer render with a
  green `✓` and aren't counted as "found" in the trailing summary. They now
  display with the same blue `○ (optional)` styling already used in the
  missing-required path, and the summary appends `, N optional` whenever
  optional secrets are absent (e.g. `Summary: 4 found, 0 missing, 1 optional`).
  If every optional secret is set, the summary line stays in its previous
  `X found, Y missing` form. Fixes
  [#72](https://github.com/ifiokjr/monosecret/issues/72).

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
  [#80](https://github.com/ifiokjr/monosecret/issues/80).
- Vault / OpenBao provider: HTTPS requests now trust certificates from the
  operating system trust store (and honor `SSL_CERT_FILE` / `SSL_CERT_DIR`),
  so servers fronted by a private / internal CA work without modification.
  Previously the bundled `webpki-roots` set was the only trust anchor and any
  non-public CA produced `Failed to connect to Vault ... error sending
  request`. Switches the `reqwest` workspace dependency from `rustls-tls` to
  `rustls-tls-native-roots`. Fixes
  [#85](https://github.com/ifiokjr/monosecret/issues/85).

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
  `MONOSECRET_PROVIDER` environment variable. Previously the env var was
  consulted before the value forwarded from `--provider` (via `set_provider`),
  so users could not temporarily override the provider on the command line
  while the env var was set. Fixes
  [#77](https://github.com/ifiokjr/monosecret/issues/77).
- Per-secret `providers = [...]` chains now behave as a true fallback chain
  when an upstream provider errors (e.g. a 403 from a vault the current user
  cannot access). Previously the first provider's error short-circuited the
  whole operation; now the error is logged as a warning and the next provider
  in the chain is tried. The original error is only surfaced if every
  provider in the chain failed (so genuine outages still bubble up), or if
  the secret has no alternative to fall back to. Fixes
  [#83](https://github.com/ifiokjr/monosecret/issues/83).
- `monosecret run` now removes the temporary files it creates for
  `as_path = true` secrets after the child process exits. Previously the
  files were leaked under `/tmp` because `std::process::exit` skipped the
  destructors that own them. Fixes
  [#71](https://github.com/ifiokjr/monosecret/issues/71).
- Provider URIs now support spaces and special characters in names
  (e.g., `onepassword://Home Lab`). All providers receive automatically
  percent-decoded values via a new `ProviderUrl` wrapper type.
- dotenv provider: setting a secret no longer corrupts neighboring values
  that contain double quotes, backslashes, dollar signs, or newlines
  (e.g. JSON values). The underlying `serde-envfile` serializer did not
  escape these characters; fix is pinned via a fork until
  [lucagoslar/serde-envfile#6](https://github.com/lucagoslar/serde-envfile/pull/6)
  lands upstream. Fixes [#74](https://github.com/ifiokjr/monosecret/issues/74).
- `--provider` (and `MONOSECRET_PROVIDER`) is now honored on every command
  even when a `providers = [...]` chain is configured for the secret or
  profile. Previously `set`, `get`, `check`, `import`, and `run` silently
  used the first provider in the chain and ignored the explicit override,
  making `monosecret set --provider <alias>` a no-op against the requested
  target. The flag now consistently takes precedence: `set`/`import`/
  generation write only to the chosen provider, and `get`/`validate` read
  only from it (no chain fallback). Provider aliases declared in
  `~/.config/monosecret/config.toml` can now be passed directly to
  `--provider`. Fixes [#81](https://github.com/ifiokjr/monosecret/issues/81).

### Added

- BWS (Bitwarden Secrets Manager) provider with async SDK integration, secret caching, and full read-write support (requires `--features bws`)

### Changed

- `monosecret_derive` now depends on `monosecret` with `default-features = false`, avoiding pulling in CLI and provider features when only the derive macro is used.

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
- Support running monosecret from subdirectories: the CLI now walks up the directory tree to find the nearest `monosecret.toml`, similar to `cargo` and `git`. Also adds a `-f`/`--file` flag (and `MONOSECRET_FILE` env var) to explicitly specify the config file path (#59)

### Changed

- Extract shared `block_on` async helper from AWSSM and GCSM providers into `provider::block_on`

### Fixed

- GCSM provider no longer panics when called from within an existing tokio runtime

## [0.7.2] - 2026-02-24

### Added

- Keyring and pass providers now support `folder_prefix` via URI (e.g., `keyring://monosecret/shared/{profile}/{key}`)
  to share secrets across projects, matching the existing OnePassword and LastPass behavior

### Changed

- Support `XDG_CONFIG_HOME` on macOS by switching from `directories` to `etcetera` crate.
  Existing macOS configs at `~/Library/Application Support/monosecret/` are automatically
  migrated to `~/.config/monosecret/` (#28)

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

- CLI: Add `--no-prompt` (`-n`) flag to `monosecret check` command for non-interactive mode.
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

- Display correct error message when extended config file is not found, instead of the misleading "No monosecret.toml found in current directory" error

## [0.4.1] - 2025-11-27

### Added

- OnePassword provider: Support for `MONOSECRET_OPCLI_PATH` environment variable to specify custom path to the OnePassword CLI
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
- Export `Provider` trait from monosecret crate for use in derived code

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
- Fix MONOSECRET_PROFILE and MONOSECRET_PROVIDER environment variable resolution
- Ensure CLI arguments take precedence over environment variables
- add CLI integration tests
- Update test script to handle non-TTY environments correctly

## [0.1.2] - 2025-01-17

### Fixed

- SDK: Hide internal functions

## [0.1.1] - 2025-07-16

### Added

- `monosecret --version`

### Fixed

- Profile inheritance: fields are merged with current profile taking precedence

## [0.1.0] - 2025-07-16

Initial release of Monosecret - a declarative secrets manager for development workflows.
