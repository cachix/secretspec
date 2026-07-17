# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Composed secrets derive read-only values such as connection strings from
  other declared secrets using strict `{SECRET_NAME}` templates. Dependencies
  are order-independent, may include other compositions, and are validated for
  unknown references and cycles before provider access; unlike dotenv
  expansion, values are substituted once without ambient environment lookup,
  fallback operators, recursive expansion, or silent empty replacements.
- C# SDK (`Cachix.SecretSpec`, available in 0.16): resolve secrets from .NET
  through the shared native resolver, with fluent builder and one-shot APIs,
  typed failure exceptions, value-free preflight reports, provenance,
  environment export, typed-codegen input, and deterministic cleanup of
  `as_path` files. The NuGet package includes native resolver builds for Linux
  x64/Arm64, macOS Arm64, and Windows x64.
- Infisical provider (`infisical://`), for Infisical Cloud and self-hosted
  instances. Authenticates as a machine identity via Universal Auth, whose
  `client_id` and `client_secret` can be sourced as provider credentials (with
  `INFISICAL_CLIENT_ID`/`INFISICAL_CLIENT_SECRET` fallbacks), or with a
  ready-made `token`/`INFISICAL_TOKEN`. A profile names the Infisical
  environment, so a `production` profile reads the `production` environment;
  projects whose environments do not correspond to profiles pin one with
  `?env=`, and profiles stay separate either way. Secrets live at
  `/secretspec/{project}/{profile}` (`?path=` overrides the prefix), with keys
  stored verbatim, and secrets sharing a folder are fetched in one request. A
  folder's imported secrets resolve too, with Infisical's own precedence. A
  secret's `ref` can name an Infisical secret by folder, key and `version`.
  Self-hosted and EU instances are named by the URI host, `INFISICAL_DOMAIN`, or
  Infisical's legacy `INFISICAL_API_URL`. Provider selection and Rust API
  documentation identify Infisical as available from SecretSpec 0.16.

## [0.15.0] - 2026-07-16

### Added

- Password Manager provider. `bitwarden://` uses the `bw` CLI for vault-wide secret storage across all Bitwarden item types.
- Gopass provider (`gopass://`) for GPG-based password manager with git-synced password store.
- `secretspec export` command that resolves every secret for the active profile
  and writes them to stdout without running a command, in a chosen `--format`:
  `shell` (`export KEY='value'`, for `eval "$(secretspec export)"`), `dotenv`,
  `json`, or `gha` (appends to `$GITHUB_ENV` and emits `::add-mask::` for each
  value). Unlike `run` it never prompts and exits non-zero on a missing required
  secret, so CI can gate on it.
- Azure Key Vault provider (`akv://`). Authenticates via a service principal
  whose `tenant_id`, `client_id`, and `client_secret` can be sourced as provider
  credentials (with `AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET`
  fallbacks), falling back to a signed-in Azure CLI / Azure Developer CLI
  session when none are available; managed identity and
  AKS workload identity are also available via `?auth=managed_identity` and
  `?auth=workload_identity`. Sovereign clouds can be addressed with a full
  DNS hostname or an explicit `?suffix=` override. Project/profile/key
  components use lowercase, unpadded Base32 so case and punctuation remain
  distinct within Azure's restricted, case-insensitive secret-name namespace.
- The `awssm` provider accepts `kms_key_id` and `tag.NAME=VALUE` query
  parameters (e.g. `awssm://prod@us-east-1?kms_key_id=alias/my-key&tag.team=platform`).
  Both are applied only when secretspec creates a secret, so accounts that enforce
  a customer-managed KMS key or "tag-on-create" guardrails (an SCP requiring
  `aws:RequestTag/*` on `CreateSecret`) can now store secrets. A pre-existing
  secret keeps the key and tags it was created with.
- PHP SDK (`cachix/secretspec`): resolve secrets from PHP, Laravel, and Symfony
  over the same shared resolver as the other language SDKs. It ships as a native
  PHP extension that embeds the resolver (works under PHP-FPM with no
  `ffi.enable`, like `ext-redis`), with an `ext-ffi` fallback that dlopens the
  library at runtime for CLI and local development.
- Provider aliases can now source their own credentials from another provider.
  An alias in `[providers]` may declare a `credentials` map binding a semantic,
  provider-specific name (such as `access_token`, `token`, `role_id`, or
  `client_secret`) to a source: a bare provider spec, which reads the value at
  the convention path, or a table with a `ref` giving the exact coordinates.
  The credential is fetched from that provider and handed to the store, so a
  machine token can live in the OS keyring instead of a plaintext environment
  variable, and is never written
  into the environment of processes started by `secretspec run`. A configured
  credential is authoritative; providers retain their conventional environment
  fallback when no explicit credential is supplied. Chains are limited to one
  hop, and that limit is enforced wherever the alias appears, as a chain
  fallback or the default provider included. Provider credentials also apply
  when the alias is selected with an explicit `--provider <alias>` or
  `SECRETSPEC_PROVIDER`, and
  they are fetched from their source once per invocation and profile, then
  reused across all secrets routed at the alias (convention-path credentials
  live under a profile, so switching profiles re-reads them). Each source read,
  and each credential stored through `login`, is audited with a `credential`
  marker naming the semantic credential and the source store; a credential
  stored through `login` takes effect immediately. Unsupported credential names
  fail validation before a source is accessed.

  ```toml
  [providers]
  bws = { uri = "bws://project-uuid", credentials = { access_token = "keyring" } }
  akv = { uri = "akv://myvault", credentials = { tenant_id = "keyring", client_id = "keyring", client_secret = "keyring" } }
  vault = { uri = "vault://kv/app?auth=approle", credentials = {
    role_id   = { provider = "onepassword", ref = { vault = "Infra", item = "approle", field = "role_id" } },
    secret_id = { provider = "onepassword", ref = { vault = "Infra", item = "approle", field = "secret_id" } },
  } }
  ```
- `secretspec config provider login <alias>` prompts for each provider
  credential a provider alias declares and stores it in its source provider, so
  it can be read back on the next resolution. `secretspec config provider add`
  gains a repeatable `--credential NAME=PROVIDER` flag for declaring credential
  sources from the command line.

### Changed
- Rust SDK validation errors now store their detailed report out of line,
  reducing the size of `SecretSpecError` values while preserving diagnostics.
- Generated types now describe the values resolution can actually return:
  omitted `required` still means required, secrets supplied by a manifest
  default or generator are non-nullable, and profile-specific types include
  secrets inherited from the `default` profile. Profile JSON Schemas are now
  exhaustive (`additionalProperties: false`) for the same reason.
- A `ref` routed at a single store (an explicit `--provider`, a single-provider
  chain, or the default provider) is now checked up front, before any store is
  contacted, for coordinates that store cannot honor (e.g. a `field` ref pointed
  at a `.env` file), failing fast with a clear message instead of at fetch time.
  A `ref` on a multi-store fallback chain is still validated per store as the
  chain is walked, so a coordinate a later store cannot express never blocks a
  provider earlier in the chain that can.
- Provider chains accept bare provider names and `scheme:path` shorthand
  (e.g. `providers = ["keyring"]`), the same specs `--provider` accepts.
  Previously a chain entry had to be a declared alias or a full `scheme://` URI.
- An explicitly empty `providers = []` list now uses the default provider for
  `get` as well, matching how `check` and `run` already treated it.
- A `providers` chain whose *first* entry misspells `onepassword` as
  `1password` now fails up front with the corrective "use `onepassword`
  instead" message — the same hard error any other invalid primary gets —
  instead of warning and falling through to the rest of the chain. As a
  fallback entry it is still skipped with a warning, like any broken link.
- Rust SDK: `ProviderAlias::credentials` is a plain map whose empty state means
  "no provider credentials", rather than an `Option`, so the two ways of spelling
  an alias without credentials cannot diverge.

### Removed
- The unused public `Config::merge_with` and `Profile::merge_with` methods.
  Configuration inheritance (`extends`) is now applied entirely through the
  internal overlay used by the loader, so these self-wins merge helpers no
  longer had any callers.

### Fixed
- Configuration inheritance now loads an `extends` hierarchy as a DAG. Shared
  ancestors in diamond-shaped graphs are applied once instead of being reported
  as cycles, later entries in `extends` correctly override earlier entries, and
  profile `[defaults]` are inherited across source files.
- Runtime planning, semantic validation, Rust derive output, and JSON Schema
  generation now share one compiled effective-manifest model and one
  missing-value policy, preventing raw `required`/`default` interpretation from
  drifting between surfaces.
- Profile overrides no longer need to repeat the secret's `description`:
  validation now checks each secret's effective, merged configuration, so a
  partial override like `[profiles.development] DATABASE_URL = { default =
  "sqlite:///dev.db" }` inherits the description (and `type`, for `generate`)
  from the default profile instead of failing with "missing description".
  The merged view is also validated for real conflicts, so a `generate`
  secret in the default profile combined with a `default` value from an
  override or a profile `[defaults]` table is now rejected at load instead of
  silently generating a random value and ignoring the default. Validation
  errors are reported deterministically, attributed to the profile that
  declares the offending field, and `check` and `run` list secrets in stable
  name-sorted order.
- Provider fallback chains (`providers = [...]`) are now tried strictly in
  order: each link is resolved only when a read actually reaches it, and a
  broken link (an undefined alias, an unreachable store) is skipped with a
  warning so a working provider later in the chain still answers. `check`,
  `run`, and `get` all walk the chain the same way.
- `get` and `set` now record an audit event when a secret's provider routing
  fails to resolve (for example an undefined alias), matching how `check` and
  `run` audit every attempted read.
- A provider chain entry that misspells `onepassword` as `1password` now gets
  the same "use `onepassword` instead" correction that `--provider 1password`
  gives, instead of a generic undefined-alias error.
- Blank or whitespace-only profile and provider overrides (`--profile`,
  `SECRETSPEC_PROFILE`, `--provider`, `SECRETSPEC_PROVIDER`, and the Rust SDK
  builder) are now trimmed and treated as unset, so a padded value such as a
  trailing newline from `$(cat file)` can no longer select a nonexistent
  profile or provider.
- `import` prints its per-secret summary in a stable, name-sorted order.
- `run` no longer aborts when the environment contains a non-UTF-8 variable.
  Such variables are now passed through to the child process untouched, with
  resolved secrets overlaid on top.
- The prebuilt Linux addons of the Node SDK are now built against glibc 2.28
  (manylinux_2_28) with libdbus compiled in statically, so `npm install
  secretspec` works on Amazon Linux 2023, RHEL 8/9, and other distros with an
  older glibc, instead of the addon failing to load with "version `GLIBC_2.38'
  not found". ([#136](https://github.com/cachix/secretspec/issues/136))

## [0.14.0] - 2026-07-09

### Added
- **`ref`: native secret references on secrets**: a secret can name one
  externally managed secret by its store's own coordinates, instead of
  SecretSpec's `{project}/{profile}/{key}` naming:

  ```toml
  [profiles.production]
  DATABASE_URL = { description = "...", ref = { item = "db", field = "password" }, providers = ["prod_op"] }
  ```

  `item` is the store's own name for the secret (1Password item title, Vault
  KV path, AWS secret name or ARN, `.env` key, environment variable, ...);
  optional keys refine it where the store supports them: `field` (1Password
  field label, Vault KV field, AWS JSON key, keyring account), `vault` and
  `section` (1Password), and `version` (Google Secret Manager). Every provider
  resolves refs; coordinates a store has no equivalent for are rejected with a
  clear error rather than guessed at.

  The coordinates supply naming only — *which* store resolves them follows the
  same routing as every other secret (the secret's `providers` chain, the
  `--provider`/`SECRETSPEC_PROVIDER` override, or the default provider). That
  means refs compose with `providers` fallback chains, and an explicit
  override redirects them like any secret, e.g. at a `.env` fixtures file
  during tests. Writes are symmetric where the backend allows it:
  `secretspec set` and `check` prompting write through the coordinates in
  place (1Password `op item edit`, keyring, pass, dotenv, Bitwarden, Proton
  Pass, LastPass); Vault, AWS, and GCSM refs are read-only. Secrets sharing
  identical coordinates fetch once, and audit events record the coordinates in
  a new `ref` field. A `ref` also composes with `generate`: a missing
  referenced secret is minted and written straight to its coordinates.
- **Inline provider URIs in `providers` chains**: chain entries that are
  already URIs (`providers = ["onepassword://Production", "keyring"]`) now
  pass through without declaring a `[providers]` alias first.

### Changed
- **Faster multi-provider resolution**: `check`, `run`, and SDK resolution now
  group secrets by store and fetch the groups concurrently instead of one
  after another; within a group, `ref` secrets batch through the store's bulk
  surface where it has one (AWS `BatchGetSecretValue`, the single Bitwarden,
  Proton Pass, and 1Password listings) and otherwise resolve concurrently,
  each unique coordinate fetched once. CLI authentication (1Password,
  LastPass, Proton Pass) is probed once per account/session instead of once
  per provider instance.
- **Provider trait speaks one address vocabulary** (affects custom providers
  built on the Rust library): each provider now compiles SecretSpec's
  `{project}/{profile}/{key}` convention into its native coordinates via a
  new required `convention_address` method, and reads resolve every address
  through the same coordinate path a `ref` uses. The convention-only
  `get_batch` method is replaced by `get_many`, which takes addresses and so
  batches `ref` secrets too. A provider declares the `ref` coordinates it
  honors with `supported_coords` and the rest are rejected for it, and
  `allows_set` is replaced by `check_writable`, which returns the reason a
  write is refused rather than a bare `false`.
- **Manifest validation runs on load**: the semantic rules `secretspec.toml`
  documents (a required secret cannot carry a `default`, `generate` needs a
  `type`, `ref` coordinates must be non-empty and non-whitespace) are now
  enforced whenever the config is loaded. Configs that silently violated them
  previously will now fail with a pointed error.

### Fixed
- **onepassword**: URIs carrying an item path (e.g. the
  `onepassword://vault/Production` form some older docs showed) previously
  discarded the path silently and targeted a vault literally named `vault`.
  Item paths — including pasted `op://vault/item/field` references — now fail
  with an error spelling out the exact `ref` coordinates to write instead.
- **`set` on a read-only `ref`** reported "Provider '<name>' is read-only and
  does not support setting values", which is untrue of Vault, AWS, and GCSM —
  they write the conventional layout fine and refuse only refs. The store's own
  reason is now shown (e.g. writing one Vault field would clobber the sibling
  fields at the same KV path).

## [0.13.0] - 2026-07-03

### Added
- **Language SDKs for Python, Go, Ruby, Node.js / TypeScript, and Haskell**
  (`secretspec-py`, `secretspec-go`, `secretspec-rb`, `secretspec-node`,
  `secretspec-hs`). Resolve the secrets declared in your `secretspec.toml` from
  each language using the same providers, profiles, fallback chains, and
  generators as the CLI and the Rust SDK — no per-language configuration. Each
  mirrors the Rust derive crate's vocabulary: a builder taking a provider,
  profile, and access reason; `load()` returns the resolved secrets and can export
  them into the process environment, while a value-free `report()` previews how
  each secret would resolve without reading any value. A missing required secret
  raises a typed error; `as_path` secrets are returned as a readable file path,
  with an explicit (or scope-based) cleanup that removes the backing temp file.
- **`secretspec-ffi` crate**: a small, versioned C ABI for resolving secrets from
  any language, plus the public Rust building blocks the SDKs are built on
  (`Secrets::resolve()` and `Secrets::report()`). Use it to write a binding for a
  language we do not ship yet.
- **`secretspec schema`**: emits a JSON Schema for your manifest's typed shape
  (the union of all profiles, or one profile via `--profile`). Feed it to
  [quicktype](https://quicktype.io) to generate idiomatic typed classes in any
  language, populated from each SDK's `fields()` map — type-safe secret access
  without hand-writing a generator per language.
- **`secretspec check --json` / `--explain`**: a value-free report of how every
  declared secret resolves for the active profile — its status (`resolved`,
  `missing_required`, `missing_optional`), where the value would come from
  (a provider, with a credential-free URI; a generator; or a committed default),
  and whether it is exposed `as_path`. Values are never included, and both flags
  skip the interactive prompt and exit non-zero when a required secret is missing,
  so CI can gate on them. The same report is available to the Rust SDK via
  `ValidatedSecrets::report()` / `ValidationErrors::report()`.

### Fixed
- A per-secret provider chain whose primary provider errors (e.g. an unreachable
  vault) and whose fallback chain yields no value now surfaces that provider error
  instead of silently reporting the secret as `missing_required`, so a provider
  outage is distinguishable from an unprovisioned secret.

## [0.12.2] - 2026-06-22

### Added
- The `pass` provider accepts a `store_dir` query parameter (e.g.
  `pass://?store_dir=/path/to/store`) to use a password store directory other
  than the default `~/.password-store`. It is applied as `PASSWORD_STORE_DIR`
  scoped to each `pass` invocation.

### Fixed
- Provider URIs now correctly round-trip query parameters whose values contain
  characters that are significant in a query string (`&`, `+`, `#`, `%`, and
  spaces). Previously such characters in the `awssm` `prefix` (and the new `pass`
  `store_dir`) were emitted unescaped, so the value could be silently truncated
  or altered when the URI was parsed back.
- `secretspec import <FROM>` now accepts a provider alias (from `[providers]` or
  the global `[defaults.providers]`) as its source, not just a literal provider
  URI. Passing an unknown provider or alias now reports the available aliases.

## [0.12.1] - 2026-06-15

### Fixed
- Windows: a `dotenv://` provider URI built from an absolute path (e.g.
  `dotenv://C:\path\.env`) no longer fails to parse with "invalid port number".
  The drive-letter colon was being read as a `host:port` separator; such paths
  are now carried through the URL intact.
- Windows: the audit log no longer fails to reset at its size cap. Truncation on
  the append-only handle was denied by the OS; it now truncates through a
  separate write handle.
- Relative `dotenv` paths (e.g. `dotenv:.config/.env`) now resolve against the
  directory containing `secretspec.toml` instead of the current working
  directory. Running `secretspec run --file ../secretspec.toml` from a
  subdirectory previously failed to find the referenced `.env` file because it
  was looked up relative to the working directory rather than the project root
  (#59). Absolute `dotenv` paths are unaffected.
- The `protonpass` provider now works with Proton Pass CLI `pass-cli >= 2.0.3`.
  The `item list --output json` payload changed shape in 2.0.3 (the item title
  moved from a nested `content.title` to a top-level `title`, and `content` was
  dropped from list output), which made `secretspec` report active secrets as
  missing. Both the old (`<= 2.0.2`) and new (`>= 2.0.3`) list shapes are now
  accepted. ([#104](https://github.com/cachix/secretspec/issues/104))

## [0.12.0] - 2026-06-08

### Added
- Audit logging for secret access, on by default. Every secret read and write,
  from both the CLI and the Rust SDK, is appended to a local per-user log as JSON
  Lines. Only metadata is recorded (secret names, the serving provider with any
  embedded credentials redacted, outcome, reason, and actor including a detected
  coding agent); secret values are never written. Each operation is recorded once:
  `get` and `set` per secret, `check` as a single event, `run` when the child
  process starts, and `import` per copied secret. Auditing never blocks secret
  access; if it cannot write the log it warns on stderr and continues. The log is
  a single file capped at 1 MiB. It is configured per machine via the `[audit]`
  table in `~/.config/secretspec/config.toml` (not the project's
  `secretspec.toml`), so a cloned repository cannot redirect or silence it. The
  new `secretspec audit` command reads the log, with `--project`, `--action`,
  `--tail`/`-n`, and `--json` filters. See
  [Audit Logging](https://secretspec.dev/concepts/audit/) for details.
- `--reason` CLI flag (and `SECRETSPEC_REASON` env var) records a human-readable
  reason for a session's secret access, forwarded to providers that support audit
  logging. `SECRETSPEC_REASON` is honored across the SDK/library too: it is resolved
  by `Secrets::load`/`load_from` (so `secretspec-derive`-generated code and other
  library callers can satisfy the `require_reason` policy and supply an audit reason
  without code changes), and `Secrets::with_reason(...)` sets it explicitly, taking
  precedence. The `secretspec-derive`-generated typed builder also gains a
  `with_reason(...)` method, so SDK callers can satisfy `require_reason` in code
  (not only via the env var). Blank or whitespace-only reasons are ignored so they
  cannot satisfy the policy. Backed by a new `Provider::set_reason` trait method
  (default no-op).
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

### Changed
- Minimum supported Rust version raised to 1.92 (required by the
  `detect-coding-agent` dependency). The devenv toolchain is pinned accordingly.

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
