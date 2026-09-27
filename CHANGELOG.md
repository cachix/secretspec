# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0](https://github.com/ifiokjr/monosecret/releases/tag/v0.4.0) (2026-09-26)

Grouped release for `monosecret`.

### Breaking

#### Sync upstream SecretSpec 0.21: resolver IPC, binary secrets

Merge `cachix/secretspec` from `5ea68378` (the recorded 0.21-era merge base) through upstream `main` @ `b3a29191` (post-0.21 fixes), rebranded into the `crates/monosecret`, `crates/monosecret_derive`, `crates/monosecret_ffi`, and per-language `monosecret_*` SDK layout.

###### What breaks

- **Secret values are byte-native.** `Secrets::set` now takes `SecretBytes`; text callers use `set_text` and deletions use `prompt_and_set`. Custom providers update `get`/`set`/`get_many` to `SecretBytes`; `Provider::name` returns `&str` and `generator::generate` returns bytes.
- **Cache entries use the v4 envelope** preserving binary values. New entries are unreadable by 0.20 and earlier (they fall back to the provider); old entries remain readable.
- **Command-generated values include all stdout bytes** including trailing newlines and spaces; trim in the command when unwanted. Empty or whitespace-only output is still rejected.
- **`monosecret get` no longer appends a newline** when writing to a pipe or file; terminal output still ends in a newline. Piped `monosecret set` input remains trimmed text; use `--from-file -` to preserve exact bytes from stdin.
- **Building the C resolver client requires system yyjson** via pkg-config/CMake; static consumers link `-lyyjson`.

###### New providers

- **Doppler** (`doppler://PROJECT[/CONFIG]`): read, write, delete, and discover with profile-selected configs and `DOPPLER_TOKEN` auth.
- **Tailscale Setec** (`setec://`): read, write, delete, and discover through a tailnet-authenticated server, with binary values and version-pinned reads.

###### New features

- **`monosecret serve` resolver IPC**: request single declared secrets from another process over a versioned stdio protocol, with leases, prompts, store/delete, expiry/revision metadata, and `--read-only` mode. Rust clients use the new `monosecret-ipc` crate (async and blocking, including SSH transports); C clients use `libmonosecret-resolver`.
- **External providers**: trusted executables can serve the versioned provider protocol with credential negotiation, interaction references in audit logs, and per-endpoint scoped environments.
- **Project-wide `[defaults].providers` chains**, editor JSON Schemas (`monosecret schema --config project|global`), OpenPGP/OpenSSH key generation, Bitwarden UUID targeting, and JVM inline specs.

###### Fixes

- Bounded HTTP timeouts (10s connect, 60s request) across Vault, OpenBao, Infisical, Cloudflare, Scaleway, AAC, Doppler, and Setec.
- macOS keyring no longer prompts on every run after an upgrade; reads preserve items and access settings.
- KDBX 4.0 files upgrade to 4.1 on write preserving encryption/KDF settings.
- Bitwarden batch reads use one vault listing with search fallback; pass/gopass/LastPass whitespace handling hardened; cache planning avoids provider reads and refuses self-overlapping caches.
- Post-0.21 upstream fixes: C-resolver early-output registration, timing-independent regression checks, crate-internal test fixtures, flaky-test hardening, and Nix-sandbox ancestor-walk isolation.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #73](https://github.com/ifiokjr/monosecret/pull/73) · _Related issues:_ [#71](https://github.com/ifiokjr/monosecret/issues/71)

### Fixes

#### ejson timeout tests no longer fail on a loaded machine

_Packages:_ 🟢 _rust:monosecret_

The two tests that prove a hung or exited `ejson` CLI is stopped at its timeout
read the stub's descendant-PID file with `unwrap`, and a loaded runner could
kill the process group before the shell wrote it — so the suite failed with "No
such file or directory" on a machine that was busy with something else. They now
wait for the file with a bounded retry, which keeps the assertion (the stub must
record its descendant, and the descendant must be gone) while removing the race,
and the exit-path test's timeout is generous because what it checks is the cost
relative to the deadline rather than how fast the stub runs.

No runtime behavior changes: the provider's timeout handling is untouched.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #76](https://github.com/ifiokjr/monosecret/pull/76)

#### `depends_on` cycles no longer overflow the stack

_Packages:_ 🟢 _rust:monosecret_

Forcing a provider that declares `depends_on` (e.g. `monosecret run
--provider op`) applied the session-wide override to the bootstrap secret too,
so building the provider needed the provider: unbounded recursion ending in
`thread 'main' has overflowed its stack` with no error to report or retry
against. The same abort happened for genuine configuration cycles (a
`depends_on` secret routed back at its own provider directly or through
profile defaults).

Bootstrap secrets now resolve from their own declared routes — the
`--provider` flag, the builder override, and `MONOSECRET_PROVIDER` are ignored
while they resolve — so `--provider op` reads `OP_SERVICE_ACCOUNT_TOKEN` from
where it is configured and then queries 1Password. Re-entrant construction is
tracked per thread and fails with a `provider dependency cycle: store ->
TOKEN -> store` error naming the chain, and config loading rejects the direct
form up front (`monosecret check` reports it before anything runs). Six
regression tests cover the flag, the environment variable, both config-cycle
spellings, and static validation.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #71](https://github.com/ifiokjr/monosecret/pull/71) · _Closed issues:_ [#70](https://github.com/ifiokjr/monosecret/issues/70) · _Related issues:_ [#71](https://github.com/ifiokjr/monosecret/issues/71)

## [0.3.5](https://github.com/ifiokjr/monosecret/releases/tag/v0.3.5) (2026-09-12)

Grouped release for `monosecret`.

### Fixes

#### Resolution no longer dies on SIGPIPE when a provider CLI exits without draining stdin

_Packages:_ _rust:monosecret_

The CLI restores SIGPIPE's default disposition (`monosecret check | head`), but
every provider that pipes data into a child CLI — `op item get` batch reads,
`op inject`, `pass insert`, `lpass add`, `pass-cli` — spawned the child and then
wrote to its stdin. If the child rejected the input and exited without draining
stdin (exactly how `op item get` refuses a batch with an ambiguous title), the
write could land after the child's exit and terminate monosecret with SIGPIPE
mid-resolution: no error message, no inject fallback, exit by signal. The window
is normally won by the writer, so regular CI passed; the slower
coverage-instrumented build on Linux reliably lost it.

Child stdin writes now run with SIGPIPE blocked on the writing thread (the
process disposition stays untouched, so sibling batch threads and shell pipes
keep their semantics) and a broken pipe is treated as the child's verdict: the
child's exit status and stderr flow through the existing error classification,
so an ambiguous-title batch still defers to the inject fallback. A regression
test drives a child that closes its read end without draining an oversized
batch, which pins the fix deterministically.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #64](https://github.com/ifiokjr/monosecret/pull/64)

#### Record the downloaded FFI payload as a hook build dependency

_Packages:_ _dart_

The Dart build hook downloads the release's `monosecret-ffi-*` payload into a
shared cache and copies it into the build output, but never recorded the
payload as a hook dependency. Hook inputs do not change when a release
changes the downloaded artifact, so runners that cache by input could replay
the previous release's library: a Dart SDK upgrade from 0.3.3 to 0.3.4 kept
loading a cached 0.3.3 dylib and every resolve failed with
`Native ABI version 0.3.3 does not match Dart package version 0.3.4` until
`.dart_tool` was deleted by hand.

The downloaded payload is now recorded through `output.dependencies`, keyed
under `monosecret/<verified-sha256>/` in the shared output directory, so a
changed release artifact (or a cleared cache) re-runs the hook instead of
replaying stale output.

The failure modes of this bug class are now covered by end-to-end hook tests
(`testBuildHook` against a fake release fetcher): the copied asset and its
recorded dependency must track the served payload across runs with identical
hook inputs, a payload that violates its sidecar fails closed, and the
`Native ABI version` mismatch error now tells consumers how to recover
(delete `.dart_tool` and rebuild). Consumers recovering from an
already-cached stale library still need to do that once; the check keeps
failing closed.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #61](https://github.com/ifiokjr/monosecret/pull/61)

## [0.3.4](https://github.com/ifiokjr/monosecret/releases/tag/v0.3.4) (2026-09-10)

Grouped release for `monosecret`.

### Fixes

#### Cut 1Password service-account reads from one-per-secret to one-per-item

_Packages:_ _rust:monosecret_

Every secret reference `op inject` resolves is an individually billed read
against the 1Password service-account rate limits. Manifests that pin a whole
profile to one shared item (`op+token://Vault/Item`, with `path`-routed
secrets) paid one request per secret on every resolve, `run`, and devenv
startup — the global dotfiles manifest (17 secrets) spent ~18 reads per run,
nifty's development profile ~20 — which drains the account-wide daily pool.

Field references are now served from batched `op item get` reads: one billed
read per _item_, however many secrets read fields of it, with section and
field matched client-side. The full-resolution budget for a shared-item
manifest is two requests per run (auth preflight + one item read), and `op
inject` plus the per-secret read recovery remain as the correctness fallback
for references the item reads cannot serve (ambiguous titles, unusable
output, fields present but unservable).

`Too many requests` is also classified as a global failure alongside auth
errors. While throttled, every retried or fanned-out attempt is itself a
billed request that extends the lockout, so a rate-limited batch now surfaces
the error after its single failed request instead of cascading.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #56](https://github.com/ifiokjr/monosecret/pull/56)

### Other

#### Refresh toolchain, dependencies, and CI action pins

_Packages:_ _monosecret_

Toolchain moves to nightly-2026-09-07 with the clippy fixes its newer lints
require, Rust workspace dependencies are upgraded (base64 0.23, sha2 0.11,
syn 3, reqwest 0.13 with its reworked rustls features, jsonschema 0.55), the
Node native addon moves to napi 3, and GitHub Actions pins advance to their
latest releases. No behavioral changes: the clippy fixes are test-only
assertions, and dead workspace dependency entries are removed.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #58](https://github.com/ifiokjr/monosecret/pull/58)

## [0.3.3](https://github.com/ifiokjr/monosecret/releases/tag/v0.3.3) (2026-09-08)

Grouped release for `monosecret`.

### Fixes

#### Fix keyring lookups and 1Password `depends_on` tokens broken in 0.3.2

_Packages:_ _rust:monosecret_, _rust:monosecret_derive_, _rust:monosecret_ffi_, _@monosecret/client_

Two regressions broke every keyring-backed secret for specs whose providers
declare `depends_on` (e.g. an `op+token` provider bootstrapped from a
keyring-stored service account token):

- **whoami compiled without its `std` feature**: the workspace dependency
  `whoami = { default-features = false }` selected whoami's stub platform
  backend, which reports `"anonymous"` as the current username on every
  native platform. The keyring provider addresses convention entries by
  `(service = monosecret/{project}/{profile}/{key}, account = username)`, so
  every lookup silently missed and every `set` would have written to a
  non-existent account. Default features are restored (the `std` feature is
  what compiles the real macOS/Windows/Linux backend), and a regression test
  asserts the resolved username is not the stub value.

- **`PreflightGuard` dropped `depends_on` bootstrap secrets**: the guard
  wrapping providers with auth preflights forwarded `set_reason`,
  `set_profile`, and `with_base_dir`, but not
  `Provider::configure_dependency_secrets` — so the trait's no-op default
  swallowed every resolved dependency. A provider declared with
  `depends_on = [{ secret = "OP_SERVICE_ACCOUNT_TOKEN" }]` resolved the token
  correctly and then discarded it, running every `op` child tokenless (which
  fails with `"<vault>" isn't a vault in this account` or `account is not
  signed in`). The guard now forwards the call, and the `onepassword` provider
  (`op+token://`) implements it: a delivered `OP_SERVICE_ACCOUNT_TOKEN` is
  exported to every `op` child process, ranked after an explicitly supplied
  provider credential and ahead of the ambient environment variable, matching
  `onepassword+env`'s existing behavior. Forwarding and token-precedence
  regression tests included.
- **`Arc` wrapping dropped the same hook one layer deeper** (caught by the
  new end-to-end regression tests): providers registered with a preflight are
  built as `Box<Arc<P>>`, and the blanket `impl Provider for Arc<T>` cannot
  forward a `&mut self` hook — an `Arc` gives no `&mut` access — so the
  delivery died at that layer even with the guard fixed.
  `configure_dependency_secrets` is now a `&self` hook with interior
  mutability (matching `set_reason`/`set_profile`), forwarded explicitly by
  the `Arc` blanket impl and `PreflightGuard`. This also fixes the
  `onepassword+env` provider, whose pre-existing implementation was silently
  swallowed by the same wrapper stack.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #50](https://github.com/ifiokjr/monosecret/pull/50)

### Other

#### End-to-end regression tests for provider `depends_on` delivery

_Packages:_ _rust:monosecret_, _rust:monosecret_derive_, _rust:monosecret_ffi_, _@monosecret/client_

Adds `crates/monosecret/tests/provider_dependency_token.rs`, two integration
tests that run the real CLI binary against a temporary manifest mirroring the
dotfiles setup that broke in 0.3.2: an `op+token` provider alias bootstrapped
from a `depends_on` secret stored in another provider, with the `op` CLI
replaced by a stub that records the `OP_SERVICE_ACCOUNT_TOKEN` it was
exported.

- **`depends_on_token_reaches_op_child_through_full_resolution`** resolves a
  secret through the full pipeline (manifest parsing, fallback planning,
  `PreflightGuard`, the `Arc`-wrapped concrete provider, child-process
  environment) and asserts every `op` child ran with the delivered token and
  the value resolved. This test caught the `Arc` layer of the 0.3.2
  regression after the isolated unit tests all passed — a refactor that
  builds providers through a path that skips dependency delivery fails here
  even when wrapper-level tests stay green.
- **`missing_dependency_secret_fails_resolution_loudly`** asserts a missing
  bootstrap secret fails resolution hard with the
  `requires secret '<name>'` error, rather than silently continuing
  tokenless.

Together with the wrapper-level unit tests on PR #50 (guard forwarding,
`Arc` forwarding, child-env export, precedence), every layer of the delivery
path is pinned so the regression cannot return unnoticed on a future release.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #51](https://github.com/ifiokjr/monosecret/pull/51) · _Related issues:_ [#50](https://github.com/ifiokjr/monosecret/issues/50)

## [0.3.2](https://github.com/ifiokjr/monosecret/releases/tag/v0.3.2) (2026-09-05)

Grouped release for `monosecret`.

### Features

#### Sync upstream SecretSpec through 0.20.0 + 0.21-era main

_Packages:_ _monosecret_

Merge cachix/secretspec from `671de322` (the recorded 0.19.1-era merge base) through upstream `main` @ `5ea68378` (2026-09-04), rebranded into the `crates/monosecret`, `crates/monosecret_derive`, `crates/monosecret_ffi`, and per-language `monosecret_*` SDK layout.

###### New providers

- **EJSON** (`ejson://`): encrypted JSON key/value files through `ejson`, with preflight discovery of the secrets directory (0.20+).

###### New features

- **Project default provider chains (0.21+)**: a project-level `[defaults]` table with a `providers` chain applied to every provider-backed secret that neither its profile nor a secret selects. Resolution order: secret → profile `[defaults].providers` → project `[defaults].providers` → user-global default. The inline-spec envelope moves to v2 with optional inline `defaults`.
- **OpenPGP and OpenSSH private-key generation (0.21+)**: `type = "openpgp_private_key"` (ed25519 default, configurable RSA, user ID, sign/encrypt capability profiles) and `type = "ssh_private_key"` (ed25519 default, configurable RSA and comments), generated entirely in Rust via rPGP and `ssh-key`.
- **Claude Code credential integration (0.21+)**: `monosecret claude configure`/`unconfigure`/`login`/`logout` wire Anthropic API and LLM gateway credentials through Claude Code's `apiKeyHelper`, with settings-scope isolation, worktree handling, and `CLAUDE_CONFIG_DIR` support.
- **Providers disabled at compile time now report clearly**: a secret routed at a feature-gated provider whose Cargo feature is off returns a stable `provider_feature_disabled` error naming the provider and the feature.

###### Fixes

- Provider metadata centralized into a shared catalog shared by enabled and disabled registrations, so discovery and error metadata stay identical in every build.
- Inline-spec resolution gains the v2 envelope across the FFI and every SDK (`monosecret_call` sources now advertise `spec_version` 2).
- Docs: EJSON provider guide, Claude Code integration guide, OpenPGP/SSH key-generation reference, project-defaults configuration reference, and a dotenv discouragement notice; the Claude OAuth security post is rebranded for the fork.

#### Default cargo builds to the CLI crate

_Packages:_ _monosecret_

Plain `cargo build`, `cargo check`, and `cargo test` now operate on the CLI crate only via workspace `default-members`. The language SDK members (FFI, npm, PHP, Python, and examples) require the `php`, `python`, and `node` interpreters at build time and are now selected explicitly with `--workspace` / `-p` in CI, devenv tasks, and publish workflows. Sandboxed CLI-only builds — such as Nix packaging, which installs monosecret without those interpreters — work again with a bare `cargo build`.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #44](https://github.com/ifiokjr/monosecret/pull/44)

#### Dart SDK: inline specs and caller context via the versioned call ABI

_Packages:_ _dart_

The Dart SDK now binds the versioned `monosecret_call` native entry point,
matching the other language SDKs:

- `MonosecretBuilder.withInlineSpec(spec, baseDir)` resolves strict
  inline-spec v1 declarations through the versioned call envelope; inline
  resolution never falls back to a filesystem manifest, and `withPath`
  clears the inline spec.
- `CallerContext` and `MonosecretBuilder.withCaller` record the invoking
  integration in audit records (they never satisfy a `require_reason`
  policy); `MonosecretClient.resolve`/`report` accept an optional caller.
- The bundled native library is probed for the call entry point and the
  result is cached; older libraries raise a `capability`
  `MonosecretException` on inline requests instead of an opaque ffi error.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #48](https://github.com/ifiokjr/monosecret/pull/48)

### Fixes

#### Refresh cargo, pnpm, dart, and devenv dependencies

_Packages:_ _rust:monosecret_, _rust:monosecret_derive_, _rust:monosecret_ffi_, _@monosecret/client_, _dart_

`cargo update`, `pnpm update --latest` (vitest 4 → 5, tsdown 0.22 → 0.23,
oxfmt 0.63 → 0.66, oxlint 1.78 → 1.81), `dart pub upgrade`, and
`devenv update` (devenv CLI, git-hooks.nix, custom nixpkgs inputs).

`keepass` is pinned to `=0.13.17`: the 0.13.25 release depends on a
cipher/cbc combination that `aes` 0.8 does not implement, which broke the
kdbx provider's build.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #49](https://github.com/ifiokjr/monosecret/pull/49)

#### Eliminate every clippy warning and promote lint groups to deny

_Packages:_ _rust:monosecret_, _rust:monosecret_derive_, _rust:monosecret_ffi_, _@monosecret/client_

Fixed ~1330 clippy warnings across the workspace (format-arg inlining,
doc-comment backticks, digit-separated literals, redundant
qualifications/closures, needless borrows, `let … else`, internal
pass-by-value → references, `#[must_use]` additions, unnecessary `Result`
wraps, dead code) and converted `indexing_slicing` in production parsers to
bounds-checked access with error propagation, so malformed provider responses
can no longer panic. Fixed a latent `cached_route` panic (inline-URI alias
caching into its own store), a pre-existing flaky Infisical TCP test, and
reverted a clippy `--fix` regression that flipped the vault missing-`tls`
default.

All clippy groups (`complexity`, `pedantic`, `perf`, `style`, `suspicious`)
are now `deny`, the ffi/node/php/python crates inherit the workspace lints,
and CI clippy runs with `-D warnings`.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #45](https://github.com/ifiokjr/monosecret/pull/45)

## [0.3.1](https://github.com/ifiokjr/monosecret/releases/tag/v0.3.1) (2026-08-28)

Grouped release for `monosecret`.

### Features

#### Sync upstream SecretSpec (v0.19.1 → upstream main)

_Packages:_ _monosecret_

Merges `cachix/secretspec` from v0.19.0 (the previous sync in #25) through upstream `main` @ `671de322` (2026-08-28), rebranded into the `crates/monosecret`, `crates/monosecret_derive`, `crates/monosecret_ffi`, and per-language `monosecret_*` SDK layout. Also records the upstream v0.19.0 merge ancestry that PR #25 lost to GitHub's squash button, so future syncs diff against the correct base.

##### New providers

- **Fly.io** (`fly://`): write-only application secrets via `flyctl`, with rename compatibility for older stores.
- **Azure App Configuration** (`aac://`): connection-string auth reusing Azure Core's HMAC, reversible discovery, HTTP-redirect rejection, and operational setup docs.
- **Cloudflare Secrets Store** (`cloudflare://`): write-only secrets in a Cloudflare account-level store.
- **Kubernetes** (`kubernetes://`): read/write/delete secrets in a cluster via JSON patch, with patch authorization enforcement, early address resolution in `check_writable`, and a reserved delimiter for namespaced coordinates.

##### New features

- **Rust-first Spec API (0.20+)**: `Spec` / `SpecBuilder` let applications declare secrets directly in Rust; `spec_edit` preserves TOML formatting through builder edits and `spec_edit`-backed `add` writes descriptions back to `monosecret.toml` with inherited-edit provenance. The typed loader supports interactive prompt-and-store and preserves TOML edits through the builder.
- **Inline specifications for all SDKs**: a versioned `call` ABI (`monosecret_call`, `INLINE_SPEC_SCHEMA_VERSION`) lets SDKs resolve strict inline-spec v1 declarations with an explicit source (`search`, `path`, or `inline`), with capability detection against older native libraries. Ported to the .NET, Go, Haskell, Node (napi), PHP, Python, Ruby, and Swift SDKs.
- **Structured caller context (0.20+)**: `CallerContext` (`--caller`, `--caller-version`, `--caller-operation`) records _what_ invoked access in audit records without ever satisfying `require_reason`; threaded through the CLI, FFI (`monosecret_call` envelope), and every SDK.
- **Shell completions**: `monosecret completions` for bash, zsh, fish, and nushell (clap_complete + clap_complete_nushell).
- **Git credential helper integration**: `git-credential-monosecret` binary plus `monosecret git` configuration command, with repository-local includes, percent-encoding-aware paths, Windows support, and quiet Unix pipe-close handling.
- **Docker credential helper integration**: `docker-credential-monosecret` binary and `monosecret docker` configuration that avoids persisting ambient profiles.
- **JSON Schema generation** (`monosecret schema`): expose generated JSON Schema for specs, with property descriptions emitted by codegen.
- **INI extraction**: `extract` with `format = "ini"` selects values from INI documents alongside JSON pointers.
- **Interactive prompt-and-store for the typed loader**: `prompt_missing` resolves declared-but-missing secrets by prompting and storing.
- **Spec builder round-trips**: TOML edits through the builder preserve comments and unknown tables.
- **`import` rework**: imports run through explicit preparation, collision-check, copy, verification, and source-cleanup phases; `--delete-source` removes values only after every destination write succeeds.

##### Fixes

- `check` / value-free resolution surfaces (`check --json`, `check --explain`, SDK report resolutions) no longer report an unprovisioned required `generate` secret as resolved; such secrets are now `missing_required` with a non-zero exit until one real `check`/`run` mints the value. Optional `generate` secrets and non-retaining providers (e.g. `null`) are unaffected.
- `run` forwards signals to the child process, and the CLI restores the default SIGPIPE disposition so `monosecret check | head` exits quietly.
- 1Password: `op inject` batch recovery when referenced items are missing, fail-fast on auth errors, scoped auth diagnostic matching, and per-secret fallback preservation for unrecoverable batch failures.
- Infisical: separate Universal Auth login connection, shared metadata-only environment probes, ref environment resolved from the profile, path defaults in entry identity.
- GCSM: collision-safe `monosecret2--{project}--{profile}--{key}` convention names with legacy fallback.
- BWS: use the vault host as the default server URL.
- Bitwarden: preserve convention discovery and migration refs when project/profile contain `/`; case-insensitive convention recognition on `init --from bw://`.
- AWSSM: provider path boundary joining and IAM docs now grant `BatchGetSecretValue` on `*`.
- dotenv parsing switched from dotenvy to **dotenv-ng**: `$`-containing values stay literal, bcrypt-style strings round-trip, hyphens/unicode keys accepted, and output uses minimal quoting.
- AWS SSM / Scaleway: a JSON `null` field is treated as no value with shared rendering; SDK `close()` attempts every `as_path` file.
- Age provider supports deleting entries (0.20+).
- `set`/`check` preview the resolved write destination; `check` writes its report to stdout.
- Infisical: ambiguous-404 environment probes shared across reads, resolved environments compared structurally.
- BWS: default server URL from the vault host.
- GCSM legacy migration reads fixed; convention names collision-safe.

##### SDK & tooling

- All SDKs (Dart, Go, Haskell, Node, PHP, Python, Ruby, Swift, .NET) gain caller context, inline-spec `call` support, and the AWS-state release / `close()` fixes; the Node addon and CLI also learn musl target handling, and SDK CI builds every Rust-backed native package in one cargo invocation.
- The derive crate now generates code through the shared codegen IR with `__private` re-exports and supports `prompt_missing` interactive store on first access.
- FFI gains `monosecret_call` (versioned native operations incl. inline spec sources) plus its C header contract and cinstall updates.

##### Documentation & skill

- New provider guides (Fly.io, Azure App Configuration, Cloudflare, Kubernetes), git/docker integration guides, the dotenv-ng fork and moving-secrets blog posts, KDBX manual setup, GCSM versioned naming, Infisical environment probing, split AWS IAM policy examples, and the 0.20 CLI/caller-context reference updates.
- The `@monosecret/skill` agent skill now documents the 0.20 command surface (completions, integrations, import preflight, typed SDKs, declarative features).

##### Deferred

- Upstream's JVM SDK (`secretspec-jvm`) is **not** ported in this sync; the fork's per-language SDK set is unchanged. A follow-up will port it as a `jvm/` workspace SDK with its own CI.
- Upstream's cargo-dist/WinGet/ARM64 release workflows stay out of scope — the fork keeps its monochange-based publishing.

### Fixes

#### Restore op+token:// scheme and batch shared-item reads

_Packages:_ _monosecret_

Restore the legacy `op+token://<account>/<basePath>` provider scheme and route its field references through the batched `op inject` path. Secrets that live as sections of one shared 1Password item are now fetched in a single `op inject` call (plus one auth preflight) instead of one `op read` per secret, cutting `monosecret run` / `msload` secret-loading time by roughly an order of magnitude. The `onepassword+token://` scheme keeps its current behavior; `op+token://` is restored for backward compatibility and still requires the token as a provider credential or OP_SERVICE_ACCOUNT_TOKEN.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #40](https://github.com/ifiokjr/monosecret/pull/40)

## [0.3.0](https://github.com/ifiokjr/monosecret/releases/tag/v0.3.0) (2026-08-15)

Grouped release for `monosecret`.

### Breaking

#### Sync upstream SecretSpec through v0.19.0

_Packages:_ _monosecret_

Merge `cachix/secretspec` v0.15.0 through v0.19.0 and rebrand into the
`crates/monosecret`, `crates/monosecret_derive`, and per-language
`monosecret_*` SDK layout.

##### What breaks

- Provider URIs may no longer carry credentials (`scheme://user:secret@host`
  is rejected) and `onepassword+token://` no longer accepts the service
  account token in its userinfo. Supply credentials through provider
  credentials (`monosecret config provider login <alias>`, or
  `credentials = { ... }` on the provider) instead.
- Native secret `ref` coordinates replace provider-specific addressing for
  externally managed secrets; provider implementations must migrate to the
  address-oriented `Provider` trait APIs.

##### What's new

- Native secret references (`ref`) with provider-independent coordinates,
  `resolve_named` / `with_default_reason` Rust SDK APIs, `prompt = true`
  hidden-value prompting, `set`/`check` preview, profile opt-out of
  `[profiles.default]` inheritance.
- New providers: passbolt, null, file, age, akv, awsps, dashlane, gopass,
  infisical, kdbx, keeper, openbao, scaleway, systemd_credential.
- SOPS provider (directory + single-file, multiple formats).
- Cached provider aliases, provider credential declarations, base64/urlsafe
  /hex value decoders, RFC 6901 JSON pointer selection, composition,
  manifest scopes.
- PHP, C#/.NET, and Swift language SDKs (rebranded under `monosecret_*`).
- FFI static-link contract, `cinstall` header, `schema`/`check --json`,
  non-UTF-8 env handling.

##### Preserved fork-only behavior

- `monosecret env` / `load-env` shell command and `monosecret audit` CLI.
- Dart typed SDK generator (`monosecret_builder`), `@monosecret/client`
  TypeScript client, `@monosecret/cli` npm packages.
- `monochange` release workflows and `SECRETSPEC_*` legacy env-var aliases.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #25](https://github.com/ifiokjr/monosecret/pull/25)

## [0.2.1](https://github.com/ifiokjr/monosecret/releases/tag/v0.2.1) (2026-08-14)

Grouped release for `monosecret`.

### Fixes

#### Remove stale proc-macro-error2 crates-io git patch

_Packages:_ _monosecret_

The .cargo/config.toml [patch.crates-io] section pointed at a git fork of proc-macro-error2 that nothing in the dependency graph uses (the Cargo.lock entries are [[patch.unused]]). cargo still tries to fetch the git source during resolution, which breaks offline vendored builds (e.g. nixpkgs' buildRustPackage). Removing the patch and pruning the stale lockfile entries fixes the offline build.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #33](https://github.com/ifiokjr/monosecret/pull/33)

## [0.2.0](https://github.com/ifiokjr/monosecret/releases/tag/v0.2.0) (2026-08-13)

Grouped release for `monosecret`.

### Breaking

#### Integrate native references and language SDKs

_Packages:_ _monosecret_

Add provider-independent table-form `ref` coordinates, address-based provider
resolution, batch reads, writable checks, and value-free resolution reports.
Provider implementations must migrate to the new address-oriented APIs.

Integrate the shared native resolver source, local build paths, and tests for
`monosecret_ffi`, Dart, `@monosecret/client`, Python, Go, Ruby, and Haskell
bindings. The Dart package now resolves through `dart:ffi` without a separately
installed CLI, and release builds publish verified C ABI assets for Linux,
macOS, and Windows servers. Registry distribution for the other new native SDK
artifacts remains deferred.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #24](https://github.com/ifiokjr/monosecret/pull/24) · _Related issues:_ [#23](https://github.com/ifiokjr/monosecret/issues/23), [#27](https://github.com/ifiokjr/monosecret/issues/27), [#28](https://github.com/ifiokjr/monosecret/issues/28)

#### Move the Dart builder package entrypoint

_Packages:_ _dart:monosecret_builder_

Expose the builder factory from `package:monosecret_builder/monosecret_builder.dart`, update `build.yaml` to use that package-named library, and remove the previous `package:monosecret_builder/builder.dart` entrypoint. Consumers importing the builder directly should update to the new package-named library.

_Owner:_ Ifiok Jr. · _Review:_ [PR #29](https://github.com/ifiokjr/monosecret/pull/29) · _Related issues:_ [#23](https://github.com/ifiokjr/monosecret/issues/23), [#27](https://github.com/ifiokjr/monosecret/issues/27), [#28](https://github.com/ifiokjr/monosecret/issues/28)

### Documentation

#### Fix the `depends_on` docs example and validate docs snippets

_Packages:_ _rust:monosecret_

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

_Packages:_ _rust:monosecret_

Point historical issue references to the original `cachix/secretspec` repository, restore the original SecretSpec announcement and devenv integration URLs, and replace the unavailable custom installer with the published `@monosecret/cli` npm package.

_Owner:_ Ifiok Jr. · _Review:_ [PR #29](https://github.com/ifiokjr/monosecret/pull/29) · _Related issues:_ [#23](https://github.com/ifiokjr/monosecret/issues/23), [#27](https://github.com/ifiokjr/monosecret/issues/27), [#28](https://github.com/ifiokjr/monosecret/issues/28)

## [0.1.0](https://github.com/ifiokjr/monosecret/releases/tag/v0.1.0) (2026-07-05)

Grouped release for `monosecret`.

### Breaking

#### Rebrand secretspec as monosecret

_Packages:_ _monosecret_

Rename crates, CLI, npm packages, and Dart SDK to monosecret while preserving compatibility fallbacks.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #2](https://github.com/ifiokjr/monosecret/pull/2)

#### Add the initial TypeScript client package for invoking Monosecret from Node.js applications.

_Packages:_ _@monosecret/client_

```ts
import { MonosecretClient } from "@monosecret/client";

const monosecret = new MonosecretClient();
const databaseUrl = await monosecret.get("DATABASE_URL", {
  profile: "development",
});

const environment = await monosecret.loadEnvironment({
  include: ["DATABASE_URL", "API_KEY"],
});
```

_Owner:_ Ifiok Jr. · _Introduced in:_ [`36f1fec`](https://github.com/ifiokjr/monosecret/commit/36f1fecd84f3666edbc1aafcc4825049a72e951b)

- **dart:monosecret_builder**: Add a secret-value-free manifest command for SDK code generation, introduce a build_runner-based Dart typed SDK generator, reorganize source by ecosystem into `crates/`, `npm/`, and `dart/`, and wire Rust, Dart, and npm coverage reports with package-level Codecov flags.

### Features

- **rust:monosecret**: Port upstream audit log support

#### `monosecret env`: load secrets into any shell

_Packages:_ _rust:monosecret_

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
  _Packages:_ _rust:monosecret_, _dart_

#### Sync upstream secretspec 0.12.2 support

_Packages:_ _rust:monosecret_

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

#### Fix release PR formatting and CI packaging failures so auto-generated release

_Packages:_ _monosecret_

PRs always pass checks. Run `fix:format` before committing in the release PR
workflow, use `dart pub publish --dry-run --skip-validation` in CI to avoid
server-side validation errors, and call `build:dist` directly in the publish
workflow instead of nesting devenv shells.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #11](https://github.com/ifiokjr/monosecret/pull/11)

- **monosecret**: Port upstream secret-access reason policy into Monosecret, including CLI/SDK reason handling, config enforcement, and Proton Pass audit reason forwarding.
- **rust:monosecret**: Update Monosecret documentation and CLI website links to the GitHub Pages site.

### Other

- Add a secret-value-free manifest command for SDK code generation, introduce a build_runner-based Dart typed SDK generator, reorganize source by ecosystem into `crates/`, `npm/`, and `dart/`, and wire Rust, Dart, and npm coverage reports with package-level Codecov flags.
  _Packages:_ _rust:monosecret_derive_, _@monosecret/cli_, _@monosecret/client_, _@monosecret/skill_, _@monosecret/cli-darwin-arm64_, _@monosecret/cli-darwin-x64_, _@monosecret/cli-linux-arm64-gnu_, _@monosecret/cli-linux-arm64-musl_, _@monosecret/cli-linux-x64-gnu_, _@monosecret/cli-linux-x64-musl_, _@monosecret/cli-win32-arm64-msvc_, _@monosecret/cli-win32-x64-msvc_

## [Unreleased]

### Added

- Synced upstream SecretSpec v0.15-v0.19 functionality into Monosecret. New
  providers cover Gopass, Azure Key Vault, Infisical, SOPS, Scaleway Secret
  Manager, age, systemd credentials, KeePass KDBX, OpenBao, Bitwarden Password
  Manager, Dashlane, Keeper Secrets Manager, AWS Systems Manager Parameter Store,
  Passbolt, and the `file` and `null` providers. Core resolution now supports
  provider-sourced credentials, ordered fallbacks with ownership-aware expiring
  caches, provider-scoped references and templates, composed and scoped secrets,
  required groups, prompting, JSON extraction, value encoding, profile inheritance
  opt-out, safe single-secret reads, and rejection and redaction of credentials in
  provider URIs. The Monosecret CLI adds `export`, `add`, `delete`, `cache clear`,
  provider-login and global-config workflows, broader `init --from` discovery,
  safer `import --delete-source`, and `set`/interactive `check` write-destination
  previews. C#, PHP, and Swift SDKs join updated Rust and cross-language SDK/FFI
  APIs; code-generation and resolution-report schemas now cover scopes,
  provenance, single-secret resolution, path-backed and encoded values, precise
  nullability and requiredness, and inherited profiles.
- `--reason` CLI flag (and `MONOSECRET_REASON` env var) records a human-readable
  reason for a session's secret access, forwarded to providers that support audit
  logging. `MONOSECRET_REASON` is honored across the SDK/library too: it is resolved
  by `Secrets::load`/`load_from` (so `monosecret_derive`-generated code and other
  library callers can satisfy the `require_reason` policy and supply an audit reason
  without code changes), and `Secrets::with_reason(...)` sets it explicitly, taking
  precedence. Blank or whitespace-only reasons are ignored so they cannot satisfy the
  policy. Backed by a new `Provider::set_reason` trait method (default no-op).
- The `pass` provider accepts a `store_dir` query parameter (e.g.
  `pass://?store_dir=/path/to/store`) to use a password store directory other
  than the default `~/.password-store`. It is applied as `PASSWORD_STORE_DIR`
  scoped to each `pass` invocation.
- `monosecret env` (alias `load-env`) loads resolved secrets into the surrounding
  shell or a CI environment with one command. `--shell` selects the output format —
  `bash`/`sh`/`zsh`, `fish`, `powershell`/`pwsh`, `nushell`/`nu`, `github`
  (appends `KEY<<DELIM` heredoc blocks to `$GITHUB_ENV` and masks values),
  `gitlab`/`dotenv` (portable `KEY="value"`). Apply the output with
  `eval "$(monosecret env --shell bash)"`, `monosecret env --shell fish | source`,
  `monosecret env --shell powershell | iex`, or write to a file with `--output`.
  Values are escaped per the target's rules; reuses the same resolution path and
  `require_reason` policy as `monosecret run`.
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

- Provider URIs now correctly round-trip query parameters whose values contain
  characters that are significant in a query string (`&`, `+`, `#`, `%`, and
  spaces). Previously such characters in the `awssm` `prefix` (and the new `pass`
  `store_dir`) were emitted unescaped, so the value could be silently truncated
  or altered when the URI was parsed back.
- Cargo workspace metadata now keeps `monosecret_derive` on the workspace `monosecret`
  dependency with default features disabled during package validation.
- Proton Pass provider now works with `pass-cli` >= 2.1.0 agent sessions. Since
  2.1.0, audited item operations (`item view`, `item create`, `item delete`)
  fail unless `PROTON_PASS_AGENT_REASON` is set, which made existing secrets
  appear missing under an agent session. The provider now sets this variable on
  every `pass-cli` invocation. The reason is resolved as `--reason`/`with_reason`,
  then `PROTON_PASS_AGENT_REASON`, then a Monosecret-versioned default
  (`monosecret/<version> (https://ifiokjr.github.io/monosecret)`); each source is normalized first,
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

### Fixed

- `monosecret import <FROM>` now accepts a provider alias (from `[providers]` or
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
  directory containing `monosecret.toml` instead of the current working
  directory. Running `monosecret run --file ../monosecret.toml` from a
  subdirectory previously failed to find the referenced `.env` file because it
  was looked up relative to the working directory rather than the project root
  (#59). Absolute `dotenv` paths are unaffected.
- The `protonpass` provider now works with Proton Pass CLI `pass-cli >= 2.0.3`.
  The `item list --output json` payload changed shape in 2.0.3 (the item title
  moved from a nested `content.title` to a top-level `title`, and `content` was
  dropped from list output), which made `monosecret` report active secrets as
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
  table in `~/.config/monosecret/config.toml` (not the project's
  `monosecret.toml`), so a cloned repository cannot redirect or silence it. The
  new `monosecret audit` command reads the log, with `--project`, `--action`,
  `--tail`/`-n`, and `--json` filters. See
  [Audit Logging](https://ifiokjr.github.io/monosecret/concepts/audit/) for details.
- `--reason` CLI flag (and `SECRETSPEC_REASON` env var) records a human-readable
  reason for a session's secret access, forwarded to providers that support audit
  logging. `SECRETSPEC_REASON` is honored across the SDK/library too: it is resolved
  by `Secrets::load`/`load_from` (so `monosecret-derive`-generated code and other
  library callers can satisfy the `require_reason` policy and supply an audit reason
  without code changes), and `Secrets::with_reason(...)` sets it explicitly, taking
  precedence. The `monosecret-derive`-generated typed builder also gains a
  `with_reason(...)` method, so SDK callers can satisfy `require_reason` in code
  (not only via the env var). Blank or whitespace-only reasons are ignored so they
  cannot satisfy the policy. Backed by a new `Provider::set_reason` trait method
  (default no-op).
- `[project] require_reason` policy in `monosecret.toml`, controlling when secret
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
  then `PROTON_PASS_AGENT_REASON`, then a monosecret-versioned default
  (`monosecret/<version> (https://ifiokjr.github.io/monosecret)`); each source is normalized first,
  so a blank reason falls through to the next rather than masking it. It is ignored by
  older releases and non-agent sessions.
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
  [#79](https://github.com/cachix/secretspec/issues/79).

## [0.11.0] - 2026-05-22

### Added

- AWS Secrets Manager (`awssm`) provider: support for a `?prefix=` query
  parameter in the provider URI (e.g., `awssm://us-east-1?prefix=myteam`).
  The prefix is prepended to all secret names
  (`myteam/monosecret/{project}/{profile}/{key}`). Closes
  [#92](https://github.com/cachix/secretspec/issues/92).
- Provider aliases can now be declared at the project level in a top-level
  `[providers]` table of `monosecret.toml`. Aliases declared there are visible
  to per-secret `providers = [...]` lists and to `--provider`/`MONOSECRET_PROVIDER`,
  and are merged with the existing user-level `[defaults.providers]` map in
  `~/.config/monosecret/config.toml`. On name conflicts the project entry wins,
  so a team's checked-in mapping cannot be silently shadowed by a stale local
  config. Closes [#79](https://github.com/cachix/secretspec/issues/79) and
  addresses the "share aliases via VCS" half of
  [#90](https://github.com/cachix/secretspec/issues/90).

### Fixed

- Profile-not-found errors no longer surface as the confusing
  `Secret 'Profile 'X' not found' not found`. They now use the dedicated
  `InvalidProfile` variant and include the list of profiles defined in
  `monosecret.toml`, e.g.
  `Invalid profile: 'production' is not defined in monosecret.toml. Available profiles: default, dev`.
  Affects `check`, `run`, `get`, `set`, and `import`. Surfaced via
  [#79](https://github.com/cachix/secretspec/issues/79).

## [0.10.1] - 2026-05-11

### Fixed

- `monosecret check`: optional secrets that aren't set no longer render with a
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
  `MONOSECRET_PROVIDER` environment variable. Previously the env var was
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
- `monosecret run` now removes the temporary files it creates for
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
- `--provider` (and `MONOSECRET_PROVIDER`) is now honored on every command
  even when a `providers = [...]` chain is configured for the secret or
  profile. Previously `set`, `get`, `check`, `import`, and `run` silently
  used the first provider in the chain and ignored the explicit override,
  making `monosecret set --provider <alias>` a no-op against the requested
  target. The flag now consistently takes precedence: `set`/`import`/
  generation write only to the chosen provider, and `get`/`validate` read
  only from it (no chain fallback). Provider aliases declared in
  `~/.config/monosecret/config.toml` can now be passed directly to
  `--provider`. Fixes [#81](https://github.com/cachix/secretspec/issues/81).

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
