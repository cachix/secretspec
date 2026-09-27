# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0](https://github.com/ifiokjr/monosecret/releases/tag/v0.4.0) (2026-09-26)

### Fixes

#### ejson timeout tests no longer fail on a loaded machine

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

### Fixes

#### Resolution no longer dies on SIGPIPE when a provider CLI exits without draining stdin

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

## [0.3.4](https://github.com/ifiokjr/monosecret/releases/tag/v0.3.4) (2026-09-10)

### Fixes

#### Cut 1Password service-account reads from one-per-secret to one-per-item

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

## [0.3.3](https://github.com/ifiokjr/monosecret/releases/tag/v0.3.3) (2026-09-08)

### Fixes

#### Fix keyring lookups and 1Password `depends_on` tokens broken in 0.3.2

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

### Fixes

#### Refresh cargo, pnpm, dart, and devenv dependencies

`cargo update`, `pnpm update --latest` (vitest 4 → 5, tsdown 0.22 → 0.23,
oxfmt 0.63 → 0.66, oxlint 1.78 → 1.81), `dart pub upgrade`, and
`devenv update` (devenv CLI, git-hooks.nix, custom nixpkgs inputs).

`keepass` is pinned to `=0.13.17`: the 0.13.25 release depends on a
cipher/cbc combination that `aes` 0.8 does not implement, which broke the
kdbx provider's build.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #49](https://github.com/ifiokjr/monosecret/pull/49)

#### Eliminate every clippy warning and promote lint groups to deny

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

### Changed

- No package-specific changes were recorded; `monosecret` was updated to 0.3.1 as part of group `monosecret`.

## [0.3.0](https://github.com/ifiokjr/monosecret/releases/tag/v0.3.0) (2026-08-15)

### Changed

- No package-specific changes were recorded; `monosecret` was updated to 0.3.0 as part of group `monosecret`.

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
