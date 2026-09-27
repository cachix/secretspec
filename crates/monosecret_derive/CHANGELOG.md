# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0](https://github.com/ifiokjr/monosecret/releases/tag/v0.4.0) (2026-09-26)

### Changed

#### No package-specific changes were recorded; `monosecret_derive` was updated to 0.4.0 as part of group `monosecret`.

## [0.3.5](https://github.com/ifiokjr/monosecret/releases/tag/v0.3.5) (2026-09-12)

### Changed

- **No package-specific changes were recorded; `monosecret_derive` was updated to 0.3.5 as part of group `monosecret`.**

## [0.3.4](https://github.com/ifiokjr/monosecret/releases/tag/v0.3.4) (2026-09-10)

### Changed

- No package-specific changes were recorded; `monosecret_derive` was updated to 0.3.4 as part of group `monosecret`.

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

- No package-specific changes were recorded; `monosecret_derive` was updated to 0.3.1 as part of group `monosecret`.

## [0.3.0](https://github.com/ifiokjr/monosecret/releases/tag/v0.3.0) (2026-08-15)

### Changed

- No package-specific changes were recorded; `monosecret_derive` was updated to 0.3.0 as part of group `monosecret`.

## [0.2.1](https://github.com/ifiokjr/monosecret/releases/tag/v0.2.1) (2026-08-14)

### Changed

- No package-specific changes were recorded; `monosecret_derive` was updated to 0.2.1 as part of group `monosecret`.

## [0.2.0](https://github.com/ifiokjr/monosecret/releases/tag/v0.2.0) (2026-08-13)

### Changed

- No package-specific changes were recorded; `monosecret_derive` was updated to 0.2.0 as part of group `monosecret`.

## [0.1.0](https://github.com/ifiokjr/monosecret/releases/tag/v0.1.0) (2026-07-05)

### Other

- Add a secret-value-free manifest command for SDK code generation, introduce a build_runner-based Dart typed SDK generator, reorganize source by ecosystem into `crates/`, `npm/`, and `dart/`, and wire Rust, Dart, and npm coverage reports with package-level Codecov flags.
