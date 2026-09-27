# Changelog

## [0.4.0](https://github.com/ifiokjr/monosecret/releases/tag/v0.4.0) (2026-09-26)

### Changed

#### No package-specific changes were recorded; `monosecret` was updated to 0.4.0 as part of group `monosecret`.

## [0.3.5](https://github.com/ifiokjr/monosecret/releases/tag/v0.3.5) (2026-09-12)

### Fixes

#### Record the downloaded FFI payload as a hook build dependency

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

### Changed

- No package-specific changes were recorded; `monosecret` was updated to 0.3.4 as part of group `monosecret`.

## [0.3.3](https://github.com/ifiokjr/monosecret/releases/tag/v0.3.3) (2026-09-08)

### Changed

- No package-specific changes were recorded; `monosecret` was updated to 0.3.3 as part of group `monosecret`.

## [0.3.2](https://github.com/ifiokjr/monosecret/releases/tag/v0.3.2) (2026-09-05)

### Features

#### Dart SDK: inline specs and caller context via the versioned call ABI

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

`cargo update`, `pnpm update --latest` (vitest 4 → 5, tsdown 0.22 → 0.23,
oxfmt 0.63 → 0.66, oxlint 1.78 → 1.81), `dart pub upgrade`, and
`devenv update` (devenv CLI, git-hooks.nix, custom nixpkgs inputs).

`keepass` is pinned to `=0.13.17`: the 0.13.25 release depends on a
cipher/cbc combination that `aes` 0.8 does not implement, which broke the
kdbx provider's build.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #49](https://github.com/ifiokjr/monosecret/pull/49)

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

### Changed

- No package-specific changes were recorded; `monosecret` was updated to 0.2.0 as part of group `monosecret`.

## [0.1.0](https://github.com/ifiokjr/monosecret/releases/tag/v0.1.0) (2026-07-05)

### Breaking

#### Rebrand monosecret as monosecret

Rename crates, CLI, npm packages, and Dart SDK to monosecret while preserving compatibility fallbacks.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #2](https://github.com/ifiokjr/monosecret/pull/2)

### Features

- Add a secret-value-free manifest command for SDK code generation, introduce a build_runner-based Dart typed SDK generator, reorganize source by ecosystem into `crates/`, `npm/`, and `dart/`, and wire Rust, Dart, and npm coverage reports with package-level Codecov flags.

## 0.0.0

- Initial Dart SDK package.
