# Changelog

## [0.1.0](https://github.com/ifiokjr/monosecret/releases/tag/v0.1.0) (2026-07-05)

### Breaking

#### Rebrand secretspec as monosecret

Rename crates, CLI, npm packages, and Dart SDK to monosecret while preserving compatibility fallbacks.

_Owner:_ [@ifiokjr](https://github.com/ifiokjr) · _Review:_ [PR #2](https://github.com/ifiokjr/monosecret/pull/2)

### Features

- Add a secret-value-free manifest command for SDK code generation, introduce a build_runner-based Dart typed SDK generator, reorganize source by ecosystem into `crates/`, `npm/`, and `dart/`, and wire Rust, Dart, and npm coverage reports with package-level Codecov flags.

## 0.0.0

- Initial Dart SDK package.
