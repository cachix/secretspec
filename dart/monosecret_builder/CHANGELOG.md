# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1](https://github.com/ifiokjr/monosecret/releases/tag/v0.2.1) (2026-08-14)

### Changed

- No package-specific changes were recorded; `monosecret_builder` was updated to 0.2.1 as part of group `monosecret`.

## [0.2.0](https://github.com/ifiokjr/monosecret/releases/tag/v0.2.0) (2026-08-13)

### Breaking

#### Move the Dart builder package entrypoint

Expose the builder factory from `package:monosecret_builder/monosecret_builder.dart`, update `build.yaml` to use that package-named library, and remove the previous `package:monosecret_builder/builder.dart` entrypoint. Consumers importing the builder directly should update to the new package-named library.

_Owner:_ Ifiok Jr. · _Review:_ [PR #29](https://github.com/ifiokjr/monosecret/pull/29) · _Related issues:_ [#23](https://github.com/ifiokjr/monosecret/issues/23), [#27](https://github.com/ifiokjr/monosecret/issues/27), [#28](https://github.com/ifiokjr/monosecret/issues/28)

## [0.1.0](https://github.com/ifiokjr/monosecret/releases/tag/v0.1.0) (2026-07-05)

### Breaking

- Add a secret-value-free manifest command for SDK code generation, introduce a build_runner-based Dart typed SDK generator, reorganize source by ecosystem into `crates/`, `npm/`, and `dart/`, and wire Rust, Dart, and npm coverage reports with package-level Codecov flags.
