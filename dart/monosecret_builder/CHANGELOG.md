# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0](https://github.com/ifiokjr/monosecret/releases/tag/v0.2.0) (2026-08-12)

### Breaking

#### Move the Dart builder package entrypoint

Expose the builder factory from `package:monosecret_builder/monosecret_builder.dart`, update `build.yaml` to use that package-named library, and remove the previous `package:monosecret_builder/builder.dart` entrypoint. Consumers importing the builder directly should update to the new package-named library.

_Owner:_ Ifiok Jr. · _Introduced in:_ [`5191c5a`](https://github.com/ifiokjr/monosecret/commit/5191c5a65f9beaa9b746637cc99e9bd5e0248f2e)

## [0.1.0](https://github.com/ifiokjr/monosecret/releases/tag/v0.1.0) (2026-07-05)

### Breaking

- Add a secret-value-free manifest command for SDK code generation, introduce a build_runner-based Dart typed SDK generator, reorganize source by ecosystem into `crates/`, `npm/`, and `dart/`, and wire Rust, Dart, and npm coverage reports with package-level Codecov flags.
