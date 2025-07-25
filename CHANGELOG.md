# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Integrate `secrecy` crate for secure secret handling with automatic memory zeroing
- Bitwarden provider supports Bitwarden & Bitwarden Secrets Manager via
  `bitwarden://` & `bws://` URIs with enhanced error message sanitization.
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
