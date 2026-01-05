# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
