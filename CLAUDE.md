# CLAUDE.md

When commiting changes, make sure to update /CHANGELOG.md with one entry (can be multi-line)

## Project Overview

SecretSpec is a declarative secrets manager for development workflows written in Rust. It provides a CLI tool and Rust library for managing environment variables and secrets across different environments using multiple storage backends (keyring, dotenv, environment variables, OnePassword, LastPass).

## Build and Development Commands

```bash
# Enter development environment
devenv shell

# Run tests
cargo test --all

# Run a single test
cargo test test_name

# Run the CLI
cargo run -- <command>
cargo run -- init --from .env
cargo run -- check
cargo run -- set DATABASE_URL
cargo run -- run -- npm start

# Format code / Run linter
pre-commit run -a
```

## Architecture

The project is organized as a Rust workspace with two crates:

1. **secretspec** (src/): Main CLI and library
   - `bin/secretspec.rs`: CLI entry point that calls the main CLI module
   - `cli/mod.rs`: CLI command definitions (init, config, set/get, check, run, import)
   - `lib.rs`: Core library with `Secrets` struct, validation logic, and CRUD operations
   - `config.rs`: Core configuration types (Config, Secret), TOML parsing, and inheritance logic
   - `provider/`: Storage backend implementations with trait-based plugin architecture

2. **secretspec-derive**: Proc macro for type-safe code generation
   - Reads `secretspec.toml` at compile time
   - Generates strongly-typed structs from configuration
   - Supports both union types (safe for any profile) and profile-specific types
   - Validates secret names produce valid Rust identifiers

## Provider System

The provider system uses a trait-based architecture defined in `src/provider/mod.rs`. When implementing new providers:

1. Create module in `src/provider/your_provider.rs`
2. Implement the `Provider` trait with methods: `get()`, `set()`, `allows_set()`, `name()`, `description()`
3. Use the `#[provider]` macro for automatic registration
4. Handle profile-aware storage paths (e.g., `secretspec/{project}/{profile}/{key}`)

Providers support URI-based configuration (e.g., `keyring://`, `onepassword://vault`, `dotenv://.env.production`). The provider system handles URI parsing and provider instantiation directly within each provider module.

### Adding Provider Documentation

When adding a new provider, update these docs files:

1. `docs/src/content/docs/providers/<provider>.md` - Create the provider's doc page
2. `docs/astro.config.mjs` - Add to sidebar navigation under "Providers"
3. `docs/src/content/docs/concepts/providers.md` - Add to "Available Providers" table
4. `docs/src/content/docs/reference/providers.md` - Add provider section and update "Security Considerations" table

## Configuration System

### Profile Resolution
1. CLI flag (`--profile`)
2. Environment variable (`SECRETSPEC_PROFILE`)
3. User config default
4. Falls back to "default" profile

### Provider Resolution
1. **Per-secret providers** (with fallback chain): specified in `secretspec.toml` as `providers: [alias1, alias2, ...]`
   - Aliases resolved against `~/.config/secretspec/config.toml` providers map
   - Tries each provider in order until secret is found
2. CLI flag (`--provider`)
3. Environment variable (`SECRETSPEC_PROVIDER`)
4. User config default provider
5. Falls back to keyring provider

### Per-Secret Provider Configuration
Secrets can specify their own providers using the `providers` field to override global defaults:

```toml
[profiles.production]
DATABASE_URL = { description = "Production DB", providers = ["prod_vault", "keyring"] }
API_KEY = { description = "API Key", providers = ["shared"] }
GITHUB_TOKEN = { description = "GitHub token from env", providers = ["env"] }
```

Provider aliases are defined in `~/.config/secretspec/config.toml`:
```toml
[defaults]
provider = "keyring"

[providers]
prod_vault = "onepassword://vault/Production"
shared = "onepassword://vault/Shared"
env = "env://"
```

Or managed via CLI:
```bash
# Add provider alias
secretspec config provider add prod_vault "onepassword://vault/Production"

# List all aliases
secretspec config provider list

# Remove alias
secretspec config provider remove prod_vault
```

### Secret Resolution
1. Check active profile for secret
2. Fall back to "default" profile
3. Apply defaults if configured
4. Validate required secrets are present

### Config Inheritance
Projects can extend other configurations via `extends = ["../shared/common"]`. The system loads configs recursively and merges them with proper precedence.

## Testing

- Unit tests are located alongside the code
- Integration tests in `secretspec-derive/tests/` and `tests/integration/`
- UI tests using `trybuild` for macro error testing
- Run specific test: `cargo test test_name`
- Test CI runs on Ubuntu and macOS using devenv

### Provider Integration Tests

Provider tests are located in `secretspec/src/provider/tests.rs` and test all provider implementations generically.

```bash
# Run provider tests
cargo test --package secretspec provider::tests

# Test specific providers using SECRETSPEC_TEST_PROVIDERS env var
SECRETSPEC_TEST_PROVIDERS=keyring,dotenv cargo test --package secretspec provider::tests::integration_tests

# Run with output visible
SECRETSPEC_TEST_PROVIDERS=dotenv cargo test --package secretspec provider::tests -- --nocapture
```

The integration tests cover:
- Basic get/set operations
- Multiple secrets handling
- Special characters and Unicode
- Profile-specific storage
- Error handling for edge cases

Note: Some providers (like `env`) are read-only and will skip write tests.

## Key Files

- `secretspec.toml`: Project secrets configuration
- `secretspec/src/provider/mod.rs`: Provider trait definition and documentation
- `secretspec/src/cli/mod.rs`: CLI command definitions
- `secretspec/src/bin/secretspec.rs`: CLI entry point
- `secretspec/src/lib.rs`: Core SecretSpec implementation
- `secretspec-derive/src/lib.rs`: Code generation macro implementation
- `secretspec/src/provider/tests.rs`: Generic provider test suite
