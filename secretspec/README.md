[![Build Status](https://img.shields.io/github/check-runs/cachix/secretspec/main)](https://github.com/cachix/secretspec/actions)
[![Crates.io](https://img.shields.io/crates/v/secretspec)](https://crates.io/crates/secretspec)
[![docs.rs](https://docs.rs/secretspec/badge.svg)](https://docs.rs/secretspec)
[![Discord channel](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fdiscord.com%2Fapi%2Finvites%2FnaMgvexb6q%3Fwith_counts%3Dtrue&query=%24.approximate_member_count&logo=discord&logoColor=white&label=Discord%20users&color=green&style=flat)](https://discord.gg/naMgvexb6q)

# SecretSpec

Declarative secrets, every environment, any provider.

SecretSpec separates the declaration of what secrets an application needs from where they are stored, enabling portable applications that work across different secret storage backends without code changes.

[Documentation](https://secretspec.dev) | [Quick Start](https://secretspec.dev/quick-start) | [Announcement Blog Post](https://devenv.sh/blog/2025/07/21/announcing-secretspec-declarative-secrets-management)

## Features

- **[Declarative Configuration](https://secretspec.dev/reference/configuration/)**: Define your secrets in `secretspec.toml` with descriptions and requirements
- **[Multiple Provider Backends](https://secretspec.dev/concepts/providers/)**: [Keyring](https://secretspec.dev/providers/keyring), [.env](https://secretspec.dev/providers/dotenv), [OnePassword](https://secretspec.dev/providers/onepassword), [LastPass](https://secretspec.dev/providers/lastpass), and [environment variables](https://secretspec.dev/providers/env)
- **[Type-Safe Rust SDK](https://secretspec.dev/sdk/rust/)**: Generate strongly-typed structs from your `secretspec.toml` for compile-time safety
- **[Profile Support](https://secretspec.dev/concepts/profiles/)**: Override secret requirements and defaults per profile (development, production, etc.)
- **Configuration Inheritance**: Extend and override shared configurations using the `extends` feature
- **Discovery**: `secretspec init` to discover secrets from existing `.env` files

## Quick Start

```shell-session
# 1. Initialize secretspec.toml (discovers secrets from .env)
$ secretspec init
✓ Created secretspec.toml with 0 secrets

Next steps:
  1. secretspec config init    # Set up user configuration
  2. secretspec check          # Verify all secrets are set
  3. secretspec run -- your-command  # Run with secrets

# 2. Set up provider backend
$ secretspec config init
? Select your preferred provider backend:
> onepassword: OnePassword password manager
  dotenv: Traditional .env files
  env: Read-only environment variables
  keyring: Uses system keychain (Recommended)
  lastpass: LastPass password manager
? Select your default profile:
> development
  default
  none
✓ Configuration saved to /home/user/.config/secretspec/config.toml

# 3. Check and configure secrets
$ secretspec check

# 4. Run your application with secrets
$ secretspec run -- npm start

# Or with a specific profile and provider
$ secretspec run --profile production --provider dotenv -- npm start
```

See the [Quick Start Guide](https://secretspec.dev/quick-start) for detailed instructions.

## Installation

```shell-session
$ curl -sSL https://install.secretspec.dev | sh
```

See the [installation guide](https://secretspec.dev/quick-start#installation) for more options including Nix and Devenv.

## Configuration

Each project has a `secretspec.toml` file that declares the required secrets:

```toml
[project]
name = "my-app"  # Inferred from current directory name when using `secretspec init`
revision = "1.0"
# Optional: extend other configuration files
extends = ["../shared/common", "../shared/auth"]

[profiles.default]
DATABASE_URL = { description = "PostgreSQL connection string", required = true }
REDIS_URL = { description = "Redis connection string", required = false, default = "redis://localhost:6379" }

# Profile-specific configurations
[profiles.development]
DATABASE_URL = { description = "PostgreSQL connection string", required = false, default = "sqlite://./dev.db" }
REDIS_URL = { description = "Redis connection string", required = false, default = "redis://localhost:6379" }

[profiles.production]
DATABASE_URL = { description = "PostgreSQL connection string", required = true }
REDIS_URL = { description = "Redis connection string", required = true }
```

See the [configuration reference](https://secretspec.dev/reference/configuration/) for all available options.

## Profiles

Profiles allow you to define different secret requirements for each environment (development, production, etc.):

```shell-session
$ secretspec run --profile development -- npm start
$ secretspec run --profile production -- npm start

# Set default profile
$ secretspec config init
```

Learn more about [profiles](https://secretspec.dev/concepts/profiles) and [profile selection](https://secretspec.dev/concepts/profiles#profile-selection).

## Providers

SecretSpec supports multiple storage backends for secrets:

- **[Keyring](https://secretspec.dev/providers/keyring)** - System credential store (recommended)
- **[.env files](https://secretspec.dev/providers/dotenv)** - Traditional dotenv files
- **[Environment variables](https://secretspec.dev/providers/env)** - Read-only for CI/CD
- **[OnePassword](https://secretspec.dev/providers/onepassword)** - Team secret management
- **[LastPass](https://secretspec.dev/providers/lastpass)** - Cloud password manager

```bash
$ secretspec run --provider keyring -- npm start
$ secretspec run --provider dotenv -- npm start

# Configure default provider
$ secretspec config init
```

See [provider concepts](https://secretspec.dev/concepts/providers) and [provider reference](https://secretspec.dev/reference/providers) for details.

## Rust SDK

Generate strongly-typed Rust structs from your `secretspec.toml`:

```rust
secretspec_derive::declare_secrets!("secretspec.toml");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load secrets with type safety
    let secrets = SecretSpec::load(Provider::Keyring)?;

    // Access secrets as struct fields
    println!("Database: {}", secrets.database_url);

    // Optional secrets are Option<String>
    if let Some(redis) = &secrets.redis_url {
        println!("Redis: {}", redis);
    }

    Ok(())
}
```

See the [Rust SDK documentation](https://secretspec.dev/sdk/rust) for advanced usage including profile-specific types.

## CLI Reference

Common commands:

```bash
# Initialize and configure
secretspec init                    # Create secretspec.toml
secretspec config init            # Set up user configuration

# Manage secrets
secretspec check                  # Verify all secrets are set
secretspec set KEY               # Set a secret interactively
secretspec get KEY               # Retrieve a secret
secretspec import PROVIDER       # Import secrets from another provider

# Run with secrets
secretspec run -- command        # Run command with secrets as env vars
```

See the [full CLI reference](https://secretspec.dev/reference/cli) for all commands and options.

## Contributing

We welcome contributions! Areas where you can help:

- **New provider backends** - See the [provider implementation guide](https://secretspec.dev/reference/adding-providers)
- **Language SDKs** - Help us support more languages beyond Rust
- **Package managers** - Get SecretSpec into your favorite package manager
- **Documentation** - Improve guides and examples

See our [GitHub repository](https://github.com/cachix/secretspec) to get started.

## License

This project is licensed under the Apache License 2.0.

<img referrerpolicy="no-referrer-when-downgrade" src="https://static.scarf.sh/a.png?x-pxid=ddbe4178-cff6-4549-9365-facbc08f3b6f" />
