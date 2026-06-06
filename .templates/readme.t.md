<!-- {@projectReadme} -->

[![Build Status](https://img.shields.io/github/check-runs/ifiokjr/monosecret/main)](https://github.com/ifiokjr/monosecret/actions)
[![Crates.io](https://img.shields.io/crates/v/monosecret)](https://crates.io/crates/monosecret)
[![docs.rs](https://docs.rs/monosecret/badge.svg)](https://docs.rs/monosecret)
[![Discord channel](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fdiscord.com%2Fapi%2Finvites%2FnaMgvexb6q%3Fwith_counts%3Dtrue&query=%24.approximate_member_count&logo=discord&logoColor=white&label=Discord%20users&color=green&style=flat)](https://discord.gg/naMgvexb6q)

# Monosecret

Stop committing secrets to git and putting them to .env files.

Secrets end up in `.env` files that get accidentally committed, shared over Slack, or copy pasted between machines. Each developer has their own version, nobody knows which secrets are actually needed, and onboarding means asking around for values.

Monosecret fixes this by separating secret **declaration** from secret **storage**. You commit a `monosecret.toml` that declares what secrets your application needs, while the actual values live in a secure provider like your system keyring, 1Password, or any other backend. No secrets in git, no `.env` files to leak.

[Documentation](https://monosecret.dev) | [Quick Start](https://monosecret.dev/quick-start) | [Announcement Blog Post](https://devenv.sh/blog/2025/07/21/announcing-monosecret-declarative-secrets-management)

## Features

- **[Declarative Configuration](https://monosecret.dev/reference/configuration/)**: Define your secrets in `monosecret.toml` with descriptions and requirements
- **[Multiple Provider Backends](https://monosecret.dev/concepts/providers/)**: [Keyring](https://monosecret.dev/providers/keyring), [.env](https://monosecret.dev/providers/dotenv), [OnePassword](https://monosecret.dev/providers/onepassword), [LastPass](https://monosecret.dev/providers/lastpass), [Pass](https://monosecret.dev/providers/pass), [Proton Pass](https://monosecret.dev/providers/protonpass), [environment variables](https://monosecret.dev/providers/env), [Google Cloud Secret Manager](https://monosecret.dev/providers/gcsm), [AWS Secrets Manager](https://monosecret.dev/providers/awssm), and [Vault/OpenBao](https://monosecret.dev/providers/vault)
- **[Type-Safe Rust SDK](https://monosecret.dev/sdk/rust/)**: Generate strongly-typed structs from your `monosecret.toml` for compile-time safety
- **[Profile Support](https://monosecret.dev/concepts/profiles/)**: Override secret requirements and defaults per profile (development, production, etc.)
- **Secret Generation**: Auto-generate passwords, tokens, UUIDs, and more when secrets are missing — declarative "generate if absent"
- **Configuration Inheritance**: Extend and override shared configurations using the `extends` feature
- **Discovery**: `monosecret init` to discover secrets from existing `.env` files

## Quick Start

```shell-session
# 1. Initialize monosecret.toml (discovers secrets from .env)
$ monosecret init
✓ Created monosecret.toml with 0 secrets

Next steps:
  1. monosecret config init    # Set up user configuration
  2. monosecret check          # Verify all secrets are set
  3. monosecret run -- your-command  # Run with secrets

# 2. Set up provider backend
$ monosecret config init
? Select your preferred provider backend:
> keyring: Uses system keychain (Recommended)
  onepassword: OnePassword password manager
  dotenv: Traditional .env files
  env: Read-only environment variables
  pass: Unix password manager with GPG encryption
  protonpass: Proton Pass via official pass-cli
  lastpass: LastPass password manager
  gcsm: Google Cloud Secret Manager
  awssm: AWS Secrets Manager
  vault: HashiCorp Vault / OpenBao secret management
  bws: Bitwarden Secrets Manager
? Select your default profile:
> development
  default
  none
✓ Configuration saved to /home/user/.config/monosecret/config.toml

# 3. Check and configure secrets
$ monosecret check

# 4. Run your application with secrets
$ monosecret run -- npm start

# Or with a specific profile and provider
$ monosecret run --profile production --provider dotenv -- npm start
```

See the [Quick Start Guide](https://monosecret.dev/quick-start) for detailed instructions.

## Installation

```shell-session
$ curl -sSL https://install.monosecret.dev | sh
```

See the [installation guide](https://monosecret.dev/quick-start#installation) for more options including Nix and Devenv.

## Configuration

Each project has a `monosecret.toml` file that declares the required secrets:

```toml
[project]
name = "my-app" # Inferred from current directory name when using `monosecret init`
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

See the [configuration reference](https://monosecret.dev/reference/configuration/) for all available options.

## Profiles

Profiles allow you to define different secret requirements for each environment (development, production, etc.):

```shell-session
$ monosecret run --profile development -- npm start
$ monosecret run --profile production -- npm start

# Set default profile
$ monosecret config init
```

Learn more about [profiles](https://monosecret.dev/concepts/profiles) and [profile selection](https://monosecret.dev/concepts/profiles#profile-selection).

## Providers

Monosecret supports multiple storage backends for secrets:

- **[Keyring](https://monosecret.dev/providers/keyring)** - System credential store (recommended)
- **[.env files](https://monosecret.dev/providers/dotenv)** - Traditional dotenv files
- **[Environment variables](https://monosecret.dev/providers/env)** - Read-only for CI/CD
- **[Pass](https://monosecret.dev/providers/pass)** - Unix password manager with GPG encryption
- **[Proton Pass](https://monosecret.dev/providers/protonpass)** - End-to-end encrypted via Proton's official pass-cli
- **[OnePassword](https://monosecret.dev/providers/onepassword)** - Team secret management; `onepassword://` keeps Monosecret-owned storage while `op://` opts into native 1Password references
- **[LastPass](https://monosecret.dev/providers/lastpass)** - Cloud password manager
- **[Google Cloud Secret Manager](https://monosecret.dev/providers/gcsm)** - GCP secret management
- **[AWS Secrets Manager](https://monosecret.dev/providers/awssm)** - AWS secret management
- **[Vault / OpenBao](https://monosecret.dev/providers/vault)** - HashiCorp Vault and OpenBao KV engine
- **[Bitwarden Secrets Manager](https://monosecret.dev/providers/bws)** - Bitwarden Secrets Manager integration

```bash
$ monosecret run --provider keyring -- npm start
$ monosecret run --provider dotenv -- npm start

# Legacy Monosecret-owned 1Password storage
$ monosecret run --provider onepassword://Development -- npm start

# Native 1Password references, e.g. op://Development/dotfiles/forges/GITHUB_TOKEN
$ monosecret run --provider op://Development/dotfiles -- npm start

# Configure default provider
$ monosecret config init
```

See [provider concepts](https://monosecret.dev/concepts/providers) and [provider reference](https://monosecret.dev/reference/providers) for details.

## Rust SDK

Generate strongly-typed Rust structs from your `monosecret.toml`:

```rust
monosecret_derive::declare_secrets!("monosecret.toml");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load secrets with type safety
    let secrets = Monosecret::load(Provider::Keyring)?;

    // Access secrets as struct fields
    println!("Database: {}", secrets.database_url);

    // Optional secrets are Option<String>
    if let Some(redis) = &secrets.redis_url {
        println!("Redis: {}", redis);
    }

    Ok(())
}
```

See the [Rust SDK documentation](https://monosecret.dev/sdk/rust) for advanced usage including profile-specific types.

## CLI Reference

Common commands:

```bash
# Initialize and configure
monosecret init                    # Create monosecret.toml
monosecret config init            # Set up user configuration

# Manage secrets
monosecret check                  # Verify all secrets are set
monosecret set KEY               # Set a secret interactively
monosecret get KEY               # Retrieve a secret
monosecret import PROVIDER       # Import secrets from another provider

# Run with secrets
monosecret run -- command        # Run command with secrets as env vars
```

See the [full CLI reference](https://monosecret.dev/reference/cli) for all commands and options.

## Contributing

We welcome contributions! Areas where you can help:

- **New provider backends** - See the [provider implementation guide](https://monosecret.dev/reference/adding-providers)
- **Language SDKs** - Help us support more languages beyond Rust
- **Package managers** - Get Monosecret into your favorite package manager
- **Documentation** - Improve guides and examples

See our [GitHub repository](https://github.com/ifiokjr/monosecret) to get started.

## License

This project is licensed under the Apache License 2.0.

<img referrerpolicy="no-referrer-when-downgrade" src="https://static.scarf.sh/a.png?x-pxid=ddbe4178-cff6-4549-9365-facbc08f3b6f" />
<!-- {/projectReadme} -->
