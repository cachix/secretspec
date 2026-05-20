---
title: Providers
description: Understanding secret storage providers in SecretSpec
---

Providers are pluggable storage backends that handle the storage and retrieval of secrets. They allow the same `secretspec.toml` to work across development machines, CI/CD pipelines, and production environments.

## Available Providers

| Provider | Description | Read | Write | Encrypted |
|----------|-------------|------|-------|-----------|
| **keyring** | System credential storage (macOS Keychain, Windows Credential Manager, Linux Secret Service) | ✓ | ✓ | ✓ |
| **dotenv** | Traditional `.env` file in your project directory | ✓ | ✓ | ✗ |
| **env** | Read-only access to existing environment variables | ✓ | ✗ | ✗ |
| **pass** | Unix password manager with GPG encryption | ✓ | ✓ | ✓ |
| **protonpass** | Integration with Proton password manager | ✓ | ✓ | ✓ |
| **onepassword** | Integration with OnePassword password manager | ✓ | ✓ | ✓ |
| **lastpass** | Integration with LastPass password manager | ✓ | ✓ | ✓ |
| **gcsm** | Google Cloud Secret Manager (requires `--features gcsm`) | ✓ | ✓ | ✓ |
| **awssm** | AWS Secrets Manager (requires `--features awssm`) | ✓ | ✓ | ✓ |
| **vault** | HashiCorp Vault / OpenBao (requires `--features vault`) | ✓ | ✓ | ✓ |
| **bws** | Bitwarden Secrets Manager (requires `--features bws`) | ✓ | ✓ | ✓ |

## Provider Selection

SecretSpec determines which provider to use in this order:

1. **Per-secret providers**: `providers` field in `secretspec.toml` (highest priority, with fallback chain)
2. **CLI flag**: `secretspec --provider` flag
3. **Environment**: `SECRETSPEC_PROVIDER`
4. **Global default**: Default provider in user config set via `secretspec config init`

## Configuration

Set your default provider:

```bash
$ secretspec config init
```

Override for specific commands:

```bash
# Use dotenv for this command
$ secretspec run --provider dotenv -- npm start

# Set for shell session
$ export SECRETSPEC_PROVIDER=env
$ secretspec check
```

Configure providers with URIs:

```toml
# ~/.config/secretspec/config.toml
[defaults]
provider = "keyring"
profile = "development"  # optional default profile
```

You can use provider URIs for more specific configuration:

```bash
# Use a specific OnePassword vault
$ secretspec run --provider "onepassword://Personal/Development" -- npm start
# Native 1Password references are opt-in with op://
$ secretspec run --provider "op://Development/dotfiles" -- npm start

# Use a specific dotenv file
$ secretspec run --provider "dotenv:/home/user/work/.env" -- npm test
```

## Per-Secret Provider Configuration

For fine-grained control, you can specify different providers for individual secrets using the `providers` field in `secretspec.toml`. This enables fallback chains where secrets are retrieved from multiple providers in order of preference:

```toml
[profiles.production]
DATABASE_URL = { description = "Production DB", providers = ["prod_vault", "keyring"] }
API_KEY = { description = "API key from env", providers = ["env"] }
SENTRY_DSN = { description = "Error tracking", providers = ["shared_vault", "keyring"] }
```

### Profile-Level Default Providers

You can also set default providers for an entire profile using `profiles.<name>.defaults`. See [Profile-Level Defaults](/concepts/profiles/#profile-level-defaults) for details.

Provider aliases can be defined in two places:

- **Project-level** — a top-level `[providers]` table in `secretspec.toml`. Check this into version control so the whole team and CI runners share the same mapping.
- **User-level** — a `[defaults.providers]` table in `~/.config/secretspec/config.toml` for personal overrides.

On name conflicts the project-level alias wins, so a stale user config cannot silently shadow the team's mapping.

```toml title="secretspec.toml"
[providers]
prod_vault = "onepassword://vault/Production"
shared_vault = "onepassword://vault/Shared"
keyring = "keyring://"
env = "env://"
```

```toml title="~/.config/secretspec/config.toml"
[defaults]
provider = "keyring"

[defaults.providers]
prod_vault = "onepassword://vault/Production"
shared_vault = "onepassword://vault/Shared"
keyring = "keyring://"
env = "env://"
```

### Fallback Chains

When a secret specifies multiple providers, SecretSpec tries each provider in order until it finds the secret:

```toml
# Try OnePassword first, then fall back to keyring if not found
DATABASE_URL = { description = "DB", providers = ["prod_vault", "keyring"] }
```

This enables complex workflows:
- **Shared vs environment-specific**: Try a shared vault first, fall back to local keyring
- **Redundancy**: Maintain secrets in multiple locations for backup
- **Migration**: Gradually move secrets from one provider to another
- **Multi-team setups**: Different teams can manage different providers

### Managing Provider Aliases

Use CLI commands to manage user-level provider aliases in `~/.config/secretspec/config.toml`:

```bash
# Add a provider alias
$ secretspec config provider add prod_vault "onepassword://vault/Production"

# List all aliases
$ secretspec config provider list

# Remove an alias
$ secretspec config provider remove prod_vault
```

These commands operate on the user-level config only. To change project-level aliases, edit the `[providers]` table in `secretspec.toml` directly.

## Next Steps

- Browse individual provider docs in the [Providers](/providers/keyring/) section
- Learn how [Profiles](/concepts/profiles/) control per-environment behavior
- Share secret definitions across projects with [Configuration Inheritance](/concepts/inheritance/)
