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
| **onepassword** | Integration with OnePassword password manager | ✓ | ✓ | ✓ |
| **lastpass** | Integration with LastPass password manager | ✓ | ✓ | ✓ |

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

Provider aliases are defined in your user configuration file (`~/.config/secretspec/config.toml`):

```toml
[defaults]
provider = "keyring"

[providers]
prod_vault = "onepassword://vault/Production"
shared_vault = "onepassword://vault/Shared"
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

Use CLI commands to manage provider aliases:

```bash
# Add a provider alias
$ secretspec config provider add prod_vault "onepassword://vault/Production"

# List all aliases
$ secretspec config provider list

# Remove an alias
$ secretspec config provider remove prod_vault
```

## Next Steps

- Learn about specific providers in the [Providers](/providers/keyring/) section
- Understand how providers work with [Profiles](/concepts/profiles/)
- Explore [Configuration Inheritance](/concepts/inheritance/) for complex setups
