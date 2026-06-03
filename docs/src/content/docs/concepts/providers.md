---
title: Providers
description: Understanding secret storage providers in Monosecret
---

Providers are pluggable storage backends that handle the storage and retrieval of secrets. They allow the same `monosecret.toml` to work across development machines, CI/CD pipelines, and production environments.

## Available Providers

| Provider        | Description                                                                                  | Read | Write | Encrypted |
| --------------- | -------------------------------------------------------------------------------------------- | ---- | ----- | --------- |
| **keyring**     | System credential storage (macOS Keychain, Windows Credential Manager, Linux Secret Service) | ✓    | ✓     | ✓         |
| **dotenv**      | Traditional `.env` file in your project directory                                            | ✓    | ✓     | ✗         |
| **env**         | Read-only access to existing environment variables                                           | ✓    | ✗     | ✗         |
| **pass**        | Unix password manager with GPG encryption                                                    | ✓    | ✓     | ✓         |
| **protonpass**  | Integration with Proton password manager                                                     | ✓    | ✓     | ✓         |
| **onepassword** | Integration with OnePassword password manager                                                | ✓    | ✓     | ✓         |
| **lastpass**    | Integration with LastPass password manager                                                   | ✓    | ✓     | ✓         |
| **gcsm**        | Google Cloud Secret Manager (requires `--features gcsm`)                                     | ✓    | ✓     | ✓         |
| **awssm**       | AWS Secrets Manager (requires `--features awssm`)                                            | ✓    | ✓     | ✓         |
| **vault**       | HashiCorp Vault / OpenBao (requires `--features vault`)                                      | ✓    | ✓     | ✓         |
| **bws**         | Bitwarden Secrets Manager (requires `--features bws`)                                        | ✓    | ✓     | ✓         |

## Provider Selection

Monosecret determines which provider to use in this order:

1. **Per-secret providers**: `providers` field in `monosecret.toml` (highest priority, with fallback chain)
2. **CLI flag**: `monosecret --provider` flag
3. **Environment**: `MONOSECRET_PROVIDER`
4. **Global default**: Default provider in user config set via `monosecret config init`

## Configuration

Set your default provider:

```bash
$ monosecret config init
```

Override for specific commands:

```bash
# Use dotenv for this command
$ monosecret run --provider dotenv -- npm start

# Set for shell session
$ export MONOSECRET_PROVIDER=env
$ monosecret check
```

Configure providers with URIs:

```toml
# ~/.config/monosecret/config.toml
[defaults]
provider = "keyring"
profile = "development" # optional default profile
```

You can use provider URIs for more specific configuration:

```bash
# Use a specific OnePassword vault
$ monosecret run --provider "onepassword://Personal/Development" -- npm start
# Native 1Password references are opt-in with op://
$ monosecret run --provider "op://Development/dotfiles" -- npm start

# Use a specific dotenv file
$ monosecret run --provider "dotenv:/home/user/work/.env" -- npm test
```

## Per-Secret Provider Configuration

For fine-grained control, you can specify different providers for individual secrets using the `providers` field in `monosecret.toml`. This enables fallback chains where secrets are retrieved from multiple providers in order of preference:

```toml
[profiles.production]
DATABASE_URL = { description = "Production DB", providers = ["prod_vault", "keyring"] }
API_KEY = { description = "API key from env", providers = ["env"] }
SENTRY_DSN = { description = "Error tracking", providers = ["shared_vault", "keyring"] }
```

### Profile-Level Default Providers

You can also set default providers for an entire profile using `profiles.<name>.defaults`. See [Profile-Level Defaults](/concepts/profiles/#profile-level-defaults) for details.

Provider aliases can be defined in two places:

- **Project-level** — a top-level `[providers]` table in `monosecret.toml`. Check this into version control so the whole team and CI runners share the same mapping.
- **User-level** — a `[defaults.providers]` table in `~/.config/monosecret/config.toml` for personal overrides.

On name conflicts the project-level alias wins, so a stale user config cannot silently shadow the team's mapping.

```toml title="monosecret.toml"
[providers]
prod_vault = "onepassword://vault/Production"
shared_vault = "onepassword://vault/Shared"
keyring = "keyring://"
env = "env://"
```

```toml title="~/.config/monosecret/config.toml"
[defaults]
provider = "keyring"

[defaults.providers]
prod_vault = "onepassword://vault/Production"
shared_vault = "onepassword://vault/Shared"
keyring = "keyring://"
env = "env://"
```

### Fallback Chains

When a monosecretifies multiple providers, Monosecret tries each provider in order until it finds the secret:

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

Use CLI commands to manage user-level provider aliases in `~/.config/monosecret/config.toml`:

```bash
# Add a provider alias
$ monosecret config provider add prod_vault "onepassword://vault/Production"

# List all aliases
$ monosecret config provider list

# Remove an alias
$ monosecret config provider remove prod_vault
```

These commands operate on the user-level config only. To change project-level aliases, edit the `[providers]` table in `monosecret.toml` directly.

## Next Steps

- Browse individual provider docs in the [Providers](/providers/keyring/) section
- Learn how [Profiles](/concepts/profiles/) control per-environment behavior
- Share secret definitions across projects with [Configuration Inheritance](/concepts/inheritance/)
