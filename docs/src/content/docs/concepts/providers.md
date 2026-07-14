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
| **akv** | Azure Key Vault (requires `--features akv`) | ✓ | ✓ | ✓ |

## Provider Selection

SecretSpec determines which provider to use for each secret in this order:

1. **Explicit override**: the `--provider` CLI flag or the `SECRETSPEC_PROVIDER` environment variable
2. **Per-secret providers**: `providers` field in `secretspec.toml` (with fallback chain)
3. **Profile defaults**: `providers` under `[profiles.<name>.defaults]`
4. **Global default**: Default provider in user config set via `secretspec config init`

A secret's [`ref`](/reference/configuration/#secret-references) field never
affects provider selection: it only changes what name is looked up in the store,
not which store is used. The same order above picks the store for ref secrets
and convention secrets alike.

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
$ secretspec run --provider "onepassword://Development" -- npm start

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

Chain entries are provider aliases (see below) or inline provider URIs, which
need no alias declaration:

```toml
[profiles.production]
DATABASE_URL = { description = "Production DB", providers = ["onepassword://Production", "keyring"] }
```

### Profile-Level Default Providers

You can also set default providers for an entire profile using `profiles.<name>.defaults`. See [Profile-Level Defaults](/concepts/profiles/#profile-level-defaults) for details.

Provider aliases can be defined in two places:

- **Project-level** — a top-level `[providers]` table in `secretspec.toml`. Check this into version control so the whole team and CI runners share the same mapping.
- **User-level** — a `[defaults.providers]` table in `~/.config/secretspec/config.toml` for personal overrides.

On name conflicts the project-level alias wins, so a stale user config cannot silently shadow the team's mapping.

```toml title="secretspec.toml"
[providers]
prod_vault = "onepassword://Production"
shared_vault = "onepassword://Shared"
keyring = "keyring://"
env = "env://"
```

```toml title="~/.config/secretspec/config.toml"
[defaults]
provider = "keyring"

[defaults.providers]
prod_vault = "onepassword://Production"
shared_vault = "onepassword://Shared"
keyring = "keyring://"
env = "env://"
```

### Bootstrap Credentials

:::note
Bootstrap providers are available since version 0.15.
:::

Some providers need a secret of their own before they can serve any secrets — a Bitwarden machine token (`BWS_ACCESS_TOKEN`), a Vault token or AppRole credentials, a 1Password service account token. Normally these come from environment variables, which pushes plaintext tokens back into shell profiles and CI variable pages. An alias can instead source them from another provider, so the token lives in your keyring or vault:

```toml title="secretspec.toml"
[providers]
keyring = "keyring://"

# BWS_ACCESS_TOKEN is read from keyring before the provider is used
bws = { uri = "bws://a9230ec4-5507-4870-b8b5-b3f500587e4c", env = { BWS_ACCESS_TOKEN = "keyring" } }
```

Each entry in `env` binds an environment variable the provider needs to a source. A bare string is a provider spec and reads the credential at the convention path (`{project}/{profile}/{VAR}`) for the active profile. A table pins the exact location with the same `ref` coordinates a secret uses:

```toml title="secretspec.toml"
[providers.vault_prod]
uri = "vault://secret/myapp?auth=approle"
env = { VAULT_ROLE_ID   = { provider = "onepassword", ref = { vault = "Infra", item = "vault-approle", field = "role_id" } },
        VAULT_SECRET_ID = { provider = "onepassword", ref = { vault = "Infra", item = "vault-approle", field = "secret_id" } } }
```

Store the credentials once with [`secretspec config provider login`](/reference/cli/#config-provider-login), which prompts for each one and writes it to its source:

```bash
$ secretspec config provider login bws
Enter BWS_ACCESS_TOKEN for provider 'bws' (source: keyring): ****
✓ stored BWS_ACCESS_TOKEN in keyring at smoke/default/BWS_ACCESS_TOKEN
```

A few things hold by design:

- **The environment still wins.** If the variable is already exported (as in CI), that value is used and the source is not consulted, so CI keeps working with no extra configuration.
- **Nothing leaks.** The credential is handed to the provider in memory; it is never written to the environment, and never reaches processes started by `secretspec run`.
- **One hop.** A bootstrap source may not itself declare bootstrap credentials, which is validated up front and makes cycles impossible.
- **Machine-wide vs per-profile.** A bare-string source is stored per project and profile; use a `ref` to pin a token to one location shared across projects.

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
$ secretspec config provider add prod_vault "onepassword://Production"

# Add an alias whose provider bootstraps a credential from another provider
$ secretspec config provider add bws "bws://project-uuid" --env BWS_ACCESS_TOKEN=keyring

# Store the bootstrap credentials an alias declares
$ secretspec config provider login bws

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
