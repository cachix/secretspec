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
| **infisical** | Integration with Infisical secrets management platform | ✓ | ✓ | ✓ |
| **onepassword** | Integration with OnePassword password manager | ✓ | ✓ | ✓ |
| **lastpass** | Integration with LastPass password manager | ✓ | ✓ | ✓ |

## Provider Selection

SecretSpec determines which provider to use in this order:

1. **CLI flag**: `secretspec --provider` flag
2. **Environment**: `SECRETSPEC_PROVIDER` (highest priority)
3. **Global default**: Default provider in user config set via `secretspec config init`

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

## Next Steps

- Learn about specific providers in the [Providers](/providers/keyring/) section
- Understand how providers work with [Profiles](/concepts/profiles/)
- Explore [Configuration Inheritance](/concepts/inheritance/) for complex setups
