---
title: CLI Commands Reference
description: Complete reference for Monosecret CLI commands
---

The Monosecret CLI provides commands for managing secrets across different providers and profiles.

## Global Options

These options are available on every command:

| Option              | Description                                                                                                                                                                                                                |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-f, --file <FILE>` | Path to `monosecret.toml` (default: auto-detect). Env: `MONOSECRET_FILE` (legacy: `SECRETSPEC_FILE`)                                                                                                                       |
| `--reason <REASON>` | Reason for accessing secrets, recorded by providers that support audit logging (e.g. Proton Pass agent sessions). Takes precedence over `PROTON_PASS_AGENT_REASON`. Env: `MONOSECRET_REASON` (legacy: `SECRETSPEC_REASON`) |

```bash
$ monosecret run --reason "Deploying web frontend" -- ./deploy.sh
```

## Commands

### init

Initialize a new `monosecret.toml` configuration file from an existing .env file.

```bash
monosecret init [OPTIONS]
```

**Options:**

- `--from <PATH>` - Path to .env file to import from (default: `.env`)

**Example:**

```bash
$ monosecret init --from .env.example
✓ Created monosecret.toml with 5 secrets
```

### config init

Initialize user configuration interactively.

```bash
monosecret config init
```

**Example:**

```bash
$ monosecret config init
? Select your preferred provider backend:
> keyring: System keychain
? Select your default profile:
> development
✓ Configuration saved to ~/.config/monosecret/config.toml
```

### config show

Display current configuration.

```bash
monosecret config show
```

**Example:**

```bash
$ monosecret config show
Provider: keyring
Profile:  development
```

### config provider add

Add a provider alias to your user-level configuration (`~/.config/monosecret/config.toml`).

To share aliases with your team, declare them in a top-level `[providers]` table in `monosecret.toml` instead — they take precedence over user-level aliases on name conflict.

```bash
monosecret config provider add <ALIAS> <URI>
```

**Arguments:**

- `<ALIAS>` - Short name for the provider (e.g., `prod_vault`, `shared`)
- `<URI>` - Provider URI (e.g., `onepassword://vault/Production`, `env://`)

**Example:**

```bash
$ monosecret config provider add prod_vault "onepassword://vault/Production"
✓ Provider alias 'prod_vault' saved

$ monosecret config provider add shared "onepassword://vault/Shared"
✓ Provider alias 'shared' saved
```

### config provider list

List all configured user-level provider aliases. Project-level aliases declared in `monosecret.toml` are not shown by this command.

```bash
monosecret config provider list
```

**Example:**

```bash
$ monosecret config provider list
prod_vault  → onepassword://vault/Production
shared      → onepassword://vault/Shared
env         → env://
```

### config provider remove

Remove a provider alias from your user-level configuration. To remove a project-level alias, edit the `[providers]` table in `monosecret.toml` directly.

```bash
monosecret config provider remove <ALIAS>
```

**Arguments:**

- `<ALIAS>` - Name of the alias to remove

**Example:**

```bash
$ monosecret config provider remove prod_vault
✓ Provider alias 'prod_vault' removed
```

### check

Check if all required secrets are available, with interactive prompting for missing secrets.

```bash
monosecret check [OPTIONS]
```

**Options:**

- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use

**Example:**

```bash
$ monosecret check --profile production
✓ DATABASE_URL - Database connection string
✗ API_KEY - API key for external service (required)
Enter value for API_KEY (profile: production): ****
✓ Secret 'API_KEY' saved to keyring (profile: production)
```

### get

Get a secret value.

```bash
monosecret get [OPTIONS] <NAME>
```

**Options:**

- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use

**Example:**

```bash
$ monosecret get DATABASE_URL --profile production
postgresql://prod.example.com/mydb
```

### set

Set a secret value.

```bash
monosecret set [OPTIONS] <NAME> [VALUE]
```

**Options:**

- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use

**Example:**

```bash
$ monosecret set API_KEY sk-1234567890
✓ Secret 'API_KEY' saved to keyring (profile: development)
```

### run

Run a command with secrets injected as environment variables.

```bash
monosecret run [OPTIONS] -- <COMMAND>
```

**Options:**

- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use
- `--include <SECRET>` - Only inject named secrets. Repeatable and comma-aware.
- `--group <GROUP>` - Only inject secrets in declared groups. Repeatable and comma-aware.

**Examples:**

```bash
# Run npm with secrets available as environment variables
$ monosecret run --profile production -- npm run deploy

# Verify secrets are injected
$ monosecret run -- env | grep DATABASE_URL
DATABASE_URL=postgresql://localhost/mydb

# Run with only selected secrets injected
$ monosecret run --include DATABASE_URL --include API_KEY -- npm test

# Run with all secrets in the "web" group injected
$ monosecret run --group web -- npm start
```

:::note[Shell Variable Expansion]
Variables like `$DATABASE_URL` in the command line are expanded by your **shell before** monosecret runs. To use injected secrets in the command itself, wrap it in a subshell:

```bash
# This won't work - $DATABASE_URL is expanded before monosecret runs
$ monosecret run -- echo $DATABASE_URL
# Output: (empty, because DATABASE_URL isn't set in current shell)

# This works - variable expansion happens in the subprocess
$ monosecret run -- sh -c 'echo $DATABASE_URL'
# Output: postgresql://localhost/mydb
```

For most use cases, simply run your application and it will read secrets from its environment:

```bash
$ monosecret run -- node app.js  # app.js reads process.env.DATABASE_URL
```

:::

### import

Import secrets from one provider to another.

```bash
monosecret import <FROM_PROVIDER>
```

The destination provider and profile are determined from your configuration. Secrets that already exist in the destination provider will not be overwritten.

**Arguments:**

- `<FROM_PROVIDER>` - Provider to import from (e.g., `env`, `dotenv:/path/to/.env`)

**Example:**

```bash
# Import from environment variables to your default provider
$ monosecret import env
Importing secrets from env to keyring (profile: development)...

✓ DATABASE_URL - Database connection string
○ API_KEY - API key for external service (already exists in target)
✗ REDIS_URL - Redis connection URL (not found in source)

Summary: 1 imported, 1 already exists, 1 not found in source

# Import from a specific .env file
$ monosecret import dotenv:/home/user/old-project/.env
```

**Use Cases:**

- Migrate from .env files to a secure provider like keyring or OnePassword
- Copy secrets between different profiles or projects
- Import existing environment variables into Monosecret management

## Environment Variables

| Variable              | Description                                                                    |
| --------------------- | ------------------------------------------------------------------------------ |
| `MONOSECRET_PROFILE`  | Default profile to use (legacy: `SECRETSPEC_PROFILE`)                          |
| `MONOSECRET_PROVIDER` | Default provider to use (legacy: `SECRETSPEC_PROVIDER`)                        |
| `MONOSECRET_FILE`     | Path to `monosecret.toml` (same as `--file`; legacy: `SECRETSPEC_FILE`)        |
| `MONOSECRET_REASON`   | Reason for accessing secrets (same as `--reason`; legacy: `SECRETSPEC_REASON`) |

## Quick Start Workflow

```bash
# Initialize from existing .env
$ monosecret init --from .env

# Set up user configuration
$ monosecret config init

# Import existing secrets (optional)
$ monosecret import env  # or: monosecret import dotenv:.env.old

# Check and set missing secrets
$ monosecret check

# Run your application
$ monosecret run -- npm start
```
