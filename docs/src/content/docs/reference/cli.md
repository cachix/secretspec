---
title: CLI Commands Reference
description: Complete reference for SecretSpec CLI commands
---

The SecretSpec CLI provides commands for managing secrets across different providers and profiles.

## Commands

### init
Initialize a new `secretspec.toml` configuration file from an existing .env file.

```bash
secretspec init [OPTIONS]
```

**Options:**
- `-f, --from <PATH>` - Path to .env file to import from (default: `.env`)

**Example:**
```bash
$ secretspec init --from .env.example
✓ Created secretspec.toml with 5 secrets
```

### config init
Initialize user configuration interactively.

```bash
secretspec config init
```

**Example:**
```bash
$ secretspec config init
? Select your preferred provider backend:
> keyring: System keychain
? Select your default profile:
> development
✓ Configuration saved to ~/.config/secretspec/config.toml
```

### config show
Display current configuration.

```bash
secretspec config show
```

**Example:**
```bash
$ secretspec config show
Provider: keyring
Profile:  development
```

### config provider add
Add a provider alias to your configuration.

```bash
secretspec config provider add <ALIAS> <URI>
```

**Arguments:**
- `<ALIAS>` - Short name for the provider (e.g., `prod_vault`, `shared`)
- `<URI>` - Provider URI (e.g., `onepassword://vault/Production`, `env://`)

**Example:**
```bash
$ secretspec config provider add prod_vault "onepassword://vault/Production"
✓ Provider alias 'prod_vault' saved

$ secretspec config provider add shared "onepassword://vault/Shared"
✓ Provider alias 'shared' saved
```

### config provider list
List all configured provider aliases.

```bash
secretspec config provider list
```

**Example:**
```bash
$ secretspec config provider list
prod_vault  → onepassword://vault/Production
shared      → onepassword://vault/Shared
env         → env://
```

### config provider remove
Remove a provider alias from your configuration.

```bash
secretspec config provider remove <ALIAS>
```

**Arguments:**
- `<ALIAS>` - Name of the alias to remove

**Example:**
```bash
$ secretspec config provider remove prod_vault
✓ Provider alias 'prod_vault' removed
```

### check
Check if all required secrets are available, with interactive prompting for missing secrets.

```bash
secretspec check [OPTIONS]
```

**Options:**
- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use

**Example:**
```bash
$ secretspec check --profile production
✓ DATABASE_URL - Database connection string
✗ API_KEY - API key for external service (required)
Enter value for API_KEY (profile: production): ****
✓ Secret 'API_KEY' saved to keyring (profile: production)
```

### get
Get a secret value.

```bash
secretspec get [OPTIONS] <NAME>
```

**Options:**
- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use

**Example:**
```bash
$ secretspec get DATABASE_URL --profile production
postgresql://prod.example.com/mydb
```

### set
Set a secret value.

```bash
secretspec set [OPTIONS] <NAME> [VALUE]
```

**Options:**
- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use

**Example:**
```bash
$ secretspec set API_KEY sk-1234567890
✓ Secret 'API_KEY' saved to keyring (profile: development)
```

### run
Run a command with secrets injected as environment variables.

```bash
secretspec run [OPTIONS] -- <COMMAND>
```

**Options:**
- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use

**Examples:**
```bash
# Run npm with secrets available as environment variables
$ secretspec run --profile production -- npm run deploy

# Verify secrets are injected
$ secretspec run -- env | grep DATABASE_URL
DATABASE_URL=postgresql://localhost/mydb
```

:::note[Shell Variable Expansion]
Variables like `$DATABASE_URL` in the command line are expanded by your **shell before** secretspec runs. To use injected secrets in the command itself, wrap it in a subshell:

```bash
# This won't work - $DATABASE_URL is expanded before secretspec runs
$ secretspec run -- echo $DATABASE_URL
# Output: (empty, because DATABASE_URL isn't set in current shell)

# This works - variable expansion happens in the subprocess
$ secretspec run -- sh -c 'echo $DATABASE_URL'
# Output: postgresql://localhost/mydb
```

For most use cases, simply run your application and it will read secrets from its environment:
```bash
$ secretspec run -- node app.js  # app.js reads process.env.DATABASE_URL
```
:::

### import
Import secrets from one provider to another.

```bash
secretspec import <FROM_PROVIDER>
```

The destination provider and profile are determined from your configuration. Secrets that already exist in the destination provider will not be overwritten.

**Arguments:**
- `<FROM_PROVIDER>` - Provider to import from (e.g., `env`, `dotenv:/path/to/.env`)

**Example:**
```bash
# Import from environment variables to your default provider
$ secretspec import env
Importing secrets from env to keyring (profile: development)...

✓ DATABASE_URL - Database connection string
○ API_KEY - API key for external service (already exists in target)
✗ REDIS_URL - Redis connection URL (not found in source)

Summary: 1 imported, 1 already exists, 1 not found in source

# Import from a specific .env file
$ secretspec import dotenv:/home/user/old-project/.env
```

**Use Cases:**
- Migrate from .env files to a secure provider like keyring or OnePassword
- Copy secrets between different profiles or projects
- Import existing environment variables into SecretSpec management

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SECRETSPEC_PROFILE` | Default profile to use |
| `SECRETSPEC_PROVIDER` | Default provider to use |

## Quick Start Workflow

```bash
# Initialize from existing .env
$ secretspec init --from .env

# Set up user configuration
$ secretspec config init

# Import existing secrets (optional)
$ secretspec import env  # or: secretspec import dotenv:.env.old

# Check and set missing secrets
$ secretspec check

# Run your application
$ secretspec run -- npm start
```