---
title: CLI Commands Reference
description: Complete reference for SecretSpec CLI commands
---

The SecretSpec CLI provides commands for managing secrets across different providers and profiles.

## Global Options

These options are available on every command:

| Option | Description |
|--------|-------------|
| `-f, --file <FILE>` | Path to `secretspec.toml` (default: auto-detect). Env: `SECRETSPEC_FILE` |
| `--reason <REASON>` | Reason for accessing secrets, recorded by providers that support audit logging (e.g. Proton Pass agent sessions). Takes precedence over `PROTON_PASS_AGENT_REASON`. Env: `SECRETSPEC_REASON` |

```bash
$ secretspec run --reason "Deploying web frontend" -- ./deploy.sh
```

## Commands

### init
Initialize a new `secretspec.toml` configuration file from an existing .env file.

```bash
secretspec init [OPTIONS]
```

**Options:**
- `--from <PATH>` - Path to .env file to import from (default: `.env`)

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
Add a provider alias to your user-level configuration (`~/.config/secretspec/config.toml`).

To share aliases with your team, declare them in a top-level `[providers]` table in `secretspec.toml` instead — they take precedence over user-level aliases on name conflict.

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
List all configured user-level provider aliases. Project-level aliases declared in `secretspec.toml` are not shown by this command.

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
Remove a provider alias from your user-level configuration. To remove a project-level alias, edit the `[providers]` table in `secretspec.toml` directly.

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
- `-n, --no-prompt` - Don't prompt for missing secrets (exit with error if any are missing)
- `--json` - Print a value-free resolution report as JSON instead of prompting
- `--explain` - Print a value-free, human-readable resolution trace instead of prompting

**Example:**
```bash
$ secretspec check --profile production
✓ DATABASE_URL - Database connection string
✗ API_KEY - API key for external service (required)
Enter value for API_KEY (profile: production): ****
✓ Secret 'API_KEY' saved to keyring (profile: production)
```

#### Resolution report (`--json` / `--explain`)

`--json` and `--explain` report how every declared secret resolved for the
active profile without prompting and without ever printing a secret value. Both
exit non-zero when a required secret is missing, so they work as a CI gate.

`--explain` prints a human-readable trace:

```bash
$ secretspec check --profile production --explain
profile:  production
provider: keyring://
  DATABASE_URL  ok        source keyring://
  JWT_SECRET    ok        generated
  LOG_LEVEL     ok        default value
  SENTRY_DSN    missing   optional
  STRIPE_KEY    MISSING   required
```

`--json` emits a versioned, machine-readable object for tooling and CI. Each
entry reports the `status` (`resolved`, `missing_required`, `missing_optional`),
whether the value came from a provider (`source_provider`, credential-free), a
generator (`generated`), or a committed default (`default_applied`), and whether
it is exposed `as_path`. No secret values appear. The canonical JSON Schema is
committed at `schema/resolution-report.schema.json`.

```bash
$ secretspec check --profile production --json
{
  "schema_version": 1,
  "provider": "keyring://",
  "profile": "production",
  "secrets": [
    { "name": "DATABASE_URL", "status": "resolved", "required": true, "source_provider": "keyring://", "default_applied": false, "generated": false, "as_path": false },
    { "name": "STRIPE_KEY", "status": "missing_required", "required": true, "default_applied": false, "generated": false, "as_path": false }
  ]
}
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

### resolve
Resolve every declared secret and print it as JSON. This is the SDK boundary:
other-language clients consume this payload (over a subprocess or the C ABI)
rather than reimplementing resolution.

```bash
secretspec resolve [OPTIONS]
```

Unlike `check`, `resolve` prints secret **values** to stdout. Pipe it into a
program; do not display it. Use `--no-values` for a value-free structural view.
When a required secret is missing, the command exits non-zero with an empty
`secrets` object and a populated `missing_required` list (mirroring the SDK's
`load()`).

**Options:**
- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use
- `--no-values` - Omit secret values, emitting only structure and provenance

**Example:**
```bash
$ secretspec resolve --profile production
{
  "schema_version": 1,
  "provider": "keyring://",
  "profile": "production",
  "secrets": {
    "DATABASE_URL": { "value": "postgresql://prod.example.com/mydb", "as_path": false, "source": "provider", "source_provider": "keyring://" },
    "TLS_CERT": { "path": "/tmp/.tmpAbc123", "as_path": true, "source": "provider", "source_provider": "keyring://" }
  },
  "missing_required": [],
  "missing_optional": []
}
```

Each entry reports the value (or, for `as_path` secrets, the `path` to a
persisted temp file), its `source` (`provider`, `generated`, or `default`), and
the serving provider's credential-free URI. The canonical JSON Schema is
committed at `schema/resolve-response.schema.json`.

### schema
Emit a JSON Schema for the manifest's typed shapes: a `SecretSpec` type (the
union, safe for any profile) plus one `<Profile>Secrets` type per profile.
Value-free: reads only the manifest, never a provider.

```bash
secretspec schema [-o FILE]
```

**Options:**
- `-o, --output <FILE>` - Write to this file instead of stdout

Rather than ship a typed-accessor generator per language, feed this schema to
[quicktype](https://quicktype.io), which generates idiomatic types **and**
deserializers for any language. At runtime, hand the generated deserializer the
flat `{SECRET_NAME: value}` map from the SDK's `fields()` helper:

```bash
$ secretspec schema | quicktype -s schema --lang python -o secrets_gen.py
```
```python
from secretspec import SecretSpec
from secrets_gen import SecretSpec as Secrets  # quicktype-generated, typed

resolved = SecretSpec.builder().with_profile("production").with_reason("boot").load()
s = Secrets.from_dict(resolved.fields())
print(s.database_url)   # typed str
```

The same pattern works in every SDK: Go `UnmarshalSecretSpec(resolved.FieldsJSON())`,
TypeScript `Convert.toSecretSpec(resolved.fieldsJson())`, Ruby
`SecretSpec.from_dynamic!(resolved.fields)`.

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

### audit

Show the local [audit log](/concepts/audit/) of secret access.

```bash
secretspec audit [--project <NAME>] [--action <ACTION>] [-n <N>] [--json]
```

**Options:**
- `--project <NAME>` - Only show entries for this project
- `--action <ACTION>` - Only show entries for this action (`get`, `set`, `check`, `run`, `import`)
- `-n, --tail <N>` - Show only the last N entries
- `--json` - Output raw JSON Lines instead of the formatted summary

The log location is read from your user-global config (`[audit]` in `~/.config/secretspec/config.toml`), defaulting to the per-user state directory.

**Example:**
```bash
$ secretspec audit --action run -n 5
2026-06-04T18:06:29Z  run    found  ./deploy.sh  API_KEY,DATABASE_URL  (my-app/production)  reason: deploy  [claude-code]

# Pipe raw entries to jq
$ secretspec audit --json | jq 'select(.outcome == "missing")'
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SECRETSPEC_PROFILE` | Default profile to use |
| `SECRETSPEC_PROVIDER` | Default provider to use |
| `SECRETSPEC_FILE` | Path to `secretspec.toml` (same as `--file`) |
| `SECRETSPEC_REASON` | Reason for accessing secrets (same as `--reason`) |

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