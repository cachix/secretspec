---
title: secretspec.toml Reference
description: Complete reference for secretspec.toml configuration options
---

## secretspec.toml Reference

The `secretspec.toml` file defines project-specific secret requirements. This file should be checked into version control.

### [project] Section

```toml
[project]
name = "my-app"              # Project name (required)
revision = "1.0"             # Format version (required, must be "1.0")
extends = ["../shared"]      # Paths to parent configs for inheritance (optional)
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Project identifier |
| `revision` | string | Yes | Format version (must be "1.0") |
| `extends` | array[string] | No | Paths to parent configuration files |

### [profiles.*] Section

Defines secret variables for different environments. At least a `[profiles.default]` section is required.

```toml
[profiles.default]           # Default profile (required)
DATABASE_URL = { description = "PostgreSQL connection", required = true }
API_KEY = { description = "External API key", required = true }
REDIS_URL = { description = "Redis cache", required = false, default = "redis://localhost:6379" }

[profiles.production]        # Additional profile (optional)
DATABASE_URL = { description = "Production database", required = true }
```

#### Secret Variable Options

Each secret variable is defined as a table with the following fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `description` | string | Yes | Human-readable description of the secret |
| `required` | boolean | No* | Whether the value must be provided (default: true) |
| `default` | string | No** | Default value if not provided |
| `providers` | array[string or table] | No | List of provider references (see [Provider References](#provider-references)) |
| `groups` | array[string] | No | Declared groups this secret belongs to (see [Secret Groups](#secret-groups)) |
| `as_path` | boolean | No | Write secret to temp file and return file path (default: false) |
| `type` | string | No*** | Secret type for generation: `password`, `hex`, `base64`, `uuid`, `command`, `rsa_private_key` |
| `generate` | boolean or table | No*** | Enable auto-generation when secret is missing |

*If `default` is provided, `required` defaults to false
**Only valid when `required = false`
***`type` is required when `generate` is enabled; `generate` and `default` cannot both be set

## Complete Example

```toml
# secretspec.toml
[project]
name = "web-api"
revision = "1.0"
extends = ["../shared/secretspec.toml"]  # Optional inheritance

# Groups used by filtered `secretspec run --group ...`
[groups]
web = "Secrets needed by the web app"
worker = "Secrets needed by background workers"

# Provider aliases used by profile provider chains
[providers]
prod_vault = "onepassword://vault/Production"
shared_vault = "onepassword://vault/Shared"
keyring = "keyring://"
env = "env://"

# Default profile - always loaded first
[profiles.default]
APP_NAME = { description = "Application name", required = false, default = "MyApp" }
LOG_LEVEL = { description = "Log verbosity", required = false, default = "info" }
GITHUB_TOKEN = { description = "GitHub token", required = true, groups = ["web", "worker"], providers = ["env"] }

# Development profile - extends default
[profiles.development]
DATABASE_URL = { description = "Database connection", required = false, default = "sqlite://./dev.db" }
API_URL = { description = "API endpoint", required = false, default = "http://localhost:3000" }
DEBUG = { description = "Debug mode", required = false, default = "true" }

# Production profile - extends default
[profiles.production]
DATABASE_URL = { description = "PostgreSQL cluster connection", required = true, providers = ["prod_vault", "keyring"] }
API_URL = { description = "Production API endpoint", required = true }
SENTRY_DSN = { description = "Error tracking service", required = true, providers = ["shared_vault"] }
REDIS_URL = { description = "Redis cache connection", required = true }
```

### Provider Aliases

Provider aliases may be declared in two places:

1. **In `secretspec.toml`** — a top-level `[providers]` table. Check this into version control so every team member and CI runner sees the same mapping out of the box.
2. **In `~/.config/secretspec/config.toml`** — a per-user `[defaults.providers]` table for personal overrides.

On conflict the project-level alias wins, so a stale local config cannot silently shadow the team's mapping.

```toml title="secretspec.toml"
[providers]
prod_vault = "onepassword://vault/Production"
shared_vault = "onepassword://vault/Shared"
keyring = "keyring://"
env = "env://"

[profiles.production]
DATABASE_URL = { description = "Production DB", providers = ["prod_vault", "keyring"] }
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

Manage user-level aliases via CLI:

```bash
# Add a provider alias to your user config
$ secretspec config provider add prod_vault "onepassword://vault/Production"

# List all aliases known to your user config
$ secretspec config provider list

# Remove an alias from your user config
$ secretspec config provider remove prod_vault
```

The CLI commands operate on the user-global config only — edit `secretspec.toml` by hand to change project-level aliases.

### Secret Groups

Declare allowed groups in a top-level `[groups]` table, then attach secrets with `groups = [...]`:

```toml
[groups]
web = "Secrets needed by the web application"
worker = "Secrets needed by background workers"

[profiles.default]
DATABASE_URL = { description = "Database URL", groups = ["web", "worker"] }
STRIPE_KEY = { description = "Stripe API key", groups = ["web"] }
```

Groups power filtered runs:

```bash
secretspec run --group web -- npm start
```

Secrets may only reference declared groups. When a profile overrides a secret, omitted `groups` inherit from `[profiles.default]`; explicitly setting `groups = [...]` replaces the default groups rather than merging them.

### Provider References with Path and Key

Per-secret `providers` entries can be either simple alias strings or detailed
reference tables that include a provider-relative `path` and `key`:

```toml
[profiles.default]
# Simple alias — backward compatible.
DATABASE_URL = { description = "Dev DB", providers = ["env"] }

# Detailed provider ref with path and key.
GITHUB_TOKEN = {
  description = "GitHub personal access token",
  providers = [
    { provider = "op-dev", path = ["GitHub"], key = "token" }
  ]
}

# Mixed aliases and details in one chain.
API_KEY = {
  description = "External API key",
  providers = ["keyring", { provider = "op-dev", path = ["APIs"] }]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `provider` | string | Yes | The provider alias name |
| `path` | array[string] | No | Location path within the provider (e.g. a 1Password section name) |
| `key` | string | No | Field key at that path; defaults to the SecretSpec secret name |

For 1Password, `onepassword://` keeps the original SecretSpec-owned storage behavior. Use `op://` when the provider ref should compose a native 1Password reference:

```toml
[providers]
op = "op://Development/dotfiles"

[profiles.default.GITHUB_TOKEN]
providers = [{ provider = "op", path = ["forges"] }]
# Reads op://Development/dotfiles/forges/GITHUB_TOKEN
```

### Structured Provider Configs with Dependencies

Project-level `[providers]` entries can also be tables with an optional
`depends_on` section to declare that a provider depends on another secret
for authentication:

```toml
[providers]
keyring = "keyring://"              # Simple alias — backward compatible

[providers.op-dev]
uri = "onepassword://Development"
[[providers.op-dev.depends_on]]
service_token = { secret = "OP_SERVICE_ACCOUNT_TOKEN" }
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `uri` | string | Yes | The provider URI |
| `depends_on` | table | No | Secrets this provider needs for authentication |

Each entry under `depends_on` has:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `secret` | string | Yes | The SecretSpec secret name that provides the value |

### as_path Option

When `as_path = true`, the secret value is written to a temporary file and the file path is returned instead of the value:

```toml
[profiles.default]
TLS_CERT = { description = "TLS certificate", as_path = true }
GOOGLE_APPLICATION_CREDENTIALS = { description = "GCP service account", as_path = true }
```

| Context | Behavior |
|---------|----------|
| CLI (`get`, `check`, `run`) | Files are persisted (not deleted after command exits) |
| Rust SDK | Files cleaned up when `ValidatedSecrets` is dropped; use `keep_temp_files()` to persist |
| Rust SDK types | `PathBuf` or `Option<PathBuf>` instead of `String` |

### Secret Generation

:::note
Secret generation is available since version 0.7.
:::

When `type` and `generate` are set, missing secrets are automatically generated during `check` or `run` and stored via the configured provider:

```toml
[profiles.default]
# Simple: generate with type defaults
DB_PASSWORD = { description = "Database password", type = "password", generate = true }
REQUEST_ID = { description = "Request ID prefix", type = "uuid", generate = true }

# Custom options
API_TOKEN = { description = "API token", type = "hex", generate = { bytes = 32 } }
SESSION_KEY = { description = "Session key", type = "base64", generate = { bytes = 64 } }

# Shell command
MONGO_KEY = { description = "MongoDB keyfile", type = "command", generate = { command = "openssl rand -base64 765" } }

# RSA private key (PKCS1 PEM)
JWT_SIGNING_KEY = { description = "JWT signing key", type = "rsa_private_key", generate = true }

# Type without generate: informational only, no auto-generation
MANUAL_SECRET = { description = "Manually managed", type = "password" }
```

#### Generation Types

| Type | Default Output | Options |
|------|---------------|---------|
| `password` | 32 alphanumeric chars | `length` (int), `charset` (`"alphanumeric"` or `"ascii"`) |
| `hex` | 64 hex chars (32 bytes) | `bytes` (int) |
| `base64` | 44 chars (32 bytes) | `bytes` (int) |
| `uuid` | UUID v4 (36 chars) | none |
| `command` | stdout of command | `command` (string, required) |
| `rsa_private_key` | 2048-bit RSA private key (PKCS1 PEM) | `bits` (int) |

#### Behavior

- Generation only triggers when a secret is **missing** — existing secrets are never overwritten
- Generated values are stored via the secret's configured provider (or the default provider)
- Subsequent runs find the stored value and skip generation (idempotent)
- `generate` and `default` cannot both be set on the same secret
- `type = "command"` requires `generate = { command = "..." }` (not just `generate = true`)

## Profile Inheritance

- All profiles automatically inherit from `[profiles.default]`
- Profile-specific values override default values
- Use the `extends` field in `[project]` to inherit from other secretspec.toml files
