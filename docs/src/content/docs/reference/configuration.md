---
title: monosecret.toml Reference
description: Complete reference for monosecret.toml configuration options
---

## monosecret.toml Reference

The `monosecret.toml` file defines project-specific secret requirements. This file should be checked into version control.

### [project] Section

```toml
[project]
name = "my-app"           # Project name (required)
revision = "1.0"          # Format version (required, must be "1.0")
extends = ["../shared"]   # Paths to parent configs for inheritance (optional)
require_reason = "agents" # When to require a reason for secret access (optional)
```

| Field            | Type                  | Required | Description                                                                                                                          |
| ---------------- | --------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `name`           | string                | Yes      | Project identifier                                                                                                                   |
| `revision`       | string                | Yes      | Format version (must be "1.0")                                                                                                       |
| `extends`        | array[string]         | No       | Paths to parent configuration files                                                                                                  |
| `require_reason` | `"agents"` \| boolean | No       | When secret access must supply a reason (via `--reason`, `MONOSECRET_REASON`, or the SDK's `with_reason()`). Defaults to `"agents"`. |

#### Requiring a reason for secret access

`require_reason` controls when monosecret demands a reason for accessing secrets.
It accepts three values:

| Value                | Behavior                                                                                             |
| -------------------- | ---------------------------------------------------------------------------------------------------- |
| `"agents"` (default) | Require a reason **only when an AI agent is detected**. Humans running interactively are unaffected. |
| `true`               | Require a reason from **every** caller (humans, CI, agents).                                         |
| `false`              | Never require a reason.                                                                              |

Because the rule is enforced inside monosecret and checked into `monosecret.toml`,
every clone, CI runner, and AI agent is held to it — there is no per-tool opt-out:

```bash
# Under an AI agent, with the default "agents" policy:
$ monosecret run -- ./deploy.sh
Error: Accessing secrets requires a reason. Provide one with --reason "<why...>" ...

$ monosecret run --reason "Deploy web frontend" -- ./deploy.sh   # ok
```

**Agent detection.** monosecret delegates detection of known agents to the
[`detect-coding-agent`](https://crates.io/crates/detect-coding-agent) crate. In addition,
monosecret checks its own `MONOSECRET_AGENT` environment variable as an explicit opt-in:

```bash
# Mark any harness the detector does not recognize as an agent:
$ export MONOSECRET_AGENT=1
```

If your agent isn't auto-detected, set `MONOSECRET_AGENT=1` (legacy: `SECRETSPEC_AGENT=1`) or use
`require_reason = true` to require a reason from everyone.

The reason is also forwarded to providers that support audit logging (e.g. the
[Proton Pass](/providers/protonpass/) provider records it in the agent audit log).

### [profiles.*] Section

Defines secret variables for different environments. At least a `[profiles.default]` section is required.

```toml
[profiles.default] # Default profile (required)
DATABASE_URL = { description = "PostgreSQL connection", required = true }
API_KEY = { description = "External API key", required = true }
REDIS_URL = { description = "Redis cache", required = false, default = "redis://localhost:6379" }

[profiles.production] # Additional profile (optional)
DATABASE_URL = { description = "Production database", required = true }
```

#### Secret Variable Options

Each secret variable is defined as a table with the following fields:

| Field         | Type                   | Required | Description                                                                                   |
| ------------- | ---------------------- | -------- | --------------------------------------------------------------------------------------------- |
| `description` | string                 | Yes      | Human-readable description of the secret                                                      |
| `required`    | boolean                | No*      | Whether the value must be provided (default: true)                                            |
| `default`     | string                 | No**     | Default value if not provided                                                                 |
| `providers`   | array[string or table] | No       | List of provider references (see [Provider References](#provider-references))                 |
| `groups`      | array[string]          | No       | Declared groups this secret belongs to (see [Secret Groups](#secret-groups))                  |
| `as_path`     | boolean                | No       | Write secret to temp file and return file path (default: false)                               |
| `type`        | string                 | No***    | Secret type for generation: `password`, `hex`, `base64`, `uuid`, `command`, `rsa_private_key` |
| `generate`    | boolean or table       | No***    | Enable auto-generation when secret is missing                                                 |

*If `default` is provided, `required` defaults to false
**Only valid when `required = false`
***`type` is required when `generate` is enabled; `generate` and `default` cannot both be set

## Complete Example

```toml
# monosecret.toml
[project]
name = "web-api"
revision = "1.0"
extends = ["../shared/monosecret.toml"] # Optional inheritance

# Groups used by filtered `monosecret run --group ...`
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
GITHUB_TOKEN = { description = "GitHub token", required = true, groups = [
  "web",
  "worker",
], providers = [
  "env",
] }

# Development profile - extends default
[profiles.development]
DATABASE_URL = { description = "Database connection", required = false, default = "sqlite://./dev.db" }
API_URL = { description = "API endpoint", required = false, default = "http://localhost:3000" }
DEBUG = { description = "Debug mode", required = false, default = "true" }

# Production profile - extends default
[profiles.production]
DATABASE_URL = { description = "PostgreSQL cluster connection", required = true, providers = [
  "prod_vault",
  "keyring",
] }
API_URL = { description = "Production API endpoint", required = true }
SENTRY_DSN = { description = "Error tracking service", required = true, providers = [
  "shared_vault",
] }
REDIS_URL = { description = "Redis cache connection", required = true }
```

### Provider Aliases

Provider aliases may be declared in two places:

1. **In `monosecret.toml`** — a top-level `[providers]` table. Check this into version control so every team member and CI runner sees the same mapping out of the box.
2. **In `~/.config/monosecret/config.toml`** — a per-user `[defaults.providers]` table for personal overrides.

On conflict the project-level alias wins, so a stale local config cannot silently shadow the team's mapping.

```toml title="monosecret.toml"
[providers]
prod_vault = "onepassword://vault/Production"
shared_vault = "onepassword://vault/Shared"
keyring = "keyring://"
env = "env://"

[profiles.production]
DATABASE_URL = { description = "Production DB", providers = [
  "prod_vault",
  "keyring",
] }
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

Manage user-level aliases via CLI:

```bash
# Add a provider alias to your user config
$ monosecret config provider add prod_vault "onepassword://vault/Production"

# List all aliases known to your user config
$ monosecret config provider list

# Remove an alias from your user config
$ monosecret config provider remove prod_vault
```

The CLI commands operate on the user-global config only — edit `monosecret.toml` by hand to change project-level aliases.

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
monosecret run --group web -- npm start
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

| Field      | Type          | Required | Description                                                       |
| ---------- | ------------- | -------- | ----------------------------------------------------------------- |
| `provider` | string        | Yes      | The provider alias name                                           |
| `path`     | array[string] | No       | Location path within the provider (e.g. a 1Password section name) |
| `key`      | string        | No       | Field key at that path; defaults to the Monosecret secret name    |

For 1Password, `onepassword://` keeps the original Monosecret-owned storage behavior. Use `op://` when the provider ref should compose a native 1Password reference:

```toml
[providers]
op = "op://Development/dotfiles"

[profiles.default.GITHUB_TOKEN]
providers = [{ provider = "op", path = ["forges"] }]
# Reads op://Development/dotfiles/forges/GITHUB_TOKEN
```

### Secret References

The `ref` field names one externally managed secret by the store's own
coordinates instead of Monosecret's `{project}/{profile}/{key}` convention. See
[Secret References](/concepts/references/) for the concept, model, and examples;
this section is the specification.

```toml
[profiles.production]
DATABASE_URL = { description = "Postgres DSN", ref = { item = "db", field = "password" }, providers = [
  "prod_vault",
] }
INFRA_TOKEN = { description = "Infra token", ref = { vault = "Production", item = "infra", field = "token" } }
GITHUB_TOKEN = { description = "GitHub token", ref = { item = "GITHUB_PAT" }, providers = [
  "env",
] }
```

`ref` is a table of provider-independent coordinates. Unknown keys are rejected
at parse time. Only `item` is universal; it is the secret's complete name in the
store and replaces the whole convention path, including any `folder_prefix` or
format string configured for the provider. A coordinate a store has no equivalent
for is rejected with an error naming it, never silently ignored.

| Coordinate | Required | Meaning                                                                                                       |
| ---------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| `item`     | Yes      | The store's complete name for the secret; replaces the whole convention path                                  |
| `field`    | No       | A named component inside the item; rejected by stores whose secrets hold a single value                       |
| `vault`    | No       | The container holding the item; 1Password only, while other stores take their container from the provider URI |
| `section`  | No       | A named group of fields inside the item; 1Password only and requires `field`                                  |
| `version`  | No       | Which revision to read; Google Secret Manager only and defaults to the latest                                 |

Stores fall into two groups for `field`:

| Store                                               | Shape of one secret     | `field`                                                |
| --------------------------------------------------- | ----------------------- | ------------------------------------------------------ |
| dotenv, env, pass, LastPass, Proton Pass, Bitwarden | A single value          | Rejected: there is nothing to select                   |
| 1Password, Vault KV, AWS Secrets Manager, keyring   | A record of named parts | Selects the field label, map key, JSON key, or account |

`vault` is the only container coordinate. For every store except 1Password, the
container is part of the provider URI rather than the ref:

```toml
# The mount `kv2` comes from the URI; the ref names the path inside it.
DB = { description = "DB", ref = { item = "myapp/config", field = "pw" }, providers = [
  "vault://vault.example.com:8200/kv2",
] }

# On 1Password, `vault` on the ref overrides the URI's default vault.
TOKEN = { description = "Token", ref = { vault = "Production", item = "infra", field = "token" }, providers = [
  "onepassword://Private",
] }
```

Which provider resolves a `ref` follows the ordinary [provider resolution order](/concepts/providers/). A `ref` composes with the `providers` fallback
chain, and each provider is asked for the same coordinates.

#### How providers interpret the coordinates

| Provider                                                   | `item`                            | `field`                                  | Without `field`                          | Writes via ref                                             |
| ---------------------------------------------------------- | --------------------------------- | ---------------------------------------- | ---------------------------------------- | ---------------------------------------------------------- |
| [OnePassword](/providers/onepassword/#secret-references)   | Item title or UUID                | Field label; `vault` and `section` apply | Reads the item's value or password field | ✅ via `op item edit`; adds fields but never creates items |
| [keyring](/providers/keyring/#secret-references)           | Service                           | Account                                  | Current user's entry                     | ✅                                                         |
| [dotenv](/providers/dotenv/#secret-references)             | `.env` key                        | Rejected                                 | Reads the key                            | ✅                                                         |
| [env](/providers/env/#secret-references)                   | Variable name                     | Rejected                                 | Reads the variable                       | — (read-only)                                              |
| [pass](/providers/pass/#secret-references)                 | Entry path                        | Rejected                                 | Reads the entry                          | ✅                                                         |
| [LastPass](/providers/lastpass/#secret-references)         | Item name                         | Rejected                                 | Reads the item                           | ✅                                                         |
| [Proton Pass](/providers/protonpass/#secret-references)    | Item title                        | Rejected                                 | Reads the note                           | ✅                                                         |
| [Vault / OpenBao](/providers/vault/#secret-references)     | KV path relative to the mount     | Required                                 | Error                                    | — (read-only)                                              |
| [AWS Secrets Manager](/providers/awssm/#secret-references) | Secret name or ARN                | JSON key                                 | Whole secret string                      | — (read-only)                                              |
| [GCSM](/providers/gcsm/#secret-references)                 | Secret id; `version` also applies | Rejected                                 | Reads latest or the pinned version       | — (read-only)                                              |
| [Bitwarden (bws)](/providers/bws/#secret-references)       | BWS key name                      | Rejected                                 | Reads the key                            | ✅                                                         |

A provider rejects coordinates it has no equivalent for, with an error naming
the coordinate (for example, `field` on the env provider).

#### Writing through a ref

Writes are symmetric with reads: `monosecret set` and interactive `check`
prompting write through the coordinates in place wherever the table above says
writes are supported. Read-only stores fail with a clear error instead.

#### No string refs

`ref` is always a table. String and URI forms (`ref = "op://vault/item/field"`,
`ref = "env://VAR"`, query-parameter URIs, and similar) are rejected, and the
error spells out the exact table translation. For example, a pasted 1Password
reference `op://Production/infra/token` translates to:

```toml
INFRA_TOKEN = { description = "Infra token", ref = { vault = "Production", item = "infra", field = "token" }, providers = [
  "onepassword://Production",
] }
```

Provider URIs remain store addresses; the `ref` table provides the complete
native coordinates for the secret.

#### Deduplication, auditing, and reporting

- Secrets sharing identical coordinates and store are fetched once.
- [Audit log](/concepts/audit/) events carry a `ref` field with the coordinates.
- `check --explain` and `check --json` attribute ref secrets to the store URI
  they resolved from.

### Structured Provider Configs with Dependencies

Project-level `[providers]` entries can also be tables with an optional
`depends_on` section to declare that a provider depends on another secret
for authentication:

```toml
[providers]
keyring = "keyring://" # Simple alias — backward compatible

[providers.op-dev]
uri = "onepassword://Development"
[[providers.op-dev.depends_on]]
service_token = { secret = "OP_SERVICE_ACCOUNT_TOKEN" }
```

| Field        | Type   | Required | Description                                    |
| ------------ | ------ | -------- | ---------------------------------------------- |
| `uri`        | string | Yes      | The provider URI                               |
| `depends_on` | table  | No       | Secrets this provider needs for authentication |

Each entry under `depends_on` has:

| Field    | Type   | Required | Description                                        |
| -------- | ------ | -------- | -------------------------------------------------- |
| `secret` | string | Yes      | The Monosecret secret name that provides the value |

### Audit Logging

Monosecret records every secret access to a local [audit log](/concepts/audit/).
Auditing is a per-machine/operator concern — where the log lives and whether it is
on — so it is configured in the **user-global config**, not the project's
`monosecret.toml`. A cloned repository therefore cannot redirect or silence your
audit log. Auditing is **on by default**; configure it under the top-level
`[audit]` table:

```toml title="~/.config/monosecret/config.toml"
[audit]
enabled = true                               # set false to turn auditing off
path = "~/.local/state/monosecret/audit.log" # default: per-user XDG state dir
max_size_bytes = 1048576                     # default: 1 MiB
```

| Field            | Type    | Default            | Description                                                                                                                            |
| ---------------- | ------- | ------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| `enabled`        | boolean | `true`             | Whether to record secret access.                                                                                                       |
| `path`           | string  | per-user state dir | Where to write the JSON Lines log. Must be absolute (a leading `~` is expanded); a relative path is rejected and auditing is disabled. |
| `max_size_bytes` | integer | `1048576` (1 MiB)  | Hard size cap. At the cap the file is truncated and restarted; no rotated backups are kept.                                            |

Secret values are never written to the log, and credentials embedded in provider
URIs are redacted. Audit failures never block secret access. See
[Audit Logging](/concepts/audit/) for the record format and full details.

### as_path Option

When `as_path = true`, the secret value is written to a temporary file and the file path is returned instead of the value:

```toml
[profiles.default]
TLS_CERT = { description = "TLS certificate", as_path = true }
GOOGLE_APPLICATION_CREDENTIALS = { description = "GCP service account", as_path = true }
```

| Context                     | Behavior                                                                                |
| --------------------------- | --------------------------------------------------------------------------------------- |
| CLI (`get`, `check`, `run`) | Files are persisted (not deleted after command exits)                                   |
| Rust SDK                    | Files cleaned up when `ValidatedSecrets` is dropped; use `keep_temp_files()` to persist |
| Rust SDK types              | `PathBuf` or `Option<PathBuf>` instead of `String`                                      |

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

| Type              | Default Output                       | Options                                                   |
| ----------------- | ------------------------------------ | --------------------------------------------------------- |
| `password`        | 32 alphanumeric chars                | `length` (int), `charset` (`"alphanumeric"` or `"ascii"`) |
| `hex`             | 64 hex chars (32 bytes)              | `bytes` (int)                                             |
| `base64`          | 44 chars (32 bytes)                  | `bytes` (int)                                             |
| `uuid`            | UUID v4 (36 chars)                   | none                                                      |
| `command`         | stdout of command                    | `command` (string, required)                              |
| `rsa_private_key` | 2048-bit RSA private key (PKCS1 PEM) | `bits` (int)                                              |

#### Behavior

- Generation only triggers when a secret is **missing** — existing secrets are never overwritten
- Generated values are stored via the secret's configured provider (or the default provider)
- Subsequent runs find the stored value and skip generation (idempotent)
- `generate` and `default` cannot both be set on the same secret
- `type = "command"` requires `generate = { command = "..." }` (not just `generate = true`)

## Profile Inheritance

- All profiles automatically inherit from `[profiles.default]`
- Profile-specific values override default values
- Use the `extends` field in `[project]` to inherit from other monosecret.toml files
