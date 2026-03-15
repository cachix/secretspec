---
title: Secret Generation
description: Automatically generating passwords, tokens, and keys for missing secrets
---

:::note
Secret generation is available since version 0.7.
:::

Secrets can be declared with `type` and `generate` to be auto-generated when missing. This is useful for passwords, tokens, and keys that do not need to be shared across developers.

## Basic Usage

```toml
[profiles.default]
DB_PASSWORD = { description = "Database password", type = "password", generate = true }
API_TOKEN = { description = "API token", type = "hex", generate = { bytes = 32 } }
SESSION_KEY = { description = "Session key", type = "base64", generate = { bytes = 64 } }
REQUEST_ID = { description = "Request ID prefix", type = "uuid", generate = true }
```

## Generation Types

| Type | Default Output | Options |
|------|---------------|---------|
| `password` | 32 alphanumeric chars | `length` (int), `charset` (`"alphanumeric"` or `"ascii"`) |
| `hex` | 64 hex chars (32 bytes) | `bytes` (int) |
| `base64` | 44 chars (32 bytes) | `bytes` (int) |
| `uuid` | UUID v4 (36 chars) | none |
| `command` | stdout of command | `command` (string, required) |

### Command type

The `command` type runs a shell command and uses its stdout as the generated value:

```toml
MONGO_KEY = { description = "MongoDB keyfile", type = "command", generate = { command = "openssl rand -base64 765" } }
```

`command` requires `generate = { command = "..." }` rather than just `generate = true`.

## How it works

- Generation only triggers when a secret is **missing**. Existing secrets are never overwritten.
- Generated values are stored via the secret's configured provider (or the default provider).
- Subsequent runs find the stored value and skip generation (idempotent).
- `generate` and `default` cannot both be set on the same secret.
- Setting `type` without `generate` is informational only and does not trigger auto-generation.

## Example

```toml
[profiles.default]
# Auto-generated on first run, reused after that
DB_PASSWORD = { description = "Database password", type = "password", generate = true }

# Custom length and character set
ADMIN_PASSWORD = { description = "Admin password", type = "password", generate = { length = 64, charset = "ascii" } }

# 64-byte key encoded as base64
ENCRYPTION_KEY = { description = "Encryption key", type = "base64", generate = { bytes = 64 } }

# Informational type only, no generation
EXTERNAL_API_KEY = { description = "Provided by vendor", type = "password" }
```

See the [configuration reference](/reference/configuration/#secret-generation) for the full specification.
