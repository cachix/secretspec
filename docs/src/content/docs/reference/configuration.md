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
require_reason = "agents"    # When to require a reason for secret access (optional)
require_approval = false     # When to require human approval before releasing secrets (optional)
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Project identifier |
| `revision` | string | Yes | Format version (must be "1.0") |
| `extends` | array[string] | No | Paths to parent configuration files |
| `require_reason` | `"agents"` \| boolean | No | When secret access must supply a reason (via `--reason`, `SECRETSPEC_REASON`, or the SDK's `with_reason()`). Defaults to `"agents"`. |
| `require_approval` | `"agents"` \| boolean | No | When releasing secrets to a `run`/`get` requires human approval at a trusted prompt. Defaults to `false`. |

#### Requiring a reason for secret access

`require_reason` controls when secretspec demands a reason for accessing secrets.
It accepts three values:

| Value | Behavior |
|-------|----------|
| `"agents"` (default) | Require a reason **only when an AI agent is detected**. Humans running interactively are unaffected. |
| `true` | Require a reason from **every** caller (humans, CI, agents). |
| `false` | Never require a reason. |

Because the rule is enforced inside secretspec and checked into `secretspec.toml`,
every clone, CI runner, and AI agent is held to it — there is no per-tool opt-out:

```bash
# Under an AI agent, with the default "agents" policy:
$ secretspec run -- ./deploy.sh
Error: Accessing secrets requires a reason. Provide one with --reason "<why...>" ...

$ secretspec run --reason "Deploy web frontend" -- ./deploy.sh   # ok
```

**Agent detection.** secretspec delegates detection of known agents to the
[`detect-coding-agent`](https://crates.io/crates/detect-coding-agent) crate, which
maintains the per-tool signal list (Claude Code, Cursor, Codex, Gemini CLI,
Copilot, and more). It treats **autonomous and hybrid** environments as agents but
not human-driven interactive editors. In addition, secretspec checks its own
`SECRETSPEC_AGENT` environment variable as an explicit opt-in:

```bash
# Mark any harness the detector does not recognize as an agent:
$ export SECRETSPEC_AGENT=1
```

If your agent isn't auto-detected, set `SECRETSPEC_AGENT=1` (or use
`require_reason = true` to require a reason from everyone).

The reason is recorded in secretspec's own [audit log](/concepts/audit/) and is also
forwarded to providers that support auditing (e.g. the
[Proton Pass](/providers/protonpass/) provider records it in the agent audit log).

#### Requiring human approval before releasing secrets

`require_approval` gates the moment secrets are handed to a command. Before
`secretspec run` injects secrets into a child process (or `secretspec get`
prints a value), secretspec pops a **trusted approval prompt** summarizing the
secrets and the command, and proceeds only if you approve. It accepts the same
three values as `require_reason`:

| Value | Behavior |
|-------|----------|
| `false` (default) | Never require approval. |
| `"agents"` | Require approval **only when an AI agent is detected** (same detection as `require_reason`). Humans running interactively are unaffected. |
| `true` | Require approval from **every** caller. |

The prompt is shown by [pinentry](https://www.gnupg.org/related_software/pinentry/)
(GnuPG's prompt helper — a GUI or terminal dialog), falling back to `/dev/tty`
when no pinentry binary is installed. Because it is read on a channel the calling
process does not control, an orchestrator that only *triggers* the operation
cannot approve on your behalf — so you can let an agent run `secretspec run`
while you remain the one who releases the secrets. A denial aborts the command
and is recorded in the [audit log](/concepts/audit/).

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
| `providers` | array[string] | No | List of provider aliases to use in fallback order |
| `as_path` | boolean | No | Write secret to temp file and return file path (default: false) |
| `interactive` | boolean | No | When set via `set`/`--ask` or filled by `check`, collect the value via a trusted local prompt instead of stdin (default: false) |
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
GITHUB_TOKEN = { description = "GitHub token", required = true, providers = ["env"] }

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

### Audit Logging

secretspec records every secret access to a local [audit log](/concepts/audit/).
Auditing is a per-machine/operator concern — where the log lives and whether it is
on — so it is configured in the **user-global config**, not the project's
`secretspec.toml`. A cloned repository therefore cannot redirect or silence your
audit log. Auditing is **on by default**; configure it under the top-level
`[audit]` table:

```toml title="~/.config/secretspec/config.toml"
[audit]
enabled = true                                   # set false to turn auditing off
path = "~/.local/state/secretspec/audit.log"     # default: per-user XDG state dir
max_size_bytes = 1048576                          # default: 1 MiB
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Whether to record secret access. |
| `path` | string | per-user state dir | Where to write the JSON Lines log. Must be absolute (a leading `~` is expanded); a relative path is rejected and auditing is disabled. |
| `max_size_bytes` | integer | `1048576` (1 MiB) | Hard size cap. At the cap the file is truncated and restarted; no rotated backups are kept. |

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

| Context | Behavior |
|---------|----------|
| CLI (`get`, `check`, `run`) | Files are persisted (not deleted after command exits) |
| Rust SDK | Files cleaned up when `ValidatedSecrets` is dropped; use `keep_temp_files()` to persist |
| Rust SDK types | `PathBuf` or `Option<PathBuf>` instead of `String` |

### interactive Option

When `interactive = true`, `secretspec set` collects the value from a **trusted
local prompt** ([pinentry](https://www.gnupg.org/related_software/pinentry/), with
a `/dev/tty` fallback) instead of reading it from stdin:

```toml
[profiles.production]
STRIPE_SECRET_KEY = { description = "Stripe secret key", interactive = true }
```

The value is typed on pinentry's own channel, not this process's stdin, so a
caller that only *triggers* the `set` (CI, a coding agent) never sees what you
type. secretspec itself still handles the value in order to write it to the
provider, so the guarantee is "the calling tool never sees it", not "only the
provider ever sees it". This works with **every provider**, since the prompt
happens before the value reaches the backend. Passing a value inline (`secretspec
set KEY value`) skips the prompt; the `--ask` flag forces it for any secret.

Because the value is read on the trusted channel and never on stdin, an
`interactive` secret does **not** consume a piped value: `echo secret | secretspec
set KEY` prompts instead of storing `secret` (and, with no pinentry and no
terminal, fails rather than reading the pipe). To set non-interactively (scripts,
CI seeding), pass the value inline (`secretspec set KEY "$VALUE"`) — inline always
wins — or leave the secret non-`interactive` so stdin is read.

`secretspec check` honors it too: when it fills a missing `interactive` secret it
uses the trusted prompt rather than stdin. Because that prompt does not read
stdin, `check` can fill an all-`interactive` set even when stdin is not a terminal
(e.g. an agent triggers `check` and a human fills the values); a missing
non-`interactive` secret still requires an interactive terminal.

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
