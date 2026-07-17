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
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Project identifier |
| `revision` | string | Yes | Format version (must be "1.0") |
| `extends` | array[string] | No | Paths to parent configuration files |
| `require_reason` | `"agents"` \| boolean | No | When secret access must supply a reason (via `--reason`, `SECRETSPEC_REASON`, or the SDK's `with_reason()`). Defaults to `"agents"`. |

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

#### Cross-secret presence constraints (0.17+)

:::caution[Version compatibility]
Added in SecretSpec 0.17.
:::

A profile can require alternative credentials by assigning secrets to a named
group:

```toml
[profiles.default]
PASSWORD = { description = "Account password", required = { at_least_one = "account_auth" } }
ACCESS_TOKEN = { description = "Personal access token", required = { at_least_one = "account_auth" } }

GITHUB_TOKEN = { description = "GitHub token", required = { exactly_one = "github_auth" } }
GITHUB_APP_KEY = { description = "GitHub App private key", required = { exactly_one = "github_auth" } }
```

`at_least_one` requires one or more group members to resolve; `exactly_one`
requires one. Each field also accepts an array of group names for overlapping
groups. Groups must contain at least two secrets and cannot mix modes. Group
members are individually optional.

#### Secret Variable Options

Each secret variable is defined as a table with the following fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `description` | string | Yes (see notes) | Human-readable description of the secret |
| `required` | boolean or table | No | Whether absence is an error; the table form (0.17+) accepts `at_least_one`/`exactly_one` presence groups (defaults to true; false with `default` or a presence group) |
| `default` | string | No | Default value if not provided |
| `composed` (0.16+) | string | No | Derive a read-only value from other declared secrets using `${UPPERCASE_NAME}` references |
| `providers` | array[string] | No | List of provider aliases to use in fallback order |
| `ref` | table | No | Coordinates naming an externally managed secret in the provider's store (e.g. `ref = { item = "db", field = "password" }`) |
| `as_path` | boolean | No | Write secret to temp file and return file path (default: false) |
| `type` | string | No | Secret type for generation: `password`, `hex`, `base64`, `uuid`, `command`, `rsa_private_key` |
| `generate` | boolean or table | No | Enable auto-generation when secret is missing |

Field notes:

- `description` is required in the `default` profile. A secret overriding one
  that the default profile already declares inherits its `description` (and
  other omitted fields) and may leave it out.
- `required` defaults to false when `default` is provided. In 0.17+, its table
  form accepts `at_least_one` and `exactly_one` as a group name or array of names.
- `default` is invalid with an explicit `required = true`. A defaulted secret is
  guaranteed to be present in successful resolution and generated types, even
  though the provider does not have to supply it.
- `type` is required when `generate` is enabled.
- `generate` and `default` cannot both be set.

#### Composed secrets

:::caution[Version compatibility]
Available since SecretSpec 0.16.
:::

A composed secret derives a value from other secrets in the effective profile.
See [Composed Secrets](/concepts/composed-secrets/) for the dependency model,
CLI behavior, profile inheritance, and the differences from dotenv expansion:

```toml
[profiles.default]
DB_USER = { description = "Database user" }
DB_PASSWORD = { description = "Database password" }
DB_HOST = { description = "Database host" }
DATABASE_URL = { description = "PostgreSQL DSN", composed = "postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}/app" }
```

References form a static dependency graph. Declaration order does not matter,
and composed secrets may reference other composed secrets. SecretSpec rejects
unknown references, cycles, malformed references, and source conflicts while
loading the manifest. A composed secret is read-only and cannot also set
`default`, `providers`, `ref`, `type`, or enabled `generate`.

Composition intentionally does **not** implement dotenv or shell expansion:

- only `${UPPERCASE_NAME}` is a reference, and the name must match
  `[A-Z][A-Z0-9_]*` and identify a declared secret;
- ambient environment variables are never consulted;
- fallback operators such as `${NAME:-fallback}`, commands, and recursive
  expansion are unsupported;
- inserted values are opaque and are never scanned again;
- `$$` produces a literal `$` (`$${NAME}` renders `${NAME}`), while ordinary
  braces are literal;
- a missing dependency makes a required composition missing, while a
  `required = false` composition is omitted;
- empty values remain empty and are distinct from missing values.

If a dependency uses `as_path = true`, its exported temporary-file path is the
text inserted into the composed value. Applying `as_path = true` to the
composed secret materializes the final combined value.

Composition is raw string concatenation. SecretSpec cannot know whether a
component occupies a URL username, password, host, path, query, or structured
document position, so it does not URL-encode or JSON-encode components. Store
components in the form required by the target format; use
`secretspec export --format json` when exporting the resolved secret map as
JSON.

### [scopes] Section

:::note[Version compatibility]
Scopes are available from **SecretSpec 0.16**. They are not available in
0.15 or earlier.
:::

Scopes name membership-only subsets of a profile's secrets, so a single service
or task resolves only what it declares instead of the entire profile. They are
**orthogonal to profiles**: a profile decides how each secret resolves
(`required`, `default`, providers, references, generation, `as_path`, and the
storage namespace); a scope only decides *which* secrets take part in a given
resolution.

```toml
[profiles.default]
DATABASE_URL = { description = "Database", required = true }
API_KEY      = { description = "API key", required = true }
QUEUE_TOKEN  = { description = "Queue token", required = true }

[scopes.api]
secrets = ["DATABASE_URL", "API_KEY"]

[scopes.worker]
secrets = ["DATABASE_URL", "QUEUE_TOKEN"]
```

```bash
secretspec run --scope api    -- ./api      # sees DATABASE_URL, API_KEY
secretspec run --scope worker -- ./worker   # sees DATABASE_URL, QUEUE_TOKEN
secretspec check  --scope api
secretspec export --scope worker --format dotenv
```

Behavior:

- **No scope** resolves the complete profile, exactly as before scopes existed.
- Selecting a scope resolves the **intersection** of the merged profile and the
  scope's `secrets` list — the *visible* set. A secret the profile does not
  declare is simply absent from that resolution rather than an error, so a scope
  can be reused across profiles that declare different subsets.
- A required secret **excluded** by the active scope does not block resolution —
  it is not part of the scoped set.
- **Composed secrets resolve their inputs without exposing them.** When a visible
  [composed secret](/concepts/composed-secrets/) references secrets the scope
  leaves out (for example `DATABASE_URL` built from `DB_USER` and `DB_PASSWORD`),
  those dependencies are fetched to build the composition and then dropped from
  the output — the child sees `DATABASE_URL`, never `DB_USER`/`DB_PASSWORD`. A
  secret that is neither visible nor a dependency of a visible secret is never
  fetched, so no provider is contacted for it.
- A scope does not change a secret's storage address
  (`{project}/{profile}/{key}`); it only narrows the set.
- `run --scope` removes **every** manifest-declared secret outside the visible
  set from the launched command's environment — across *all* profiles, not just
  the selected one — **even if the parent shell already exported them**, so a
  value inherited from another profile cannot leak into the child. This is secret
  minimization, not an authorization boundary: a process that still holds
  provider credentials could resolve another scope itself.
- An **empty** scope (or a scope whose intersection with the profile is empty)
  resolves to nothing and contacts no provider.
- Under project `extends`, a child `[scopes.<name>]` **replaces** the parent
  scope of the same name outright — the two `secrets` lists are not unioned (see
  [Configuration Inheritance](/concepts/inheritance/)).
- Selecting an undefined scope, or a scope that lists a secret no profile
  declares, is a configuration error.

The `--scope` flag (and the `SECRETSPEC_SCOPE` environment variable) apply to
`check`, `run`, and `export`. The typed SDK loaders generated by
`secretspec-derive` deliberately **ignore** an ambient `SECRETSPEC_SCOPE`, since a
generated struct always expects the full profile; scope a typed load explicitly
through its builder if you need one.

## Complete Example

```toml
# secretspec.toml
[project]
name = "web-api"
revision = "1.0"
extends = ["../shared/secretspec.toml"]  # Optional inheritance

# Provider aliases used by profile provider chains
[providers]
prod_vault = "onepassword://Production"
shared_vault = "onepassword://Shared"
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

:::note[Version compatibility]
Provider alias tables with `uri` and `credentials` are available since
SecretSpec 0.15. SecretSpec 0.14 accepts only bare URI strings; when using
0.14, configure provider credentials through the provider's existing
environment variables, such as `BWS_ACCESS_TOKEN`.
:::

```toml title="secretspec.toml"
[providers]
prod_vault = "onepassword://Production"
shared_vault = "onepassword://Shared"
keyring = "keyring://"
env = "env://"

[profiles.production]
DATABASE_URL = { description = "Production DB", providers = ["prod_vault", "keyring"] }
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

Manage user-level aliases via CLI:

```bash
# Add a provider alias to your user config
$ secretspec config provider add prod_vault "onepassword://Production"

# List all aliases known to your user config
$ secretspec config provider list

# Remove an alias from your user config
$ secretspec config provider remove prod_vault
```

The CLI commands operate on the user-global config only — edit `secretspec.toml` by hand to change project-level aliases.

#### SecretSpec 0.15 alias values

In SecretSpec 0.15 and later, an alias value is either a bare provider URI
string or a table that also declares the credentials the provider needs. Both
forms are accepted in the project `[providers]` and user
`[defaults.providers]` tables.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `uri` | string | Yes (table form) | The provider URI. A bare-string alias is shorthand for `{ uri = "..." }`. |
| `credentials` | table | No | Maps a semantic provider credential name to its [source](/concepts/providers/#provider-credentials). |

Each `credentials` value is either a bare provider spec — read at the convention path for the active project and profile — or a table `{ provider = "...", ref = { ... } }` that pins the exact location with the same `ref` coordinates a secret uses.

```toml title="secretspec.toml"
[providers]
keyring = "keyring://"
# bare string: read access_token from keyring at the convention path
bws = { uri = "bws://project-uuid", credentials = { access_token = "keyring" } }

[providers.vault_prod]
uri = "vault://secret/myapp?auth=approle"
credentials = { role_id   = { provider = "onepassword", ref = { vault = "Infra", item = "vault-approle", field = "role_id" } },
                secret_id = { provider = "onepassword", ref = { vault = "Infra", item = "vault-approle", field = "secret_id" } } }
```

Configured credentials take precedence over provider environment fallbacks, credential chains are limited to one hop, and a fetched credential is never written to the environment. Store the credentials with [`secretspec config provider login`](/reference/cli/#config-provider-login). See [Provider Credentials](/concepts/providers/#provider-credentials) for the full behavior.

#### SecretSpec 0.14 alias values

In SecretSpec 0.14, every alias value must be a provider URI string:

```toml title="secretspec.toml"
[providers]
bws = "bws://project-uuid"
```

For example, authenticate the 0.14 BWS provider by setting its environment
variable before running SecretSpec:

```bash
export BWS_ACCESS_TOKEN="0.your-access-token..."
secretspec check
```

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

### Secret References

The `ref` field names one externally managed secret by the store's own
coordinates, instead of SecretSpec's `{project}/{profile}/{key}` convention. See
[Secret References](/concepts/references/) for the concept, model, and examples;
this section is the specification.

```toml
[profiles.production]
DATABASE_URL = { description = "Postgres DSN", ref = { item = "db", field = "password" }, providers = ["prod_vault"] }
INFRA_TOKEN  = { description = "Infra token", ref = { vault = "Production", item = "infra", field = "token" } }
GITHUB_TOKEN = { description = "GitHub token", ref = { item = "GITHUB_PAT" }, providers = ["env"] }
```

`ref` is a table of provider-independent coordinates. Unknown keys are rejected
at parse time. Only `item` is universal; it is the secret's complete name in the
store and replaces the whole convention path, including any `folder_prefix` or
format string the provider is configured with (nothing is prepended). A
coordinate a store has no equivalent for is rejected with an error naming it,
never silently ignored.

| Coordinate | Required | Meaning |
|------------|----------|---------|
| `item` | Yes | The store's complete name for the secret. Replaces the whole convention path |
| `field` | No | A named component inside the item. Rejected by stores whose secrets hold a single value |
| `vault` | No | The container holding the item. 1Password only; other stores take their container from the provider URI |
| `section` | No | A named group of fields inside the item. 1Password only; requires `field` |
| `version` | No | Which revision of the secret to read. Google Secret Manager only; defaults to the latest |

Stores fall into two groups for `field`:

| Store | Shape of one secret | `field` |
|-------|---------------------|---------|
| dotenv, env, pass, LastPass, Proton Pass, Bitwarden | a single value | Rejected: there is nothing to select |
| 1Password, Vault KV, AWS Secrets Manager, keyring | a record of named parts | Selects the part: field label, map key, JSON key, account |

`vault` is the only container coordinate. For every store except 1Password the
container is part of the provider URI, not the ref:

```toml
# The mount `kv2` comes from the URI; the ref names the path inside it.
DB = { description = "DB", ref = { item = "myapp/config", field = "pw" }, providers = ["vault://vault.example.com:8200/kv2"] }

# 1Password: `vault` on the ref overrides the URI's default vault.
TOKEN = { description = "Token", ref = { vault = "Production", item = "infra", field = "token" }, providers = ["onepassword://Private"] }
```

Which provider resolves a `ref` follows the ordinary [provider resolution
order](/concepts/providers/); a `ref` composes with the `providers` fallback
chain, and each provider is asked for the same coordinates.

#### How providers interpret the coordinates

| Provider | `item` | `field` | Without `field` | Writes via ref |
|----------|--------|---------|-----------------|----------------|
| [OnePassword](/providers/onepassword/#use-existing-secrets) | Item title or UUID | Field label; `vault` and `section` also apply | Reads the item like a convention secret (its value or password field); writes edit the `value` field | ✅ via `op item edit` (adds a missing field, never creates items) |
| [keyring](/providers/keyring/#use-existing-secrets) | Service | Account (defaults to the current system username) | Current user's entry | ✅ |
| [dotenv](/providers/dotenv/#use-existing-secrets) | `.env` key | Rejected | Reads the key | ✅ |
| [env](/providers/env/#use-existing-secrets) | Variable name | Rejected | Reads the variable | — (read-only) |
| [systemd credentials (0.17+)](/providers/systemd-credential/#use-an-existing-credential-name) | Credential filename | Rejected | Reads the credential | — (read-only) |
| [pass](/providers/pass/#use-existing-secrets) | Entry path | Rejected | Reads the entry | ✅ |
| [Gopass (0.15+)](/providers/gopass/#use-existing-secrets) | Entry path, including any mount-point prefix | Rejected | Reads the entry | ✅ |
| [LastPass](/providers/lastpass/#use-existing-secrets) | Item name | Rejected | Reads the item | ✅ |
| [Proton Pass](/providers/protonpass/#use-existing-secrets) | Item title | Rejected | Reads the note | ✅ |
| [Vault](/providers/vault/#use-existing-secrets) | KV path relative to the mount | Required (KV entries are maps) | Error | — (read-only) |
| [OpenBao](/providers/openbao/#use-existing-secrets) (0.17+) | KV path relative to the mount | Required (KV entries are maps) | Error | — (read-only) |
| [AWS Secrets Manager](/providers/awssm/#use-existing-secrets) | Secret name or ARN | JSON key | Whole secret string | — (read-only) |
| [GCSM](/providers/gcsm/#use-existing-secrets) | Secret id; `version` also applies | Rejected | Reads latest or the pinned version | — (read-only) |
| [Bitwarden (bws)](/providers/bws/#use-existing-secrets) | BWS key name | Rejected | Reads the key | ✅ |
| [Azure Key Vault (0.15+)](/providers/akv/#use-existing-secrets) | Secret name | Rejected | Reads the secret | — (read-only) |
| [Infisical (0.16+)](/providers/infisical/#use-existing-secrets) | Folder and key; `version` also applies | Rejected | Reads the latest version | ✅ unless a version is pinned |

A provider rejects coordinates it has no equivalent for, with an error naming
the coordinate (for example, `field` on the env provider).

#### Writing through a ref

Writes are symmetric with reads: `secretspec set` and interactive `check`
prompting write through the coordinates in place wherever the table above says
writes are supported. Read-only stores fail with a clear error instead.

#### No string refs

`ref` is always a table. String and URI forms (`ref = "op://vault/item/field"`,
`ref = "env://VAR"`, query-parameter URIs, and similar) are rejected, and the
error spells out the exact table translation. For example, a pasted 1Password
reference `op://Production/infra/token` translates to:

```toml
INFRA_TOKEN = { description = "Infra token", ref = { vault = "Production", item = "infra", field = "token" }, providers = ["onepassword://Production"] }
```

Provider URIs stay store addresses only: `onepassword://Production` names a
vault, and item paths on provider URIs are errors.

#### Deduplication, auditing, and reporting

- Secrets sharing identical coordinates and store are fetched once.
- [Audit log](/concepts/audit/) events carry a `ref` field with the coordinates.
- `check --explain` and `check --json` attribute ref secrets to the store URI
  they resolved from.

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
