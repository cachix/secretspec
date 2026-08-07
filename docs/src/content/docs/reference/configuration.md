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

The `1.0` revision is backward compatible: newer SecretSpec versions continue
to support existing `revision = "1.0"` configurations, although they may add
features to the revision before SecretSpec 1.0 is released. With the SecretSpec
1.0 release, revision `1.0` will be finalized. Later configuration format
changes may be introduced under new revision numbers.

#### Requiring a reason for secret access

`require_reason` controls when secretspec demands a reason for accessing secrets.
It accepts three values:

| Value | Behavior |
|-------|----------|
| `"agents"` (default) | Require a reason only when SecretSpec heuristically classifies the current process as an AI agent. Sessions not classified as agents are unaffected. |
| `true` | Require a reason from every caller using SecretSpec (humans, CI, and agents). |
| `false` | Never require a reason. |

The policy is enforced at SecretSpec's secret-access entry points and travels
with the checked-in `secretspec.toml`. With `true`, every caller using the
manifest must supply a reason before SecretSpec proceeds:

```bash
# In a session SecretSpec detects as an agent, with the default "agents" policy:
$ secretspec run -- ./deploy.sh
Error: Accessing secrets requires a reason. Provide one with --reason "<why...>" ...

$ secretspec run --reason "Deploy web frontend" -- ./deploy.sh   # ok
```

:::caution[Agent detection is heuristic]
The default `"agents"` policy depends on detection. It can miss an unknown or
changed agent and can classify a session incorrectly. Use
`require_reason = true` when every SecretSpec caller must supply a reason.
:::

**Agent detection.** secretspec delegates heuristic detection of known agents to the
[`detect-coding-agent`](https://crates.io/crates/detect-coding-agent) crate, which
maintains the per-tool signal list (Claude Code, Cursor, Codex, Gemini CLI,
Copilot, and more). It treats **autonomous and hybrid** environments as agents but
not human-driven interactive editors. In addition, secretspec checks its own
`SECRETSPEC_AGENT` environment variable as an explicit opt-in:

```bash
# Mark any harness the detector does not recognize as an agent:
$ export SECRETSPEC_AGENT=1
```

Cooperative harnesses that are not auto-detected can set `SECRETSPEC_AGENT=1`.
Do not rely on a caller to identify itself when a reason is mandatory; use
`require_reason = true` instead.

The reason is recorded in secretspec's own [audit log](/concepts/audit/) and is
also forwarded to providers that support auditing (e.g. the
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

Under a [scope](#scopes-section), a group is judged over the members that scope
exposes, so a scoped consumer never inherits a guarantee that rests on a secret
it cannot see.

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
| `refs` (0.19+) | table | No | Provider-alias-scoped coordinates, keyed by leaf alias (e.g. `refs = { source = { item = "old" }, target = { item = "new" } }`); mutually exclusive with `ref` |
| `as_path` | boolean | No | Write secret to temp file and return file path (default: false) |
| `encoding` (0.19+) | `"base64"`, `"base64url"`, or `"hex"` | No | Encode logical values before storage writes and decode stored values after reads |
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

#### Composed Secrets

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
`default`, `providers`, `ref`, `refs` (0.19+), `type`, enabled `generate`, or
`encoding` (0.19+).

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
Scopes are added in **SecretSpec 0.17** and are unavailable in the current 0.16
release. With 0.16, give each service its own profile, or its own
`secretspec.toml`.
:::

See [Scopes](/concepts/scopes/) for the conceptual model and a focused
guide to narrowing services and tasks. This section specifies the complete
configuration and resolution behavior.

Scopes name membership-only subsets of a profile's secrets, so a single service
or task resolves only what it declares instead of the entire profile. They are
**orthogonal to profiles**: a profile decides how each secret resolves
(`required`, `default`, providers, references, generation, `as_path`,
`encoding` (0.19+), and the storage namespace); a scope only decides *which*
secrets take part in a given resolution.

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
- **Presence groups are judged over the visible members.** A `required =
  { at_least_one = … }` or `{ exactly_one = … }` group (see
  [Cross-secret presence constraints](#cross-secret-presence-constraints-017))
  is evaluated against the members
  the scope actually exposes. A group with no visible member is not that
  consumer's concern and is not enforced. A group with some visible members is
  enforced over those alone, so a scope never inherits a guarantee that rests on
  a secret it hides — if `at_least_one = "cloud"` is satisfied profile-wide by
  `GCP_KEY`, a scope showing only `AWS_KEY` still fails when `AWS_KEY` is absent.
  `exactly_one` remains enforced whenever two visible members are both present:
  scoping narrows what is judged, never whether it is judged. A secret fetched
  only as a hidden composition input does not count as present, and a violation
  message names only visible members. The reverse case cannot be detected,
  because a secret the scope hides is never fetched: if `exactly_one = "token"`
  is violated profile-wide by both `PRIMARY` and `FALLBACK` being present, a
  scope showing only `PRIMARY` reports success. A scoped check validates the
  scoped consumer, not the profile; run an unscoped `secretspec check` to
  validate the profile as a whole.
- `run --scope` removes **every** manifest-declared secret the scope does not
  admit from the launched command's environment, across *all* profiles rather
  than only the selected one, **even if the parent shell already exported
  them**, so a value inherited from another profile cannot leak into the child.
  Membership decides this, so a secret the scope lists survives even when the
  selected profile does not declare it (see the admitted rule below). This is
  secret minimization, not an authorization boundary: a process that still holds
  provider credentials could resolve another scope itself.
- `export --scope` **emits** the visible set but unsets nothing, since its
  output formats have no way to express an unset. Narrowing an environment that
  already holds a wider set therefore needs `run --scope`: after
  `eval "$(secretspec export)"`, a later
  `eval "$(secretspec export --scope api)"` leaves the previously exported
  values live in the shell.
- An **empty** scope (or a scope whose intersection with the profile is empty)
  resolves to nothing and contacts no provider.
- **Diagnostics do not name what the scope hides.** A provider warning about a
  hidden composition input calls it `a hidden composition input` rather than
  naming it, matching the way prompting is filtered, so a failing provider
  cannot disclose the very name the output filter removed. A visible secret is
  still named. This covers secretspec's own messages; a provider's error text is
  written by that provider and may still mention the address it searched.
- [Audit](#audit-logging) records what was **read**, not what was exposed: a
  scoped `check` logs the accessed set, including a composition input the scope
  hides, since the point of the log is to capture provider access. A `run` event
  logs what it injected — the visible set. Scoped `check`, `run`, and `export`
  events also carry the selected `scope` name (SecretSpec 0.17+).
- An `as_path` secret's resolved value is its temp-file path, so a visible
  composition built from a hidden `as_path` input embeds that path. The file
  stays alive for the duration of the command rather than being cleaned up with
  the hidden secret, so the path resolves. The hidden input is still absent from
  the environment; only its content, in the form the composition derived, is
  reachable — the same contract as a composed DSN that embeds a password.
- A secret the scope **admits** is never scrubbed from `run`, whether it fails
  to resolve (an optional secret with no stored value) or the selected profile
  does not declare it at all. A value the parent exported is inherited exactly
  as it would be without a scope; scoping changes which secrets are in play,
  never the semantics of one it admits. This is what lets a single scope be
  reused across profiles that declare different subsets.
- Under project `extends`, a child `[scopes.<name>]` **replaces** the parent
  scope of the same name outright — the two `secrets` lists are not unioned (see
  [Configuration Inheritance](/concepts/inheritance/)).
- Selecting an undefined scope, or a scope that lists a secret no profile
  declares, is a configuration error.
- A scope's `secrets` list must name at least one secret, with no blank or
  repeated entries. An empty scope is rejected rather than treated as "resolves
  to nothing": it would contact no provider, so `check --scope` would report a
  clean `0 found, 0 missing` while `run --scope` started the command with every
  manifest secret scrubbed and none injected. An empty *intersection* between a
  valid scope and the selected profile is still fine, since a scope is meant to
  be reused across profiles that declare different subsets.

The `--scope` flag (and the `SECRETSPEC_SCOPE` environment variable) apply to
`check`, `run`, and `export`. Scopes are a resolution-time feature of these
untyped paths. The write and copy commands are unaffected: `set` and `import`
ignore an ambient `SECRETSPEC_SCOPE` entirely, so a scope neither restricts what
they may write nor narrows the secrets they list. The untyped language SDK
builders also accept an explicit scope and return its name in resolve/report
results, and they honor `SECRETSPEC_SCOPE` when given none. The typed SDK
loaders generated by `secretspec-derive` always resolve the **full** profile and
deliberately **ignore** an ambient `SECRETSPEC_SCOPE`, since a generated struct
expects every declared field.

A **blank** `--scope` clears an inherited scope rather than being ignored:
`SECRETSPEC_SCOPE=api secretspec run --scope "" -- ./job` resolves the whole
profile and scrubs nothing. A blank `SECRETSPEC_SCOPE` with no flag means the
same, so a CI template that materializes an unset variable as an empty string
cannot silently narrow a job.

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
SESSION_SECRET = { description = "Session signing secret", required = true, providers = ["shared_vault"] }
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
Provider alias `ref` templates are available starting with SecretSpec 0.19.
Cached alias tables with `fallback` and `cache` are available since SecretSpec
0.17.
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
# SecretSpec 0.17+: add a provider alias to your user config
$ secretspec config global provider add prod_vault "onepassword://Production"

# SecretSpec 0.17+: list all aliases known to your user config
$ secretspec config global provider list

# SecretSpec 0.17+: remove an alias from your user config
$ secretspec config global provider remove prod_vault
```

These explicitly scoped CLI commands operate on the user-global config only —
edit `secretspec.toml` by hand to change project-level aliases.

#### SecretSpec 0.15 alias values

In SecretSpec 0.15 and later, an alias value is either a bare provider URI
string or a table that also declares the credentials the provider needs. Both
forms are accepted in the project `[providers]` and user
`[defaults.providers]` tables.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `uri` | string | Yes (table form) | The provider URI. A bare-string alias is shorthand for `{ uri = "..." }`. |
| `credentials` | table | No | Maps a semantic [provider credential](/reference/provider-credentials/) name to its source. |
| `ref` (0.19+) | table | No | Native-address template for this leaf alias. Coordinate strings may contain `{project}`, `{profile}`, and `{key}`. |

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

Configured credentials take precedence over provider environment fallbacks, credential chains are limited to one hop, and a fetched credential is never written to the environment. Store the credentials with [`secretspec config provider login`](/reference/cli/#config-provider-login). See [Provider credentials](/concepts/providers/#provider-credentials) for the full behavior.

Starting with SecretSpec 0.19, a leaf alias may also compile logical secret
names into that provider's native coordinates. Templates expand each
placeholder once; text inserted from a project, profile, or key is never
interpreted as another placeholder.

```toml title="secretspec.toml"
[providers]
remote = { uri = "onepassword://Production", ref = { item = "{project}-{profile}", field = "{key}" } }
local = { uri = "dotenv://.env", ref = { item = "{key}" } }

[profiles.production]
API_KEY = { description = "API key", providers = ["remote", "local"] }
```

Templates belong on the leaf aliases in a cached route, not on the cached
alias itself. Bare provider names and literal URIs have no alias identity, so
they use provider convention naming unless the secret declares legacy `ref`.

#### SecretSpec 0.19 inline provider cache

:::caution[Version compatibility]
Attaching `cache` directly to an alias with `uri` is available starting with
SecretSpec 0.19.
:::

Use `uri` and `cache` when one provider is authoritative. `credentials` remains
optional and configures that same provider:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `uri` | string | Yes | Authoritative provider URI. |
| `credentials` | table | No | Provider-specific credential sources for `uri`. |
| `cache` | table | Yes | Local cache policy containing `provider` and `max_age`. |
| `cache.provider` | string | Yes | Leaf provider spec used to store cache entries. Must support deletion and address a different store from `uri`. |
| `cache.max_age` | string | Yes | Positive duration with `s`, `m`, `h`, `d`, or `w` units, such as `30m`, `8h`, or `1d`. |

```toml title="secretspec.toml"
[providers]
local = "keyring://secretspec/cache/{project}/{profile}/{key}"
azure = {
  uri = "akv://team-vault",
  credentials = { client_secret = "keyring" },
  cache = { provider = "local", max_age = "8h" }
}

[profiles.development.defaults]
providers = ["azure"]
```

The alias remains both the selected cached route and the build key for its
authoritative provider, so its configured credentials apply normally.

#### SecretSpec 0.17 cached fallback alias values

:::caution[Version compatibility]
Cached provider aliases are available starting with SecretSpec 0.17.
:::

A cached fallback alias uses `fallback` and `cache` when more than one provider
can answer:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `fallback` | array[string] | Yes | Non-empty authoritative provider route. Reads try entries in order; writes use the first entry. |
| `cache` | table | Yes | Local cache policy containing `provider` and `max_age`. |
| `cache.provider` | string | Yes | Leaf provider spec used to store cache entries. Must support deletion (keyring, pass, gopass, dotenv, Vault/OpenBao KV v2) and be a different store from every `fallback` entry. |
| `cache.max_age` | string | Yes | Positive duration with `s`, `m`, `h`, `d`, or `w` units, such as `30m`, `8h`, or `1d`. |

```toml title="secretspec.toml"
[providers]
azure = { uri = "akv://team-vault", credentials = { client_secret = "keyring" } }
env = "env://"
local = "keyring://secretspec/cache/{project}/{profile}/{key}"
myprovider = { fallback = ["azure", "env"], cache = { provider = "local", max_age = "8h" } }

[profiles.development.defaults]
providers = ["myprovider"]
```

Every cached alias is a complete route and must be the only entry when selected
through `providers`, in any position. Fallback entries and the cache provider
accept aliases, provider names, and URIs, but must resolve to leaf providers;
cached aliases cannot be nested, and the cache must resolve to a different
store than the route's own authoritative providers, since it holds its entries
at the same logical address. The cache provider must also be one SecretSpec can
delete from — keyring, pass, gopass, dotenv, or a Vault/OpenBao KV v2 mount —
since every form of invalidation is a delete. Put credentials on leaf aliases
rather than the cached fallback alias.
See [Provider caching](/concepts/providers/caching/)
for freshness, failure, invalidation, and clearing behavior.

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

When combined with `encoding` (0.19+), the file contains the decoded bytes
rather than the stored textual representation.

| Context | Behavior |
|---------|----------|
| CLI (`get`, `check`, `run`) | Files are persisted (not deleted after command exits) |
| Rust SDK | Files cleaned up when `ValidatedSecrets` is dropped; use `keep_temp_files()` to persist |
| Rust SDK types | `PathBuf` or `Option<PathBuf>` instead of `String` |

### Secret Encoding (0.19+)

:::caution[Version compatibility]
Available starting in SecretSpec 0.19.
:::

`encoding` (0.19+) defines the textual representation stored by providers and
the cache. It is independent of `as_path`: decoded UTF-8 remains an ordinary
environment or SDK value, while arbitrary decoded bytes can be materialized to
a file.

```toml
[profiles.default]
# encoding is available in SecretSpec 0.19+
TEXT_CONFIG = { description = "Encoded text", encoding = "base64" }
KEYSTORE = { description = "Binary mTLS keystore", encoding = "base64", as_path = true }
URL_SAFE_KEY = { description = "URL-safe encoded key", encoding = "base64url", as_path = true }
HEX_KEY = { description = "Hex-encoded key", encoding = "hex", as_path = true }
```

| Encoding (0.19+) | Written representation | Accepted stored representation |
|------------------|------------------------|--------------------------------|
| `base64` | RFC 4648 standard Base64 with padding | Padded or unpadded standard Base64 |
| `base64url` | RFC 4648 URL-safe Base64 without padding | Padded or unpadded URL-safe Base64 |
| `hex` | Lowercase RFC 4648 Base16 | Uppercase, lowercase, or mixed-case Base16 |

Exactly one trailing LF or CRLF is accepted so command-captured values work
without preprocessing. Other whitespace and non-alphabet characters are
rejected. Without `as_path = true`, decoded bytes must be valid UTF-8.

`secretspec set`, interactive prompts, and generated secrets provide logical
text; SecretSpec encodes it before writing to a provider or cache. Defaults and
composed results are already logical and are not transformed. The
`secretspec import` command copies the stored representation verbatim, avoiding
double encoding.

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
| `version` | No | Which revision of the secret to read. Supported by versioned stores such as Google Secret Manager and AWS Parameter Store (0.18+); defaults to the latest |

Stores fall into two groups for `field`:

| Store | Shape of one secret | `field` |
|-------|---------------------|---------|
| dotenv, env, pass, LastPass, Proton Pass, Bitwarden, AWS Parameter Store (0.18+) | a single value | Rejected: there is nothing to select |
| 1Password, Keeper (0.18+), Vault KV, AWS Secrets Manager, keyring | a record of named parts | Selects the part: field label, map key, JSON key, account |

`vault` is the only container coordinate. For every store except 1Password the
container is part of the provider URI, not the ref:

```toml
# The mount `kv2` comes from the URI; the ref names the path inside it.
DB = { description = "DB", ref = { item = "myapp/config", field = "pw" }, providers = ["vault://vault.example.com:8200/kv2"] }

# 1Password: `vault` on the ref overrides the URI's default vault.
TOKEN = { description = "Token", ref = { vault = "Production", item = "infra", field = "token" }, providers = ["onepassword://Private"] }
```

Which provider resolves a `ref` follows the ordinary [provider resolution
order](/concepts/providers/fallback/); a `ref` composes with the `providers` fallback
chain, and each provider is asked for the same coordinates.

#### Provider-scoped references (0.19+)

:::caution[Version compatibility]
Provider-scoped `refs` and provider-alias `ref` templates are available
starting with SecretSpec 0.19.
:::

Use `refs` when one logical secret already has different native coordinates in
different providers. Keys are leaf provider aliases; they are identity, not a
URI lookup, so aliases that happen to resolve to the same URI remain distinct.
An entry may name an import-only source alias that is absent from the secret's
ordinary `providers` route.

```toml
[providers]
old = "onepassword://Legacy"
new = { uri = "onepassword://Production", ref = { item = "{project}-{profile}", field = "{key}" } }
local = "keyring://"

[profiles.production]
API_KEY = { description = "API key", providers = ["new", "local"], refs = { old = { item = "legacy-api", field = "token" } } }
```

For each selected endpoint, address resolution is:

1. Legacy route-wide `ref`, when present (for compatibility).
2. The matching `refs.<alias>` entry.
3. The matching alias's `ref` template.
4. The provider's ordinary `{project}/{profile}/{key}` convention.

`ref` and `refs` cannot be combined on one effective secret. Every `refs` key
must name a defined leaf alias; cached route aliases cannot own templates or be
used as scoped-ref keys. A literal URI or bare provider name has no alias key,
so only legacy `ref` or convention naming applies to it.

During profile inheritance, `ref` and `refs` (0.19+) form one setting rather
than two independently inherited fields. The most specific profile entry that
declares either form supplies the whole setting: an explicit `refs` replaces an
inherited `ref`, and an explicit `ref` replaces inherited `refs`. If the profile
entry declares neither, it inherits whichever form `[profiles.default]` uses.

#### How providers interpret the coordinates

| Provider | `item` | `field` | Without `field` | Writes via ref |
|----------|--------|---------|-----------------|----------------|
| [OnePassword](/providers/onepassword/#use-existing-secrets) | Item title or UUID | Field label; `vault` and `section` also apply | Reads the item like a convention secret (its value or password field); writes edit the `value` field | ✅ via `op item edit` (adds a missing field, never creates items) |
| [Keeper (0.18+)](/providers/keeper/#use-existing-records) | Record UID or exact title | Standard field type/label or custom field label | Reads `password` | ✅ for existing records and fields |
| [keyring](/providers/keyring/#use-existing-secrets) | Service | Account (defaults to the current system username) | Current user's entry | ✅ |
| [dotenv](/providers/dotenv/#use-existing-secrets) | `.env` key | Rejected | Reads the key | ✅ |
| [env](/providers/env/#use-existing-secrets) | Variable name | Rejected | Reads the variable | — (read-only) |
| [systemd credentials (0.17+)](/providers/systemd-credential/#use-an-existing-credential-name) | Credential filename | Rejected | Reads the credential | — (read-only) |
| [pass](/providers/pass/#use-existing-secrets) | Entry path | Rejected | Reads the entry | ✅ |
| [Gopass (0.15+)](/providers/gopass/#use-existing-secrets) | Entry path, including any mount-point prefix | Rejected | Reads the entry | ✅ |
| [LastPass](/providers/lastpass/#use-existing-secrets) | Item name | Rejected | Reads the item | ✅ |
| [Dashlane (0.18+)](/providers/dashlane/#use-existing-secrets) | Item title or identifier | Field name on the item | Reads the type's default field (`content`, or `password` for a login) | — (read-only) |
| [Proton Pass](/providers/protonpass/#use-existing-secrets) | Item title | Rejected | Reads the note | ✅ |
| [Vault](/providers/vault/#use-existing-secrets) | KV path relative to the mount | Required (KV entries are maps) | Error | — (read-only) |
| [OpenBao](/providers/openbao/#use-existing-secrets) (0.17+) | KV path relative to the mount | Required (KV entries are maps) | Error | — (read-only) |
| [AWS Secrets Manager](/providers/awssm/#use-existing-secrets) | Secret name or ARN | JSON key | Whole secret string | — (read-only) |
| [AWS Parameter Store (0.18+)](/providers/awsps/#use-existing-parameters) | Parameter name or ARN; `version` selects a version or label | Rejected | Reads the decrypted value | ✅ by unversioned parameter name; version, label, and ARN refs are read-only |
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
- With `providers = ["null"]` (0.19+), a fresh generated value is returned only for the current resolution and is not written to provider storage
- Subsequent runs find the stored value and skip generation (idempotent)
- `generate` and `default` cannot both be set on the same secret
- `type = "command"` requires `generate = { command = "..." }` (not just `generate = true`)

## Profile Inheritance

- All profiles automatically inherit from `[profiles.default]`
- Profile-specific values override default values
- `ref` and `refs` (0.19+) are alternative forms of one setting: declaring
  either in a profile replaces the form inherited from `[profiles.default]`,
  while declaring neither inherits it
- Use the `extends` field in `[project]` to inherit from other secretspec.toml files
