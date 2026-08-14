---
title: monosecret.toml Reference
description: Complete reference for monosecret.toml configuration options
---

## monosecret.toml Reference

The `monosecret.toml` file defines project-specific secret requirements. This file should be checked into version control.

### [project] Section

<!-- monosecret-test: project -->

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

The `1.0` revision is backward compatible: newer Monosecret versions continue
to support existing `revision = "1.0"` configurations, although they may add
features to the revision before Monosecret 1.0 is released. With the Monosecret
1.0 release, revision `1.0` will be finalized. Later configuration format
changes may be introduced under new revision numbers.

#### Requiring a reason for secret access

`require_reason` controls when monosecret demands a reason for accessing secrets.
It accepts three values:

| Value                | Behavior                                                                                                                                             |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `"agents"` (default) | Require a reason only when Monosecret heuristically classifies the current process as an AI agent. Sessions not classified as agents are unaffected. |
| `true`               | Require a reason from every caller using Monosecret (humans, CI, and agents).                                                                        |
| `false`              | Never require a reason.                                                                                                                              |

The policy is enforced at Monosecret's secret-access entry points and travels
with the checked-in `monosecret.toml`. With `true`, every caller using the
manifest must supply a reason before Monosecret proceeds:

```bash
# In a session Monosecret detects as an agent, with the default "agents" policy:
$ monosecret run -- ./deploy.sh
Error: Accessing secrets requires a reason. Provide one with --reason "<why...>" ...

$ monosecret run --reason "Deploy web frontend" -- ./deploy.sh   # ok
```

:::caution[Agent detection is heuristic]
The default `"agents"` policy depends on detection. It can miss an unknown or
changed agent and can classify a session incorrectly. Use
`require_reason = true` when every Monosecret caller must supply a reason.
:::

**Agent detection.** monosecret delegates heuristic detection of known agents to the
[`detect-coding-agent`](https://crates.io/crates/detect-coding-agent) crate, which
maintains the per-tool signal list (Claude Code, Cursor, Codex, Gemini CLI,
Copilot, and more). It treats **autonomous and hybrid** environments as agents but
not human-driven interactive editors. In addition, monosecret checks its own
`MONOSECRET_AGENT` environment variable as an explicit opt-in:

```bash
# Mark any harness the detector does not recognize as an agent:
$ export MONOSECRET_AGENT=1
```

Cooperative harnesses that are not auto-detected can set `MONOSECRET_AGENT=1`.
Do not rely on a caller to identify itself when a reason is mandatory; use
`require_reason = true` instead.

The reason is recorded in monosecret's own [audit log](/concepts/audit/) and is
also forwarded to providers that support auditing (e.g. the
[Proton Pass](/providers/protonpass/) provider records it in the agent audit log).

### [profiles.*] Section

Defines secret variables for different environments. At least one profile is
required. A `default` profile is optional; when present, other profiles inherit
from it unless they opt out in Monosecret 0.2+.

```toml
[profiles.default] # Optional shared base profile
DATABASE_URL = { description = "PostgreSQL connection", required = true }
API_KEY = { description = "External API key", required = true }
REDIS_URL = { description = "Redis cache", required = false, default = "redis://localhost:6379" }

[profiles.production] # Additional profile (optional)
DATABASE_URL = { required = true } # description inherited from default
```

#### Profile defaults

`[profiles.<name>.defaults]` supplies settings for secrets declared in that
profile:

| Field            | Type          | Required | Description                                                                                                             |
| ---------------- | ------------- | -------- | ----------------------------------------------------------------------------------------------------------------------- |
| `inherit` (0.2+) | boolean       | No       | For a non-default profile, whether to inherit declarations and omitted fields from `[profiles.default]` (default: true) |
| `required`       | boolean       | No       | Default requiredness for secrets declared in this profile                                                               |
| `default`        | string        | No       | Default value for secrets declared in this profile                                                                      |
| `providers`      | array[string] | No       | Default provider chain for secrets declared in this profile                                                             |

In Monosecret 0.2+, set `inherit = false` for a standalone profile:

```toml
[profiles.deployment.defaults]
inherit = false

[profiles.deployment]
DEPLOY_TOKEN = { description = "Deployment credential", required = true }
```

This excludes every `[profiles.default]` declaration and prevents explicitly
redeclared secrets from inheriting omitted fields. The setting has no effect on
the `default` profile itself. A standalone profile must declare at least one
secret.

#### Cross-secret presence constraints (0.2+)

:::caution[Version compatibility]
Added in Monosecret 0.2.
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

| Field             | Type                                  | Required        | Description                                                                                                                                                          |
| ----------------- | ------------------------------------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `description`     | string                                | Yes (see notes) | Human-readable description of the secret                                                                                                                             |
| `required`        | boolean or table                      | No              | Whether absence is an error; the table form (0.2+) accepts `at_least_one`/`exactly_one` presence groups (defaults to true; false with `default` or a presence group) |
| `default`         | string                                | No              | Default value if not provided                                                                                                                                        |
| `composed` (0.2+) | string                                | No              | Derive a read-only value from other declared secrets using `${UPPERCASE_NAME}` references                                                                            |
| `providers`       | array[string]                         | No              | List of provider aliases to use in fallback order                                                                                                                    |
| `ref`             | table                                 | No              | Coordinates naming an externally managed secret in the provider's store (e.g. `ref = { item = "db", field = "password" }`)                                           |
| `refs` (0.2+)     | table                                 | No              | Provider-alias-scoped coordinates, keyed by leaf alias (e.g. `refs = { source = { item = "old" }, target = { item = "new" } }`); mutually exclusive with `ref`       |
| `as_path`         | boolean                               | No              | Write secret to temp file and return file path (default: false)                                                                                                      |
| `encoding` (0.2+) | `"base64"`, `"base64url"`, or `"hex"` | No              | Encode logical values before storage writes and decode stored values after reads                                                                                     |
| `extract` (0.2+)  | table                                 | No              | Select one logical value from stored structured data, for example `extract = { format = "json", pointer = "/database/password" }`                                    |
| `type`            | string                                | No              | Secret type for generation: `password`, `hex`, `base64`, `uuid`, `command`, `rsa_private_key`                                                                        |
| `generate`        | boolean or table                      | No              | Enable auto-generation when secret is missing                                                                                                                        |
| `prompt` (0.2+)   | boolean                               | No              | Securely prompt for a missing value during `monosecret run`; the selected provider controls persistence                                                              |

Field notes:

- `description` is required on the effective secret. An inheriting profile may
  omit it when a matching default declaration supplies it. A standalone
  profile using `inherit = false` (0.2+) must supply its own description.
- `required` defaults to false when `default` is provided. In 0.2+, its table
  form accepts `at_least_one` and `exactly_one` as a group name or array of names.
- `default` is invalid with an explicit `required = true`. A defaulted secret is
  guaranteed to be present in successful resolution and generated types, even
  though the provider does not have to supply it.
- `type` is required when `generate` is enabled.
- `generate` and `default` cannot both be set.
- `prompt = true` (0.2+) is for individually required secrets and cannot be
  combined with `default`, enabled `generate`, `extract`, or `composed`.
- `extract` (0.2+) is read-only and cannot be combined with enabled
  `generate`.

#### Composed Secrets

:::caution[Version compatibility]
Available since Monosecret 0.2.
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
and composed secrets may reference other composed secrets. Monosecret rejects
unknown references, cycles, malformed references, and source conflicts while
loading the manifest. A composed secret is read-only and cannot also set
`default`, `providers`, `ref`, `refs` (0.2+), `type`, enabled `generate`,
`encoding` (0.2+), or `extract` (0.2+).

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

Composition is raw string concatenation. Monosecret cannot know whether a
component occupies a URL username, password, host, path, query, or structured
document position, so it does not URL-encode or JSON-encode components. Store
components in the form required by the target format; use
`monosecret export --format json` when exporting the resolved secret map as
JSON.

### [scopes] Section

:::note[Version compatibility]
Scopes are added in **Monosecret 0.2** and are unavailable in the current 0.2
release. With 0.2, give each service its own profile, or its own
`monosecret.toml`.
:::

See [Scopes](/concepts/scopes/) for the conceptual model and a focused
guide to narrowing services and tasks. This section specifies the complete
configuration and resolution behavior.

Scopes name membership-only subsets of a profile's secrets, so a single service
or task resolves only what it declares instead of the entire profile. They are
**orthogonal to profiles**: a profile decides how each secret resolves
(`required`, `default`, providers, references, generation, prompts (0.2+), `as_path`,
`encoding` (0.2+), `extract` (0.2+), and the storage namespace); a scope only
decides _which_ secrets take part in a given resolution.

```toml
[profiles.default]
DATABASE_URL = { description = "Database", required = true }
API_KEY = { description = "API key", required = true }
QUEUE_TOKEN = { description = "Queue token", required = true }

[scopes.api]
secrets = ["DATABASE_URL", "API_KEY"]

[scopes.worker]
secrets = ["DATABASE_URL", "QUEUE_TOKEN"]
```

```bash
$ monosecret run --scope api    -- ./api      # sees DATABASE_URL, API_KEY

$ monosecret run --scope worker -- ./worker   # sees DATABASE_URL, QUEUE_TOKEN

$ monosecret check  --scope api

$ monosecret export --scope worker --format dotenv
```

Behavior:

- **No scope** resolves the complete profile, exactly as before scopes existed.
- Selecting a scope resolves the **intersection** of the merged profile and the
  scope's `secrets` list — the _visible_ set. A secret the profile does not
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
  scoped consumer, not the profile; run an unscoped `monosecret check` to
  validate the profile as a whole.
- `run --scope` removes **every** manifest-declared secret the scope does not
  admit from the launched command's environment, across _all_ profiles rather
  than only the selected one, **even if the parent shell already exported
  them**, so a value inherited from another profile cannot leak into the child.
  Membership decides this, so a secret the scope lists survives even when the
  selected profile does not declare it (see the admitted rule below). This is
  secret minimization, not an authorization boundary: a process that still holds
  provider credentials could resolve another scope itself.
- `export --scope` **emits** the visible set but unsets nothing, since its
  output formats have no way to express an unset. Narrowing an environment that
  already holds a wider set therefore needs `run --scope`: after
  `eval "$(monosecret export)"`, a later
  `eval "$(monosecret export --scope api)"` leaves the previously exported
  values live in the shell.
- An **empty** scope (or a scope whose intersection with the profile is empty)
  resolves to nothing and contacts no provider.
- **Diagnostics do not name what the scope hides.** A provider warning about a
  hidden composition input calls it `a hidden composition input` rather than
  naming it, matching the way prompting is filtered, so a failing provider
  cannot disclose the very name the output filter removed. A visible secret is
  still named. This covers monosecret's own messages; a provider's error text is
  written by that provider and may still mention the address it searched.
- [Audit](#audit-logging) records what was **read**, not what was exposed: a
  scoped `check` logs the accessed set, including a composition input the scope
  hides, since the point of the log is to capture provider access. A `run` event
  logs what it injected — the visible set. Scoped `check`, `run`, and `export`
  events also carry the selected `scope` name (Monosecret 0.2+).
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
  manifest secret scrubbed and none injected. An empty _intersection_ between a
  valid scope and the selected profile is still fine, since a scope is meant to
  be reused across profiles that declare different subsets.

The `--scope` flag (and the `MONOSECRET_SCOPE` environment variable) apply to
`check`, `run`, and `export`. Scopes are a resolution-time feature of these
untyped paths. The write and copy commands are unaffected: `set` and `import`
ignore an ambient `MONOSECRET_SCOPE` entirely, so a scope neither restricts what
they may write nor narrows the secrets they list. The untyped language SDK
builders also accept an explicit scope and return its name in resolve/report
results, and they honor `MONOSECRET_SCOPE` when given none. The typed SDK
loaders generated by `monosecret_derive` always resolve the **full** profile and
deliberately **ignore** an ambient `MONOSECRET_SCOPE`, since a generated struct
expects every declared field.

A **blank** `--scope` clears an inherited scope rather than being ignored:
`MONOSECRET_SCOPE=api monosecret run --scope "" -- ./job` resolves the whole
profile and scrubs nothing. A blank `MONOSECRET_SCOPE` with no flag means the
same, so a CI template that materializes an unset variable as an empty string
cannot silently narrow a job.

## Complete Example

```toml
# monosecret.toml
[project]
name = "web-api"
revision = "1.0"
extends = ["../shared/monosecret.toml"] # Optional inheritance

# Provider aliases used by profile provider chains
[providers]
prod_vault = "onepassword://Production"
shared_vault = "onepassword://Shared"
keyring = "keyring://"
env = "env://"

# Default profile - always loaded first
[profiles.default]
APP_NAME = { description = "Application name", required = false, default = "MyApp" }
SESSION_SECRET = { description = "Session signing secret", required = true, providers = [
  "shared_vault",
] }
GITHUB_TOKEN = { description = "GitHub token", required = true, providers = [
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

:::note[Version compatibility]
Provider alias tables with `uri` and `credentials` are available since
Monosecret 0.2. Monosecret 0.1 accepts only bare URI strings; when using
0.1, configure provider credentials through the provider's existing
environment variables, such as `BWS_ACCESS_TOKEN`.
Provider alias `ref` templates are available starting with Monosecret 0.2.
Cached alias tables with `fallback` and `cache` are available since Monosecret
0.2.
:::

<!-- monosecret-test: providers -->

```toml title="monosecret.toml"
[providers]
prod_vault = "onepassword://Production"
shared_vault = "onepassword://Shared"
keyring = "keyring://"
env = "env://"

[profiles.production]
DATABASE_URL = { description = "Production DB", providers = [
  "prod_vault",
  "keyring",
] }
```

<!-- monosecret-test: global -->

```toml title="~/.config/monosecret/config.toml"
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
# Monosecret 0.2+: add a provider alias to your user config
$ monosecret config global provider add prod_vault "onepassword://Production"

# Monosecret 0.2+: list all aliases known to your user config
$ monosecret config global provider list

# Monosecret 0.2+: remove an alias from your user config
$ monosecret config global provider remove prod_vault
```

These explicitly scoped CLI commands operate on the user-global config only —
edit `monosecret.toml` by hand to change project-level aliases.

#### Monosecret 0.2 alias values

In Monosecret 0.2 and later, an alias value is either a bare provider URI
string or a table that also declares the credentials the provider needs. Both
forms are accepted in the project `[providers]` and user
`[defaults.providers]` tables.

| Field         | Type   | Required         | Description                                                                                                        |
| ------------- | ------ | ---------------- | ------------------------------------------------------------------------------------------------------------------ |
| `uri`         | string | Yes (table form) | The provider URI. A bare-string alias is shorthand for `{ uri = "..." }`.                                          |
| `credentials` | table  | No               | Maps a semantic [provider credential](/reference/provider-credentials/) name to its source.                        |
| `ref` (0.2+)  | table  | No               | Native-address template for this leaf alias. Coordinate strings may contain `{project}`, `{profile}`, and `{key}`. |

Each `credentials` value is either a bare provider spec — read at the convention path for the active project and profile — or a table `{ provider = "...", ref = { ... } }` that pins the exact location with the same `ref` coordinates a secret uses.

```toml title="monosecret.toml"
[providers]
keyring = "keyring://"
# bare string: read access_token from keyring at the convention path
bws = { uri = "bws://project-uuid", credentials = { access_token = "keyring" } }

[providers.vault_prod]
uri = "vault://secret/myapp?auth=approle"
credentials = { role_id   = { provider = "onepassword", ref = { vault = "Infra", item = "vault-approle", field = "role_id" } },
                secret_id = { provider = "onepassword", ref = { vault = "Infra", item = "vault-approle", field = "secret_id" } } }
```

Configured credentials take precedence over provider environment fallbacks, credential chains are limited to one hop, and a fetched credential is never written to the environment. Store the credentials with [`monosecret config provider login`](/reference/cli/#config-provider-login). See [Provider credentials](/concepts/providers/#provider-credentials) for the full behavior.

Starting with Monosecret 0.2, a leaf alias may also compile logical secret
names into that provider's native coordinates. Templates expand each
placeholder once; text inserted from a project, profile, or key is never
interpreted as another placeholder.

```toml title="monosecret.toml"
[providers]
remote = { uri = "onepassword://Production", ref = { item = "{project}-{profile}", field = "{key}" } }
local = { uri = "dotenv://.env", ref = { item = "{key}" } }

[profiles.production]
API_KEY = { description = "API key", providers = ["remote", "local"] }
```

Templates belong on the leaf aliases in a cached route, not on the cached
alias itself. Bare provider names and literal URIs have no alias identity, so
they use provider convention naming unless the secret declares legacy `ref`.

#### Monosecret 0.2 inline provider cache

:::caution[Version compatibility]
Attaching `cache` directly to an alias with `uri` is available starting with
Monosecret 0.2.
:::

Use `uri` and `cache` when one provider is authoritative. `credentials` remains
optional and configures that same provider:

| Field            | Type   | Required | Description                                                                                                     |
| ---------------- | ------ | -------- | --------------------------------------------------------------------------------------------------------------- |
| `uri`            | string | Yes      | Authoritative provider URI.                                                                                     |
| `credentials`    | table  | No       | Provider-specific credential sources for `uri`.                                                                 |
| `cache`          | table  | Yes      | Local cache policy containing `provider` and `max_age`.                                                         |
| `cache.provider` | string | Yes      | Leaf provider spec used to store cache entries. Must support deletion and address a different store from `uri`. |
| `cache.max_age`  | string | Yes      | Positive duration with `s`, `m`, `h`, `d`, or `w` units, such as `30m`, `8h`, or `1d`.                          |

```toml title="monosecret.toml"
[providers]
local = "keyring://monosecret/cache/{project}/{profile}/{key}"
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

#### Monosecret 0.2 cached fallback alias values

:::caution[Version compatibility]
Cached provider aliases are available starting with Monosecret 0.2.
:::

A cached fallback alias uses `fallback` and `cache` when more than one provider
can answer:

| Field            | Type          | Required | Description                                                                                                                                                                      |
| ---------------- | ------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fallback`       | array[string] | Yes      | Non-empty authoritative provider route. Reads try entries in order; writes use the first entry.                                                                                  |
| `cache`          | table         | Yes      | Local cache policy containing `provider` and `max_age`.                                                                                                                          |
| `cache.provider` | string        | Yes      | Leaf provider spec used to store cache entries. Must support deletion (keyring, pass, gopass, dotenv, Vault/OpenBao KV v2) and be a different store from every `fallback` entry. |
| `cache.max_age`  | string        | Yes      | Positive duration with `s`, `m`, `h`, `d`, or `w` units, such as `30m`, `8h`, or `1d`.                                                                                           |

```toml title="monosecret.toml"
[providers]
azure = { uri = "akv://team-vault", credentials = { client_secret = "keyring" } }
env = "env://"
local = "keyring://monosecret/cache/{project}/{profile}/{key}"
myprovider = { fallback = [
  "azure",
  "env",
], cache = { provider = "local", max_age = "8h" } }

[profiles.development.defaults]
providers = ["myprovider"]
```

Every cached alias is a complete route and must be the only entry when selected
through `providers`, in any position. Fallback entries and the cache provider
accept aliases, provider names, and URIs, but must resolve to leaf providers;
cached aliases cannot be nested, and the cache must resolve to a different
store than the route's own authoritative providers, since it holds its entries
at the same logical address. The cache provider must also be one Monosecret can
delete from — keyring, pass, gopass, dotenv, or a Vault/OpenBao KV v2 mount —
since every form of invalidation is a delete. Put credentials on leaf aliases
rather than the cached fallback alias.
See [Provider caching](/concepts/providers/caching/)
for freshness, failure, invalidation, and clearing behavior.

#### Monosecret 0.1 alias values

In Monosecret 0.1, every alias value must be a provider URI string:

```toml title="monosecret.toml"
[providers]
bws = "bws://project-uuid"
```

For example, authenticate the 0.1 BWS provider by setting its environment
variable before running Monosecret:

```bash
$ export BWS_ACCESS_TOKEN="0.your-access-token..."

$ monosecret check
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

<!-- monosecret-test: validate -->

```toml
[project]
name = "myapp"
revision = "1.0"

[providers]
keyring = "keyring://" # Simple alias — backward compatible

[providers.op-dev]
uri = "onepassword://Development"
[[providers.op-dev.depends_on]]
secret = "OP_SERVICE_ACCOUNT_TOKEN"

[profiles.default]
# The dependency secret must itself be declared and resolved from a
# bootstrap provider (one without its own `depends_on`), such as keyring.
OP_SERVICE_ACCOUNT_TOKEN = { providers = [
  "keyring",
], description = "1Password service account token" }
DATABASE_URL = { providers = [
  "op-dev",
], description = "Database connection string" }
```

| Field        | Type   | Required | Description                                    |
| ------------ | ------ | -------- | ---------------------------------------------- |
| `uri`        | string | Yes      | The provider URI                               |
| `depends_on` | table  | No       | Secrets this provider needs for authentication |

Each entry under `depends_on` has:

| Field    | Type   | Required | Description                                                                                                                                      |
| -------- | ------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `secret` | string | Yes      | The Monosecret secret name that provides the value                                                                                               |
| `as`     | string | No       | Environment variable name to inject the value as. Defaults to `secret` (e.g. inject a per-account keyring secret as `OP_SERVICE_ACCOUNT_TOKEN`). |
