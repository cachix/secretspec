---
title: Infisical Provider
description: Infisical integration
---

The Infisical provider integrates with [Infisical](https://infisical.com) over its REST API, for
both Infisical Cloud and self-hosted instances.

:::note[Version compatibility]
Available since SecretSpec 0.16.
:::

## At a glance

| | |
| --- | --- |
| Provider | `infisical` |
| URI | `infisical://[host]/PROJECT_ID[?options]` |
| Access | Read and write; version-pinned references are read-only |
| Best for | Infisical Cloud or self-hosted Infisical deployments |
| Authentication | Universal Auth machine identity or access token |
| Availability | SecretSpec 0.16+; requires the `infisical` build feature |
| Default storage | Key `{key}` in `{path}/{project}/{profile}` |

## Quick start

```bash
# Store a secret
$ secretspec set DATABASE_URL --provider "infisical://app.infisical.com/7e2f1a4c-...?env=dev"

# Verify every secret is set
$ secretspec check --provider "infisical://app.infisical.com/7e2f1a4c-...?env=dev"

# Run with secrets injected
$ secretspec run --provider "infisical://app.infisical.com/7e2f1a4c-...?env=dev" -- npm start
```

Secrets sharing a folder are fetched in one request, so a run costs one call
per folder rather than one per secret.

## Setup

### Prerequisites

- An Infisical project
- A machine identity with access to it
- Build with `--features infisical`

### Universal Auth machine identity

Create a machine identity in Infisical, grant it access to the project, and set:

```bash
$ export INFISICAL_CLIENT_ID=...
$ export INFISICAL_CLIENT_SECRET=...
```

The provider exchanges these for a short-lived access token once per run.

### Access token

A token minted elsewhere can be used directly:

```bash
$ export INFISICAL_TOKEN=...
```

Service tokens are not supported: Infisical deprecated them in favour of
machine identities.

### Credentials from another provider

A machine identity's credentials can live in another store rather than in the
environment, declared as
[provider credentials](/concepts/providers/#provider-credentials):

```toml title="secretspec.toml"
[providers.infisical]
uri = "infisical://app.infisical.com/7e2f1a4c-..."

[providers.infisical.credentials]
client_id = "keyring"
client_secret = "keyring"
```

The provider declares `client_id` and `client_secret` for Universal Auth, and
`token` for a ready-made access token. Each falls back to its corresponding
environment variable when it is not declared. Use
`secretspec config provider login infisical` to store declared credentials.

## Configuration

### URI format

```
infisical://[host]/{project-id}[?env=slug&path=/prefix&layout=flat&tls=false]
```

- `host`: the Infisical instance (falls back to `INFISICAL_DOMAIN`, then the legacy
  `INFISICAL_API_URL`, then `app.infisical.com`)
- `{project-id}`: the project's **UUID**, from Project Settings → Project ID
- `?env=`: environment slug. Without it, the SecretSpec profile names the environment
- `?path=`: folder prefix holding SecretSpec's secrets. Defaults to `/secretspec` under the
  nested layout and to the environment root (`/`) under the flat one
- `?layout=` (0.17+): `nested` (default) or `flat` — see [Layout](#layout-017)
- `?tls=false`: disable TLS, for self-hosted instances served over plain HTTP

Infisical's API addresses a project by UUID, not by the slug shown in its UI.

### URI examples

```text
infisical://app.infisical.com/7e2f1a4c-...
infisical://eu.infisical.com/7e2f1a4c-...
infisical://vault.example.com/7e2f1a4c-...
infisical://localhost:8080/7e2f1a4c-...?tls=false
```

### Project configuration

```toml title="secretspec.toml"
[providers]
infisical = "infisical://app.infisical.com/7e2f1a4c-...?env=prod"

[profiles.production]
DATABASE_URL = { description = "Database URL", providers = ["infisical"] }
```

## Storage model

### Profiles and environments

By default a SecretSpec profile names the Infisical environment: a `production` profile reads the
`production` environment, and `dev` reads `dev`. New Infisical projects come with `dev`, `staging`
and `prod`, so this works out of the box for profiles named after them.

A project whose environments do not correspond to profiles pins one with `?env=`:

```bash
# Every profile reads Infisical's "dev" environment
secretspec run --provider "infisical://app.infisical.com/7e2f1a4c-...?env=dev" -- npm start
```

Profiles stay separate either way: the profile names the folder as well as the environment, so
pinning `?env=` cannot make two profiles share a secret.

To route each profile to a different environment, give each one its own alias:

```toml
[providers]
infisical_dev = "infisical://app.infisical.com/7e2f1a4c-...?env=dev"
infisical_prod = "infisical://app.infisical.com/7e2f1a4c-...?env=prod"

[profiles.production]
DATABASE_URL = { description = "Production database", providers = ["infisical_prod"] }
```

### Secret naming

Secrets are stored under the folder `{path}/{project}/{profile}`, in the environment named by the
profile (or by `?env=`):

```
project "myapp", profile "prod", key "DATABASE_URL"
  -> environment prod
     folder      /secretspec/myapp/prod
     key         DATABASE_URL
```

Keys are stored exactly as written: Infisical accepts any non-empty key, so nothing is rewritten
and two keys can never collide. Folder names are narrower — letters, digits, dashes and
underscores — so a project or profile Infisical cannot spell is refused rather than quietly
renamed.

Folders are created as needed when writing a secret.

### Layout (0.17+)

Added in SecretSpec 0.17; the flat layout is not available in SecretSpec 0.16.

The default **nested** layout stores secrets under `{path}/{project}/{profile}`, so many projects
and profiles can share one Infisical store without colliding.

The **flat** layout (`?layout=flat`) drops the `{project}/{profile}` folders, so a secret sits
directly at the folder prefix — the environment root by default, or `{path}` when one is given:

```
project "myapp", profile "prod", key "DATABASE_URL", layout flat
  -> environment prod
     folder      /
     key         DATABASE_URL
```

```toml title="secretspec.toml"
[providers]
# Read secrets straight from each environment's root
infisical = "infisical://app.infisical.com/7e2f1a4c-...?layout=flat"

# ...or from a shared prefix, still with no project/profile folders
infisical_team = "infisical://app.infisical.com/7e2f1a4c-...?layout=flat&path=/team"
```

This is the natural shape for a **single-project store** — one migrated from another secret
manager, say — where SecretSpec's namespace folders would only be in the way. Because the flat
layout no longer puts the project or profile in a folder name, those names are unconstrained under
it.

The profile still names the environment, so distinct profiles stay apart:

```
dev  profile, key DATABASE_URL  -> environment dev,  folder /, key DATABASE_URL
prod profile, key DATABASE_URL  -> environment prod, folder /, key DATABASE_URL
```

:::caution
Pinning `?env=` **and** `?layout=flat` together collapses every profile onto one environment root,
so they share a key. That combination gives up profile separation deliberately, and is only safe
when a single profile is ever resolved against the store.
:::

## Use existing secrets

A secret can name one Infisical secret by its own coordinates, instead of SecretSpec's layout:

```toml
[providers]
infisical_prod = "infisical://app.infisical.com/7e2f1a4c-...?env=prod"

[profiles.production]
DATABASE_URL = { description = "Postgres DSN", ref = { item = "/infra/shared/DB_PASSWORD" }, providers = ["infisical_prod"] }
API_KEY = { description = "Pinned key", ref = { item = "/infra/API_KEY", version = "3" }, providers = ["infisical_prod"] }
```

- `item`: the folder and key. A leading slash names the environment's root — `/infra/shared/DB_PASSWORD`
  is read from `/infra/shared`. Without one, the folder is read under the configured prefix, so
  `team/DB_PASSWORD` means `/secretspec/team/DB_PASSWORD` and a bare `DB_PASSWORD` sits at
  `/secretspec` itself
- `version`: an Infisical secret version. Version-pinned refs are read-only, since a past version cannot be rewritten

A ref has no profile to name an environment with, so the provider URI must pin one with `?env=`.
Infisical secrets are single values with no sub-components, so `field`, `section` and `vault` are
rejected.

## CI/CD

Use Universal Auth credentials stored in the CI platform, or provide an access
token minted by your deployment environment:

```bash
$ export INFISICAL_CLIENT_ID="$CI_INFISICAL_CLIENT_ID"
$ export INFISICAL_CLIENT_SECRET="$CI_INFISICAL_CLIENT_SECRET"
$ secretspec run --provider "infisical://app.infisical.com/7e2f1a4c-...?env=prod" -- deploy
```

## Advanced configuration

### Imported folders

A folder that imports another resolves the imported keys too, with Infisical's own precedence: a
secret defined directly in the folder wins over an imported one, and a later import wins over an
earlier one. This matches their CLI, so a value reads the same way through either tool.

### Secret references inside values

Values are read with Infisical's own `${...}` references expanded, matching its CLI, so a value of
`postgres://${DB_USER}@host` arrives resolved.

### Self-hosting

Point the URI at the instance, or set `INFISICAL_DOMAIN`:

```bash
export INFISICAL_DOMAIN=https://vault.example.com
secretspec run --provider "infisical:///7e2f1a4c-..." -- npm start
```

Infisical's legacy `INFISICAL_API_URL` is honoured too, so an instance already configured for
their CLI works unchanged. `INFISICAL_DOMAIN` wins when both are set, matching the CLI.

### Approval policies

A project under an approval policy turns a write into a change request: Infisical stores nothing
until a human merges it. `secretspec set` reports that rather than claiming the secret was stored,
so the value is written once the request is approved.

## Troubleshooting and limitations

- The project is addressed by UUID; Infisical's API does not accept a project slug
- A project or profile whose name is not spellable as an Infisical folder (letters, digits, dashes,
  underscores) is refused rather than rewritten
- Refs need `?env=`, having no profile to name an environment with
- `secretspec import infisical://…` is not supported: the provider does not enumerate existing
  secrets, so import has nothing to discover
- The domain variables name a host, not a path: an instance served under a sub-path
  (`https://example.com/infisical`) is not addressable. A trailing `/api` is the exception and is
  accepted, since Infisical's own CLI takes the domain in that form
- An environment or project that does not exist reads as an unset secret rather than an error:
  Infisical answers a missing secret, folder, environment and project with the same bare 404.
  Writing one reports the environment by name. If a profile does not match an environment slug —
  Infisical's own default projects use `dev`, `staging` and `prod` — pin the right one with `?env=`
