---
title: Infisical Provider
description: Infisical integration
---

The Infisical provider integrates with [Infisical](https://infisical.com) over its REST API, for
both Infisical Cloud and self-hosted instances.

:::note[Version compatibility]
The Infisical provider is an upcoming SecretSpec 0.16 feature and is not available
in SecretSpec 0.15.
:::

## Prerequisites

- An Infisical project
- A machine identity with access to it (see [Authentication](#authentication))
- Build with `--features infisical`

## Configuration

### URI Format

```
infisical://[host]/{project-id}[?env=slug&path=/prefix&tls=false]
```

- `host`: the Infisical instance (falls back to `INFISICAL_DOMAIN`, then `app.infisical.com`)
- `{project-id}`: the project's **UUID**, from Project Settings → Project ID
- `?env=`: environment slug. Without it, the SecretSpec profile names the environment
- `?path=`: folder prefix holding SecretSpec's secrets (default: `/secretspec`)
- `?tls=false`: disable TLS, for self-hosted instances served over plain HTTP

Infisical's API addresses a project by UUID, not by the slug shown in its UI.

### Examples

```bash
# Infisical Cloud (US, and the default host)
secretspec set DATABASE_URL --provider infisical://app.infisical.com/7e2f1a4c-...

# Infisical Cloud (EU)
secretspec check --provider infisical://eu.infisical.com/7e2f1a4c-...

# Self-hosted
secretspec run --provider infisical://vault.example.com/7e2f1a4c-... -- npm start

# Self-hosted over plain HTTP
secretspec run --provider "infisical://localhost:8080/7e2f1a4c-...?tls=false" -- npm start
```

## Profiles and environments

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

### Secret Naming

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

## Secret References

A secret can name one Infisical secret by its own coordinates, instead of SecretSpec's layout:

```toml
[profiles.production]
DATABASE_URL = { description = "Postgres DSN", ref = { item = "/infra/shared/DB_PASSWORD" } }
API_KEY = { description = "Pinned key", ref = { item = "/infra/API_KEY", version = "3" } }
```

- `item`: the folder and key. A leading slash names the environment's root — `/infra/shared/DB_PASSWORD`
  is read from `/infra/shared`. Without one, the folder is read under the configured prefix, so
  `team/DB_PASSWORD` means `/secretspec/team/DB_PASSWORD` and a bare `DB_PASSWORD` sits at
  `/secretspec` itself
- `version`: an Infisical secret version. Version-pinned refs are read-only, since a past version cannot be rewritten

A ref has no profile to name an environment with, so the provider URI must pin one with `?env=`.
Infisical secrets are single values with no sub-components, so `field`, `section` and `vault` are
rejected.

## Secret references inside values

Values are read with Infisical's own `${...}` references expanded, matching its CLI, so a value of
`postgres://${DB_USER}@host` arrives resolved.

## Authentication

### Universal Auth (machine identity)

Create a machine identity in Infisical, grant it access to the project, and set:

```bash
export INFISICAL_CLIENT_ID=...
export INFISICAL_CLIENT_SECRET=...
```

The provider exchanges these for a short-lived access token once per run.

### Token

A token minted elsewhere is used as it stands, which is what CI often has to hand:

```bash
export INFISICAL_TOKEN=...
```

Service tokens are not supported: Infisical deprecated them in favour of machine identities.

### Sourcing credentials from another provider

A machine identity's credentials can live in another store rather than in the environment, declared
as [provider credentials](/concepts/providers/#provider-credentials):

```toml title="secretspec.toml"
[providers]
infisical = { uri = "infisical://app.infisical.com/7e2f1a4c-...", credentials = {
  client_id = "keyring",
  client_secret = "keyring",
} }
```

The provider declares three credentials: `client_id` and `client_secret` for Universal Auth, and
`token` for a ready-made access token. Each falls back to its environment variable
(`INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET`, `INFISICAL_TOKEN`) when not declared here.

`secretspec config provider login infisical` prompts for each and stores it where resolution later
reads it from.

## Usage

```bash
# Store a secret
secretspec set DATABASE_URL --provider infisical://app.infisical.com/7e2f1a4c-...

# Verify every secret is set
secretspec check --provider infisical://app.infisical.com/7e2f1a4c-...

# Run with secrets injected
secretspec run --provider infisical://app.infisical.com/7e2f1a4c-... -- npm start
```

Secrets sharing a folder are fetched in one request, so a run costs one call per folder rather than
one per secret.

## Self-hosting

Point the URI at the instance, or set `INFISICAL_DOMAIN`:

```bash
export INFISICAL_DOMAIN=https://vault.example.com
secretspec run --provider "infisical:///7e2f1a4c-..." -- npm start
```

## Approval policies

A project under an approval policy turns a write into a change request: Infisical stores nothing
until a human merges it. `secretspec set` reports that rather than claiming the secret was stored,
so the value is written once the request is approved.

## Limitations

- The project is addressed by UUID; Infisical's API does not accept a project slug
- A project or profile whose name is not spellable as an Infisical folder (letters, digits, dashes,
  underscores) is refused rather than rewritten
- Refs need `?env=`, having no profile to name an environment with
- `secretspec import infisical://…` is not supported: the provider does not enumerate existing
  secrets, so import has nothing to discover
- `INFISICAL_DOMAIN` names a host, not a path: an instance served under a sub-path
  (`https://example.com/infisical`) is not addressable. A trailing `/api` is the exception and is
  accepted, since Infisical's own CLI takes the domain in that form
- An environment or project that does not exist reads as an unset secret rather than an error:
  Infisical answers a missing secret, folder, environment and project with the same bare 404.
  Writing one reports the environment by name. If a profile does not match an environment slug —
  Infisical's own default projects use `dev`, `staging` and `prod` — pin the right one with `?env=`
