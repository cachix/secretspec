---
title: Proton Pass Provider
description: Proton Pass integration via the official pass-cli
---

The Proton Pass provider integrates with [Proton Pass](https://proton.me/pass) for end-to-end encrypted cloud secret storage.

## At a glance

| | |
| --- | --- |
| Provider | `protonpass` |
| URI | `protonpass://[vault_name[/title-template]]` |
| Access | Read and write |
| Best for | End-to-end encrypted cloud storage through Proton Pass |
| Authentication | A `pass-cli` login or personal access token |
| Default storage | Note item `{project}/{profile}/{key}` in the `secretspec` vault |

## Quick start

```bash
# Set a secret
$ secretspec set DATABASE_URL --provider protonpass://Personal
Enter value for DATABASE_URL: postgresql://localhost/mydb

# Get a secret
$ secretspec get DATABASE_URL --provider protonpass://Personal

# Run with secrets
$ secretspec run --provider protonpass://Personal -- npm start
```

## Setup

### Prerequisites

- Proton Pass CLI (`pass-cli`) - download from [proton.me/pass/download](https://proton.me/pass/download)
- A Proton account, signed in via `pass-cli login`
- A vault to store secrets in (e.g. `pass-cli vault create secretspec`)

### Authentication

For local use, sign in interactively:

```bash
$ pass-cli login
```

For CI, use a personal access token as shown in [CI/CD](#cicd).

## Configuration

### URI format

```
protonpass://[vault_name[/title-template]]
```

- `vault_name`: Target vault (defaults to `secretspec`)
- `title-template`: Item title pattern supporting `{project}`, `{profile}`, `{key}` placeholders

### URI examples

```bash
# Default vault ("secretspec")
protonpass://

# Specific vault
protonpass://Work

# Specific vault and custom title template
protonpass://Work/{project}/{profile}/{key}
```

### Project configuration

```toml title="secretspec.toml"
[providers]
team = "protonpass://Work"

[profiles.production]
DATABASE_URL = { description = "Database URL", providers = ["team"] }
```

## Storage model

Secrets are stored as note items. The vault defaults to `secretspec`, and the
item title defaults to `{project}/{profile}/{key}`. The URI can select another
vault or replace the title template.

## Use existing secrets

A secret's [`ref`](/reference/configuration/#secret-references) field names an
existing item instead: `item` is the exact item title, whose note is read
(`field` is not supported). Reads and writes target that item in place.

```toml
[profiles.production]
DATABASE_URL = { description = "DB", ref = { item = "Production Database" }, providers = ["protonpass://Work"] }
```

## CI/CD

```bash
# Create a token
$ pass-cli personal-access-token create --name ci --expiration 1y

# Authenticate in CI (store the token as a CI secret)
$ pass-cli login --pat $PROTON_PASS_PAT
$ secretspec run -- deploy
```

## Advanced configuration

### Agent sessions

`pass-cli` 2.1.0 introduced agent sessions, which require a
`PROTON_PASS_AGENT_REASON` to be set for audited item operations (reading,
creating, and deleting items). SecretSpec sets this automatically, so existing
secrets resolve correctly under an agent session.

The reason recorded in the Proton Pass audit log is resolved in this order:

1. The `--reason` flag (or `SECRETSPEC_REASON` environment variable):

   ```bash
   $ secretspec run --reason "Deploying app from CI" -- ./deploy.sh
   ```

   When using the Rust SDK, set it for the session with `with_reason`:

   ```rust
   use secretspec::Secrets;

   let spec = Secrets::load()?.with_reason("Deploying app from CI");
   ```

2. The `PROTON_PASS_AGENT_REASON` environment variable read by `pass-cli`:

   ```bash
   $ export PROTON_PASS_AGENT_REASON="Deploying app from CI"
   ```

3. A default that identifies the secretspec version (e.g. `secretspec/0.11.0 (https://secretspec.dev)`).

To force a meaningful reason instead of falling back to the default, use the
[`require_reason`](/reference/configuration/#requiring-a-reason-for-secret-access)
policy in `secretspec.toml`. It defaults to `"agents"`, so AI agents must always
explain why they read a secret (humans are unaffected); set it to `true` to require
a reason from every caller. secretspec then refuses any access that does not supply
an explicit reason.
