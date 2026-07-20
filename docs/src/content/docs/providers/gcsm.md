---
title: Google Cloud Secret Manager Provider
description: Google Cloud Secret Manager integration
---

The Google Cloud Secret Manager provider integrates with GCP for centralized secret management.

## At a glance

| | |
| --- | --- |
| Provider | `gcsm` |
| URI | `gcsm://PROJECT_ID` |
| Access | Read and write; secret references are read-only |
| Best for | Workloads and teams on Google Cloud |
| Authentication | Google Application Default Credentials |
| Build feature | `gcsm` |
| Default storage | `secretspec-{project}-{profile}-{key}` |

## Quick start

```bash
# Set a secret
$ secretspec set DATABASE_URL --provider gcsm://my-gcp-project
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret 'DATABASE_URL' saved to gcsm (profile: default)

# Run with secrets
$ secretspec run --provider gcsm://my-gcp-project -- npm start
```

## Setup

### Prerequisites

- Google Cloud CLI (`gcloud`)
- GCP project with Secret Manager API enabled
- Build with `--features gcsm`

### Authentication

Google Cloud Secret Manager uses Application Default Credentials. For local
development:

```bash
$ gcloud auth application-default login
```

In Google Cloud runtimes, Application Default Credentials use the attached
service account automatically.

## Configuration

### URI format

```
gcsm://PROJECT_ID[?layout=flat]
```

- `PROJECT_ID`: Your GCP project ID
- `?layout=flat` (0.17+): use the key alone as the secret id, with no `secretspec-{project}-{profile}-` prefix — see [Layout](#layout-017)

### URI examples

```text
gcsm://my-gcp-project
```

### Project configuration

```toml title="secretspec.toml"
[providers]
google = "gcsm://my-gcp-project"

[profiles.production]
DATABASE_URL = { description = "Database URL", providers = ["google"] }
```

## Storage model

Secrets are stored as `secretspec-{project}-{profile}-{key}`. For example,
project `myapp`, profile `production`, and key `DATABASE_URL` map to
`secretspec-myapp-production-DATABASE_URL`.

### Layout (0.17+)

Added in SecretSpec 0.17; `?layout=flat` is not available in SecretSpec 0.16 or earlier.

`?layout=` is a [general provider setting](/reference/providers/#layout-flat-017), spelled the same
way across every hierarchical backend. The default **nested** layout builds the secret id
`secretspec-{project}-{profile}-{key}`, as above.

The **flat** layout (`?layout=flat`) drops that prefix, so a convention secret's id is the `{key}`
itself — `DATABASE_URL` maps straight to a `DATABASE_URL` secret. This is the natural shape for a
single-project store, e.g. one migrated from another manager. The project and profile name no part
of the id under flat, so they are not required; the key must still be a legal GCP secret id
(letters, digits, hyphens and underscores), since there is no `secretspec-` prefix rewriting the
rest of the name.

```toml title="secretspec.toml"
[providers]
gcsm = "gcsm://my-gcp-project?layout=flat"
```

## Use existing secrets

A secret's [`ref`](/reference/configuration/#secret-references) field names an
existing secret instead: `item` is the secret id, and the optional `version`
pins a version (defaults to latest; `field` is not supported). References are
**read-only** in this provider.

```toml
[profiles.production]
DATABASE_URL = { description = "DB", ref = { item = "database-url" }, providers = ["gcsm://my-gcp-project"] }
SIGNING_KEY = { description = "Key", ref = { item = "signing-key", version = "3" }, providers = ["gcsm://my-gcp-project"] }
```

## CI/CD

```bash
# Set credentials
$ export GOOGLE_APPLICATION_CREDENTIALS="/path/to/key.json"

# Run command
$ secretspec run --provider gcsm://my-gcp-project -- deploy
```
