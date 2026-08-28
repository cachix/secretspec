---
title: Google Cloud Secret Manager Provider
description: Google Cloud Secret Manager integration
---

The [Google Cloud Secret Manager](https://cloud.google.com/security/products/secret-manager)
provider integrates with GCP for centralized secret management.

## At a glance

| | |
| --- | --- |
| Provider | `gcsm` |
| URI | `gcsm://PROJECT_ID` |
| Access | Read and write; secret references are read-only |
| Best for | Workloads and teams on Google Cloud |
| Authentication | Google Application Default Credentials |
| Build feature | `gcsm` |
| Default storage | `secretspec2--{project}--{profile}--{key}` (0.20+) |

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
gcsm://PROJECT_ID
```

- `PROJECT_ID`: Your GCP project ID

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

:::caution[Version compatibility]
The collision-safe convention below is used starting with SecretSpec 0.20.
Releases through 0.19 used `secretspec-{project}-{profile}-{key}`.
:::

SecretSpec joins the project, profile, and key with validated `--` boundaries.
Distinct logical addresses therefore cannot collapse onto one GCSM secret when
a project or profile contains a single internal hyphen. For example, project
`myapp`, profile `production`, and key `DATABASE_URL` map to:

```text
secretspec2--myapp--production--DATABASE_URL
```

Each component may contain ASCII letters, digits, underscores, and single
internal hyphens. A component cannot start or end with `-` or contain `--`,
because those forms could overlap a boundary. The complete GCSM id must fit the
service's 255-character limit.

Releases through 0.19 accepted project, profile, and key names the new layout
cannot represent, such as a project directory named `my--app`. Reads of such an
address keep serving the 0.19 secret and print a warning, but writes fail until
the name changes. Rename the offending component and run `secretspec set` to
store the value under the new id, or address the secret with an explicit
[`ref`](/reference/configuration/#secret-references), which is exempt from the
convention.

### Reading secrets stored by 0.19

SecretSpec 0.20 reads the new id first. When that secret holds no value, the
read falls back to the 0.19 `secretspec-{project}-{profile}-{key}` id and
returns its latest value, printing one warning per run. A project upgraded from
0.19 therefore keeps working with no migration step.

With secret-level IAM, an unbound new id can return `PERMISSION_DENIED` instead
of `NOT_FOUND`. SecretSpec still probes the legacy id in that case and uses it
when readable. If the legacy id supplies no value, the original denial remains
an error; failures other than the expected permission denial from a legacy-id
probe are also reported rather than treated as a missing secret.

The fallback is a read. Nothing is created, copied, or deleted, so the upgrade
needs no new permissions: credentials holding only
`roles/secretmanager.secretAccessor`, the usual CI principal, keep working
unchanged.

Writes always use the new id. Running `secretspec set` for a secret is what
moves it, and afterwards reads stop consulting the legacy id. The 0.19 secret
is left in place, so an older SecretSpec keeps reading the value it knows and a
rollback needs no recovery step.

Two consequences are worth planning for:

- A secret still served by the fallback depends on the 0.19 id continuing to
  exist. Delete legacy secrets only after the values that matter have been
  written under the new id.
- While a secret is served by the fallback, a 0.19 writer and a 0.20 writer
  update different ids. Point every writer at the same SecretSpec version, or
  set the secret with 0.20 to settle it on the new id.

Only the value is read across. Labels, rotation settings, secret-level IAM
bindings, and other resource metadata belong to the legacy secret; reproduce
any such configuration when you write the secret under its new id. If the
legacy id had already received writes from colliding logical addresses, the
provider cannot determine which historical version belonged to which address.

An explicit `ref` is a native address and is never renamed or migrated:

```toml
[profiles.production]
DATABASE_URL = {
  description = "DB",
  ref = { item = "secretspec-myapp-production-DATABASE_URL" },
  providers = ["google"]
}
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
