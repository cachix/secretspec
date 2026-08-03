---
title: AWS Systems Manager Parameter Store Provider
description: AWS Systems Manager Parameter Store integration
---

:::note
The AWS Systems Manager Parameter Store provider is available in SecretSpec
0.18+.
:::

The AWS Parameter Store provider stores secrets as encrypted
[`SecureString`](https://docs.aws.amazon.com/systems-manager/latest/userguide/secure-string-parameter-kms-encryption.html)
parameters.

## At a glance

| | |
| --- | --- |
| Provider | `awsps` (0.18+) |
| URI | `awsps://[AWS_PROFILE@]REGION[?options]` |
| Access | Read and write; version-, label-, and ARN-pinned references are read-only |
| Best for | AWS workloads using Parameter Store for application configuration |
| Authentication | Standard AWS SDK credential chain |
| Build feature | `awsps` (0.18+) |
| Default storage | `/secretspec/{project}/{profile}/{key}`; replaceable with `template` |

## Quick start

```bash
# Set an encrypted parameter
$ secretspec set DATABASE_URL --provider awsps://us-east-1
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret 'DATABASE_URL' saved to awsps (profile: default)

# Get it back
$ secretspec get DATABASE_URL --provider awsps://us-east-1
postgresql://localhost/mydb

# Run with parameters
$ secretspec run --provider awsps://us-east-1 -- npm start
```

## Setup

### Prerequisites

- An AWS account with Systems Manager Parameter Store enabled
- IAM permission to read and write the target parameter hierarchy
- Build with `--features awsps` using SecretSpec 0.18+

### Authentication

The provider uses the standard AWS SDK credential chain, including:

1. `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optional
   `AWS_SESSION_TOKEN`
2. Shared AWS config and credentials files
3. IAM Identity Center (SSO) sessions
4. ECS task roles, EC2 instance profiles, and other workload identities

Set a shared-config profile before the region in the URI:

```text
awsps://production@us-east-1
```

When the profile and region are omitted, the SDK resolves both from its
ordinary environment and shared-config chains:

```text
awsps
```

## Configuration

### URI format

```text
awsps://[AWS_PROFILE@]REGION[?prefix=PREFIX][&template=TEMPLATE][&kms_key_id=KEY][&tier=TIER]
```

- `AWS_PROFILE`: Optional profile from the shared AWS config.
- `REGION`: Optional AWS region. If omitted, the SDK region chain is used.
- `prefix`: Optional hierarchy before `/secretspec`. A leading slash is
  optional and normalized.
- `template`: Optional complete hierarchy using `{project}`, `{profile}`, and
  `{key}`. It must start with `/`, contain `{key}` exactly once as the final
  path segment, and include a parent path before it. `template` and `prefix`
  are mutually exclusive.
- `kms_key_id`: Optional customer-managed KMS key ID, ARN, or alias used for
  `SecureString` writes. If omitted, Parameter Store uses the account's default
  key.
- `tier`: Optional `standard`, `advanced`, or `intelligent-tiering` value.
  Omitting it uses the account's Parameter Store default tier.

### URI examples

```text
awsps://us-east-1
awsps://production@us-east-1
awsps://us-east-1?prefix=/myteam
awsps://us-east-1?template=/{profile}/{project}/{key}
awsps://us-east-1?kms_key_id=alias/my-key&tier=advanced
awsps://
```

### Project configuration

```toml title="secretspec.toml"
[providers]
parameters = "awsps://production@us-east-1?prefix=/myteam&kms_key_id=alias/parameter-store"

[profiles.production]
DATABASE_URL = { description = "Database URL", providers = ["parameters"] }
```

## Storage model

Convention secrets are stored at
`[/prefix]/secretspec/{project}/{profile}/{key}`. For example,
`DATABASE_URL` in project `myapp` and profile `production` maps to:

```text
/secretspec/myapp/production/DATABASE_URL
```

With `?prefix=/myteam`, it maps to:

```text
/myteam/secretspec/myapp/production/DATABASE_URL
```

Use `template` to replace the whole convention. This is useful when Terraform
already provisions a Chamber-style hierarchy. For example,
`?template=/{profile}/{project}/{key}` maps the same declaration to:

```text
/production/myapp/DATABASE_URL
```

The `{project}` and `{profile}` placeholders are optional, but `{key}` must be
the final path segment. That restriction gives discovery a bounded parent path
and a reversible mapping from parameter names to SecretSpec declarations.

## Discover existing parameters

SecretSpec 0.18+ can create declarations for the direct children of the
rendered Parameter Store hierarchy. It calls `GetParametersByPath` without
decryption, does not write parameter values to the manifest, and does not scan
outside that one path:

```bash
$ secretspec init \
    --from 'awsps://production@us-east-1?template=/{profile}/{project}/{key}' \
    --project payments \
    --profile production
✓ Created secretspec.toml with 12 secrets
```

`--project` defaults to the current directory name and `--profile` defaults to
`default`. Initialization discovers declarations only. To continue reading the
values from Parameter Store, add the URI as a checked-in provider alias and use
it as the profile default:

```toml title="secretspec.toml"
[providers]
parameters = "awsps://production@us-east-1?template=/{profile}/{project}/{key}"

[profiles.production.defaults]
providers = ["parameters"]
```

Alternatively, `secretspec import` copies the now-declared values from the
source into your configured destination provider; it does not perform
discovery itself.

Every value SecretSpec creates is a `SecureString`. Writes set
`Overwrite=true`, so updating a value creates a new Parameter Store version.
Parameter Store retains its normal version history.

Standard parameters accept values up to 4 KB; advanced parameters accept up to
8 KB and incur AWS charges. A standard parameter can be promoted to advanced,
but Parameter Store does not downgrade an advanced parameter in place.

:::caution
SecretSpec does not change an existing parameter from `String` or `StringList`
to `SecureString`. Parameter Store rejects that type change; create a new
encrypted parameter or migrate the existing parameter first.
:::

## Use existing parameters

In SecretSpec 0.18+, a secret's
[`ref`](/reference/configuration/#secret-references) field can name an existing
Parameter Store parameter. `item` is its full name or ARN. The optional
`version` is appended as a Parameter Store selector and may be a numeric
version or label. An unversioned reference by parameter name is writable;
references using a version, label, or ARN are read-only.

```toml
[profiles.production]
# Latest value
DATABASE_URL = { description = "DB", ref = { item = "/prod/database-url" }, providers = ["awsps://us-east-1"] }

# Version 7
SIGNING_KEY = { description = "Signing key", ref = { item = "/prod/signing-key", version = "7" }, providers = ["awsps://us-east-1"] }

# Version carrying the "current" label
API_TOKEN = { description = "API token", ref = { item = "/prod/api-token", version = "current" }, providers = ["awsps://us-east-1"] }

# Generate at an existing hierarchy on first use, then reuse it
DB_PASSWORD = { description = "DB password", ref = { item = "/prod/db-password" }, type = "password", generate = true, providers = ["awsps://us-east-1"] }
```

`secretspec set`, interactive `check`, generation, and `import` write an
unversioned name reference at that exact parameter name. As with convention
writes, an existing value receives a new Parameter Store version and is never
changed from `String` or `StringList` to `SecureString`.

Cross-account shared parameters must be read by ARN. ARN references are
read-only; SecretSpec writes only by parameter name in the provider's
configured account and region.

## IAM permissions

Reads require `ssm:GetParameter` and `ssm:GetParameters`; convention and
unversioned name-reference writes require `ssm:PutParameter`. A
customer-managed KMS key also needs the corresponding KMS permissions for
encryption and decryption.

Discovery requires `ssm:GetParametersByPath`. It requests encrypted values
without decrypting them, while normal secret reads do decrypt.

Scope IAM resources to the configured hierarchy where possible. For the
`/myteam/secretspec/` prefix in `us-east-1`, that resource pattern is:

```text
arn:aws:ssm:us-east-1:ACCOUNT_ID:parameter/myteam/secretspec/*
```

## CI/CD

Prefer an AWS workload identity or short-lived OIDC credentials:

```bash
$ export AWS_REGION=us-east-1
$ secretspec run --provider awsps -- deploy
```
