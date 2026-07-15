---
title: AWS Secrets Manager Provider
description: AWS Secrets Manager integration
---

The AWS Secrets Manager provider integrates with AWS for centralized secret management.

## Prerequisites

- AWS account with Secrets Manager access
- AWS credentials configured (CLI, environment variables, IAM roles, or SSO)
- Build with `--features awssm`

## Configuration

### URI Format

```
awssm://[AWS_PROFILE@]REGION[?prefix=PREFIX][&kms_key_id=KEY][&tag.NAME=VALUE...]
```

- `REGION`: AWS region (e.g., `us-east-1`). If omitted, the SDK default region chain is used.
- `AWS_PROFILE`: Optional AWS profile from `~/.aws/credentials`. If omitted, the SDK default credential chain is used.
- `PREFIX`: Optional root prefix prepended to all secret names. Useful when IAM policies scope access by prefix (e.g., only allow `myteam/*`).
- `kms_key_id`: Optional KMS key (id, ARN, or `alias/...`) used to encrypt secrets that secretspec creates.
- `tag.NAME=VALUE`: Optional tags applied to secrets that secretspec creates. Repeat for multiple tags.

`kms_key_id` and `tag.NAME=VALUE` are applied **only when secretspec creates a
secret** (`CreateSecret`); updating a value (`PutSecretValue`) accepts neither,
and a pre-existing secret keeps the key and tags it was created with. This
supports AWS "tag-on-create" guardrails, where an SCP or IAM condition denies
`CreateSecret` unless required `aws:RequestTag/*` tags (and often a
customer-managed key) are present in the same call.

### Examples

```bash
# Set a secret (SDK default credentials)
$ secretspec set DATABASE_URL --provider awssm://us-east-1

# Use a specific AWS profile
$ secretspec check --provider awssm://production@us-east-1

# Use a prefix to scope secrets under "myteam/"
$ secretspec set DATABASE_URL --provider "awssm://us-east-1?prefix=myteam"

# Create secrets with a customer-managed KMS key and required tags
$ secretspec set DATABASE_URL --provider "awssm://prod@us-east-1?kms_key_id=alias/my-key&tag.team=platform&tag.env=prod"

# Get a secret
$ secretspec get DATABASE_URL --provider awssm://us-east-1

# Run with secrets
$ secretspec run --provider awssm://us-east-1 -- npm start

# Use SDK defaults for both profile and region
$ secretspec set DATABASE_URL --provider awssm
```

Because guardrail tags and keys usually vary per environment, they are a natural
fit for a checked-in [provider alias](/reference/configuration/) in
`secretspec.toml`:

```toml
[providers]
prod = "awssm://prod@us-east-1?kms_key_id=alias/my-key&tag.team=platform&tag.env=prod"
```

## Secret References

By default each secret is stored under `secretspec/{project}/{profile}/{key}`. A
secret's [`ref`](/reference/configuration/#secret-references) field names an
existing secret instead: `item` is the secret name (or ARN), and the optional
`field` selects one key of a JSON secret value. Without `field`, the whole
secret string is returned. References are **read-only** in this provider.

```toml
[profiles.production]
# Whole secret value
DATABASE_URL = { description = "DB", ref = { item = "prod/database-url" }, providers = ["awssm://us-east-1"] }
# One key of a JSON secret value
DB_PASSWORD = { description = "DB pw", ref = { item = "prod/db-credentials", field = "password" }, providers = ["awssm://us-east-1"] }
```

## Usage

### Basic Commands

```bash
# Set a secret
$ secretspec set DATABASE_URL --provider awssm://us-east-1
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret 'DATABASE_URL' saved to awssm (profile: default)

# Import from .env
$ secretspec import dotenv://.env
```

### Secret Naming

Secrets are stored as: `[prefix/]secretspec/{project}/{profile}/{key}`

Example: `secretspec/myapp/production/DATABASE_URL`

With `?prefix=myteam`: `myteam/secretspec/myapp/production/DATABASE_URL`

### Authentication

AWS Secrets Manager uses the standard AWS SDK credential chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. Shared credentials file (`~/.aws/credentials`)
3. AWS SSO (`aws sso login`)
4. IAM roles (EC2 instance profiles, ECS task roles, Lambda execution roles)

### Required IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:BatchGetSecretValue",
        "secretsmanager:CreateSecret",
        "secretsmanager:PutSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:secretspec/*"
    }
  ]
}
```

If you use a prefix (e.g., `?prefix=myteam`), adjust the resource ARN accordingly:

```
arn:aws:secretsmanager:*:*:secret:myteam/secretspec/*
```

:::note
The `BatchGetSecretValue` permission is required for batch fetching, which is used automatically during `check` and `run` commands to reduce API calls. If your IAM policy was created before this feature, you may need to add this permission.
:::

:::note
Using `tag.NAME=VALUE` additionally requires `secretsmanager:TagResource`, and a
`kms_key_id` requires `kms:GenerateDataKey` and `kms:Decrypt` on that key.
:::

### CI/CD

```bash
# Using environment variables
$ export AWS_ACCESS_KEY_ID=AKIA...
$ export AWS_SECRET_ACCESS_KEY=...
$ export AWS_DEFAULT_REGION=us-east-1

# Run command
$ secretspec run --provider awssm://us-east-1 -- deploy

# Or with IAM roles (no credentials needed)
$ secretspec run --provider awssm://us-east-1 -- deploy
```
