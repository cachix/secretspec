---
title: Google Cloud Secret Manager Provider
description: Google Cloud Secret Manager integration
---

The Google Cloud Secret Manager provider integrates with GCP for centralized secret management.

## Prerequisites

- Google Cloud CLI (`gcloud`)
- GCP project with Secret Manager API enabled
- Authenticated via `gcloud auth application-default login`
- Build with `--features gcsm`

## Configuration

### URI Format

```
gcsm://PROJECT_ID
```

- `PROJECT_ID`: Your GCP project ID

### Examples

```bash
# Set a secret
$ secretspec set DATABASE_URL --provider gcsm://my-gcp-project

# Get a secret
$ secretspec get DATABASE_URL --provider gcsm://my-gcp-project

# Check secrets
$ secretspec check --provider gcsm://my-gcp-project

# Run with secrets
$ secretspec run --provider gcsm://my-gcp-project -- npm start
```

## Secret References

By default each secret is stored as `secretspec-{project}-{profile}-{key}`. A
secret's [`ref`](/reference/configuration/#secret-references) field names an
existing secret instead: `item` is the secret id, and the optional `version`
pins a version (defaults to latest; `field` is not supported). References are
**read-only** in this provider.

```toml
[profiles.production]
DATABASE_URL = { description = "DB", ref = { item = "database-url" }, providers = ["gcsm://my-gcp-project"] }
SIGNING_KEY = { description = "Key", ref = { item = "signing-key", version = "3" }, providers = ["gcsm://my-gcp-project"] }
```

## Usage

### Basic Commands

```bash
# Set a secret
$ secretspec set DATABASE_URL --provider gcsm://my-gcp-project
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret 'DATABASE_URL' saved to gcsm (profile: default)

# Import from .env
$ secretspec import dotenv://.env
```

### Secret Naming

Secrets are stored as: `secretspec-{project}-{profile}-{key}`

Example: `secretspec-myapp-production-DATABASE_URL`

### CI/CD with Service Accounts

```bash
# Set credentials
$ export GOOGLE_APPLICATION_CREDENTIALS="/path/to/key.json"

# Run command
$ secretspec run --provider gcsm://my-gcp-project -- deploy
```
