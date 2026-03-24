---
title: Bitwarden Secrets Manager Provider
description: Bitwarden Secrets Manager integration
---

The Bitwarden Secrets Manager (BWS) provider integrates with Bitwarden for centralized, end-to-end encrypted secret management.

## Prerequisites

- Bitwarden Secrets Manager subscription
- Machine account access token (`BWS_ACCESS_TOKEN` environment variable)
- Build with `--features bws`

## Configuration

### URI Format

```
bws://PROJECT_UUID
```

- `PROJECT_UUID`: Your Bitwarden Secrets Manager project UUID

### Examples

```bash
# Set a secret
$ secretspec set DATABASE_URL --provider bws://a9230ec4-5507-4870-b8b5-b3f500587e4c

# Get a secret
$ secretspec get DATABASE_URL --provider bws://a9230ec4-5507-4870-b8b5-b3f500587e4c

# Check secrets
$ secretspec check --provider bws://a9230ec4-5507-4870-b8b5-b3f500587e4c

# Run with secrets
$ secretspec run --provider bws://a9230ec4-5507-4870-b8b5-b3f500587e4c -- npm start
```

## Usage

### Authentication

Set the `BWS_ACCESS_TOKEN` environment variable with your machine account access token. Generate access tokens from the Bitwarden Secrets Manager web interface.

```bash
export BWS_ACCESS_TOKEN="0.your-access-token..."
```

### Basic Commands

```bash
# Set a secret
$ secretspec set DATABASE_URL --provider bws://a9230ec4-5507-4870-b8b5-b3f500587e4c
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret 'DATABASE_URL' saved to bws (profile: default)

# Import from .env
$ secretspec import dotenv://.env
```

### Secret Naming

Secrets are stored with flat key names matching the secret key directly (e.g., `DATABASE_URL`). The BWS project UUID in the URI provides namespace isolation, so different projects or environments should use separate BWS projects.

### CI/CD with Machine Accounts

```bash
# Set access token (from CI secrets)
$ export BWS_ACCESS_TOKEN="$BWS_TOKEN"

# Run command
$ secretspec run --provider bws://a9230ec4-5507-4870-b8b5-b3f500587e4c -- deploy
```
