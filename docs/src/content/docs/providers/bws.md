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
bws://[SERVER_BASE@]PROJECT_UUID
```

- `PROJECT_UUID`: Your Bitwarden Secrets Manager project UUID
- `SERVER_BASE` (optional): Hostname of the Bitwarden instance for EU cloud or
  self hosted deployments. Defaults to `bitwarden.com` (US cloud) when omitted.

When `SERVER_BASE` is set, the identity and API endpoints are derived as
`https://SERVER_BASE/identity` and `https://SERVER_BASE/api`, matching the
`bws config server-base` behavior described in the
[Bitwarden Secrets Manager CLI docs](https://bitwarden.com/help/secrets-manager-cli/#server).
Use the web vault hostname here, for example `vault.bitwarden.eu` for the EU
cloud. Only a bare hostname is supported (no scheme prefix or custom port).

### Examples

```bash
# US cloud (default)
$ secretspec set DATABASE_URL --provider bws://a9230ec4-5507-4870-b8b5-b3f500587e4c

# EU cloud
$ secretspec set DATABASE_URL --provider bws://vault.bitwarden.eu@a9230ec4-5507-4870-b8b5-b3f500587e4c

# Self hosted instance
$ secretspec set DATABASE_URL --provider bws://bw.example.com@a9230ec4-5507-4870-b8b5-b3f500587e4c

# Get a secret
$ secretspec get DATABASE_URL --provider bws://a9230ec4-5507-4870-b8b5-b3f500587e4c

# Check secrets
$ secretspec check --provider bws://a9230ec4-5507-4870-b8b5-b3f500587e4c

# Run with secrets
$ secretspec run --provider bws://a9230ec4-5507-4870-b8b5-b3f500587e4c -- npm start
```

## Secret References

By default each secret is matched by the BWS key name equal to the secret's own
name. A secret's [`ref`](/reference/configuration/#secret-references) field names
a different key instead: `item` is the BWS key name (`field` is not supported).
Reads and writes target that key in place.

```toml
[profiles.production]
DATABASE_URL = { description = "DB", ref = { item = "prod-db-connection" }, providers = ["bws://a9230ec4-5507-4870-b8b5-b3f500587e4c"] }
```

## Usage

### Authentication

Supply the machine account access token as a provider credential. For example,
store it in your system keyring so it never lives in a shell profile. Generate
access tokens from the Bitwarden Secrets Manager web interface. See
[Provider Credentials](/concepts/providers/#provider-credentials):

```toml title="secretspec.toml"
[providers]
bws = { uri = "bws://a9230ec4-5507-4870-b8b5-b3f500587e4c", credentials = { access_token = "keyring" } }
```

For compatibility with standalone BWS tooling, the provider falls back to
`BWS_ACCESS_TOKEN` when no explicit `access_token` credential is supplied.

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
