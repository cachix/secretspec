---
title: Bitwarden Secrets Manager Provider
description: Bitwarden Secrets Manager integration
---

The Bitwarden Secrets Manager (BWS) provider integrates with Bitwarden for centralized, end-to-end encrypted secret management.

## At a glance

| | |
| --- | --- |
| Provider | `bws` |
| URI | `bws://[SERVER_BASE@]PROJECT_UUID` |
| Access | Read and write |
| Best for | Machine and CI/CD secrets managed in Bitwarden |
| Authentication | A machine-account access token |
| Build feature | `bws` |
| Default storage | Flat key names in the selected BWS project |

## Quick start

```bash
# Set a secret
$ secretspec set DATABASE_URL --provider bws://a9230ec4-5507-4870-b8b5-b3f500587e4c
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret 'DATABASE_URL' saved to bws (profile: default)

# Run with secrets
$ secretspec run --provider bws://a9230ec4-5507-4870-b8b5-b3f500587e4c -- npm start
```

## Setup

### Prerequisites

- Bitwarden Secrets Manager subscription
- Machine account access token (`BWS_ACCESS_TOKEN` environment variable)
- Build with `--features bws`

### Authentication

Generate a machine account access token from the Bitwarden Secrets Manager web
interface.

In SecretSpec 0.15 and later, you can declare the access token as a
[provider credential](/concepts/providers/#provider-credentials), for example
to store it in your system keyring so it never lives in a shell profile:

```toml title="secretspec.toml"
[providers]
bitwarden = { uri = "bws://a9230ec4-5507-4870-b8b5-b3f500587e4c", credentials = { access_token = "keyring" } }
```

When no explicit `access_token` credential is supplied, the provider falls
back to `BWS_ACCESS_TOKEN`:

```bash
export BWS_ACCESS_TOKEN="0.your-access-token..."
```

SecretSpec 0.14 supports only the environment-variable form.

## Configuration

### URI format

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

### URI examples

```text
bws://a9230ec4-5507-4870-b8b5-b3f500587e4c
bws://vault.bitwarden.eu@a9230ec4-5507-4870-b8b5-b3f500587e4c
bws://bw.example.com@a9230ec4-5507-4870-b8b5-b3f500587e4c
```

### Project configuration

```toml title="secretspec.toml"
[providers]
bitwarden = { uri = "bws://a9230ec4-5507-4870-b8b5-b3f500587e4c", credentials = { access_token = "keyring" } }

[profiles.production]
DATABASE_URL = { description = "Database URL", providers = ["bitwarden"] }
```

## Storage model

SecretSpec uses flat key names matching the secret key directly, such as
`DATABASE_URL`. The BWS project UUID provides namespace isolation, so use
separate BWS projects when applications or environments need separate values.

## Use existing secrets

A secret's [`ref`](/reference/configuration/#secret-references) field names
a different key instead: `item` is the BWS key name (`field` is not supported).
Reads and writes target that key in place.

```toml
[profiles.production]
DATABASE_URL = { description = "DB", ref = { item = "prod-db-connection" }, providers = ["bws://a9230ec4-5507-4870-b8b5-b3f500587e4c"] }
```

## CI/CD

```bash
# Set access token (from CI secrets)
$ export BWS_ACCESS_TOKEN="$BWS_TOKEN"

# Run command
$ secretspec run --provider bws://a9230ec4-5507-4870-b8b5-b3f500587e4c -- deploy
```
