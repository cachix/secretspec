---
title: Dotenv Provider
description: Traditional .env file storage for secrets
---

The Dotenv provider stores secrets in local `.env` files for development setups and compatibility with existing tools.

## At a glance

| | |
| --- | --- |
| Provider | `dotenv` |
| URI | `dotenv[:path]` |
| Access | Read and write |
| Best for | Local development and compatibility with `.env`-based tools |
| Authentication | None |
| Default storage | `.env` next to `secretspec.toml` (plain text) |

## Quick start

```bash
# Initialize from existing .env
$ secretspec init --from .env

# Set a secret
$ secretspec set DATABASE_URL --provider dotenv
Enter value for DATABASE_URL: postgresql://localhost/mydb

# Run with secrets
$ secretspec run --provider dotenv -- npm start
```

## Configuration

### URI format

```bash
# Default (.env next to secretspec.toml)
dotenv

# Custom paths
dotenv:.env.local
dotenv:config/.env
dotenv:/absolute/path/.env
```

### Environment variable

```bash
export SECRETSPEC_PROVIDER=dotenv:.env.local
```

### Project configuration

```toml title="secretspec.toml"
[providers]
local = "dotenv:.env.local"

[profiles.default]
DATABASE_URL = { description = "Database URL", providers = ["local"] }
```

## Storage model

Dotenv uses standard `KEY=VALUE` pairs:

```bash
# .env
DATABASE_URL=postgresql://localhost/mydb
API_KEY=sk-1234567890
DEBUG=true  # Comments supported

# Multi-line values must be quoted
PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"
```

The file itself provides the namespace. Project and profile names are not
included in keys; use a different file when environments need separate values:

```bash
$ secretspec run --provider dotenv:.env.production -- node server.js
```

## Use existing secrets

By default each secret reads the key named after it. A secret's
[`ref`](/reference/configuration/#secret-references) field reads a key stored
under a different name: `item` is the `.env` key (`field` is not supported).
Reads and writes target that key in place; the secret's own name is ignored.

```toml
[profiles.default]
DATABASE_URL = { description = "DB", ref = { item = "POSTGRES_URL" }, providers = ["dotenv://.env.shared"] }
```

## Security considerations

:::caution
Secrets are stored in plain text. Use this provider only where that is
acceptable, and always add secret-bearing `.env` files to `.gitignore`.
:::
