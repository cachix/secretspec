---
title: Dotenv Provider
description: Traditional .env file storage for secrets
---

The Dotenv provider stores secrets in local `.env` files for development setups and compatibility with existing tools.

## File Format

Standard dotenv format with `KEY=VALUE` pairs:

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

## Configuration

### URI Syntax

```bash
# Default (.env in current directory)
dotenv

# Custom paths
dotenv:.env.local
dotenv:config/.env
dotenv:/absolute/path/.env
```

### Environment Variable

```bash
export SECRETSPEC_PROVIDER=dotenv:.env.local
```

## Secret References

By default each secret reads the key named after it. A secret's
[`ref`](/reference/configuration/#secret-references) field reads a key stored
under a different name: `item` is the `.env` key (`field` is not supported).
Reads and writes target that key in place; the secret's own name is ignored.

```toml
[profiles.default]
DATABASE_URL = { description = "DB", ref = { item = "POSTGRES_URL" }, providers = ["dotenv://.env.shared"] }
```

## Usage

```bash
# Initialize from existing .env
$ secretspec init --from .env

# Set a secret
$ secretspec set DATABASE_URL --provider dotenv
Enter value for DATABASE_URL: postgresql://localhost/mydb

# Run with secrets
$ secretspec run --provider dotenv -- npm start

# Use different files for different environments
$ secretspec run --provider dotenv:.env.production -- node server.js
```

## Security

⚠️ **Warning**: Secrets are stored in plain text. Use only for development and always add `.env` files to `.gitignore`.