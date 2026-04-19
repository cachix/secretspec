---
title: Vault / OpenBao Provider
description: HashiCorp Vault and OpenBao integration
---

The Vault provider integrates with HashiCorp Vault and OpenBao for centralized secret management using the KV (Key-Value) secrets engine. Since OpenBao is an API-compatible fork of Vault, a single provider works for both.

## Prerequisites

- A running Vault or OpenBao server
- Authentication credentials (see [Authentication](#authentication))
- KV secrets engine enabled (v1 or v2)
- Build with `--features vault`

## Configuration

### URI Format

```
vault://[namespace@]host[:port][/mount][?key=value&...]
openbao://[namespace@]host[:port][/mount][?key=value&...]
```

- `host[:port]`: Vault server address (falls back to `VAULT_ADDR` env var)
- `mount`: KV engine mount path (default: `secret`)
- `namespace@`: Optional Vault namespace (also reads `VAULT_NAMESPACE` env var)
- `?auth=approle`: Use AppRole authentication (default: `token`)
- `?kv=1`: Use KV v1 engine (default: v2)
- `?tls=false`: Disable TLS (for development servers)

### Examples

```bash
# Set a secret using Vault KV v2
$ secretspec set DATABASE_URL --provider vault://vault.example.com:8200/secret

# Get a secret
$ secretspec get DATABASE_URL --provider vault://vault.example.com:8200/secret

# Check secrets
$ secretspec check --provider vault://vault.example.com:8200/secret

# Run with secrets
$ secretspec run --provider vault://vault.example.com:8200/secret -- npm start
```

## Usage

### Basic Commands

```bash
# With default "secret" mount
$ secretspec set DATABASE_URL --provider vault://vault.example.com:8200
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret 'DATABASE_URL' saved to vault (profile: default)

# With custom mount
$ secretspec set API_KEY --provider vault://vault.example.com:8200/custom-kv

# Using OpenBao
$ secretspec check --provider openbao://bao.internal:8200/secret
```

### KV Version 1

```bash
# Use KV v1 engine
$ secretspec set DATABASE_URL --provider "vault://vault.example.com:8200/secret?kv=1"
```

### Vault Namespaces

```bash
# Using namespace in URI
$ secretspec check --provider vault://team-a@vault.example.com:8200/secret

# Or via environment variable
$ export VAULT_NAMESPACE=team-a
$ secretspec check --provider vault://vault.example.com:8200/secret
```

### Secret Naming

Secrets are stored at the KV path: `secretspec/{project}/{profile}/{key}`

Each secret is stored as a KV entry with a `value` field.

Example for KV v2: `GET /v1/secret/data/secretspec/myapp/production/DATABASE_URL`

### Development Mode

For local development with Vault in dev mode:

```bash
# Start Vault in dev mode
$ vault server -dev

# Use with TLS disabled
$ export VAULT_TOKEN=hvs.dev-root-token
$ secretspec check --provider "vault://127.0.0.1:8200/secret?tls=false"
```

### Authentication

The authentication method is selected via the `auth` query parameter.

#### Token (default)

Reads the token from `VAULT_TOKEN` environment variable or `~/.vault-token` file.

```bash
export VAULT_TOKEN=hvs.your-token-here
secretspec run --provider vault://vault.example.com:8200 -- npm start
```

#### AppRole

Authenticates using `VAULT_ROLE_ID` and `VAULT_SECRET_ID` environment variables. Useful for CI/CD pipelines and deployment platforms where a static token is not appropriate.

```bash
export VAULT_ROLE_ID=your-role-id
export VAULT_SECRET_ID=your-secret-id
secretspec run --provider "vault://vault.example.com:8200/secret?auth=approle" -- deploy
```
