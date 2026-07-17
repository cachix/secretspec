---
title: Vault / OpenBao Provider
description: HashiCorp Vault and OpenBao integration
---

The Vault provider integrates with HashiCorp Vault and OpenBao for centralized secret management using the KV (Key-Value) secrets engine. Since OpenBao is an API-compatible fork of Vault, a single provider works for both.

## At a glance

| | |
| --- | --- |
| Provider | `vault` or `openbao` |
| URI | `vault://[namespace@]host[:port][/mount][?options]` |
| Access | Read and write; secret references are read-only |
| Best for | Self-managed, policy-controlled secret infrastructure |
| Authentication | Token or AppRole |
| Build feature | `vault` |
| Default storage | KV path `secretspec/{project}/{profile}/{key}`, field `value` |

## Quick start

```bash
# With default "secret" mount
$ secretspec set DATABASE_URL --provider vault://vault.example.com:8200
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret 'DATABASE_URL' saved to vault (profile: default)

# Using OpenBao
$ secretspec check --provider openbao://bao.internal:8200/secret
```

## Setup

### Prerequisites

- A running Vault or OpenBao server
- Authentication credentials
- KV secrets engine enabled (v1 or v2)
- Build with `--features vault`

### Token authentication

Token authentication is the default. SecretSpec reads `VAULT_TOKEN` or
`~/.vault-token`:

```bash
$ export VAULT_TOKEN=hvs.your-token-here
```

### AppRole authentication

Select AppRole with `?auth=approle` and provide both environment variables:

```bash
$ export VAULT_ROLE_ID=your-role-id
$ export VAULT_SECRET_ID=your-secret-id
```

Starting with SecretSpec 0.15, these credentials can instead be read from
another provider so they do not live in a shell profile:

```toml title="secretspec.toml"
[providers.vault_approle]
uri = "vault://vault.example.com:8200/secret?auth=approle"

[providers.vault_approle.credentials]
role_id = { provider = "onepassword", ref = { vault = "Infra", item = "vault-approle", field = "role_id" } }
secret_id = { provider = "onepassword", ref = { vault = "Infra", item = "vault-approle", field = "secret_id" } }
```

SecretSpec 0.14 supports only `VAULT_ROLE_ID` and `VAULT_SECRET_ID`.

## Configuration

### URI format

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

### URI examples

```text
vault://vault.example.com:8200/secret
vault://team-a@vault.example.com:8200/secret
vault://vault.example.com:8200/secret?auth=approle
openbao://bao.internal:8200/secret
```

### Project configuration

```toml title="secretspec.toml"
[providers]
vault_prod = "vault://vault.example.com:8200/secret"

[profiles.production]
DATABASE_URL = { description = "Database URL", providers = ["vault_prod"] }
```

## Storage model

Each secret is stored at `secretspec/{project}/{profile}/{key}` under the
configured mount, with its value in a field named `value`.

For KV v2, `DATABASE_URL` for project `myapp` and profile `production` is read
from `GET /v1/secret/data/secretspec/myapp/production/DATABASE_URL`.

## Use existing secrets

A secret's
[`ref`](/reference/configuration/#secret-references) field names an existing KV
entry instead: `item` is the KV path relative to the mount, and `field` selects
the field to read. `field` is required, since KV entries are maps. References
are **read-only** in this provider.

```toml
[profiles.production]
DATABASE_URL = { description = "DB", ref = { item = "myapp/config", field = "db_url" }, providers = ["vault://vault.example.com:8200/secret"] }
```

The mount is not a ref coordinate: it comes from the provider URI (`secret` in
the example above). To read one secret from a different mount, give that secret
a `providers` entry with the mount in the URI.

## CI/CD

AppRole avoids relying on a user token in deployment environments:

```bash
$ export VAULT_ROLE_ID="$CI_VAULT_ROLE_ID"
$ export VAULT_SECRET_ID="$CI_VAULT_SECRET_ID"
$ secretspec run --provider "vault://vault.example.com:8200/secret?auth=approle" -- deploy
```

## Advanced configuration

### KV version 1

```bash
# Use KV v1 engine
$ secretspec set DATABASE_URL --provider "vault://vault.example.com:8200/secret?kv=1"
```

### Vault namespaces

```bash
# Using namespace in URI
$ secretspec check --provider vault://team-a@vault.example.com:8200/secret

# Or via environment variable
$ export VAULT_NAMESPACE=team-a
$ secretspec check --provider vault://vault.example.com:8200/secret
```

### Development mode

For local development with Vault in dev mode:

```bash
# Start Vault in dev mode
$ vault server -dev

# Use with TLS disabled
$ export VAULT_TOKEN=hvs.dev-root-token
$ secretspec check --provider "vault://127.0.0.1:8200/secret?tls=false"
```
