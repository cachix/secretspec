---
title: OpenBao Provider
description: OpenBao integration, available in SecretSpec 0.17+
---

The OpenBao provider integrates with OpenBao's KV (Key-Value) secrets engine
using OpenBao's own provider identity and configuration conventions.

:::caution[Version compatibility]
The `openbao` provider targets SecretSpec 0.17 and is unavailable
in the current 0.16 release. SecretSpec 0.16 can still connect to OpenBao with
an `openbao://` URI through the `vault` build feature, but reports the provider
as Vault and uses `VAULT_*` environment variables.
:::

## Using SecretSpec 0.16 today

The current release's practical form is:

```bash
$ export VAULT_TOKEN=hvs.your-token-here
$ secretspec check --provider openbao://bao.example.com:8200/secret
```

For a minimal Rust build, enable `vault`:

```toml
secretspec = { version = "0.16", default-features = false, features = ["vault"] }
```

## At a glance

| | |
| --- | --- |
| Provider | `openbao` (0.17+) |
| URI | `openbao://[namespace@]host[:port][/mount][?options]` |
| Access | Read and write; secret references are read-only |
| Best for | Open-source, policy-controlled secret infrastructure |
| Authentication | Token, AppRole, or JWT/OIDC |
| Build feature | `openbao` (0.17+) |
| Default storage | KV path `secretspec/{project}/{profile}/{key}`, field `value` |

## Quick start

```bash
$ export BAO_TOKEN=hvs.your-token-here
$ secretspec set DATABASE_URL --provider openbao://bao.example.com:8200
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret 'DATABASE_URL' saved to openbao (profile: default)
```

## Setup

### Prerequisites

- A running OpenBao server
- Authentication credentials
- KV secrets engine enabled (v1 or v2)
- Build with `--features openbao`

### Environment compatibility

For the variables defined by the OpenBao CLI, the provider follows its
documented convention: `BAO_ADDR`, `BAO_NAMESPACE`, `BAO_TOKEN`, and
`BAO_TOKEN_PATH` take precedence over their `VAULT_*` counterparts.

SecretSpec additionally defines OpenBao-prefixed provider inputs for AppRole
and JWT authentication. These are consumed by SecretSpec, not by the `bao` CLI,
and retain the corresponding `VAULT_*` names as compatibility fallbacks.

### Token authentication

Token authentication is the default. SecretSpec checks these sources in order:

1. The alias's `token` provider credential
2. `BAO_TOKEN`, then `VAULT_TOKEN`
3. The file selected by `BAO_TOKEN_PATH`, then `VAULT_TOKEN_PATH`
4. The OpenBao CLI's default `~/.vault-token`

```bash
$ export BAO_TOKEN=hvs.your-token-here
```

### AppRole authentication

Select AppRole with `?auth=approle`:

```bash
$ export BAO_ROLE_ID=your-role-id
$ export BAO_SECRET_ID=your-secret-id
```

These are SecretSpec provider inputs, not OpenBao CLI variables.
`VAULT_ROLE_ID` and `VAULT_SECRET_ID` remain accepted as fallbacks. Prefer
semantic provider credentials when configuring an alias:

```toml title="secretspec.toml"
[providers.bao_approle]
uri = "openbao://bao.example.com:8200/secret?auth=approle"

[providers.bao_approle.credentials]
role_id = { provider = "onepassword", ref = { vault = "Infra", item = "bao-approle", field = "role_id" } }
secret_id = { provider = "onepassword", ref = { vault = "Infra", item = "bao-approle", field = "secret_id" } }
```

### JWT / OIDC authentication

Select JWT with `?auth=jwt` and a `role`. The provider performs the
`auth/jwt/login` exchange itself. The JWT comes from SecretSpec's `BAO_JWT`
input, then the `VAULT_JWT` compatibility fallback. Otherwise, in a GitHub
Actions or Forgejo job with `id-token: write`, the provider mints one from the
runner's OIDC identity.

- `?role=`, `BAO_JWT_ROLE`, or `VAULT_JWT_ROLE` (required)
- `?audience=`, `BAO_JWT_AUDIENCE`, or `VAULT_JWT_AUDIENCE`

## Configuration

### URI format

```text
openbao://[namespace@]host[:port][/mount][?key=value&...]
```

- `host[:port]`: OpenBao address (falls back through `BAO_ADDR`, `VAULT_ADDR`)
- `mount`: KV engine mount path (default: `secret`)
- `namespace@`: Optional namespace (falls back through `BAO_NAMESPACE`,
  `VAULT_NAMESPACE`)
- `?auth=approle`: Use AppRole authentication (default: `token`)
- `?auth=jwt`: Use JWT/OIDC authentication (requires a role)
- `?role=`: OpenBao role for JWT auth
- `?audience=`: Audience requested from the CI OIDC issuer
- `?kv=1`: Use KV v1 (default: v2)
- `?tls=false`: Disable TLS for development servers

### URI examples

```text
openbao://bao.example.com:8200/secret
openbao://team-a@bao.example.com:8200/secret
openbao://bao.example.com:8200/secret?auth=approle
openbao://bao.example.com:8200/secret?auth=jwt&role=ci
```

### Project configuration

```toml title="secretspec.toml"
[providers]
bao_prod = "openbao://bao.example.com:8200/secret"

[profiles.production]
DATABASE_URL = { description = "Database URL", providers = ["bao_prod"] }
```

## Storage model

Each secret is stored at `secretspec/{project}/{profile}/{key}` under the
configured mount, with its value in a field named `value`.

For KV v2, `DATABASE_URL` for project `myapp` and profile `production` is read
from `GET /v1/secret/data/secretspec/myapp/production/DATABASE_URL`.

## Use existing secrets

A secret's [`ref`](/reference/configuration/#secret-references) field names an
existing KV entry: `item` is the path relative to the mount, and `field`
selects the field to read. References are **read-only** so a single-field write
cannot overwrite the entry's other fields.

```toml
[profiles.production]
DATABASE_URL = { description = "DB", ref = { item = "myapp/config", field = "db_url" }, providers = ["openbao://bao.example.com:8200/secret"] }
```

## CI/CD

AppRole avoids placing a user token in the CI environment:

```bash
$ export BAO_ROLE_ID="$CI_ROLE_ID"
$ export BAO_SECRET_ID="$CI_SECRET_ID"
$ secretspec export --format gha --provider "openbao://bao.example.com:8200/secret?auth=approle"
```

With GitHub Actions or Forgejo Actions `id-token: write`, JWT/OIDC avoids a
static authentication credential:

```bash
$ secretspec export --format gha --provider "openbao://bao.example.com:8200/secret?auth=jwt&role=ci"
```

## Advanced configuration

### KV version 1

```bash
$ secretspec set DATABASE_URL --provider "openbao://bao.example.com:8200/secret?kv=1"
```

### OpenBao namespaces

```bash
$ secretspec check --provider openbao://team-a@bao.example.com:8200/secret

$ export BAO_NAMESPACE=team-a
$ secretspec check --provider openbao://bao.example.com:8200/secret
```

### Development mode

```bash
$ bao server -dev -dev-root-token-id="dev-only-token"
$ export BAO_TOKEN="dev-only-token"
$ secretspec check --provider "openbao://127.0.0.1:8200/secret?tls=false"
```
