---
title: Azure Key Vault Provider
description: Azure Key Vault integration
---

The Azure Key Vault provider integrates with Azure for centralized secret management.

:::note[Version compatibility]
Available since SecretSpec 0.15.
:::

## At a glance

| | |
| --- | --- |
| Provider | `akv` |
| URI | `akv://VAULT_NAME[?auth=METHOD][&suffix=DNS_SUFFIX]` |
| Access | Read and write; secret references are read-only |
| Best for | Workloads and teams on Azure |
| Authentication | Service principal, Azure CLI, managed identity, or workload identity |
| Availability | SecretSpec 0.15+; requires the `akv` build feature |
| Default storage | `secretspec--{base32(project)}--{base32(profile)}--{base32(key)}` |

## Quick start

```bash
# Set a secret
$ secretspec set DATABASE_URL --provider akv://myvault
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret 'DATABASE_URL' saved to akv (profile: default)

# Get it back
$ secretspec get DATABASE_URL --provider akv://myvault
postgresql://localhost/mydb
```

## Setup

### Prerequisites

- An Azure Key Vault instance
- Authenticated via a service principal, the Azure CLI (`az login`), a managed identity, or AKS workload identity
- Build with `--features akv`

### Authentication

Select an authentication mode with the URI's `auth` option:

- `env` (default): service-principal provider credentials or environment
  variables, falling back to an Azure CLI session when none are set.
- `cli`: Azure CLI or Azure Developer CLI only.
- `managed_identity`: system-assigned managed identity.
- `workload_identity`: AKS workload identity federation.

## Configuration

### URI format

```
akv://VAULT_NAME[?auth=env|cli|managed_identity|workload_identity][&suffix=DNS_SUFFIX]
```

- `VAULT_NAME`: Your Key Vault name (e.g. `myvault`), or a full DNS name for sovereign clouds (e.g. `myvault.vault.azure.cn`)
- `auth`: Authentication method (default: `env`)
  - `env` — a service principal from the `tenant_id`, `client_id`, and `client_secret` provider credentials, with `AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET` as fallbacks (all three must be available together); falls back to the signed-in Azure CLI / Azure Developer CLI session if none are available. A partial set is an error rather than a silent fallback to a different identity.
  - `cli` — the Azure CLI / Azure Developer CLI session only
  - `managed_identity` — the VM / App Service / AKS system-assigned managed identity
  - `workload_identity` — AKS workload identity federation (`AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/`AZURE_FEDERATED_TOKEN_FILE`, injected automatically by AKS)
- `suffix`: an explicit Key Vault DNS suffix for a bare `VAULT_NAME`, e.g. `akv://myvault?suffix=vault.azure.cn` for a sovereign cloud, instead of relying on a dotted `VAULT_NAME`
- `?layout=flat` (0.17+): use the key as the Azure secret name verbatim, with no Base32-encoded `{project}/{profile}` scaffolding — see [Layout](#layout-017)

### URI examples

```text
akv://myvault
akv://myvault?auth=managed_identity
akv://myvault?auth=workload_identity
akv://myvault?suffix=vault.azure.cn
```

### Project configuration

```toml title="secretspec.toml"
[providers]
azure = "akv://myvault"

[profiles.production]
DATABASE_URL = { description = "Database URL", providers = ["azure"] }
```

## Storage model

Azure Key Vault secret names may only contain ASCII letters, digits and
hyphens, and Azure compares object identifiers case-insensitively. SecretSpec
stores convention names as
`secretspec--{base32(project)}--{base32(profile)}--{base32(key)}`, using
lowercase, unpadded Base32 for each component.

This encoding is deterministic and injective: names that differ by case,
underscores versus hyphens, or leading/trailing hyphens remain distinct even
though Key Vault's identifiers do not preserve all of those distinctions. The
encoded components contain no hyphens, so the `--` component separators cannot
be confused with component data.

### Layout (0.17+)

Added in SecretSpec 0.17; `?layout=flat` is not available in SecretSpec 0.16 or earlier.

`?layout=` is a [general provider setting](/reference/providers/#layout-flat-017), spelled the same
way across every hierarchical backend. The default **nested** layout Base32-encodes the components
into `secretspec--{base32(project)}--{base32(profile)}--{base32(key)}`, as above.

The **flat** layout (`?layout=flat`) drops the `{project}/{profile}` scaffolding and uses the
`{key}` as the Azure secret name **verbatim** — the shape a store migrated from another manager
already has. Because there is no Base32 rewrite to fall back on, the key must itself be a legal
Azure Key Vault secret name (`^[0-9a-zA-Z-]+$`): an underscore, which the nested layout would have
encoded away, is refused rather than pointing at a name Azure cannot store. The project and profile
name no part of the secret name under flat, so they are not required.

```toml title="secretspec.toml"
[providers]
akv = "akv://myvault?layout=flat"
```

## Use existing secrets

A secret's
[`ref`](/reference/configuration/#secret-references) field names an
existing secret instead: `item` is the secret name (`field` and `version` are
not yet supported). References are **read-only** in this provider, and `item`
must already be a valid Azure Key Vault secret name (letters, digits, and
hyphens only) — unlike convention secrets, it is validated but never rewritten,
since silently rewriting a `ref` could point at a different secret than the
one you named.

```toml
[profiles.production]
DATABASE_URL = { description = "DB", ref = { item = "database-url" }, providers = ["akv://myvault"] }
```

## CI/CD

### Service principal

The `auth=env` mode accepts `tenant_id`, `client_id`, and `client_secret` as
[provider credentials](/concepts/providers/#provider-credentials). For example,
the credentials can be stored in the system keyring instead of a shell profile:

```toml title="secretspec.toml"
[providers.azure]
uri = "akv://myvault"

[providers.azure.credentials]
tenant_id = "keyring"
client_id = "keyring"
client_secret = "keyring"
```

Store all three declared credentials, then use the alias:

```bash
$ secretspec config provider login azure
$ secretspec run --provider azure -- deploy
```

When a semantic credential is not explicitly configured, SecretSpec falls back
to its matching conventional environment variable:

```bash
# Set credentials
$ export AZURE_TENANT_ID="..."
$ export AZURE_CLIENT_ID="..."
$ export AZURE_CLIENT_SECRET="..."

# Run command
$ secretspec run --provider akv://myvault -- deploy
```

Across provider credentials and environment fallbacks, all three values must be
available together. A partial service principal is treated as a configuration
error rather than a silent fallback to the Azure CLI session.

### AKS workload identity

```bash
# AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_FEDERATED_TOKEN_FILE are
# injected automatically into workload-identity-enabled pods.
$ secretspec run --provider akv://myvault?auth=workload_identity -- deploy
```
