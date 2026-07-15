---
title: Azure Key Vault Provider
description: Azure Key Vault integration
---

The Azure Key Vault provider integrates with Azure for centralized secret management.

## Prerequisites

- An Azure Key Vault instance
- Authenticated via a service principal (`AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET`), the Azure CLI (`az login`), a managed identity, or AKS workload identity
- Build with `--features akv`

## Configuration

### URI Format

```
akv://VAULT_NAME[?auth=env|cli|managed_identity|workload_identity][&suffix=DNS_SUFFIX]
```

- `VAULT_NAME`: Your Key Vault name (e.g. `myvault`), or a full DNS name for sovereign clouds (e.g. `myvault.vault.azure.cn`)
- `auth`: Authentication method (default: `env`)
  - `env` — a service principal from `AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET` (all three must be set together); falls back to the signed-in Azure CLI / Azure Developer CLI session if none are set. Setting only some of the three is an error rather than a silent fallback to a different identity.
  - `cli` — the Azure CLI / Azure Developer CLI session only
  - `managed_identity` — the VM / App Service / AKS system-assigned managed identity
  - `workload_identity` — AKS workload identity federation (`AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/`AZURE_FEDERATED_TOKEN_FILE`, injected automatically by AKS)
- `suffix`: an explicit Key Vault DNS suffix for a bare `VAULT_NAME`, e.g. `akv://myvault?suffix=vault.azure.cn` for a sovereign cloud, instead of relying on a dotted `VAULT_NAME`

### Examples

```bash
# Set a secret (reads env vars, or falls back to `az login`)
$ secretspec set DATABASE_URL --provider akv://myvault

# Get a secret
$ secretspec get DATABASE_URL --provider akv://myvault

# Check secrets using a managed identity
$ secretspec check --provider akv://myvault?auth=managed_identity

# Run with secrets
$ secretspec run --provider akv://myvault -- npm start

# Sovereign cloud, via an explicit suffix instead of a dotted vault name
$ secretspec check --provider akv://myvault?suffix=vault.azure.cn
```

## Secret References

By default each secret is stored as `secretspec--{project}--{profile}--{key}`. A
secret's [`ref`](/reference/configuration/#secret-references) field names an
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

## Usage

### Basic Commands

```bash
# Set a secret
$ secretspec set DATABASE_URL --provider akv://myvault
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret 'DATABASE_URL' saved to akv (profile: default)

# Get it back
$ secretspec get DATABASE_URL --provider akv://myvault
postgresql://localhost/mydb
```

### Secret Naming

Azure Key Vault secret names may only contain ASCII letters, digits and
hyphens — notably, unlike every other cloud provider, not underscores or
slashes. Secrets are stored as: `secretspec--{project}--{profile}--{key}`,
with underscores in each component rewritten to hyphens.

Example: `DATABASE_URL` in project `myapp`, profile `production` becomes
`secretspec--myapp--production--DATABASE-URL`.

This rewrite is lossy: a project, profile, or key that differs only in using
hyphens versus underscores (e.g. `FOO_BAR` and `FOO-BAR`) maps to the same Key
Vault secret name. Prefer hyphens if that distinction matters to you. A
project, profile, or key containing a literal `--` or a `__` (which sanitizes
to `--`) is rejected outright — it would be indistinguishable from the `--`
delimiter between components and could otherwise silently collide with an
unrelated secret.

### CI/CD with a Service Principal

```bash
# Set credentials
$ export AZURE_TENANT_ID="..."
$ export AZURE_CLIENT_ID="..."
$ export AZURE_CLIENT_SECRET="..."

# Run command
$ secretspec run --provider akv://myvault -- deploy
```

All three environment variables must be set together; setting only some of
them is treated as a configuration error rather than a silent fallback to the
Azure CLI session.

### AKS with Workload Identity

```bash
# AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_FEDERATED_TOKEN_FILE are
# injected automatically into workload-identity-enabled pods.
$ secretspec run --provider akv://myvault?auth=workload_identity -- deploy
```
