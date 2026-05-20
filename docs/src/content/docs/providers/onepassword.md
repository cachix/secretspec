---
title: OnePassword Provider
description: OnePassword secrets management integration
---

The OnePassword provider integrates with OnePassword for team-based secret management with advanced access controls.

## Prerequisites

- OnePassword CLI (`op`)
- OnePassword account
- Authenticated (see [Authentication](#authentication) below)

## Authentication

`secretspec` supports three ways to authenticate against 1Password.

### Desktop app integration (recommended for local dev)

In the 1Password desktop app, open **Settings → Developer** and enable
**"Integrate with 1Password CLI"**. Once enabled, `op` calls made by
`secretspec` are unlocked through the desktop app via biometrics
(Touch ID / Windows Hello / system password) — no shell session
needed and nothing expires from under you.

Under desktop integration, `op whoami` reports `account is not signed
in` even when secret access works, so `secretspec` probes auth via
`op vault list` instead. It also strips any `OP_SESSION_*` environment
variables from spawned `op` processes, so a stale `eval $(op signin)`
session in your shell can't shadow the desktop integration.

#### Linux note

On Linux, the desktop integration requires the `op` binary to be in
the `onepassword-cli` group with the setgid bit set — the desktop
app verifies the caller's GID over its unlock socket. On NixOS this
is handled automatically by `programs._1password.enable = true`. A
plain `pkgs._1password-cli` install (e.g. via `nix-env` or Home
Manager only) does **not** carry the setgid bit and desktop
integration will fail; use the NixOS module, or fall back to a
service account token for headless setups.

### Service account tokens (recommended for CI/CD)

Set `OP_SERVICE_ACCOUNT_TOKEN` in the environment, or use the
`onepassword+token://` / `op+token://` URI schemes. See the [CI/CD section](#cicd-with-service-accounts)
below.

### Manual signin (legacy)

Run `eval $(op signin)` to set per-shell `OP_SESSION_*` tokens. These
expire after 30 minutes of inactivity; if they expire mid-session,
`secretspec` falls back to desktop integration when available.

## Configuration

### URI Format

```
onepassword://[account@]vault[/path]
onepassword+token://[token@]vault[/path]
op://vault[/item[/section...]]
op+token://[token@]vault[/item[/section...]]
```

- `onepassword://` / `onepassword+token://`: legacy SecretSpec-owned storage. Secrets are stored in items named from the provider path/folder prefix, defaulting to `secretspec/{project}/{profile}/{key}`.
- `op://` / `op+token://`: native 1Password references. The URI path is a native 1Password item/section prefix, and object-form provider refs append their `path` plus the secret name or `key` as the field label.
- `account`: Optional account shorthand for `onepassword://` URIs
- `vault`: Target vault name (defaults to "Private")
- `token`: Service account token
- `path`: Optional provider-relative path used by object-form provider refs

### Provider-relative paths with legacy `onepassword://`

For object-form provider refs on `onepassword://`, `path` is interpreted relative to the 1Password vault:

```toml
[providers]
op = "onepassword://Development"

[profiles.default.GITHUB_TOKEN]
providers = [{ provider = "op", path = ["dotfiles", "forges"] }]
```

The first path segment (`dotfiles`) is the 1Password item title. The optional
second segment (`forges`) is the section label inside that item. The field label
is the SecretSpec secret name (`GITHUB_TOKEN`) unless the ref supplies an explicit
`key`.

```toml
[profiles.default.CRATES_TOKEN]
providers = [{ provider = "op", path = ["dotfiles", "registries"], key = "CARGO_REGISTRY_TOKEN" }]
```

If an item, section, or field is missing, SecretSpec treats that provider as not
having the secret and continues to any fallback providers.

### Native 1Password references with `op://`

Use `op://` (or `op+token://` for service-account auth) when you want SecretSpec to use 1Password's native secret-reference shape:

```toml
[providers]
op = "op://Development/dotfiles"

[profiles.default.GITHUB_TOKEN]
providers = [{ provider = "op", path = ["forges"] }]
```

This reads `op://Development/dotfiles/forges/GITHUB_TOKEN` with `op read`. The provider URI contributes the vault and base item (`Development/dotfiles`), the object-form `path` contributes the section (`forges`), and the secret name contributes the field label (`GITHUB_TOKEN`). Use `key` to point a SecretSpec variable at a differently named 1Password field:

```toml
[profiles.default.CRATES_TOKEN]
providers = [{ provider = "op", path = ["registries"], key = "CARGO_REGISTRY_TOKEN" }]
```

`secretspec set` can update an existing native 1Password reference. It first verifies that the reference exists; it will not create a new native item/section/field for `op://` providers.

### Examples

```bash
# Use specific vault
$ secretspec set API_KEY --provider onepassword://Production

# Use specific account and vault
$ secretspec set DATABASE_URL --provider "onepassword://work@DevVault"

# Use service account token
$ secretspec set SECRET --provider "onepassword+token://ops_token123@Production"

# Default vault (Private)
$ secretspec set KEY --provider onepassword://
```

## Usage

### Basic Commands

```bash
# Set a secret
$ secretspec set DATABASE_URL
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret DATABASE_URL saved to OnePassword

# Get a secret
$ secretspec get DATABASE_URL

# Run with secrets
$ secretspec run -- npm start
```

### Profile Configuration

```toml
# secretspec.toml
[development]
provider = "onepassword://Development"

[production]
provider = "onepassword://Production"
```

### CI/CD with Service Accounts

```bash
# Set token
$ export OP_SERVICE_ACCOUNT_TOKEN="ops_eyJ..."

# Run command
$ secretspec run --provider onepassword://Production -- deploy
```