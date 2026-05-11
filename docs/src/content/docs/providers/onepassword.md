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

`secretspec` strips any `OP_SESSION_*` environment variables from
spawned `op` processes, so a stale `eval $(op signin)` session in
your shell won't shadow the desktop integration and produce
`account is not signed in` errors.

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
`onepassword+token://` URI scheme. See the [CI/CD section](#cicd-with-service-accounts)
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
```

- `account`: Optional account shorthand
- `vault`: Target vault name (defaults to "Private")
- `token`: Service account token
- `path`: Reserved for future use

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