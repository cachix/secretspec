---
title: Passbolt Provider
description: Passbolt self-hosted password manager via go-passbolt-cli
---

The Passbolt provider integrates with [Passbolt](https://www.passbolt.com/), the
self-hosted, open-source password manager, via the official
[`go-passbolt-cli`](https://github.com/passbolt/go-passbolt-cli) (`passbolt`).

It fits the workflow where **a human enters an API key or service password once**
(via the Passbolt web UI or CLI) and **dev machines read it at runtime** — no
secret material is ever written to `secretspec.toml` or to disk.

## Prerequisites

- The `passbolt` CLI installed and on `PATH` (build from
  [go-passbolt-cli](https://github.com/passbolt/go-passbolt-cli)).
- Credentials for your Passbolt account: the server address, your OpenPGP
  private key, and its passphrase.

## Authentication

The private key and passphrase are the bootstrap secrets that unlock every
other secret, so they never belong in `secretspec.toml` or the provider URI.
There are two ways to supply them.

### Option A — secretspec-owned env vars (no separate CLI config)

Set these in your environment (e.g. via your shell profile, a `.envrc`, or your
CI secret store) and secretspec forwards them to the CLI for you — the
passphrase and inline key go through the child process environment, never the
command line:

| Variable | Purpose |
|----------|---------|
| `SECRETSPEC_PASSBOLT_SERVER` | Server address (or use the URI's `?server=`) |
| `SECRETSPEC_PASSBOLT_PRIVATE_KEY_FILE` | Path to your OpenPGP private key file |
| `SECRETSPEC_PASSBOLT_PRIVATE_KEY` | Inline OpenPGP private key (alternative to the file) |
| `SECRETSPEC_PASSBOLT_PASSPHRASE` | Private-key passphrase |

```bash
export SECRETSPEC_PASSBOLT_SERVER=https://pass.example.com
export SECRETSPEC_PASSBOLT_PRIVATE_KEY_FILE=~/.config/passbolt/ada.asc
export SECRETSPEC_PASSBOLT_PASSPHRASE='<passphrase>'

secretspec get STRIPE_SECRET_KEY --provider passbolt
```

### Option B — the CLI's own configuration

Run `passbolt configure` once; with none of the env vars above set, the
provider inherits that configuration:

```bash
passbolt configure \
  --serverAddress https://pass.example.com \
  --userPrivateKeyFile ada.asc \
  --userPassword '<passphrase>'
```

Either way, no credentials appear in `secretspec.toml` or the provider URI.

## Configuration

### URI Format

```
passbolt://[name-template][?folder=<folder-id>&server=<server-address>]
```

- `name-template`: resource-name pattern for convention secrets, supporting the
  `{project}`, `{profile}`, `{key}` placeholders. Defaults to
  `secretspec/{project}/{profile}/{key}`.
- `folder` (optional): a Passbolt folder id. New convention resources are
  created inside it (`--folderParentID`) and name lookups are scoped to it.
- `server` (optional): overrides the CLI's configured server address
  (`--serverAddress`). Useful when one machine talks to several Passbolt servers.

### Examples

```bash
# Default resource name (secretspec/{project}/{profile}/{key})
passbolt://

# Custom resource-name template
passbolt://secretspec/{project}/{profile}/{key}

# Pin the server address (e.g. a tailnet-internal Passbolt)
passbolt://?server=https://pass.example.com

# Scope convention resources to a folder
passbolt://?folder=a9230ec4-5507-4870-b8b5-b3f500587e4c
```

## Storage model

Each convention secret maps to one Passbolt **resource**:

- The resource **name** encodes `{project}/{profile}/{key}`.
- The secret value lives in the resource's **password** field.

## Secret references

A secret's [`ref`](/reference/configuration/#secret-references) points at an
existing, human-provisioned resource instead of the convention layout — the
common case for "someone added the API key in Passbolt, I just want to read it":

- `item`: the resource **id** (a UUID, copied from the Passbolt UI) or the exact
  resource **name**.
- `field` (optional): which resource field holds the value — one of `password`
  (default), `username`, `uri`, `description`.

```toml
[profiles.production]
# By resource id (unambiguous — recommended for refs)
STRIPE_SECRET_KEY = { description = "Stripe key", ref = { item = "a9230ec4-5507-4870-b8b5-b3f500587e4c" }, providers = ["passbolt://?server=https://pass.example.com"] }

# By resource name, reading a non-default field
SERVICE_USER = { description = "Service account user", ref = { item = "Payments service account", field = "username" }, providers = ["passbolt"] }
```

Reads fetch the resource by id (or resolve the name to an id first) and decrypt
the requested field. Writes update that field on the existing resource; a `ref`
whose id resolves to nothing is an error (secretspec never creates a detached
resource for an externally managed reference).

## Usage

```bash
# Set a secret (creates or updates the secretspec/... resource's password)
$ secretspec set STRIPE_SECRET_KEY --provider passbolt
Enter value for STRIPE_SECRET_KEY: sk_live_...

# Get a secret
$ secretspec get STRIPE_SECRET_KEY --provider passbolt

# Run a process with secrets injected
$ secretspec run --provider passbolt -- npm start
```

## Environment variables

- `SECRETSPEC_PASSBOLT_SERVER`, `SECRETSPEC_PASSBOLT_PRIVATE_KEY_FILE`,
  `SECRETSPEC_PASSBOLT_PRIVATE_KEY`, `SECRETSPEC_PASSBOLT_PASSPHRASE`: credentials
  forwarded to the CLI (see [Authentication](#authentication)).
- `SECRETSPEC_PASSBOLT_CLI_PATH`: path to the `passbolt` binary when it is not
  simply `passbolt` on `PATH`.
