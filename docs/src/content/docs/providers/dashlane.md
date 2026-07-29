---
title: Dashlane Provider
description: Read-only access to a Dashlane vault through the Dashlane CLI
---

:::note[Version compatibility]
The Dashlane provider is added in SecretSpec 0.18.
:::

The Dashlane provider reads secrets from a [Dashlane](https://www.dashlane.com/)
vault through the [Dashlane CLI](https://cli.dashlane.com/) (`dcli`). It is a
**read-only** provider: `dcli` can list and read vault items but has no command
that creates or edits one, so items are authored in a Dashlane app and read from
here.

## At a glance

| | |
| --- | --- |
| Provider | `dashlane` |
| URI | `dashlane://[ITEM_TYPE]` |
| Access | Read-only |
| Best for | Teams already keeping developer secrets in Dashlane |
| Authentication | `dcli` device registration, or `DASHLANE_SERVICE_DEVICE_KEYS` |
| Network | Local reads; `dcli` re-syncs when its copy is over an hour old |
| Default storage | Item titled `secretspec/{project}/{profile}/{key}` |

## Quick start

```bash
# In a Dashlane app, create a secure note titled:
#   secretspec/myproject/default/DATABASE_URL
# with the connection string as its content, then sync the CLI:
$ dcli sync

# Check secrets are available
$ secretspec check --provider dashlane
✓ All required secrets are configured

# Run with secrets
$ secretspec run --provider dashlane -- npm start
```

## Setup

### Prerequisites

Install the Dashlane CLI:

```bash
# macOS
$ brew install dashlane/tap/dashlane-cli

# Linux: download the dcli-linux-x64 binary from
# https://github.com/Dashlane/dashlane-cli/releases
```

### Authentication

Run `dcli sync` once to register this device. It prompts for your email and a
second factor (email code, TOTP, or Duo push), then for your master password.
Supported primary methods are master password and self-hosted SSO;
password-less authentication is not supported by `dcli`.

By default the master password is saved in the OS keychain. `dcli lock` locks
the vault again, and `dcli logout` clears both the local database and the
keychain entry.

SecretSpec checks `dcli status` before reading and reports an unregistered
device or a locked vault. It never answers a `dcli` prompt — reads run with
stdin closed, so an unauthenticated CLI fails immediately rather than leaving
`secretspec run` waiting on a password.

## Configuration

### URI format

```
dashlane://[ITEM_TYPE]
```

`ITEM_TYPE` restricts the search to one Dashlane content type: `secret`,
`note`, or `password` (`login` is accepted as an alias for `password`). Omit it
to search secrets, then logins, then notes — the order `dcli read` resolves a
name in, so a title held by both a login and a note resolves the same way here
as it does through `dcli`.

Pinning the type is worth doing when you know where your secrets live: each
content type searched costs one `dcli` invocation.

### URI examples

```
dashlane://
dashlane://note
dashlane://secret
dashlane://password
```

### Project configuration

```toml title="secretspec.toml"
[providers]
vault = "dashlane://note"

[profiles.default]
DATABASE_URL = { description = "Database URL", providers = ["vault"] }
```

## Storage model

A convention secret reads the vault item **titled**
`secretspec/{project}/{profile}/{key}` — for example
`secretspec/myproject/production/DATABASE_URL`. Projects and profiles stay
isolated because the title carries both.

The value comes from the item's default field: `content` for a secret or a
secure note, `password` for a login.

Titles are matched exactly, case-insensitively. Because Dashlane does not
enforce unique titles, SecretSpec refuses a title that matches more than one
item instead of picking one; point the secret at a single item with a `ref`
naming its identifier to resolve the collision.

## Use existing secrets

To read an item you already have, name it with a `ref`:

```toml title="secretspec.toml"
[profiles.default]
# By title
GITHUB_TOKEN = { description = "GitHub token", ref = { item = "GitHub personal access token" }, providers = ["dashlane"] }

# By identifier — stable across renames, and never ambiguous
STRIPE_KEY = { description = "Stripe key", ref = { item = "D47734C4-0ABE-423A-8633-6B9F10A38905" }, providers = ["dashlane"] }

# A named field of a login
DB_USER = { description = "Database user", ref = { item = "Production database", field = "login" }, providers = ["dashlane://password"] }
```

Find an item's identifier by listing its content type — `dcli secret`,
`dcli note`, or `dcli password` with `-o json`. The `id` is emitted wrapped in
braces; both forms work here.

`ref` supports the `item` and `field` coordinates. Dashlane has no vaults or
sections, so those coordinates are rejected rather than ignored.

## CI/CD

Register a non-interactive device from a workstation:

```bash
$ dcli devices register "ci-runner"
```

This prints device credentials once. Store them and expose them to the runner
as `DASHLANE_SERVICE_DEVICE_KEYS`:

```yaml title=".github/workflows/ci.yml"
- run: secretspec run --provider dashlane -- npm test
  env:
    DASHLANE_SERVICE_DEVICE_KEYS: ${{ secrets.DASHLANE_SERVICE_DEVICE_KEYS }}
```

The credentials can also be sourced from another provider:

```toml title="secretspec.toml"
[providers]
dashlane_ci = { uri = "dashlane://note", credentials = { service_device_keys = "keyring" } }
```

Dashlane recommends a dedicated account for non-interactive devices. OTP at
every login and SSO are not supported for them.

## Troubleshooting and limitations

**`secretspec set` fails.** Add or edit the item in a Dashlane app, run
`dcli sync`, then read it here. Give the secret a writable provider as well if
you need to set values from SecretSpec.

**A new item is invisible until the CLI syncs.** `dcli` reads a local copy of
the vault. SecretSpec never asks it to sync, but `dcli` syncs itself whenever
its last sync is over an hour old, so a read is usually local and occasionally
a network round-trip. Run `dcli sync` after adding an item rather than waiting
for that, and `dcli configure disable-auto-sync true` to keep reads strictly
offline.

**Only three content types are readable.** `dcli` exposes listers for secrets,
secure notes, and logins. Passkeys, personal info, payments, and IDs have no
CLI surface and cannot be read.

**Secrets need a Business plan.** The `secret` content type is not available on
personal plans, where `dashlane://secret` finds nothing. Use secure notes there.

## Security considerations

Reads decrypt the local vault in a `dcli` subprocess and pass the value back
over a pipe; SecretSpec never writes it to disk or to a log. A read can reach
the network, because `dcli` re-syncs when its copy is over an hour stale. `dcli password`
copies a password to the system clipboard when it is run without an output
format, so SecretSpec always requests JSON explicitly.

`DASHLANE_SERVICE_DEVICE_KEYS` grants full read access to the vault. Treat it
as highly sensitive; Dashlane prefixes it with `dls_` so secret scanners can
recognize it.
