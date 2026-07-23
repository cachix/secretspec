---
title: Gopass Provider
description: GPG-encrypted, git-synced password store integration
---

The Gopass provider integrates with [gopass](https://www.gopass.pw/), a multi-user, multi-store abstraction layer on top of `pass` that keeps secrets GPG-encrypted and syncs them via git.

:::note[Version compatibility]
Available since SecretSpec 0.15.
:::

## At a glance

| | |
| --- | --- |
| Provider | `gopass` |
| URI | `gopass://[folder_prefix]` |
| Access | Read and write |
| Best for | GPG-encrypted, git-synced, multi-user password stores |
| Authentication | The GPG key configured for the password store |
| Availability | SecretSpec 0.15+ |
| Default storage | `secretspec/{project}/{profile}/{key}` |

## Quick start

```bash
# Set a secret
$ secretspec set DATABASE_URL --provider gopass
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret DATABASE_URL saved to gopass

# Get a secret
$ secretspec get DATABASE_URL --provider gopass
postgresql://localhost/mydb

# Run with secrets
$ secretspec run --provider gopass -- npm start
```

## Setup

### Prerequisites

Install the `gopass` CLI and initialize a password store:
```bash
# macOS
brew install gopass

# Debian/Ubuntu
sudo apt install gopass

# NixOS
nix-env -iA nixpkgs.gopass
```

### Authentication

SecretSpec uses the GPG identities configured by `gopass`. Confirm that the
target store is initialized and can be unlocked before using the provider.

## Configuration

### URI format

```
gopass://[folder_prefix]
```

- `folder_prefix`: Optional path prefix supporting `{project}`, `{profile}`, and `{key}` placeholders. Defaults to `secretspec/{project}/{profile}/{key}`.

### URI examples

```text
gopass
gopass://secretspec/shared/{profile}/{key}
```

### Project configuration

```toml title="secretspec.toml"
[providers]
team = "gopass://"

[profiles.default]
DATABASE_URL = { description = "Database URL", providers = ["team"] }
```

## Storage model

Each secret is stored under `secretspec/{project}/{profile}/{key}`. Gopass
encrypts the entry with GPG and can synchronize the password store through git.

## Use existing secrets

A secret's [`ref`](/reference/configuration/#secret-references) field names an
existing entry instead: `item` is the full entry path, including any mount-point
prefix for multi-store setups (`field` is not supported). Reads and writes
target that entry in place.

```toml
[profiles.production]
DATABASE_URL = { description = "Production DB", ref = { item = "work-store/infra/postgres" }, providers = ["gopass"] }
```

## Advanced configuration

### Shared secrets

By default, secrets are stored under `secretspec/{project}/{profile}/{key}`, which isolates them per project. To share secrets across projects, use a custom folder prefix via the URI:

```toml
# ~/.config/secretspec/config.toml
[defaults.providers]
shared = "gopass://secretspec/shared/{profile}/{key}"
```

The URI supports `{project}`, `{profile}`, and `{key}` placeholders. By omitting `{project}`, multiple projects can read and write the same store entry:

```toml
# secretspec.toml (in project-A and project-B)
[profiles.default]
ARTIFACTORY_USER = { description = "Artifactory user", providers = ["shared"] }
```

Both projects will resolve `ARTIFACTORY_USER` from `secretspec/shared/default/ARTIFACTORY_USER`.

## Troubleshooting and limitations

Only the first line of an entry is read back — if an entry was written outside
of `secretspec` and contains multiple lines, everything after the first line is
discarded on `get`.
