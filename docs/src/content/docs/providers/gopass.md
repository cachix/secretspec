---
title: Gopass Provider
description: GPG-encrypted, git-synced password store integration
---

The Gopass provider integrates with [gopass](https://www.gopass.pw/), a multi-user, multi-store abstraction layer on top of `pass` that keeps secrets GPG-encrypted and syncs them via git.

## Prerequisites

Install the `gopass` CLI and initialize a password store:
```bash
# macOS
brew install gopass

# Debian/Ubuntu
sudo apt install gopass

# NixOS
nix-env -iA nixpkgs.gopass
```

## Configuration

### URI Format

```
gopass://[folder_prefix]
```

- `folder_prefix`: Optional path prefix supporting `{project}`, `{profile}`, and `{key}` placeholders. Defaults to `secretspec/{project}/{profile}/{key}`.

### Examples

```bash
# Use default gopass storage
$ secretspec set DATABASE_URL --provider gopass

# Custom folder prefix (e.g., to share secrets across projects — see below)
$ secretspec set DATABASE_URL --provider "gopass://secretspec/shared/{profile}/{key}"
```

## Secret References

By default each secret is stored under `secretspec/{project}/{profile}/{key}`.
A secret's [`ref`](/reference/configuration/#secret-references) field names an
existing entry instead: `item` is the full entry path, including any mount-point
prefix for multi-store setups (`field` is not supported). Reads and writes
target that entry in place.

```toml
[profiles.production]
DATABASE_URL = { description = "Production DB", ref = { item = "work-store/infra/postgres" }, providers = ["gopass"] }
```

## Usage

```bash
# Set a secret
$ secretspec set DATABASE_URL
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret DATABASE_URL saved to gopass

# Get a secret
$ secretspec get DATABASE_URL
postgresql://localhost/mydb

# Run with secrets
$ secretspec run -- npm start

# Use with profiles
$ secretspec set API_KEY --profile production
$ secretspec run --profile production -- npm start
```

## Shared Secrets

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

## Limitations

Only the first line of an entry is read back — if an entry was written outside
of `secretspec` and contains multiple lines, everything after the first line is
discarded on `get`.
