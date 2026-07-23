---
title: Keyring Provider
description: Secure system credential store integration
---

The Keyring provider stores secrets in your system's native credential store. Recommended for local development.

## At a glance

| | |
| --- | --- |
| Provider | `keyring` |
| URI | `keyring://[folder_prefix]` |
| Access | Read and write |
| Best for | Secure local development |
| Authentication | Current operating-system user |
| Default storage | `secretspec/{project}/{profile}/{key}` |

## Quick start

```bash
# Set a secret
$ secretspec set DATABASE_URL --provider keyring
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret DATABASE_URL saved to keyring

# Get a secret
$ secretspec get DATABASE_URL --provider keyring
postgresql://localhost/mydb

# Run with secrets
$ secretspec run --provider keyring -- npm start
```

## Setup

### Supported platforms

- **macOS**: Keychain
- **Windows**: Credential Manager
- **Linux**: Secret Service (GNOME Keyring, KWallet)

### Linux prerequisites

Linux only - install if missing:
```bash
# Debian/Ubuntu
$ sudo apt-get install gnome-keyring

# Fedora
$ sudo dnf install gnome-keyring

# Arch
$ sudo pacman -S gnome-keyring
```

## Configuration

### URI format

```
keyring://[folder_prefix]
```

- `folder_prefix`: Optional path prefix supporting `{project}`, `{profile}`, and `{key}` placeholders. Defaults to `secretspec/{project}/{profile}/{key}`.

### URI examples

```text
keyring
keyring://shared/{profile}/{key}
```

### Project configuration

```toml title="secretspec.toml"
[providers]
local = "keyring://"

[profiles.default]
DATABASE_URL = { description = "Database URL", providers = ["local"] }
```

## Storage model

Each secret is stored under `secretspec/{project}/{profile}/{key}` as the
keyring service, with the current system username as the account. Project and
profile names keep convention secrets isolated.

## Use existing secrets

A secret's
[`ref`](/reference/configuration/#secret-references) field names an exact keyring
entry instead, useful for reading a credential another application already
stored: `item` is the service, and the optional `field` is the account
(defaults to the current system username). Reads and writes target that entry in
place.

```toml
[profiles.default]
API_TOKEN = { description = "Token", ref = { item = "com.example.app", field = "me@example.com" }, providers = ["keyring"] }
```

## Advanced configuration

### Shared secrets

By default, secrets are stored under `secretspec/{project}/{profile}/{key}`, which isolates them per project. To share secrets across projects, use a custom folder prefix via the URI:

```toml
# ~/.config/secretspec/config.toml
[defaults.providers]
shared = "keyring://secretspec/shared/{profile}/{key}"
```

The URI supports `{project}`, `{profile}`, and `{key}` placeholders. By omitting `{project}`, multiple projects can read and write the same keyring entry:

```toml
# secretspec.toml (in project-A and project-B)
[profiles.default]
ARTIFACTORY_USER = { description = "Artifactory user", providers = ["shared"] }
```

Both projects will resolve `ARTIFACTORY_USER` from keyring service `secretspec/shared/default/ARTIFACTORY_USER`.
