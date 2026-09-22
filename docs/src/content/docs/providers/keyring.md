---
title: Keyring Provider
description: Secure system credential store integration
---

> **Changed in version 0.21:** Secret values use the keyring's binary API,
> preserving non-UTF-8 bytes, NULs, whitespace, and line endings. Existing text
> passwords remain readable.

On Windows, text values retain the native UTF-16LE password format used by
earlier releases. Binary values use a SecretSpec-specific marker in the same
credential blob and require SecretSpec 0.21+ to read.

The [Keyring](https://github.com/open-source-cooperative/keyring-rs) provider
stores secrets in your system's native credential store. Recommended for local
development.

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

### macOS keychain prompts

macOS binds every keychain item to the code signature of the program that
created it. Builds that are not signed with an Apple Developer ID, which
includes SecretSpec installed through Nix, Homebrew, or `cargo install`, get a
new signature with every release. After an upgrade, macOS therefore asks for
the login keychain password the first time the new build reads each secret.
Choose **Always Allow**: it grants the new build lasting access, and every
later run stays silent. **Allow** grants a single read, so the dialog returns on
the next run.

> **Changed in version 0.21:** After a read approved with **Always Allow**,
> SecretSpec recreates the item so the new build owns it outright. A read
> approved with **Allow** prints a warning explaining that the dialog will
> return and how to stop it. `secretspec set` over an item written by an
> earlier build asks for the same approval instead of failing with "The
> specified item already exists in the keychain".

Secrets addressed with [`ref`](#use-existing-secrets) belong to the
application that created them and are never recreated, so reading one from
SecretSpec keeps prompting unless that application's item allows it.

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
