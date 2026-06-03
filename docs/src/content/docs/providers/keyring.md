---
title: Keyring Provider
description: Secure system credential store integration
---

The Keyring provider stores secrets in your system's native credential store. Recommended for local development.

## Supported Platforms

- **macOS**: Keychain
- **Windows**: Credential Manager
- **Linux**: Secret Service (GNOME Keyring, KWallet)

## Installation

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

### URI Format

```
keyring://[folder_prefix]
```

- `folder_prefix`: Optional path prefix supporting `{project}`, `{profile}`, and `{key}` placeholders. Defaults to `monosecret/{project}/{profile}/{key}`.

### Examples

```bash
# Use default keyring storage
$ monosecret set DATABASE_URL --provider keyring

# Custom folder prefix (e.g., to share secrets across projects — see below)
$ monosecret set DATABASE_URL --provider "keyring://shared/{profile}/{key}"
```

## Usage

```bash
# Set a secret
$ monosecret set DATABASE_URL
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret DATABASE_URL saved to keyring

# Get a secret
$ monosecret get DATABASE_URL
postgresql://localhost/mydb

# Run with secrets
$ monosecret run -- npm start

# Use with profiles
$ monosecret set API_KEY --profile production
$ monosecret run --profile production -- npm start
```

## Shared Secrets

By default, secrets are stored under `monosecret/{project}/{profile}/{key}`, which isolates them per project. To share secrets across projects, use a custom folder prefix via the URI:

```toml
# ~/.config/monosecret/config.toml
[defaults.providers]
shared = "keyring://monosecret/shared/{profile}/{key}"
```

The URI supports `{project}`, `{profile}`, and `{key}` placeholders. By omitting `{project}`, multiple projects can read and write the same keyring entry:

```toml
# monosecret.toml (in project-A and project-B)
[profiles.default]
ARTIFACTORY_USER = { description = "Artifactory user", providers = ["shared"] }
```

Both projects will resolve `ARTIFACTORY_USER` from keyring service `monosecret/shared/default/ARTIFACTORY_USER`.
