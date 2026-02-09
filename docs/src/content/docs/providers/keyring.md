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

```toml
# secretspec.toml
[project]
name = "myapp"

[[providers]]
type = "keyring"
uri = "keyring://"
```

## Usage

```bash
# Set a secret
$ secretspec set DATABASE_URL
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret DATABASE_URL saved to keyring

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
[providers]
shared = "keyring://secretspec/shared/{profile}/{key}"
```

The URI supports `{project}`, `{profile}`, and `{key}` placeholders. By omitting `{project}`, multiple projects can read and write the same keyring entry:

```toml
# secretspec.toml (in project-A and project-B)
[profiles.default]
ARTIFACTORY_USER = { description = "Artifactory user", providers = ["shared"] }
```

Both projects will resolve `ARTIFACTORY_USER` from keyring service `secretspec/shared/default/ARTIFACTORY_USER`.