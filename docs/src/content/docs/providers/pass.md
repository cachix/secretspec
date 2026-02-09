---
title: Pass Provider
description: Unix password manager integration with GPG encryption
---

The Pass provider stores secrets using the Unix password manager `pass` (password-store). Secrets are GPG-encrypted for secure local development.

## Installation

```bash
# Debian/Ubuntu
$ sudo apt-get install pass

# Fedora
$ sudo dnf install pass

# Arch
$ sudo pacman -S pass

# macOS
$ brew install pass
```

## Configuration

```toml
# secretspec.toml
[project]
name = "myapp"

[[providers]]
type = "pass"
uri = "pass://"
```

## Usage

```bash
# Initialize password store (first time only)
$ pass init <gpg-key-id>

# Set a secret
$ secretspec set DATABASE_URL
Enter value for DATABASE_URL: postgresql://localhost/mydb

# Run with secrets
$ secretspec run -- npm start
```

## Storage Format

Secrets are stored with a hierarchical path structure:
`secretspec/{project}/{profile}/{key}`

For example, with project "myapp" and profile "default":
```bash
$ pass show secretspec/myapp/default/DATABASE_URL
postgresql://localhost/mydb
```

## Shared Secrets

By default, secrets are stored under `secretspec/{project}/{profile}/{key}`, which isolates them per project. To share secrets across projects, use a custom folder prefix via the URI:

```toml
# ~/.config/secretspec/config.toml
[providers]
shared = "pass://secretspec/shared/{profile}/{key}"
```

The URI supports `{project}`, `{profile}`, and `{key}` placeholders. By omitting `{project}`, multiple projects can read and write the same pass entry:

```toml
# secretspec.toml (in project-A and project-B)
[profiles.default]
ARTIFACTORY_USER = { description = "Artifactory user", providers = ["shared"] }
```

Both projects will resolve `ARTIFACTORY_USER` from pass entry `secretspec/shared/default/ARTIFACTORY_USER`.
