---
title: LastPass Provider
description: LastPass password manager integration
---

The LastPass provider integrates with LastPass password manager for secure cloud-based secret storage.

## At a glance

| | |
| --- | --- |
| Provider | `lastpass` |
| URI | `lastpass://[item_template]` |
| Access | Read and write |
| Best for | Teams already using LastPass |
| Authentication | An authenticated `lpass` CLI session |
| Default storage | `secretspec/{project}/{profile}/{key}` |

## Quick start

```bash
# Set a secret
$ secretspec set DATABASE_URL --provider lastpass
Enter value for DATABASE_URL: postgresql://localhost/mydb

# Get a secret
$ secretspec get DATABASE_URL --provider lastpass

# Run with secrets
$ secretspec run --provider lastpass -- npm start
```

## Setup

### Prerequisites

Install LastPass CLI:
```bash
# macOS
brew install lastpass-cli

# Linux (apt)
sudo apt install lastpass-cli

# NixOS
nix-env -iA nixpkgs.lastpass-cli
```

### Authentication

```bash
# Standard login
$ lpass login your-email@example.com

# Trust device (reduces MFA prompts)
$ lpass login --trust your-email@example.com
```

## Configuration

### URI format

```
lastpass://[item_template]
```

`item_template` is optional and replaces the default
`secretspec/{project}/{profile}/{key}` layout. It supports the `{project}`,
`{profile}`, and `{key}` placeholders. Include `{key}` unless every SecretSpec
key should resolve to the same LastPass item.

### URI examples

```bash
# Default SecretSpec layout
lastpass

# Keep SecretSpec items in a team folder
lastpass://Work/SecretSpec/{project}/{profile}/{key}
```

### Project configuration

```toml title="secretspec.toml"
[providers]
team = "lastpass://"

[profiles.production]
DATABASE_URL = { description = "Database URL", providers = ["team"] }
```

## Storage model

By default, each secret maps to an item named
`secretspec/{project}/{profile}/{key}`. A custom `item_template` replaces that
layout; include all placeholders needed to keep secrets distinct.

## Use existing secrets

A secret's [`ref`](/reference/configuration/#secret-references) field names an
existing item instead: `item` is the full item name, including any folder
(`field` is not supported). Reads and writes target that item in place.

```toml
[profiles.production]
DATABASE_URL = { description = "DB", ref = { item = "Shared-Infra/Production DB" }, providers = ["lastpass"] }
```

## CI/CD

```bash
# Disable interactive pinentry and authenticate with a CI-managed password
$ export LPASS_DISABLE_PINENTRY=1
$ echo "$LASTPASS_PASSWORD" | lpass login --trust your-email@example.com

$ secretspec run --provider lastpass -- deploy
```
