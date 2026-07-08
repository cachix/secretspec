---
title: LastPass Provider
description: LastPass password manager integration
---

The LastPass provider integrates with LastPass password manager for secure cloud-based secret storage.

## Prerequisites

Install LastPass CLI:
```bash
# macOS
brew install lastpass-cli

# Linux (apt)
sudo apt install lastpass-cli

# NixOS
nix-env -iA nixpkgs.lastpass-cli
```

## Configuration

### URI Format

```bash
# Basic
lastpass

# With folder prefix
lastpass://folder_name
lastpass://Work/Projects
```

### Authentication

```bash
# Standard login
lpass login your-email@example.com

# Trust device (reduces MFA prompts)
lpass login --trust your-email@example.com

# CI/CD environments
export LPASS_DISABLE_PINENTRY=1
echo "password" | lpass login --trust your-email@example.com
```

## Secret References

By default each secret maps to an item named `secretspec/{project}/{profile}/{key}`.
A secret's [`ref`](/reference/configuration/#secret-references) field names an
existing item instead: `item` is the full item name, including any folder
(`field` is not supported). Reads and writes target that item in place.

```toml
[profiles.production]
DATABASE_URL = { description = "DB", ref = { item = "Shared-Infra/Production DB" }, providers = ["lastpass"] }
```

## Usage

```bash
# Set a secret
secretspec set DATABASE_URL --provider lastpass
Enter value for DATABASE_URL: postgresql://localhost/mydb

# Set with folder
secretspec set API_KEY --provider lastpass://Production
Enter value for API_KEY: sk-123456

# Get a secret
secretspec get DATABASE_URL --provider lastpass

# Run with secrets
secretspec run --provider lastpass -- npm start

# Profile-specific secrets
secretspec set DATABASE_URL --profile dev --provider lastpass://Development
secretspec set DATABASE_URL --profile prod --provider lastpass://Production
```

Secrets are stored as: `{folder_prefix}/{profile}/{project}/{key}`