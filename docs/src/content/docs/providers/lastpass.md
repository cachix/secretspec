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

## Usage

```bash
# Set a secret
monosecret set DATABASE_URL --provider lastpass
Enter value for DATABASE_URL: postgresql://localhost/mydb

# Set with folder
monosecret set API_KEY --provider lastpass://Production
Enter value for API_KEY: sk-123456

# Get a secret
monosecret get DATABASE_URL --provider lastpass

# Run with secrets
monosecret run --provider lastpass -- npm start

# Profile-specific secrets
monosecret set DATABASE_URL --profile dev --provider lastpass://Development
monosecret set DATABASE_URL --profile prod --provider lastpass://Production
```

Secrets are stored as: `{folder_prefix}/{profile}/{project}/{key}`
