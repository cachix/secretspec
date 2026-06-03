---
title: Proton Pass Provider
description: Proton Pass integration via the official pass-cli
---

The Proton Pass provider integrates with [Proton Pass](https://proton.me/pass) for end-to-end encrypted cloud secret storage.

## Prerequisites

- Proton Pass CLI (`pass-cli`) - download from [proton.me/pass/download](https://proton.me/pass/download)
- A Proton account, signed in via `pass-cli login`
- A vault to store secrets in (e.g. `pass-cli vault create monosecret`)

## Configuration

### URI Format

```
protonpass://[vault_name[/title-template]]
```

- `vault_name`: Target vault (defaults to `monosecret`)
- `title-template`: Item title pattern supporting `{project}`, `{profile}`, `{key}` placeholders

### Examples

```bash
# Default vault ("monosecret")
protonpass://

# Specific vault
protonpass://Work

# Specific vault and custom title template
protonpass://Work/{project}/{profile}/{key}
```

## Usage

```bash
# Set a secret
$ monosecret set DATABASE_URL --provider protonpass://Personal
Enter value for DATABASE_URL: postgresql://localhost/mydb

# Get a secret
$ monosecret get DATABASE_URL --provider protonpass://Personal

# Run with secrets
$ monosecret run --provider protonpass://Personal -- npm start

# Profile-specific vault
$ monosecret set DATABASE_URL --profile prod --provider protonpass://Production
```

Secrets are stored as note items; the item title defaults to `{project}/{profile}/{key}`.

### CI/CD with Personal Access Tokens

```bash
# Create a token
$ pass-cli personal-access-token create --name ci --expiration 1y

# Authenticate in CI (store the token as a CI secret)
$ pass-cli login --pat $PROTON_PASS_PAT
$ monosecret run -- deploy
```
