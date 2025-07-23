---
title: Infisical Provider
description: Infisical secrets management platform integration
---

The Infisical provider integrates with Infisical for centralized secrets management with advanced access controls and audit logging.

## Prerequisites

- Infisical account (cloud or self-hosted)
- Machine identity with Universal Auth configured
- Client ID and Client Secret from Infisical dashboard

## Configuration

### URI Format

```
infisical://[host/]project-id[/path]?client_id=xxx&client_secret=yyy
```

- `host`: Optional custom Infisical instance URL (defaults to app.infisical.com)
- `project-id`: Your Infisical project ID
- `path`: Optional path prefix for organizing secrets
- `client_id`: Universal Auth client ID
- `client_secret`: Universal Auth client secret

### Examples

```bash
# Basic usage with cloud Infisical
$ secretspec set API_KEY --provider "infisical://project-id?client_id=xxx&client_secret=yyy"

# Self-hosted Infisical instance
$ secretspec set DATABASE_URL --provider "infisical://infisical.company.com/project-id?client_id=xxx&client_secret=yyy"

# With path prefix for organization
$ secretspec set SECRET --provider "infisical://project-id/backend?client_id=xxx&client_secret=yyy"
```

## Usage

### Basic Commands

```bash
# Set a secret
$ secretspec set DATABASE_URL
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret DATABASE_URL saved to Infisical

# Get a secret
$ secretspec get DATABASE_URL

# Run with secrets
$ secretspec run -- npm start
```

### Profile Configuration

```toml
# secretspec.toml
[development]
provider = "infisical://dev-project-id?client_id=dev-id&client_secret=dev-secret"

[production]
provider = "infisical://prod-project-id?client_id=prod-id&client_secret=prod-secret"
```

## Environment Mapping

SecretSpec profiles map to Infisical environments:

- `default` → `dev`
- Other profiles map directly (e.g., `production` → `production`)

## Secret Naming

Secrets are stored in Infisical with the naming convention:
`SECRETSPEC_{PROJECT}_{KEY}`

For example, if your project is named "myapp" and you store "API_KEY", it will be saved as "SECRETSPEC_MYAPP_API_KEY" in Infisical.

## Self-Hosted Infisical

For self-hosted instances, specify your instance URL:

```bash
# Via URI
$ secretspec set KEY --provider "infisical://infisical.internal.com/project-id?client_id=xxx&client_secret=yyy"
```