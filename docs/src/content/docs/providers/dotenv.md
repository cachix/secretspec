---
title: Dotenv Provider
description: Traditional .env file storage for secrets
---

The Dotenv provider stores secrets in local `.env` files for development setups and compatibility with existing tools.

## File Format

Standard dotenv format with `KEY=VALUE` pairs:

```bash
# .env
DATABASE_URL=postgresql://localhost/mydb
API_KEY=sk-1234567890
DEBUG=true  # Comments supported

# Multi-line values must be quoted
PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"
```

## Configuration

### URI Syntax

```bash
# Default (.env in current directory)
dotenv

# Custom paths
dotenv:.env.local
dotenv:config/.env
dotenv:/absolute/path/.env
```

### Environment Variable

```bash
export MONOSECRET_PROVIDER=dotenv:.env.local
```

## Usage

```bash
# Initialize from existing .env
$ monosecret init --from .env

# Set a secret
$ monosecret set DATABASE_URL --provider dotenv
Enter value for DATABASE_URL: postgresql://localhost/mydb

# Run with secrets
$ monosecret run --provider dotenv -- npm start

# Use different files for different environments
$ monosecret run --provider dotenv:.env.production -- node server.js
```

## Security

⚠️ **Warning**: Secrets are stored in plain text. Use only for development and always add `.env` files to `.gitignore`.
