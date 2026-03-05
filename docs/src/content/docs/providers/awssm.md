---
title: AWS Secrets Manager Provider
description: AWS Secrets Manager integration
---

The AWS Secrets Manager provider integrates with AWS for centralized secret management.

## Prerequisites

- AWS account with Secrets Manager access
- AWS credentials configured (CLI, environment variables, IAM roles, or SSO)
- Build with `--features awssm`

## Configuration

### URI Format

```
awssm://REGION
```

- `REGION`: AWS region (e.g., `us-east-1`). If omitted, the SDK default region chain is used.

### Examples

```bash
# Set a secret
$ secretspec set DATABASE_URL --provider awssm://us-east-1

# Get a secret
$ secretspec get DATABASE_URL --provider awssm://us-east-1

# Check secrets
$ secretspec check --provider awssm://us-east-1

# Run with secrets
$ secretspec run --provider awssm://us-east-1 -- npm start

# Use SDK default region
$ secretspec set DATABASE_URL --provider awssm
```

## Usage

### Basic Commands

```bash
# Set a secret
$ secretspec set DATABASE_URL --provider awssm://us-east-1
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret 'DATABASE_URL' saved to awssm (profile: default)

# Import from .env
$ secretspec import dotenv://.env
```

### Secret Naming

Secrets are stored as: `secretspec/{project}/{profile}/{key}`

Example: `secretspec/myapp/production/DATABASE_URL`

### Authentication

AWS Secrets Manager uses the standard AWS SDK credential chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. Shared credentials file (`~/.aws/credentials`)
3. AWS SSO (`aws sso login`)
4. IAM roles (EC2 instance profiles, ECS task roles, Lambda execution roles)

### Required IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:CreateSecret",
        "secretsmanager:PutSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:secretspec/*"
    }
  ]
}
```

### CI/CD

```bash
# Using environment variables
$ export AWS_ACCESS_KEY_ID=AKIA...
$ export AWS_SECRET_ACCESS_KEY=...
$ export AWS_DEFAULT_REGION=us-east-1

# Run command
$ secretspec run --provider awssm://us-east-1 -- deploy

# Or with IAM roles (no credentials needed)
$ secretspec run --provider awssm://us-east-1 -- deploy
```
