---
title: Environment Variable Provider
description: Read-only access to environment variables
---

The Environment Variable provider reads secrets directly from process environment variables. This is a **read-only** provider designed for CI/CD compatibility and containerized environments.

## Configuration

The env provider accepts no configuration options:

```bash
# All these are equivalent
$ monosecret check --provider env
$ monosecret check --provider env:
$ monosecret check --provider env://
```

## When to Use

- Running in CI/CD pipelines where secrets are injected as environment variables
- Testing with temporary environment variables
- Working with containerized applications that use environment variables

## Example

```bash
# Set environment variables
export DATABASE_URL="postgresql://localhost/mydb"
export API_KEY="sk-1234567890"

# Check secrets are available
$ monosecret check --provider env
✓ All required secrets are configured

# Run with environment variables
$ monosecret run --provider env -- npm start
```

### CI/CD Integration

```yaml
# GitHub Actions
- name: Run with secrets
  env:
    DATABASE_URL: ${{ secrets.DATABASE_URL }}
    API_KEY: ${{ secrets.API_KEY }}
  run: |
    monosecret run --provider env -- npm run deploy
```
