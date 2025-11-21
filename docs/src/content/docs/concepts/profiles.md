---
title: Profiles
description: Managing environment-specific secret requirements with profiles
---

## What Are Profiles?

Profiles are named configurations that define how secrets behave in different environments. They specify which secrets are required vs optional, provide safe defaults for development, and enforce strict requirements for production.

A key feature of profiles is inheritance: all profiles automatically inherit secrets from the `default` profile. This means you only need to override the specific properties that change between environments, reducing duplication and making your configuration cleaner and easier to maintain.

## Basic Usage

Define profiles in your `secretspec.toml`:

```toml
[profiles.default]
DATABASE_URL = { description = "PostgreSQL connection", required = true }
API_KEY = { description = "External API key", required = true }

[profiles.development]
# Inherits DATABASE_URL and API_KEY from default, only overriding their requirements
DATABASE_URL = { required = false, default = "postgresql://localhost:5432/myapp_dev" }
API_KEY = { required = false, default = "dev-key-12345" }
DEBUG = { description = "Enable debug mode", required = false, default = "true" }

[profiles.production]
# Inherits all secrets from default profile
# Only need to add production-specific secrets
SENTRY_DSN = { description = "Error tracking", required = true }
```

## Selecting Profiles

SecretSpec resolves the active profile in this order:

1. **Command line**: `--profile production` (highest priority)
2. **Environment variable**: `SECRETSPEC_PROFILE=staging`
3. **User config**: Default profile in `~/.config/secretspec/config.toml`
4. **Fallback**: `default` profile

```bash
# Use specific profile
$ secretspec check --profile development
✓ DATABASE_URL - PostgreSQL connection (using default)
✓ API_KEY - External API key (using default)

# Set via environment
export SECRETSPEC_PROFILE=production
secretspec run -- npm start
```

## Profile Inheritance in Detail

When using profiles, inheritance works as follows:

1. **Base definition in default**: Define all your secrets with their descriptions and base requirements in the `default` profile
2. **Override only what changes**: Other profiles only need to specify the properties that differ from default
3. **Complete override**: When a profile defines a secret, it can override any or all properties (`required`, `default`, `description`)
4. **Profile-specific secrets**: Secrets not in the default profile can be added to any profile

## Profile-Level Defaults

To reduce repetition when multiple secrets in a profile share the same settings, use the `profiles.<name>.defaults` section:

```toml
[profiles.production.defaults]
providers = ["prod_vault", "keyring"]
required = true

[profiles.production]
DATABASE_URL = { description = "Production DB" }
API_KEY = { description = "API Key" }
SENTRY_DSN = { description = "Error tracking" }
```

Profile defaults apply to all secrets in that profile unless explicitly overridden. The precedence order is:

1. **Secret-level configuration** (highest priority) - explicit settings in the secret definition
2. **Profile defaults** - from `profiles.<name>.defaults`
3. **Profile inheritance** - inherited from default profile
4. **Global defaults** (lowest priority) - from CLI, environment, or global config

This is particularly useful for:
- **Providers**: Define common provider chains once instead of repeating for each secret
- **Requirements**: Set all production secrets to required at the profile level
- **Defaults**: Provide sensible defaults for development profiles

## Practical Example

A web application with different requirements per environment:

```toml
[project]
name = "web-app"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "PostgreSQL connection", required = true }
REDIS_URL = { description = "Redis for caching", required = true }
JWT_SECRET = { description = "JWT signing key", required = true }

[profiles.development]
# Inherits all secrets from default, just adding defaults
DATABASE_URL = { default = "postgresql://localhost:5432/webapp_dev" }
REDIS_URL = { default = "redis://localhost:6379/0" }
JWT_SECRET = { default = "dev-secret-change-in-prod" }
HOT_RELOAD = { description = "Enable hot reload", required = false, default = "true" }

[profiles.production]
# Inherits DATABASE_URL, REDIS_URL, JWT_SECRET from default
# Only adds production-specific secrets
SENTRY_DSN = { description = "Error tracking", required = true }
SSL_CERT = { description = "SSL certificate path", required = true }
```