---
title: Declarative Configuration
description: Understanding secretspec.toml and its declarative approach
---

SecretSpec uses `secretspec.toml` to declare what secrets your application needs, separating requirements from storage mechanisms for portability across environments.

## Basic Structure

```toml
[project]
name = "my-app"
revision = "1.0"
extends = ["../shared/common"]  # Optional: inherit from other configs

[profiles.default]
DATABASE_URL = { description = "PostgreSQL connection string", required = true }
API_KEY = { description = "External API key", required = true }
LOG_LEVEL = { description = "Logging verbosity", required = false, default = "info" }
```

## Secret Declarations

Each secret is declared with configuration options:

```toml
SECRET_NAME = {
  description = "Human-readable explanation",  # Required: shown in prompts
  required = true,                            # Optional: defaults to true
  default = "value"                           # Optional: fallback if not set
}
```

**Options:**
- `description`: Explains the secret's purpose (required)
- `required`: Whether the secret must be provided (default: `true`)
- `default`: Fallback value for optional secrets
- `type`: Secret type for auto-generation (`password`, `hex`, `base64`, `uuid`, `command`)
- `generate`: Enable auto-generation when the secret is missing (`true` or a table with options)

## Related Concepts

- [Configuration Inheritance](/concepts/inheritance/) lets projects share common secret definitions via the `extends` field
- [Secret Generation](/concepts/generation/) auto-creates passwords, tokens, and keys when secrets are missing

## Best Practices

1. **Descriptive names**: Use `STRIPE_API_KEY` instead of generic `API_KEY`
2. **Clear descriptions**: Help developers understand each secret's purpose
3. **Sensible defaults**: Provide development defaults, require production values
4. **Modular inheritance**: Create reusable base configurations for common patterns

## Complete Example

```toml
[project]
name = "web-api"
revision = "2.1.0"
extends = ["../shared/base", "../shared/auth"]

[profiles.default]
# Inherits DATABASE_URL, LOG_LEVEL from base
# Inherits JWT_SECRET, SESSION_SECRET from auth
# Service-specific additions:
STRIPE_API_KEY = { description = "Stripe payment API", required = true }
REDIS_URL = { description = "Redis cache connection", required = true }
PORT = { description = "Server port", required = false, default = "3000" }
```