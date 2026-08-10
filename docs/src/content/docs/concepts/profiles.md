---
title: Profiles
description: Managing environment-specific secret requirements with profiles
---

## What Are Profiles?

Profiles are named configurations that define how secrets behave in different environments. They specify which secrets are required vs optional, provide safe defaults for development, and enforce strict requirements for production.

A key feature of profiles is inheritance: non-default profiles inherit secrets
from the `default` profile when it exists. This means you only need to override
the specific properties that change between related environments. SecretSpec
0.19+ also lets an unrelated profile opt out and remain standalone.

If a manifest omits `default`, callers must select an existing profile with
`--profile`, `SECRETSPEC_PROFILE`, or their user config; the final fallback name
is still `default`.

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
$ export SECRETSPEC_PROFILE=production

$ secretspec run -- npm start
```

## Profile Inheritance in Detail

When using profiles, inheritance works as follows:

1. **Base definition in default**: Define all your secrets with their descriptions and base requirements in the `default` profile
2. **Override only what changes**: Other profiles only need to specify the properties that differ from default
3. **Field-level overrides**: Most explicitly set properties replace the corresponding property from `default`, while omitted properties continue to inherit
4. **Profile-specific secrets**: Secrets not in the default profile can be added to any profile

### Standalone profiles (0.19+)

:::caution[Version compatibility]
Profile-level `inherit` is available starting with SecretSpec 0.19.
:::

Set `inherit = false` in a non-default profile's `defaults` table when its
secret set is unrelated to `[profiles.default]`:

```toml
[profiles.default]
DATABASE_URL = { description = "Development database", default = "sqlite://./dev.db" }
API_KEY = { description = "Development API key" }

[profiles.production]
# Inherits both default declarations and overrides only what changes.
DATABASE_URL = { required = true }

[profiles.deployment.defaults]
inherit = false # SecretSpec 0.19+

[profiles.deployment]
# Does not inherit DATABASE_URL, API_KEY, or any of their fields.
DEPLOY_TOKEN = { description = "Deployment credential", required = true }
```

The setting disables both automatic inclusion of default secrets and
field-by-field inheritance for secrets explicitly redeclared in the standalone
profile. Omitting it preserves the existing inheritance behavior. A standalone
profile must declare at least one secret.

### Switching reference models (0.19+)

:::caution[Version compatibility]
Provider-scoped `refs` are available starting with SecretSpec 0.19.
:::

Legacy `ref` and provider-scoped `refs` are alternative forms of one inherited
address-model setting. Declaring either one in a profile replaces both forms
from `[profiles.default]`; omitting both continues to inherit the default
profile's form. This lets a profile switch from one route-wide address to
provider-specific addresses without retaining an invalid mixture of both:

```toml
[providers]
legacy = "onepassword://Legacy"
production = "onepassword://Production"

[profiles.default]
API_KEY = { description = "API key", providers = ["legacy"], ref = { item = "shared-api", field = "token" } }

[profiles.production]
# Inherits the description, but replaces providers and the complete ref/refs choice.
API_KEY = { providers = ["production"], refs = { production = { item = "production-api", field = "credential" } } }
```

The reverse switch also works: a profile's `ref` replaces inherited `refs`.
Within one effective secret, `ref` and `refs` remain mutually exclusive. See
[Secret References](/concepts/references/#different-coordinates-per-provider-019)
for how each model addresses providers.

## Profiles, Scopes, Providers, and Extends

These features solve different dimensions of a configuration:

- A **profile** chooses an environment or context. It controls requiredness,
  defaults, provider routes, references, and the `{profile}` storage namespace.
- A **scope** selects which secrets one service or task receives from the
  effective profile. It does not create another environment.
- A secret's **providers** choose where its value is read and written. Provider
  chains are also the least-privilege boundary: a process only needs access to
  the stores used by the secrets in its scope.
- **`extends`** merges separate `secretspec.toml` files. Use it to share
  manifests across projects, not to express relationships among several
  profiles in one small manifest.

For an application with `development` and `production` environments plus
`app`, `public`, and `deploy` consumers, profiles normally model the two
environments, scopes model the three consumers, and per-secret provider chains
route each value to the appropriate store.

## Profile-Level Defaults

To reduce repetition when multiple secrets in a profile share the same settings, use the `profiles.<name>.defaults` section:

```toml
[providers]
prod_vault = "onepassword://Production"
keyring = "keyring://"

[profiles.production.defaults]
providers = ["prod_vault", "keyring"]
required = true

[profiles.production]
DATABASE_URL = { description = "Production DB" }
API_KEY = { description = "API Key" }
SENTRY_DSN = { description = "Error tracking" }
```

Profile defaults apply to all secrets in that profile unless explicitly
overridden. In SecretSpec 0.19+, the same table accepts `inherit = false` to
make a non-default profile standalone; unlike `required`, `default`, and
`providers`, this controls the relationship with `[profiles.default]` rather
than supplying a value to each secret. The precedence order is:

1. **Secret-level configuration** (highest priority) -- explicit settings in the secret definition
2. **Profile defaults** -- from `profiles.<name>.defaults`
3. **Profile inheritance** -- inherited from default profile
4. **Global defaults** (lowest priority) -- from CLI, environment, or global config

This is particularly useful for setting common [provider fallback routes](/concepts/providers/fallback/#ordered-fallback-routes), requirements, or defaults across all secrets in a profile.

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
