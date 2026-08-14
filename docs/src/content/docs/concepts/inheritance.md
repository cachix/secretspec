---
title: Configuration Inheritance
description: Sharing common secret definitions across projects with extends
---

Monosecret supports sharing common secrets across projects through the `extends` field in `[project]`. This avoids duplicating secret definitions in monorepos or multi-service setups.

## Basic Example

A shared base configuration:

```toml
# shared/common/monosecret.toml
[project]
name = "common"

[profiles.default]
DATABASE_URL = { description = "Main database", required = true }
INTERNAL_API_KEY = { description = "Internal service API key", required = true }
```

A project that extends it:

```toml
# myapp/monosecret.toml
[project]
name = "myapp"
extends = ["../shared/common"]

[profiles.default]
DATABASE_URL = { description = "MyApp database", required = true } # Override
API_KEY = { description = "External API key", required = true }    # Add new
```

## Monorepo Structure

```
monorepo/
├── shared/
│   ├── base/monosecret.toml      # Common secrets
│   └── database/monosecret.toml  # DB-specific (extends base)
└── services/
    ├── api/monosecret.toml       # API service (extends database)
    └── frontend/monosecret.toml  # Frontend (extends base)
```

## Multiple Inheritance

A project can extend multiple configurations. Later sources take precedence over earlier ones:

```toml
[project]
name = "api-service"
extends = ["../../shared/base", "../../shared/database", "../../shared/auth"]
```

## Rules

- Child definitions completely replace parent definitions for the same secret
- Later sources in `extends` override earlier ones
- Shared ancestors are applied once, so diamond-shaped inheritance is supported
- Each profile is merged independently
- Profile `[defaults]` inherit field by field across source files
- The `inherit` profile-default field (0.2+) follows that same `extends`
  precedence. A child profile keeps an inherited `inherit = false` unless a
  later source explicitly sets it to `true`.
- A child `[scopes.<name>]` completely replaces the parent scope of the same
  name — its `secrets` list wins outright; the two lists are **not** unioned.
  Scopes defined only in a parent are inherited. (Whole-value replacement is the
  safe default for an allowlist: extending a config cannot silently widen a scope
  the parent narrowed.) Available from Monosecret 0.2.
- Paths are relative to the containing `monosecret.toml` file
