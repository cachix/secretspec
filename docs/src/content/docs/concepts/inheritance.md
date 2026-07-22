---
title: Configuration Inheritance
description: Sharing common secret definitions across projects with extends
---

SecretSpec supports sharing common secrets across projects through the `extends` field in `[project]`. This avoids duplicating secret definitions in monorepos or multi-service setups.

## Basic Example

A shared base configuration:

```toml
# shared/common/secretspec.toml
[project]
name = "common"

[profiles.default]
DATABASE_URL = { description = "Main database", required = true }
LOG_LEVEL = { description = "Log verbosity", required = false, default = "info" }
```

A project that extends it:

```toml
# myapp/secretspec.toml
[project]
name = "myapp"
extends = ["../shared/common"]

[profiles.default]
DATABASE_URL = { description = "MyApp database", required = true }  # Override
API_KEY = { description = "External API key", required = true }     # Add new
```

## Monorepo Structure

```
monorepo/
├── shared/
│   ├── base/secretspec.toml      # Common secrets
│   └── database/secretspec.toml  # DB-specific (extends base)
└── services/
    ├── api/secretspec.toml       # API service (extends database)
    └── frontend/secretspec.toml  # Frontend (extends base)
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
- A child `[scopes.<name>]` completely replaces the parent scope of the same
  name — its `secrets` list wins outright; the two lists are **not** unioned.
  Scopes defined only in a parent are inherited. (Whole-value replacement is the
  safe default for an allowlist: extending a config cannot silently widen a scope
  the parent narrowed.) Available from SecretSpec 0.17.
- Paths are relative to the containing `secretspec.toml` file
