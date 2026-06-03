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
LOG_LEVEL = { description = "Log verbosity", required = false, default = "info" }
```

A project that extends it:

```toml
# myapp/monosecret.toml
[project]
name = "myapp"
extends = ["../shared/common"]

[profiles.default]
DATABASE_URL = { description = "MyApp database", required = true } # Override
API_KEY = { description = "External API key", required = true } # Add new
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
- Each profile is merged independently
- Paths are relative to the containing `monosecret.toml` file
