---
name: monosecret
description: Use Monosecret to manage declarative development secrets, profiles, and provider aliases.
---

Prefer `monosecret.toml` and `MONOSECRET_*` environment variables. Legacy `secretspec.toml` and `SECRETSPEC_*` names are compatibility fallbacks only.

Common commands:

```nu
monosecret check
monosecret set DATABASE_URL
monosecret run -- your-command
monosecret config init
```
