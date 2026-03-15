---
title: Concepts Overview
description: How SecretSpec's core concepts work together
---

SecretSpec is built around three core ideas that separate concerns and keep your secrets portable across environments.

## Declare what you need

A [`secretspec.toml`](/concepts/declarative/) file lists the secrets your project depends on, with descriptions, defaults, and whether they are required. This file lives in version control so every developer and CI system sees the same requirements.

## Use profiles for environments

[Profiles](/concepts/profiles/) let you vary secret requirements per environment. A `production` profile can enforce strict requirements while a `development` profile provides safe defaults. All profiles inherit from `default`, so you only specify what changes.

## Store secrets anywhere with providers

[Providers](/concepts/providers/) are pluggable backends (keyring, dotenv, 1Password, Vault, etc.) that handle actual storage and retrieval. The same `secretspec.toml` works regardless of where secrets are stored, and you can swap providers without changing your project configuration.

## How they connect

```
secretspec.toml          Profile selected          Provider resolves
(what you need)    -->   (which requirements)  --> (where to get values)
```

1. You declare secrets in `secretspec.toml`
2. The active profile determines which secrets are required and what defaults apply
3. The provider retrieves (or stores) the actual values

Each concern is independent: you can change your storage backend without touching profile definitions, or add a new environment without modifying provider configuration.

## Additional concepts

- [Configuration Inheritance](/concepts/inheritance/) lets projects share common secret definitions via `extends`
- [Secret Generation](/concepts/generation/) auto-creates passwords, tokens, and keys when secrets are missing
