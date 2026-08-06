---
title: Null Provider
description: Use committed manifest defaults without a storage backend
---

:::caution[Version compatibility]
The `null` provider is added in SecretSpec 0.19.
:::

The null provider always reports that a value is missing. SecretSpec then
uses the declaration's `default`. This is useful for non-sensitive environment
configuration that belongs in `secretspec.toml`, not in a secret store.

## At a glance

| | |
| --- | --- |
| Provider | `null` (0.19+) |
| URI | `null://` |
| Access | Always returns missing; writes are rejected |
| Best for | Team-shared, non-sensitive defaults |
| Storage | None |

## Quick start

Route committed defaults to `null`:

```toml title="secretspec.toml"
[profiles.default]
SPRING_PROFILES_ACTIVE = { description = "Spring application profile", default = "local", providers = ["null"] }

[profiles.staging]
SPRING_PROFILES_ACTIVE = { default = "staging" }
```

```bash
$ secretspec run --profile staging -- mvn spring-boot:run
```

This keeps the application mode aligned with the SecretSpec profile and its
secrets. The same pattern works for values such as `LOCAL_PORT`.

## How it works

SecretSpec normally asks the selected provider before using a default. `null`
cannot read or write values: reads always report a missing value, and every
write is rejected. The missing read lets SecretSpec use the committed default
without provider I/O.

The provider has no options, credentials, feature flag, or persistent state.
Use it on declarations with defaults; required declarations without defaults
remain missing, and writes are rejected.

Do not use `null` for generated secrets. Secret generation writes each new value
to the configured provider, so generation through `null` fails when that write
is rejected. Configure a writable provider when using `generate`.

:::danger[Defaults are public configuration]
Manifest defaults are committed to version control in plaintext. Use `null`
only for non-sensitive values. Keep secrets in a real provider.
:::
