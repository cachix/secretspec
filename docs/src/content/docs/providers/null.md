---
title: Null Provider
description: Use committed defaults or ephemeral generation without a storage backend
---

:::caution[Version compatibility]
The `null` provider is added in SecretSpec 0.19.
:::

The null provider always reports that a value is missing. SecretSpec then uses
the declaration's committed `default` or generates a fresh value when
`generate` is enabled. This is useful for non-sensitive environment
configuration and secrets that should exist for only one resolution.

## At a glance

| | |
| --- | --- |
| Provider | `null` (0.19+) |
| URI | `null://` |
| Access | Always returns missing; ordinary writes are rejected |
| Best for | Team-shared defaults and ephemeral generated values |
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

## Ephemeral generation

:::note[SecretSpec 0.19+]
Ephemeral generation through `null://` is available starting in SecretSpec
0.19.
:::

Route a generated secret to `null` when each materializing resolution should
receive a fresh value without storing it in a provider:

```toml title="secretspec.toml"
[profiles.default]
SESSION_SECRET = { description = "Per-run session secret", type = "base64", generate = { bytes = 32 }, providers = ["null"] }
```

`secretspec run` generates `SESSION_SECRET` once for the resolved environment
and gives that value to the child process. A later `run`, `get`, `check`, or SDK
value-carrying resolution generates a new value. Value-free reports mark the
secret as generated without minting it.

## How it works

SecretSpec normally asks the selected provider before using a default or
generating a missing secret. `null` cannot read or store values: reads always
report a missing value, and every ordinary write is rejected. The missing read
lets SecretSpec use the committed default or generator without provider I/O.

The provider has no options, credentials, feature flag, or persistent state.
Use it on declarations with defaults or enabled generation. Required
declarations with neither remain missing, and explicit writes are rejected.

:::danger[Defaults are public configuration]
Manifest defaults are committed to version control in plaintext. Use `default`
only for non-sensitive values. Generated values are not committed, but still
exist in the resolving process and its configured delivery boundary.
:::

:::caution[Ephemeral means unstable]
Generated values are shared only within one resolution. Do not use `null` for
credentials that another process, machine, or later invocation must retrieve.
Use a writable provider for those values.
:::
