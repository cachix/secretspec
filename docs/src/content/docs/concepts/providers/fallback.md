---
title: Provider fallback
description: Select providers and define ordered fallback routes for secrets
---

Secrets may live in different stores across environments or during a migration.
An ordered provider route lets Monosecret read from the first store that has a
value while keeping one store as the write target.

## Provider selection order

Monosecret selects each secret's route in this order:

1. The `--provider` command-line option.
2. The `MONOSECRET_PROVIDER` environment variable.
3. The secret's effective `providers` list after profile inheritance and
   `[profiles.<name>.defaults]` are applied.
4. The default provider in the user configuration.

`--provider` and `MONOSECRET_PROVIDER` replace the configured route for every
secret. Without an override or effective `providers` list, Monosecret uses the
user-level default.

## Ordered fallback routes

Provider lists accept aliases, provider names, and inline URIs. Reads try them
from left to right:

```toml title="monosecret.toml"
[providers]
prod_vault = "onepassword://Production"
local = "keyring://"

[profiles.production.defaults]
providers = ["prod_vault", "local"]

[profiles.production]
# Uses the profile default: prod_vault, then local.
DATABASE_URL = { description = "Production database" }

# Overrides the profile default and reads only from the environment.
DEPLOY_TOKEN = { description = "Deployment token", providers = ["env"] }
```

Reads stop at the first value. Writes and generated values go only to the first
provider in the effective list (`prod_vault` above).

Later entries are resolved, constructed, and contacted only when needed. If a
reached provider cannot be resolved, constructed, or read, Monosecret warns and
continues. If every reached provider fails, the operation returns a provider
error rather than reporting the secret as absent.

:::note
A secret's [`ref`](/reference/configuration/#secret-references) changes only
the address within a provider; route selection stays the same.
:::

## Cached routes

Monosecret 0.2+ can place a local cache before an ordered route. See
[Provider caching](/concepts/providers/caching/) for configuration and
freshness rules.

## Next steps

- Learn how to [configure provider aliases](/concepts/providers/#configure-provider-aliases).
- Learn how [Profiles](/concepts/profiles/) apply provider defaults.
