---
title: Provider fallback
description: Select providers and define ordered fallback routes for secrets
---

SecretSpec can route each secret through an ordered list of providers. This
lets a shared remote store remain authoritative while environment variables,
the system keyring, or another provider supply a fallback in selected
environments.

## Provider selection order

SecretSpec resolves the provider route for each secret in the following order:

1. The `--provider` command-line option.
2. The `SECRETSPEC_PROVIDER` environment variable.
3. The secret's effective `providers` list after profile inheritance and
   `[profiles.<name>.defaults]` are applied.
4. The default provider in the user configuration.

The first two options are explicit overrides. They route every secret to the
selected provider and disable any configured fallback chain for that command.
If no override is set and the secret has no `providers` list, SecretSpec uses
the user-level default provider.

## Ordered fallback routes

Provider lists may contain aliases, provider names, and inline provider URIs.
SecretSpec tries the list from left to right until a provider returns the
secret:

```toml title="secretspec.toml"
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

The fallback order applies to reads. Writes go only to the first provider in
the effective list. In this example, SecretSpec reads `DATABASE_URL` from
`prod_vault` first and consults `local` only when the value is not found; it
writes `DATABASE_URL` only to `prod_vault`.

Fallback entries are resolved lazily. A later alias is not constructed or
contacted when an earlier provider answers. If a reached provider cannot be
resolved, constructed, or read, SecretSpec warns and tries the next entry. If
every reached provider fails, the operation returns the provider error rather
than reporting the secret as absent.

:::note
A secret's [`ref`](/reference/configuration/#secret-references) changes the
address looked up inside a provider, not the provider selection rules. Explicit
overrides and fallback routes work the same way for referenced secrets and
convention-based secrets.
:::

## Cached routes

SecretSpec 0.17+ can put a cache in front of an ordered fallback route. See
[Provider caching](/concepts/providers/caching/) for the cached alias syntax,
freshness rules, writes, and invalidation.

## Next steps

- Learn how to [configure provider aliases](/concepts/providers/#configure-provider-aliases).
- Review [Provider caching](/concepts/providers/caching/) for slow remote
  providers.
- Learn how [Profiles](/concepts/profiles/) apply provider defaults.
