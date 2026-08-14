---
title: Migration
description: Bring existing secret declarations and values into Monosecret
---

Monosecret can discover declarations from supported providers or copy values
from another provider. Secret values are never written to
`monosecret.toml`.

Dotenv files support declaration discovery in every current release.
Monosecret 0.2+ can also discover declarations from age files, AWS Systems
Manager Parameter Store, and Bitwarden Password Manager vaults.

## Start a new project from existing secrets

### From `.env`

When an existing project already has a `.env` file, initialize its manifest
from the names in that file:

```bash
$ monosecret init --from dotenv://.env
```

This creates declarations only; values are never written to
`monosecret.toml`. Review the generated declarations, then copy the values into
your configured default provider:

```bash
$ monosecret import dotenv://.env
```

### From another provider (0.2+)

:::caution[Version compatibility]
Declaration discovery from providers other than dotenv is available starting
with Monosecret 0.2.
:::

Use `init --from` with any provider that supports declaration discovery. For
example, you can discover declarations from an AWS Parameter Store hierarchy:

```bash
$ monosecret init \
    --from 'awsps://us-east-1?template=/{profile}/{project}/{key}' \
    --project payments \
    --profile production
```

Discovery creates declarations only; it does not copy secret values into
`monosecret.toml`. You can also discover declarations from age files and
Bitwarden Password Manager vaults. See the [`init` reference](/reference/cli/#init) for examples and provider-specific options.

## Import into an existing project

If `monosecret.toml` already declares the secrets, import their values from the
current environment:

```bash
$ monosecret import env
```

The source can also be any other provider name or URI. For example, to copy
declared values from a 1Password vault:

```bash
$ monosecret import onepassword://Development
```

Imports copy values into your configured default provider, or into the system
keyring when you have not configured one. They do not overwrite values that
are already present there.

## Next steps

- Learn how [providers](/concepts/providers/) select the source and destination
  for secret values
- Use [provider references](/concepts/references/) when existing values have
  provider-native names or addresses
