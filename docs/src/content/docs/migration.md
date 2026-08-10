---
title: Migration
description: Bring existing secret declarations and values into SecretSpec
---

SecretSpec can discover declarations from supported providers or copy values
from another provider. Secret values are never written to
`secretspec.toml`.

Dotenv files support declaration discovery in every current release.
SecretSpec 0.18+ can also discover declarations from age files, AWS Systems
Manager Parameter Store, and Bitwarden Password Manager vaults.

## Start a new project from existing secrets

### From `.env`

When an existing project already has a `.env` file, initialize its manifest
from the names in that file:

```bash
$ secretspec init --from dotenv://.env
```

This creates declarations only; values are never written to
`secretspec.toml`. Review the generated declarations, then copy the values into
your configured default provider:

```bash
$ secretspec import dotenv://.env
```

### From another provider (0.18+)

:::caution[Version compatibility]
Declaration discovery from providers other than dotenv is available starting
with SecretSpec 0.18.
:::

Use `init --from` with any provider that supports declaration discovery. For
example, you can discover declarations from an AWS Parameter Store hierarchy:

```bash
$ secretspec init \
    --from 'awsps://us-east-1?template=/{profile}/{project}/{key}' \
    --project payments \
    --profile production
```

Discovery creates declarations only; it does not copy secret values into
`secretspec.toml`. You can also discover declarations from age files and
Bitwarden Password Manager vaults. See the [`init`
reference](/reference/cli/#init) for examples and provider-specific options.

## Import into an existing project

If `secretspec.toml` already declares the secrets, import their values from the
current environment:

```bash
$ secretspec import env
```

The source can also be any other provider name or URI. For example, to copy
declared values from a 1Password vault:

```bash
$ secretspec import onepassword://Development
```

Imports copy values into your configured default provider and do not overwrite
values that are already present there.

## Next steps

- Learn how [providers](/concepts/providers/) select the source and destination
  for secret values
- Use [provider references](/concepts/references/) when existing values have
  provider-native names or addresses
