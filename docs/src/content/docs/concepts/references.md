---
title: Secret References
description: Point a secret at one already managed in a provider's store, by the store's own coordinates
---

:::note
Secret references are available since version 0.14.
:::

By default, SecretSpec owns the naming: it stores each secret under its own
`{project}/{profile}/{key}` convention. A **secret reference** overrides that for
one secret, naming a secret that already exists in the store and is managed
outside SecretSpec. SecretSpec then reads (and writes) that existing secret in
place, instead of a convention path it controls.

You declare a reference with the `ref` field, a table of provider-independent
coordinates:

```toml
[profiles.production]
# The 1Password item "db", its "password" field
DATABASE_URL = { description = "Postgres DSN", ref = { item = "db", field = "password" }, providers = ["prod_vault"] }

# An existing environment variable
GITHUB_TOKEN = { description = "GitHub token", ref = { item = "GITHUB_PAT" }, providers = ["env"] }
```

## Coordinates address a secret from the outside in

A `ref` is not a store-specific address like `op://vault/item/field`. It is a set
of provider-independent coordinates, each naming a level of structure that some
stores have:

```
vault                which container holds the item        (1Password only)
└── item             the store's own name for the secret   (always required)
    └── section      a named group of fields               (1Password only)
        └── field    one component inside the item          (structured stores)
            └── version   which revision to read            (GCSM only)
```

Only `item` is universal, because every store names its secrets somehow. `item`
is the **complete** name, not a suffix: it replaces the entire convention path,
so nothing is prepended.

```toml
# Reads the .env key TOTALLY_DIFFERENT_NAME, not secretspec/myapp/default/DATABASE_URL
DATABASE_URL = { description = "DB", ref = { item = "TOTALLY_DIFFERENT_NAME" }, providers = ["dotenv"] }
```

The other coordinates exist because some stores give a secret internal structure
(`field`, `section`), nest it inside a container (`vault`), or keep revisions
(`version`). A store that has no equivalent for a coordinate **rejects it with an
error naming the coordinate**, rather than silently reading the wrong secret. The
[configuration reference](/reference/configuration/#secret-references) documents
exactly how each provider maps the coordinates.

## References name, providers route

A `ref` supplies naming only. It does not pin the secret to a particular store.
Which provider actually resolves the coordinates follows the ordinary
[provider resolution order](/concepts/providers/): a `--provider` override, then
the secret's `providers` chain, then the profile and global defaults.

This is the difference from pasting a store URL into your config. Because the
store is not baked into the reference, the same `ref` works across providers.
Each provider in a fallback chain is asked for the same coordinates, and one that
cannot interpret them warns and the chain continues:

```toml
[profiles.production]
DATABASE_URL = { description = "Postgres DSN", ref = { item = "db", field = "password" }, providers = ["onepassword://Production", "keyring"] }
```

It also means `--provider` redirects reference secrets exactly like convention
secrets, which makes test fixtures trivial: point every reference at a `.env`
file without touching the manifest.

```bash
$ secretspec run --provider dotenv:.env.fixtures -- cargo test
```

## How it works

- `item` is required; `field`, `vault`, `section`, and `version` are optional and
  only accepted by stores that have that structure.
- Reads and writes are symmetric: `secretspec set` and interactive `check` write
  through the coordinates in place wherever the store supports writes. Read-only
  stores fail with a clear error.
- A `ref` combines freely with `default`, `required`, and `as_path`, but not with
  `generate`: a referenced secret is externally managed, not minted.
- `ref` is always a table. String and URI forms (`ref = "op://vault/item/field"`)
  are rejected, with an error that spells out the equivalent table.
- Secrets sharing identical coordinates and store are fetched once, and
  [audit log](/concepts/audit/) events carry the coordinates.

See the [configuration reference](/reference/configuration/#secret-references) for
the full specification: the coordinate table, how every provider interprets each
coordinate, and the exact rules.
