---
title: "SecretSpec 0.14: Secret References"
description: A secret can now point at one that already exists in a provider's store, by the store's own coordinates, instead of a name SecretSpec picks.
date: 2026-07-09
authors:
  - domen
---

SecretSpec keeps a `secretspec.toml` that declares what secrets an application
needs, and resolves the values from a provider: your system keyring, 1Password,
Vault, a `.env` file, and so on. Until now it stored every secret under a naming
convention it controlled, `secretspec/{project}/{profile}/{key}`, and that
convention was the only place it looked.

That works when SecretSpec created the secret. It does not when the secret
already exists under a name something else chose: a `db` item in a 1Password
vault, a `myapp/config` path at a Vault mount, an environment variable your
platform already sets. To manage such a secret you had to copy its value into
SecretSpec's convention, leaving two copies to rotate, or leave it out of
SecretSpec entirely.

[SecretSpec 0.14](https://github.com/cachix/secretspec/releases/tag/v0.14.0 "SecretSpec 0.14 release")
introduces `ref`. A secret can name one that already exists, by the store's own
coordinates, and SecretSpec reads and writes that secret in place:

```toml
[profiles.production]
DATABASE_URL = { description = "Postgres DSN", ref = { item = "db", field = "password" }, providers = ["prod_op"] }
```

`DATABASE_URL` now resolves from the `password` field of the 1Password item
`db`. SecretSpec does not prepend a project or profile, and does not create a
name of its own.

## Why not just paste the address

1Password will give you an address for that field: `op://Production/db/password`.
The obvious design is to accept that string in the config and be done. We built
that first and removed it.

A string like `op://Production/db/password` names the store and the secret at
the same time, which ties the secret to 1Password. The same reference cannot
then resolve from Vault in CI and 1Password on a laptop, cannot be redirected at
a `.env` fixture for a test run without editing the manifest, and does not
compose with a provider fallback chain, because the chain and the address
disagree about where the secret is.

SecretSpec already decides which store to use, through providers, profiles,
fallback chains, and the `--provider` override. A `ref` names only the secret
and leaves the store to that existing machinery.

## Coordinates

A `ref` is a table, not a URL. Each key names a level of structure that some
stores have:

```
vault                which container holds the item        (1Password only)
└── item             the store's own name for the secret   (always required)
    └── section      a named group of fields               (1Password only)
        └── field    one component inside the item          (structured stores)
            └── version   which revision to read            (GCSM only)
```

Only `item` is required, because every store names its secrets somehow. `item`
is the complete name: it replaces the whole convention path, with no project or
profile and no folder prefix prepended. `ref = { item = "GITHUB_PAT" }` on the
env provider reads the environment variable `GITHUB_PAT` and nothing else.

The other keys refine `item` for stores that have that structure. A `.env` key
holds a single value, so `field` on a dotenv ref is not meaningful. A Vault KV
entry is a map, so `field` is required. When a store has no equivalent for a
coordinate it reports an error naming that coordinate, rather than reading a
different secret:

```toml
GITHUB_TOKEN = { description = "GitHub token", ref = { item = "GITHUB_PAT", field = "x" }, providers = ["env"] }
```

```text
Error: Provider operation failed: the env provider does not support the `field` coordinate. Drop `field` from the ref for `GITHUB_PAT`.
```

All eleven providers resolve refs, and each rejects the coordinates it cannot
represent. A store whose secrets have no internal parts gets that rejection from
shared code, without any per-provider work.

## References name, providers route

A `ref` supplies the name only. Which provider resolves it follows the normal
[provider resolution order](/concepts/providers/): a `--provider` override, then
the secret's `providers` chain, then profile and global defaults. That is the
same order every other secret uses.

Because the store is not part of the reference, the same `ref` works across
providers. Each provider in a fallback chain is asked for the same coordinates,
and one that cannot interpret them logs a warning and the chain continues:

```toml
[profiles.production]
DATABASE_URL = { description = "Postgres DSN", ref = { item = "db", field = "password" }, providers = ["onepassword://Production", "keyring"] }
```

Chain entries can also be inline `scheme://` URIs, as above, with no
`[providers]` alias declared first.

The `--provider` override redirects a referenced secret the same way it
redirects a conventional one, so pointing a whole suite at a `.env` fixture needs
no change to the manifest:

```bash
$ secretspec run --provider dotenv:.env.fixtures -- cargo test
```

## Writing through a ref

Reads and writes use the same coordinates. `secretspec set` and interactive
`check` write to the referenced secret in place wherever the store supports
writes:

```bash
$ secretspec set DATABASE_URL
# writes the `password` field of the 1Password item `db`, in place
```

1Password edits the field with `op item edit` and does not create items.
Keyring, pass, dotenv, Bitwarden, Proton Pass, and LastPass write their refs as
well. Vault, AWS Secrets Manager, and Google Secret Manager are read-only for
refs and report that directly, rather than claiming the provider cannot write at
all.

A `ref` also composes with `generate`. If the referenced secret does not exist
yet, SecretSpec generates the value and writes it to the coordinates, so the
first `check` populates the item everything else already reads.

## Faster resolution

`check`, `run`, and the SDKs now group secrets by store and fetch the groups
concurrently instead of one store after another. Within a group, referenced
secrets use the store's bulk API where it has one (AWS `BatchGetSecretValue`, and
the single Bitwarden, Proton Pass, and 1Password listings) and otherwise resolve
concurrently, fetching each unique coordinate once. CLI authentication for
1Password, LastPass, and Proton Pass is probed once per account or session
instead of once per provider instance.

## Upgrading

```bash
cargo install secretspec
```

Three changes to be aware of:

- A `onepassword://` URI carrying an item path used to drop the path and target a
  vault literally named `vault`. Item paths, including pasted
  `op://vault/item/field` strings, now fail with an error that gives the `ref`
  table to write instead. Provider URIs are store addresses only.
- `ref` is always a table. String and URI forms are rejected, with the same
  translation in the error.
- Manifest validation now runs on every load. Rules that `secretspec.toml`
  documents (a required secret cannot have a `default`, `generate` needs a
  `type`, ref coordinates must be non-empty) are enforced on load rather than
  ignored. A manifest that violated one of them will now fail with a clear error.

See [Secret References](/concepts/references/) for the full model and the
[configuration reference](/reference/configuration/#secret-references) for how
each provider maps the coordinates. Questions or feedback? Join us on
[Discord](https://discord.gg/naMgvexb6q).
