---
title: age Provider
description: Store secrets in an age-encrypted file committed alongside code
---

:::note[Version compatibility]
The age provider is added in SecretSpec 0.17.
:::

The age provider keeps secrets in a single [age](https://age-encryption.org)-encrypted file that you can commit to your repository. The plaintext inside is a dotenv-style `KEY=value` blob that SecretSpec encrypts to one or more age recipients and decrypts with your age identity. A read decrypts the blob; a write decrypts it, updates one key, and re-encrypts the whole blob to the current recipients.

## At a glance

| | |
| --- | --- |
| Provider | `age` |
| URI | `age://<path>[?options]` |
| Access | Read and write |
| Best for | Encrypted secrets committed alongside code |
| Authentication | An age identity (private key) |
| Build feature | `age` |
| Default storage | A dotenv blob at the configured path, keyed by the secret name |

## Quick start

Use an age v1.3 hybrid post-quantum key for new setups. SecretSpec's Rust age
library currently accesses this key type through the non-interactive
`age-plugin-pq` compatibility plugin:

```bash
$ mkdir -p "$HOME/.config/age"
$ age-keygen -pq -o "$HOME/.config/age/keys.txt"
Public key: age1pq1...
$ age-plugin-pq -identity -o "$HOME/.config/age/plugin-identity.txt" "$HOME/.config/age/keys.txt"

$ secretspec set DATABASE_URL --provider "age://secrets.age?identity=$HOME/.config/age/plugin-identity.txt"
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret 'DATABASE_URL' saved to age (profile: default)

$ secretspec get DATABASE_URL --provider "age://secrets.age?identity=$HOME/.config/age/plugin-identity.txt"
```

With no recipients configured the blob is encrypted to your own identity, so the same key that reads it also writes it.

## Setup

### Prerequisites

- An age identity. For new keys, age's hybrid ML-KEM-768 + X25519 key generated
  by `age-keygen -pq` is recommended for post-quantum protection.
- `age-plugin-pq` on `PATH` when using the recommended hybrid key with
  SecretSpec's current Rust age library
- Build with `--features age`

### Identity

The private key is resolved from the first of these sources: the `identity` provider credential, the `AGE_IDENTITY` environment variable holding the key material, or `?identity=<path>` naming an identity file. The credential and environment forms carry the key material directly; the URI form names a file on disk. Routing the identity through the credential system lets the age key itself be a managed secret, for example one stored in the system keyring.

### Recipients

Recipients are age public keys and are never secret, so they are configured rather than supplied as credentials. With no `?recipients-file=`, the blob is encrypted to the public key derived from your own identity. To share the file, point `?recipients-file=` at a roster file listing every recipient.

A roster is a plain text file in age's recipients format: one recipient per line, `#` for comments, blank lines ignored. Recipients may be classic `age1...` keys, hybrid `age1pq1...` keys, native tagged `age1tag...`/`age1tagpq...` recipients, or `ssh-ed25519`/`ssh-rsa` keys. Hybrid `age1pq1...` encryption requires `age-plugin-pq`; tagged recipients are parsed natively before the generic plugin fallback.

```text title="secrets.age.recipients"
# alice
age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
# a deploy host
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
```

Because an age file does not record its recipients, every write re-encrypts to whatever `?recipients-file=` names at that moment. Keep that file complete and committed so a write never drops a reader. When the roster changes, run a write against each secret to re-encrypt it to the new set.

### Plugins and post-quantum keys

Native X25519 and SSH identities are supported directly. Plugin identities and recipients work when their `age-plugin-*` binary is on `PATH` **and the plugin operation is non-interactive**. SecretSpec currently supplies no age callback UI, so plugins that issue `confirm`, `request-public`, or `request-secret` requests can fail. A plugin that handles interaction entirely through its own OS UI may still work.

Post-quantum keys need one conversion step. SecretSpec is built on the Rust age library, which does not yet read the native `AGE-SECRET-KEY-PQ-1` identity form that `age-keygen -pq` writes. Convert it to the plugin form once; `-o` creates the new secret identity file with mode `0600` and refuses to overwrite it:

```bash
$ age-plugin-pq -identity -o "$HOME/.config/age/plugin-identity.txt" "$HOME/.config/age/keys.txt"
```

Use only post-quantum recipients (`age1pq1...` or `age1tagpq1...`) together in
a roster. Age intentionally rejects a mixture of post-quantum and classic
recipients, because the classic recipient would remove the file's
post-quantum protection.

## Configuration

### URI format

```text
age://<path>[?key=value&...]
```

- `path`: the encrypted blob file, resolved against the project root when relative
- `?identity=<path>`: identity file, used when no credential or `AGE_IDENTITY` is set
- `?recipients-file=<path>`: roster of recipient public keys; without it, encrypt to your own identity
- `?armor=false`: write a binary blob instead of the default ASCII armor

### URI examples

```text
age://secrets.age
age://secrets.age?identity=/home/alice/.config/age/plugin-identity.txt
age://secrets.age?recipients-file=secrets.age.recipients
age://secrets.age?armor=false
```

### Project configuration

```toml title="secretspec.toml"
[providers]
team_age = "age://secrets.age?recipients-file=secrets.age.recipients"

[profiles.production]
DATABASE_URL = { description = "Database URL", providers = ["team_age"] }
```

Each developer configures their own identity through the `identity` credential, `AGE_IDENTITY`, or a personal `?identity=`, while the committed roster and blob path stay the same for everyone.

## Storage model

Every secret is one `KEY=value` entry inside the blob, keyed by the secret name. Project and profile do not appear in the file; point separate profiles at separate blobs to keep them apart, for example `secrets.prod.age` and `secrets.dev.age`.

## Use existing secrets

A secret's [`ref`](/reference/configuration/#secret-references) names the key to read inside the blob, so a declared secret can map to a differently named entry. The age provider has no sub-address, so a `ref` sets only `item`.

```toml title="secretspec.toml"
[profiles.production]
DATABASE_URL = { description = "DB", ref = { item = "POSTGRES_URL" }, providers = ["age://secrets.age"] }
```

## CI/CD

Commit the blob and its roster, and give the job an identity to decrypt with. The identity is a natural fit for the `identity` provider credential (sourced from another provider) or the `AGE_IDENTITY` environment variable:

```bash
$ export AGE_IDENTITY="$CI_AGE_IDENTITY"
$ secretspec run --provider "age://secrets.age" -- deploy
```

## Security considerations

A recipient can decrypt every secret in a blob, not individual entries within it. Put secrets that should reach different audiences in separate files, each with its own roster.

Hybrid post-quantum recipients protect stored ciphertext against
harvest-now/decrypt-later attacks, but static file encryption does not provide
forward secrecy. Anyone who later obtains a long-term identity can decrypt
historical ciphertext that still exists in Git history or backups. Rotate and
erase identities, re-encrypt the blob, and manage repository history according
to your retention policy when that risk matters.
