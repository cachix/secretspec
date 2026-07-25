---
title: KeePass KDBX Provider
description: Store SecretSpec values in an encrypted KeePass database
---

The KDBX provider reads and writes encrypted [KeePass](https://keepass.info/)
databases directly, without requiring KeePass or KeePassXC to be installed.

:::caution[Version compatibility]
The KDBX provider is an upcoming SecretSpec 0.17 feature.
:::

## At a glance

| | |
| --- | --- |
| Provider | `kdbx` |
| URI | `kdbx:PATH[?keyfile=PATH][&prefix=TEMPLATE]` |
| Access | KDBX 3 read; KDBX 4 read and write |
| Best for | Local, portable KeePass-compatible encrypted storage |
| Authentication | Master password, key file, or both |
| Build feature | `kdbx` (0.17+) |
| Default storage | Entry `secretspec/{project}/{profile}/{key}`, field `Password` |

## Quick start

```toml title="secretspec.toml"
[providers]
kdbx = {
  uri = "kdbx:./secrets.kdbx",
  credentials = { password = "keyring" }
}
```

```bash
# Store the database master password in the bootstrap provider.
$ secretspec config provider login kdbx
Enter password for provider 'kdbx' (source: keyring): ****

# Set a secret in an existing KDBX 4 database, or create a new KDBX 4 database.
$ secretspec set DATABASE_URL --provider kdbx
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret DATABASE_URL saved to kdbx

$ secretspec get DATABASE_URL --provider kdbx
postgresql://localhost/mydb

$ secretspec run --provider kdbx -- npm start
```

## Setup

The provider is built into standard SecretSpec 0.17 binaries. Custom builds
must enable the `kdbx` feature.

### Authentication

Load the semantic `password`
[provider credential](/concepts/providers/#provider-credentials) from a
bootstrap provider such as the system keyring. This keeps the KDBX master
password out of shell profiles and child-process environments:

```toml title="secretspec.toml"
[providers]
kdbx = {
  uri = "kdbx:./secrets.kdbx",
  credentials = { password = "keyring" }
}
```

Store the declared credential once:

```bash
$ secretspec config provider login kdbx
Enter password for provider 'kdbx' (source: keyring): ****
```

`SECRETSPEC_KDBX_PASSWORD` is available as a fallback for environments without
a suitable bootstrap provider. Avoid it for normal interactive use, and do not
persist the master password in a shell profile.

Use `?keyfile=PATH` for a KeePass key file. When both a password and key file
are configured, both are required to unlock the database, matching KeePass.
Relative database and key-file paths resolve from the directory containing
`secretspec.toml`.

## Configuration

### URI format

```text
kdbx:PATH[?keyfile=PATH][&prefix=TEMPLATE]
```

- `PATH` is the KDBX database. Use `./` for a relative path so its spelling and
  case are preserved as a URI path.
- `keyfile` is an optional KeePass key file.
- `prefix` changes the convention entry path. It accepts `{project}`,
  `{profile}`, and `{key}` placeholders and defaults to
  `secretspec/{project}/{profile}/{key}`.

### URI examples

```text
kdbx:./secrets.kdbx
kdbx:/var/lib/myapp/secrets.kdbx
kdbx:./secrets.kdbx?keyfile=./secrets.key
kdbx:./shared.kdbx?prefix=teams/{project}/{profile}/{key}
```

### Project configuration

```toml title="secretspec.toml"
[providers]
local_vault = {
  uri = "kdbx:./secrets.kdbx?keyfile=./secrets.key",
  credentials = { password = "keyring" }
}

[profiles.default]
DATABASE_URL = { description = "Database URL", providers = ["local_vault"] }
```

## Storage model

The default convention address creates groups for `secretspec`, the project,
and the profile. The final path component is the entry title, and the value is
stored as its protected `Password` field:

```text
secretspec/myapp/production/DATABASE_URL
└── Password = <secret value>
```

Reads open KDBX 3 and KDBX 4 databases. Writes create KDBX 4 databases and
atomically replace an existing KDBX 4 file only after the complete encrypted
replacement has been flushed. KDBX 3 databases must be upgraded with KeePass
or KeePassXC before SecretSpec can write them.

## Use existing secrets

Use [`ref`](/reference/configuration/#secret-references) to name an existing
entry by its complete group path and title. The optional `field` selects a
standard or custom entry field; it defaults to `Password`.

```toml
[profiles.production]
DATABASE_PASSWORD = {
  description = "Existing KeePass entry",
  ref = { item = "Infrastructure/PostgreSQL", field = "Password" },
  providers = ["local_vault"]
}
DATABASE_USERNAME = {
  description = "Username from the same entry",
  ref = { item = "Infrastructure/PostgreSQL", field = "UserName" },
  providers = ["local_vault"]
}
```

Entry and group names are matched exactly. Duplicate titles within one group,
or duplicate group names under one parent, are rejected as ambiguous instead
of selecting an arbitrary value. Empty path components are not supported.
The `Title` field is readable but not writable because it forms part of the
entry address; rename entries in KeePass or KeePassXC.

## Security considerations and limitations

- Never place the master password in the URI. Use the `password` provider
  credential from a bootstrap provider. `SECRETSPEC_KDBX_PASSWORD` is a
  discouraged fallback for environments without one; reported provider URIs
  never contain the password.
- Keep key files separate from the KDBX database when possible. Possessing both
  removes the extra protection a key file provides.
- SecretSpec serializes KDBX operations within one process and replaces files
  atomically, but KDBX is still a local file rather than a multi-writer service.
  Avoid editing the same database simultaneously in SecretSpec and KeePass.
- Writing uses the `keepass` crate's KDBX 4 writer. Back up important databases
  before first use with a new SecretSpec or `keepass` version.
