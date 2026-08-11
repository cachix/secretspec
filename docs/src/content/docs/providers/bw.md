---
title: Bitwarden Password Manager Provider
description: Bitwarden Password Manager secrets management integration
---

The `bw` provider reads and writes secrets in Bitwarden Password Manager by
using the official `bw` CLI.

:::note[Version compatibility]
The Bitwarden Password Manager provider was added in SecretSpec 0.18.
:::

## At a glance

| | |
|---|---|
| Provider | `bw` |
| URI | `bw://[COLLECTION\|ORGANIZATION@COLLECTION][?options]` |
| Access | Read and write |
| Best for | Existing Bitwarden Password Manager vaults and items |
| Authentication | An unlocked `bw` CLI session through `BW_SESSION` |
| Build feature | `bw` |

## Quick start

Sign in, unlock the vault, and export the session returned by `bw unlock`:

```bash
$ bw login

$ export BW_SESSION="$(bw unlock --raw)"
```

Then write a secret and use it in a command:

```bash
$ secretspec set DATABASE_URL --provider bw://
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret 'DATABASE_URL' saved to bw (profile: default)

$ secretspec run --provider bw:// -- npm start
```

## Setup

### Prerequisites

- Bitwarden CLI (`bw`)
- Bitwarden account
- For self-hosted servers: the CLI pointed at your server with `bw config server` **before** logging in (see [Self-hosted servers](#self-hosted-servers))
- Signed in via `bw login` and unlocked with `bw unlock`
- `BW_SESSION` environment variable set

Build SecretSpec with `--features bw` when the provider is not included by
your package.

### Authentication

The provider uses the active `bw` CLI session. Export the session key after
unlocking the vault:

```bash
$ export BW_SESSION="your-session-key"
```

Before reads and writes, SecretSpec requires the CLI status to be unlocked. If
the CLI is signed out or the vault is locked, it reports combined guidance to
run `bw login` and `bw unlock`, then set `BW_SESSION`.

### Self-hosted servers

The `bw` CLI reads its server address from its own configuration file, written by
`bw config server`. It does not accept a server through an environment variable
or a per-command flag, and it refuses to change servers while a session is
active. SecretSpec therefore cannot switch servers for you.

Configure the CLI once, before logging in:

```bash
$ bw logout                                    # if already logged in

$ bw config server https://vault.company.com

$ bw login

$ bw unlock

$ export BW_SESSION="session-key-from-unlock"
```

With the CLI configured, `?server=` records which server the project expects.
SecretSpec compares it against the CLI's current setting before each operation
and fails with the commands above when they disagree, instead of silently
reading or writing secrets on the wrong server:

```toml
# secretspec.toml — documents the expected server for the whole team
[providers]
company_vault = "bw://?server=https://vault.company.com"
```

Omit `?server=` to accept whatever server the CLI is configured for.

## Configuration

### URI format

```
bw://[collection]
bw://[org@collection]
bw://?server=https://vault.company.com
bw://?type=login&field=password
```

- `collection`: Target collection, by name or by ID
- `org@collection`: Organization and collection, each by name or by ID
- `type`: Item type to require when matching an existing item and to use when
  creating a new one (`login`, `card`, `identity`, `sshkey`, or `securenote`)
- `field`: Built-in or custom field to read or write
- `server`: The self-hosted server this configuration expects. This does **not**
  configure the CLI — it is a guard that fails with remediation steps when the
  `bw` CLI is pointed somewhere else. See [Self-hosted servers](#self-hosted-servers).

### Organizations and collections (0.18+)

Names and IDs are interchangeable: SecretSpec resolves a name to the ID the
`bw` CLI requires. Names match case-insensitively, and one containing a space
must be percent-encoded (`bw://Acme%20Inc@dev-secrets`).

The organization is a scope and an assertion rather than a filter. It selects
which `dev-secrets` you mean when several organizations have one, and it must
agree with the collection you named — addressing a collection that lives
somewhere else is an error rather than a silent search of the wrong place. A
collection identifies its own organization, so naming the organization is
optional whenever the collection name is unambiguous:

```bash
$ secretspec get DATABASE_URL --provider "bw://dev-secrets"
```

An address that cannot be resolved fails immediately and lists the
organizations or collections that do exist. If a collection was created or
shared with you recently, run `bw sync` so the CLI can see it.

### URI examples

```bash
# Password Manager - Personal vault
$ secretspec set API_KEY --provider bw://

# Password Manager - Organization collection
$ secretspec set DATABASE_URL --provider "bw://myorg@dev-secrets"

# Password Manager - Self-hosted instance (CLI must already be configured
# for this server; see Self-hosted servers below)
$ secretspec set TOKEN --provider "bw://?server=https://vault.company.com"

# Password Manager - Specific item type and field
$ secretspec get 'MyApp Database' --provider 'bw://?type=login&field=username'
```

### Project configuration

Define reusable aliases when a team uses a shared organization or collection:

```toml title="secretspec.toml"
[providers]
team_vault = "bw://myorg@dev-secrets"

[profiles.default.defaults]
providers = ["team_vault"]
```

Profiles can select different aliases or the provider directly:

```toml title="secretspec.toml"
[profiles.development.defaults]
providers = ["bw"]

[profiles.production.defaults]
providers = ["bw"]
```

### Discover declarations (0.18+)

SecretSpec 0.18+ can initialize a manifest from the items visible through a
Bitwarden provider URI. Scope discovery to a collection, and optionally an
item type, so unrelated personal or organization-vault entries are not treated
as application secrets:

```bash
$ secretspec init --from 'bw://myorg@dev-secrets?type=login' # 0.18+
✓ Created secretspec.toml with 8 secrets
```

Each item name becomes a SecretSpec key. Names must therefore contain only
letters, numbers, and underscores, cannot start with a number, and cannot be
the reserved name `defaults`. Bitwarden allows duplicate names and matches them
case-insensitively; discovery stops when two selected items collide under those
rules instead of generating an ambiguous manifest. Rename the items or use
`?type=` to select one type.

Discovery writes only names and generated descriptions to `secretspec.toml`;
it never writes secret values. The `--project` and `--profile` discovery
context does not change Bitwarden item names. To migrate the discovered values
after reviewing the declarations, run the `secretspec import` command printed
by `init`.

### Environment overrides

Environment variables take precedence over organization, collection, item type,
and default field values in the provider URI. A value left in the shell can
therefore change an operation even when `--provider` supplies those settings;
unset unwanted overrides before running SecretSpec:

```bash
$ export BITWARDEN_DEFAULT_TYPE=login

$ export BITWARDEN_DEFAULT_FIELD=password

$ export BITWARDEN_ORGANIZATION=myorg

$ export BITWARDEN_COLLECTION=dev-secrets

$ secretspec get DATABASE_PASSWORD --provider bw://
```

Organization and collection values can be names or IDs and resolve in the same
way as values in the URI. The complete precedence is:

| Setting | Highest to lowest precedence |
|---------|------------------------------|
| Organization | `BITWARDEN_ORGANIZATION`, provider URI |
| Collection | `BITWARDEN_COLLECTION`, provider URI |
| Item type | `BITWARDEN_DEFAULT_TYPE`, provider URI |
| Field | Secret `ref.field`, `BITWARDEN_DEFAULT_FIELD`, provider URI, item-type default |

## Storage model

The Bitwarden provider supports every Password Manager item type. When an item
type is selected through `BITWARDEN_DEFAULT_TYPE` or `?type=`, it filters reads
and updates to that type and selects the type of a newly created item. If
neither is set, reads and updates accept any matching type, while new items are
Logins.

### Item types

#### Login items

```bash
# Get password field (default)
$ secretspec get 'Database Login' --provider 'bw://?type=login'

# Get username field
$ secretspec get 'Database Login' --provider 'bw://?type=login&field=username'

# Get custom field
$ secretspec get 'API Service' --provider 'bw://?type=login&field=api_key'
```

#### Credit card items

```bash
# Get API key from custom field (field required)
$ secretspec get 'Stripe Payment' --provider 'bw://?type=card&field=api_key'

# Get card number
$ secretspec get 'Company Card' --provider 'bw://?type=card&field=number'
```

#### SSH key items

```bash
# Get private key (default)
$ secretspec get 'Deploy Key' --provider 'bw://?type=sshkey'

# Get passphrase
$ secretspec get 'Deploy Key' --provider 'bw://?type=sshkey&field=passphrase'
```

Bitwarden requires an SSH key item to carry all three of the private key,
public key and fingerprint — it rejects or discards an item that leaves any of
them empty. When `set` creates one, the two fields it is not writing are
therefore filled with `(not set by SecretSpec)`. Replace them in Bitwarden if
you need the real values, or write them yourself with `?field=public_key` and
`?field=key_fingerprint`.

#### Identity items

```bash
# Get custom field (field required)
$ secretspec get 'Employee Record' --provider 'bw://?type=identity&field=employee_id'

# Get email field
$ secretspec get 'Personal Identity' --provider 'bw://?type=identity&field=email'
```

#### Secure note items

```bash
# Get value from secure note
$ secretspec get 'Legacy Config' --provider 'bw://?type=securenote&field=config_value'
```

### Default fields

When no field is named, each item type uses the default below. The same default
applies to reads and writes, so `secretspec set` followed by `secretspec get`
returns what was written.

| Item Type   | Default field         | Read also falls back to      |
|-------------|-----------------------|------------------------------|
| Login       | `password`            | `username`, then a custom `value` field |
| Secure Note | custom `value` field  | the note body                |
| Card        | `number`              | a custom `value` field       |
| Identity    | `email`               | `username`, then a custom `value` field |
| SSH Key     | `private_key`         | a custom `value` field       |

The default depends only on the item type, never on the secret or item name.
The extra read fallbacks exist to make existing, hand-created vault items
resolve; writes always target the default field itself.

To address anything else, name the field explicitly with `?field=` or a `ref`
mapping:

```toml
[profiles.default]
STRIPE_KEY = { description = "Card custom field", ref = { item = "Stripe Test Card", field = "api_key" } }
DEPLOY_PUBKEY = { description = "SSH public key", ref = { item = "Deploy SSH Key", field = "public_key" } }
```

Built-in field names and aliases resolve only to that built-in field. Custom
field names first match in full, case-insensitively. If there is no exact match,
SecretSpec uses the first custom field whose name contains the requested text,
also case-insensitively. Use the complete custom-field name to avoid an
unintended partial match. `field = "notes"` addresses a Secure Note's body.

### How items are matched (0.18+)

Item names are matched **in full, case-insensitively** — `test database` finds
`Test Database`, but `API_KEY` never matches `API_KEY_OLD`. The `bw` CLI itself
accepts a substring here, which works well interactively because it prints the
candidates and lets you choose; a name in `secretspec.toml` is resolved with
nobody watching, so a partial match would quietly read — or overwrite — a
neighbouring item.

Bitwarden does not require names to be unique. When more than one item matches,
SecretSpec refuses the address and lists the colliding IDs rather than picking
one. Rename the items so the selected name is unique, or use `?type=` when the
collisions have different item types.

Adding `?type=` narrows the match to that item type, on both reads and writes.
That is how a Card and a Login of the same name stay separately addressable:

```bash
$ secretspec get API_KEY --provider "bw://?type=card"
```

## Use existing secrets

The secret name selects an existing Bitwarden item by default:

```bash
$ secretspec get 'MyApp Database' --provider 'bw://?type=login'
```

Use a `ref` when the SecretSpec key and Bitwarden item name differ, or when a
specific field is required:

```toml title="secretspec.toml"
[profiles.default]
DATABASE_URL = { description = "Application database", ref = { item = "MyApp Database", field = "password" }, providers = ["bw"] }
```

`ref.item` is matched against the Bitwarden item name, not its item ID.

## CI/CD

Provide an unlocked session to the job as `BW_SESSION`, then select the
provider as usual:

```bash
$ export BW_SESSION="session-key-from-unlock"

$ secretspec run --provider bw:// -- deploy
```

Treat the session key as a CI secret and avoid printing it in job logs.

## Security considerations

- `BW_SESSION` unlocks the vault for the lifetime of the session, and the
  session can access everything granted to the signed-in account. Keep the
  session key out of checked-in configuration and shell history.
- Scope provider URIs to the intended organization and collection when
  possible.
- For self-hosted installations, use `?server=` as a guard against operating
  on a differently configured vault.
- Ambiguous item names fail instead of selecting one silently; rename them or
  use `?type=` when the duplicates have different item types.

## Troubleshooting

### CLI installation

```
Bitwarden CLI (bw) is not installed.

To install it:
  - npm: npm install -g @bitwarden/cli
  - Homebrew: brew install bitwarden-cli
  - Download: https://bitwarden.com/help/cli/
```

### Server mismatch

When `?server=` names a different server than the one the `bw` CLI is configured
for, the operation stops before touching the vault and reports both addresses
alongside the `bw logout` / `bw config server` / `bw login` / `bw unlock`
sequence needed to correct it.
