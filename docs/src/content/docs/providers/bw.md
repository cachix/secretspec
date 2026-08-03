---
title: Bitwarden Password Manager Provider
description: Bitwarden Password Manager secrets management integration
---

The `bw` provider integrates with Bitwarden Password Manager for secret management with vault-wide access to all item types.

:::note[Version compatibility]
The Bitwarden Password Manager provider is an upcoming SecretSpec 0.18 feature and is not
available in SecretSpec 0.17.
:::

## Prerequisites

- Bitwarden CLI (`bw`)
- Bitwarden account
- For self-hosted servers: the CLI pointed at your server with `bw config server` **before** logging in (see [Self-hosted servers](#self-hosted-servers))
- Signed in via `bw login` and unlocked with `bw unlock`
- `BW_SESSION` environment variable set

## Configuration

### URI Format

#### Password Manager URIs
```
bw://[collection]
bw://[org@collection]
bw://?server=https://vault.company.com
bw://?type=login&field=password
```

- `collection`: Target collection, by name or by ID
- `org@collection`: Organization and collection, each by name or by ID
- `type`: Item type (login, card, identity, sshkey, securenote)
- `field`: Specific field to extract
- `server`: The self-hosted server this configuration expects. This does **not**
  configure the CLI — it is a guard that fails with remediation steps when the
  `bw` CLI is pointed somewhere else. See [Self-hosted servers](#self-hosted-servers).

##### Addressing organizations and collections (0.18+)

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

### Examples

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

## Usage

### Basic Commands

```bash
# Set a secret (Password Manager)
$ secretspec set DATABASE_URL
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret DATABASE_URL saved to Bitwarden

# Get a secret from existing vault item
$ secretspec get 'MyApp Database' --provider 'bw://?type=login'

# Run with secrets
$ secretspec run -- npm start
```

### Item Type Configuration

The Bitwarden provider supports all Bitwarden item types with smart field detection:

#### Login Items (Default)
```bash
# Get password field (default)
$ secretspec get 'Database Login' --provider 'bw://?type=login'

# Get username field
$ secretspec get 'Database Login' --provider 'bw://?type=login&field=username'

# Get custom field
$ secretspec get 'API Service' --provider 'bw://?type=login&field=api_key'
```

#### Credit Card Items
```bash
# Get API key from custom field (field required)
$ secretspec get 'Stripe Payment' --provider 'bw://?type=card&field=api_key'

# Get card number
$ secretspec get 'Company Card' --provider 'bw://?type=card&field=number'
```

#### SSH Key Items
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

#### Identity Items
```bash
# Get custom field (field required)
$ secretspec get 'Employee Record' --provider 'bw://?type=identity&field=employee_id'

# Get email field
$ secretspec get 'Personal Identity' --provider 'bw://?type=identity&field=email'
```

#### Secure Note Items
```bash
# Get value from secure note
$ secretspec get 'Legacy Config' --provider 'bw://?type=securenote&field=config_value'
```

### Profile Configuration

```toml
# secretspec.toml
[profiles.development.defaults]
providers = ["bw"]

[profiles.production.defaults]
providers = ["bw"]

```

### Environment Variables

#### Authentication
```bash
# Password Manager session
$ export BW_SESSION="your-session-key"
```

#### Configuration Defaults
```bash
# Set item type and field defaults
$ export BITWARDEN_DEFAULT_TYPE=login
$ export BITWARDEN_DEFAULT_FIELD=password

# Organization settings (names or IDs, resolved the same way as in the URI)
$ export BITWARDEN_ORGANIZATION=myorg
$ export BITWARDEN_COLLECTION=dev-secrets

# Use defaults
$ secretspec get DATABASE_PASSWORD --provider bw://
```

### CI/CD Integration

#### Password Manager with Session Key
```bash
# Login and unlock (interactive)
$ bw login
$ bw unlock

# Export session for automation
$ export BW_SESSION="session-key-from-unlock"

# Use in CI/CD
$ secretspec run --provider bw://Production -- deploy
```

### Default Field by Item Type

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

A named field resolves to that field or to nothing. If it is absent the secret
is reported missing rather than answered from some other field, so a typo in
`field` surfaces as a missing secret instead of the wrong value. `field =
"notes"` addresses a Secure Note's body.

### How items are matched (0.18+)

Item names are matched **in full, case-insensitively** — `test database` finds
`Test Database`, but `API_KEY` never matches `API_KEY_OLD`. The `bw` CLI itself
accepts a substring here, which works well interactively because it prints the
candidates and lets you choose; a name in `secretspec.toml` is resolved with
nobody watching, so a partial match would quietly read — or overwrite — a
neighbouring item.

Bitwarden does not require names to be unique. When more than one item matches,
SecretSpec refuses the address and lists the colliding ids rather than picking
one; point the secret at a single item by using its id as the `item`:

```toml
[profiles.default]
API_KEY = { description = "Disambiguated by id", ref = { item = "5a1b2c3d-...." } }
```

Adding `?type=` narrows the match to that item type, on both reads and writes.
That is how a Card and a Login of the same name stay separately addressable:

```bash
$ secretspec get API_KEY --provider "bw://?type=card"
```

## Error Handling

The provider includes comprehensive error handling with helpful guidance:

### CLI Installation
```
Bitwarden CLI (bw) is not installed.

To install it:
  - npm: npm install -g @bitwarden/cli
  - Homebrew: brew install bitwarden-cli
  - Download: https://bitwarden.com/help/cli/
```

### Authentication Issues
- Clear distinction between "not logged in" vs "vault locked"
- Step-by-step guidance for `bw login` and `bw unlock`
- Session key setup instructions

### Server Mismatch
When `?server=` names a different server than the one the `bw` CLI is configured
for, the operation stops before touching the vault and reports both addresses
alongside the `bw logout` / `bw config server` / `bw login` / `bw unlock`
sequence needed to correct it.

### Item Access
- Graceful handling of missing items
- Field validation and suggestions
- Organization/collection permission guidance