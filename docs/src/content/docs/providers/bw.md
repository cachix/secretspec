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
bw://[collection-id]
bw://[org@collection]
bw://?server=https://vault.company.com
bw://?type=login&field=password
```

- `collection-id`: Target collection ID
- `org@collection`: Organization and collection specification
- `type`: Item type (login, card, identity, sshkey, securenote)
- `field`: Specific field to extract
- `server`: The self-hosted server this configuration expects. This does **not**
  configure the CLI — it is a guard that fails with remediation steps when the
  `bw` CLI is pointed somewhere else. See [Self-hosted servers](#self-hosted-servers).

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

# Organization settings
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

### Field Requirements by Item Type

| Item Type    | Default Field  | Field Required? | Notes                    |
|--------------|----------------|-----------------|--------------------------|
| Login        | `password`     | No              | Falls back to username   |
| SSH Key      | `private_key`  | No              | Standard SSH key field   |
| Card         | None           | **YES**         | Must specify field       |
| Identity     | None           | **YES**         | Must specify field       |
| Secure Note  | Smart detect   | No              | Uses note content/fields |

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