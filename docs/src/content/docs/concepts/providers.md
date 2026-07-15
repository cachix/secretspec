---
title: Providers
description: Choose and configure the storage backends SecretSpec uses for secrets
---

A provider is a storage backend from which SecretSpec reads secrets and, when
supported, writes them. Providers let one `secretspec.toml` describe the secrets
an application needs without requiring every environment to use the same secret
store.

For example, a developer can use the system keyring, CI can supply environment
variables, and production can use a shared password manager or cloud secret
manager. The secret definitions stay the same; only their provider configuration
changes.

## Provider specifications

Anywhere SecretSpec accepts a provider, you can use one of three forms:

- A provider name, such as `keyring` or `env`.
- A provider URI, such as `dotenv://.env.local` or
  `onepassword://Production`. The URI configures a particular instance of the
  provider.
- A provider alias, such as `prod_vault`, defined in project or user
  configuration.

Aliases are useful when a URI is shared by several secrets or should have a
meaningful, store-independent name.

```toml title="secretspec.toml"
[providers]
prod_vault = "onepassword://Production"

[profiles.production]
DATABASE_URL = { description = "Production database", providers = ["prod_vault"] }
```

## Available providers

| Provider | Storage backend | Read | Write | Encrypted at rest |
|----------|-----------------|------|-------|-------------------|
| [keyring](/providers/keyring/) | macOS Keychain, Windows Credential Manager, or Linux Secret Service | ✓ | ✓ | ✓ |
| [dotenv](/providers/dotenv/) | A `.env` file | ✓ | ✓ | ✗ |
| [env](/providers/env/) | Current process environment | ✓ | ✗ | ✗ |
| [pass](/providers/pass/) | Unix `pass` password store | ✓ | ✓ | ✓ |
| [protonpass](/providers/protonpass/) | Proton Pass | ✓ | ✓ | ✓ |
| [onepassword](/providers/onepassword/) | 1Password | ✓ | ✓ | ✓ |
| [lastpass](/providers/lastpass/) | LastPass | ✓ | ✓ | ✓ |
| [gcsm](/providers/gcsm/) | Google Cloud Secret Manager (requires the `gcsm` build feature) | ✓ | ✓ | ✓ |
| [awssm](/providers/awssm/) | AWS Secrets Manager (requires the `awssm` build feature) | ✓ | ✓ | ✓ |
| [vault](/providers/vault/) | HashiCorp Vault or OpenBao (requires the `vault` build feature) | ✓ | ✓ | ✓ |
| [bws](/providers/bws/) | Bitwarden Secrets Manager (requires the `bws` build feature) | ✓ | ✓ | ✓ |
| [akv](/providers/akv/) | Azure Key Vault (requires the `akv` build feature) | ✓ | ✓ | ✓ |

See each provider's page for its URI format, authentication requirements, and
storage conventions.

## How SecretSpec selects a provider

SecretSpec resolves the provider for each secret in the following order:

1. The `--provider` command-line option.
2. The `SECRETSPEC_PROVIDER` environment variable.
3. The secret's effective `providers` list after profile inheritance and
   `[profiles.<name>.defaults]` are applied.
4. The default provider in the user configuration.

The first two options are explicit overrides. They route every secret to one
provider and disable any configured fallback chain for that command.

If no override is set, SecretSpec tries the effective `providers` list from
left to right until a provider returns the secret. If the secret has no
`providers` list, SecretSpec uses the user-level default provider.

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
the effective list. In the example above, SecretSpec reads `DATABASE_URL` from
`prod_vault` first and falls back to `local` only when the secret is not found;
it writes `DATABASE_URL` only to `prod_vault`.

:::note
A secret's [`ref`](/reference/configuration/#secret-references) changes the
address looked up inside a provider, not the provider selection rules. Explicit
overrides and fallback chains work the same way for referenced secrets and
convention-based secrets.
:::

## Configure the default provider

Run the interactive configuration command to select the provider SecretSpec
uses when a secret has no provider-specific configuration:

```bash
$ secretspec config init
```

The resulting user configuration contains a default provider:

```toml title="~/.config/secretspec/config.toml"
[defaults]
provider = "keyring"
profile = "development" # Optional default profile
```

Use `--provider` for a one-off override, or `SECRETSPEC_PROVIDER` for commands
in the current shell or CI job:

```bash
# Route every secret in this command to a project .env file.
$ secretspec run --provider dotenv -- npm start

# Route every secret in subsequent commands to existing environment variables.
$ export SECRETSPEC_PROVIDER=env
$ secretspec check
```

A provider URI can configure the selected backend more precisely:

```bash
# Select a specific 1Password vault.
$ secretspec run --provider "onepassword://Development" -- npm start

# Select a specific dotenv file.
$ secretspec run --provider "dotenv:/home/user/work/.env" -- npm test
```

## Configure provider aliases

Provider aliases can be declared at either project or user scope:

- Define project aliases in the top-level `[providers]` table in
  `secretspec.toml`. Commit these aliases so team members and CI use the same
  mapping.
- Define user aliases in `[defaults.providers]` in
  `~/.config/secretspec/config.toml`. Use these for personal mappings that
  should apply across projects.

If both scopes define the same alias, the project alias takes precedence.

```toml title="secretspec.toml"
[providers]
prod_vault = "onepassword://Production"
shared_vault = "onepassword://Shared"
local = "keyring://"

[profiles.production]
DATABASE_URL = { description = "Production database", providers = ["prod_vault", "local"] }
SENTRY_DSN = { description = "Error reporting", providers = ["shared_vault", "local"] }
```

Provider lists may combine aliases, provider names, and inline provider URIs:

```toml title="secretspec.toml"
[profiles.production]
DATABASE_URL = { description = "Production database", providers = ["onepassword://Production", "keyring"] }
```

Use the CLI to manage user-level aliases:

```bash
$ secretspec config provider add prod_vault "onepassword://Production"
$ secretspec config provider list
$ secretspec config provider remove prod_vault
```

These commands modify only `~/.config/secretspec/config.toml`. Edit the
top-level `[providers]` table directly to change project aliases.

## Provider credentials

:::note
Provider credentials are supported in version 0.15 and later.
:::

Some providers need credentials before they can retrieve secrets. Examples
include an access token for Bitwarden Secrets Manager, a Vault token or AppRole
credentials, and a 1Password service account token.

An alias can load these credentials from another provider. This avoids storing
long-lived provider credentials in a shell profile or CI variable when a secure
store is available.

### Use the convention address

In an alias's `credentials` table, map each semantic credential name to the
provider that stores it:

```toml title="secretspec.toml"
[providers]
keyring = "keyring://"

# Read the access token from keyring before connecting to Bitwarden.
bws = { uri = "bws://a9230ec4-5507-4870-b8b5-b3f500587e4c", credentials = { access_token = "keyring" } }
```

A string value such as `"keyring"` is a provider specification. SecretSpec
reads the credential from that provider at the conventional
`{project}/{profile}/{credential}` address for the active project and profile.

### Use an explicit address

Use a table with `provider` and `ref` when the credential already exists at a
specific provider-native address:

```toml title="secretspec.toml"
[providers.vault_prod]
uri = "vault://secret/myapp?auth=approle"
credentials = {
  role_id = { provider = "onepassword", ref = { vault = "Infra", item = "vault-approle", field = "role_id" } },
  secret_id = { provider = "onepassword", ref = { vault = "Infra", item = "vault-approle", field = "secret_id" } }
}
```

The `ref` table uses the same provider-native coordinates as a secret
[`ref`](/reference/configuration/#secret-references).

### Store provider credentials

Use `config provider login` to prompt for every credential declared by an
alias and write it to the configured source:

```bash
$ secretspec config provider login bws
Enter access_token for provider 'bws' (source: keyring): ****
✓ stored access_token in keyring at smoke/default/access_token
```

You can also create a user-level alias with a convention-address credential
source from the CLI:

```bash
$ secretspec config provider add bws "bws://project-uuid" --credential access_token=keyring
$ secretspec config provider login bws
```

Provider credentials follow these rules:

- **Configured credentials are authoritative.** When an alias declares a
  credential, SecretSpec reads its configured source. Providers may still use
  their conventional environment variables when no explicit credential is
  supplied.
- **Credentials remain internal.** SecretSpec passes a retrieved credential to
  the destination provider in memory. It does not export the credential or
  include it in the environment of a process started by `secretspec run`.
- **Credential chains are one hop.** A source provider cannot require provider
  credentials of its own. SecretSpec validates this before accessing the
  provider, preventing dependency cycles.
- **Convention addresses are profile-specific.** A string source uses the
  active project and profile. Use a `ref` source when multiple projects or
  profiles should share one provider credential.
- **Names are provider-specific.** Bitwarden accepts `access_token`; Vault
  accepts `token`, `role_id`, and `secret_id`; 1Password accepts
  `service_account_token`. Unsupported names are rejected before any source is
  read.

## Next steps

- Review the URI and authentication details for an individual provider in the
  [Providers](/providers/keyring/) section.
- Learn how [Profiles](/concepts/profiles/) apply provider defaults to an
  environment.
- Learn how [Secret references](/concepts/references/) separate provider
  selection from provider-native addresses.
