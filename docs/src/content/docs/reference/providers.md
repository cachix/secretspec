---
title: Providers Reference
description: Complete reference for SecretSpec storage providers and their URI configurations
---

SecretSpec supports multiple storage backends for secrets. Each provider has its own URI format and configuration options.

This page is a compact URI reference. For installation, authentication,
copyable project configuration, storage behavior, and CI/CD guidance, follow
the link for the individual provider.

## DotEnv Provider

**URI**: `dotenv://[path]` - Stores secrets in `.env` files

```bash
dotenv://                    # Uses default .env
dotenv:///config/.env        # Custom path
dotenv://config/.env         # Relative path
```

**Features**: Read/write, profiles, human-readable, no encryption

## Environment Provider

**URI**: `env://` - Read-only access to system environment variables

```bash
env://                       # Current process environment
```

**Features**: Read-only, no setup required, no persistence

## GoPass Provider

Available starting with SecretSpec 0.15.

**URI**: `gopass://[host][path]` - Uses `gopass`, a multi-user and multi-store abstraction layer over `pass`, with GPG encryption

```bash
gopass://                                    # Default folder prefix
gopass://secretspec/shared/{profile}/{key}   # Custom folder prefix with placeholders
```

**Features**: Read/write, GPG encryption, git-backed sync, profiles, local storage
**Prerequisites**: `gopass` CLI, initialized password store
**Storage**: Path `secretspec/{project}/{profile}/{key}` by default; the URI host and path override the folder prefix and support `{project}`, `{profile}`, and `{key}` placeholders

Gopass entries store a single line; multiline secrets are truncated to their first line when read.

## Keyring Provider

**URI**: `keyring://` - Uses system keychain/keyring for secure storage

```bash
keyring://                   # System default keychain
```

**Features**: Read/write, secure encryption, profiles, cross-platform
**Storage**: Service `secretspec/{project}/{profile}/{key}`, with the current
operating-system username as the account

## LastPass Provider

**URI**: `lastpass://[item_template]` - Integrates with LastPass via `lpass` CLI

```bash
lastpass://                                      # Default layout
lastpass://Work/SecretSpec/{project}/{profile}/{key} # Custom item template
```

**Features**: Read/write, cloud sync, profiles via folders, auto-sync
**Prerequisites**: `lpass` CLI, authenticated with `lpass login`
**Storage**: Item name `secretspec/{project}/{profile}/{key}` by default. A URI
item template replaces the default and supports `{project}`, `{profile}`, and
`{key}` placeholders.

## OnePassword Provider

**URI**: `onepassword://[account@]vault` or `onepassword+token://user:token@vault`

```bash
onepassword://MyVault                           # Default account
onepassword://work@CompanyVault                 # Specific account
onepassword+token://user:op_token@SecureVault   # Service account
```

**Features**: Read/write, cloud sync, profiles via vaults, service accounts
**Prerequisites**: `op` CLI, authenticated through desktop app integration, a
service account token, or a legacy `op signin` shell session
**Storage**: Secure Note named `secretspec/{project}/{profile}/{key}`, with tags
`automated` and `{project}`

The URI names a vault only; item paths on the URI are rejected. To read and
write an existing item's field in place, name it with the `ref` field
(`SECRET = { description = "…", ref = { item = "…", field = "…" } }`); see
[Secret References](/reference/configuration/#secret-references).

## Pass Provider

**URI**: `pass://` - Uses Unix password manager with GPG encryption

```bash
pass://                       # Default password store
```

**Features**: Read/write, GPG encryption, profiles, local storage
**Prerequisites**: `pass` CLI, initialized with `pass init <gpg-key-id>`
**Storage**: Path `secretspec/{project}/{profile}/{key}`

## Proton Pass Provider

**URI**: `protonpass://[vault[/title-template]]` - Stores secrets in Proton Pass via the official `pass-cli`

```bash
protonpass://                                      # Default vault ("secretspec")
protonpass://Work                                  # Specific vault
protonpass://Work/{project}/{profile}/{key}        # Custom vault and title template
```

**Features**: Read/write, end-to-end encryption, cloud sync, vault organisation, PAT-based CI auth
**Prerequisites**: `pass-cli`, authenticated with `pass-cli login` (or `pass-cli login --pat $PAT` for CI)
**Storage**: Note item titled `{project}/{profile}/{key}` inside the configured vault

## Google Cloud Secret Manager Provider

**URI**: `gcsm://PROJECT_ID[?layout=flat]` - Stores secrets in Google Cloud Secret Manager

```bash
gcsm://my-gcp-project              # GCP project ID
gcsm://my-gcp-project?layout=flat  # (0.17+) Secret id is the key alone
```

**Features**: Read/write, cloud sync, profiles, service account support
**Prerequisites**: `gcloud` CLI, authenticated, Secret Manager API enabled, build with `--features gcsm`
**Storage**: Secret name `secretspec-{project}-{profile}-{key}`, or the `{key}` alone under [`?layout=flat`](#layout-flat-017)

## AWS Secrets Manager Provider

**URI**: `awssm://[profile@]REGION[?prefix=PREFIX][&layout=flat]` - Stores secrets in AWS Secrets Manager

```bash
awssm://us-east-1             # Specific AWS region
awssm://production@us-east-1  # Specific AWS profile and region
awssm://us-east-1?layout=flat # (0.17+) Secret name is [prefix/]key
awssm://                      # SDK default region and credentials
```

**Features**: Read/write, cloud sync, profiles, IAM/SSO authentication
**Prerequisites**: AWS credentials configured, build with `--features awssm`
**Storage**: Secret name `[prefix/]secretspec/{project}/{profile}/{key}`, or `[prefix/]{key}` under [`?layout=flat`](#layout-flat-017)

## Vault Provider

**URI**: `vault://[namespace@]host[:port][/mount][?options]` - Stores secrets in HashiCorp Vault's KV engine

```bash
vault://vault.example.com:8200/secret       # KV v2 at "secret" mount
vault://vault.example.com:8200              # Default "secret" mount
vault://ns1@vault.example.com:8200/secret   # With namespace
vault://vault.example.com:8200/secret?auth=approle
# SecretSpec 0.17+
vault://vault.example.com:8200/secret?auth=jwt&role=ci
vault://127.0.0.1:8200/secret?kv=1         # KV v1 engine
vault://127.0.0.1:8200/secret?tls=false    # Disable TLS (dev mode)
```

**Features**: Read/write, KV v1 and v2, namespaces; token and AppRole authentication; JWT/OIDC authentication (0.17+)
**Prerequisites**: Vault server, authentication credentials, build with `--features vault`
**Storage**: KV path `secretspec/{project}/{profile}/{key}` with a `value` field, or the `{key}` alone at the mount root under [`?layout=flat`](#layout-flat-017)

## OpenBao Provider (0.17+)

:::caution[Version compatibility]
The `openbao` provider is added in SecretSpec 0.17 and is unavailable in the
current 0.16 release. With 0.16, use `openbao://` through the `vault` build
feature and configure `VAULT_*` environment variables.
:::

**URI**: `openbao://[namespace@]host[:port][/mount][?options]` - Stores secrets in OpenBao's KV engine

```bash
openbao://bao.example.com:8200/secret
openbao://team-a@bao.example.com:8200/secret
openbao://bao.example.com:8200/secret?auth=approle
openbao://bao.example.com:8200/secret?auth=jwt&role=ci
openbao://127.0.0.1:8200/secret?kv=1&tls=false
openbao://bao.example.com:8200/secret?layout=flat
```

**Features**: Read/write, KV v1 and v2, namespaces; token, AppRole, and JWT/OIDC authentication; documented OpenBao CLI variables plus SecretSpec-defined `BAO_*` AppRole/JWT inputs, all with `VAULT_*` compatibility fallbacks
**Prerequisites**: OpenBao server, authentication credentials, build with `--features openbao` (0.17+)
**Storage**: KV path `secretspec/{project}/{profile}/{key}` with a `value` field, or the `{key}` alone at the mount root under [`?layout=flat`](#layout-flat-017)

## Bitwarden Secrets Manager Provider

**URI**: `bws://[SERVER_BASE@]PROJECT_UUID` - Stores secrets in Bitwarden Secrets Manager

```bash
bws://a9230ec4-5507-4870-b8b5-b3f500587e4c                    # US cloud (default)
bws://vault.bitwarden.eu@a9230ec4-5507-4870-b8b5-b3f500587e4c # EU cloud
bws://bw.example.com@a9230ec4-5507-4870-b8b5-b3f500587e4c     # Self hosted
```

`SERVER_BASE` is the bare hostname of the Bitwarden instance; the identity and
API endpoints are derived as `https://SERVER_BASE/identity` and
`https://SERVER_BASE/api`. Omit it to use the `bitwarden.com` US cloud.

**Features**: Read/write, cloud sync, project-scoped, end-to-end encryption
**Prerequisites**: BWS subscription, machine account access token, build with `--features bws`
**Storage**: Flat key names in the specified BWS project

## Azure Key Vault Provider

**URI**: `akv://VAULT_NAME[?auth=env|cli|managed_identity|workload_identity][&suffix=DNS_SUFFIX]` - Stores secrets in Azure Key Vault

```bash
akv://myvault                            # Service principal env vars, falling back to `az login`
akv://myvault?auth=managed_identity      # VM / App Service / AKS system-assigned managed identity
akv://myvault?auth=workload_identity     # AKS workload identity federation
akv://myvault.vault.azure.cn             # Sovereign cloud (full DNS name)
akv://myvault?suffix=vault.azure.cn      # Sovereign cloud (explicit suffix, bare vault name)
```

**Features**: Read/write, cloud sync, profiles, service principal/managed identity/workload identity auth
**Prerequisites**: An Azure Key Vault instance, authenticated via one of the methods above, build with `--features akv`
**Storage**: Secret name `secretspec--{base32(project)}--{base32(profile)}--{base32(key)}` (lowercase, unpadded Base32 preserves case and punctuation distinctions within Azure's case-insensitive secret-name namespace), or the `{key}` used verbatim as the secret name under [`?layout=flat`](#layout-flat-017)

## Infisical Provider

Available since SecretSpec 0.16.

**URI**: `infisical://[HOST]/PROJECT_ID[?env=SLUG][&path=/PREFIX][&layout=flat][&tls=false]` - Stores secrets in Infisical

```bash
infisical://app.infisical.com/7e2f1a4c-...            # Infisical Cloud (US)
infisical://eu.infisical.com/7e2f1a4c-...             # Infisical Cloud (EU)
infisical://vault.example.com/7e2f1a4c-...?env=prod   # Read every profile from one environment
infisical://app.infisical.com/7e2f1a4c-...?layout=flat  # (0.17+) Read from the environment root, no folders
infisical://localhost:8080/7e2f1a4c-...?tls=false     # Self-hosted over plain HTTP
```

The project is Infisical's project **UUID** (Project Settings → Project ID); its API does not
accept the project slug. Without a host, the provider reads `INFISICAL_DOMAIN`, then Infisical's
legacy `INFISICAL_API_URL`, then defaults to Infisical Cloud.

**Features**: Read/write, cloud sync, profiles, machine-identity (Universal Auth) or token auth, secret references, version-pinned refs
**Prerequisites**: An Infisical project, a machine identity with access to it, build with `--features infisical`
**Authentication**: `INFISICAL_CLIENT_ID` + `INFISICAL_CLIENT_SECRET` (Universal Auth), or a ready-made `INFISICAL_TOKEN`. Service tokens are not supported; Infisical deprecated them in favour of machine identities.
**Storage**: Secret `{key}` in folder `/secretspec/{project}/{profile}`, in the environment named by the profile (or by `?env=`). Keys are stored verbatim.

By default the SecretSpec profile names the Infisical environment, so a `production` profile reads
the `production` environment. Projects whose environments do not correspond to profiles pin one with
`?env=`; the profile still names the folder, so profiles never share a secret.

`?layout=flat` (0.17+) drops the `{project}/{profile}` folders so secrets resolve at the environment
root (or at `?path=` when given) — the natural shape for a single-project store, e.g. one migrated
from another manager. The profile still names the environment, so profiles stay apart; combining
`?layout=flat` with a pinned `?env=` collapses them onto one root and is only safe when a single
profile is resolved against the store.

Values are read with Infisical's secret references expanded, matching its own CLI, so a value of
`postgres://${DB_USER}@host` arrives resolved.

## Layout: `flat` (0.17+)

:::note[Version compatibility]
Added in SecretSpec 0.17. `?layout=flat` is not available in SecretSpec 0.16 or earlier.
:::

`?layout=` is a **general provider setting**, spelled the same way across every provider whose
store has a hierarchy: Infisical, Vault, OpenBao, AWS Secrets Manager, Google Cloud Secret Manager
and Azure Key Vault. It controls how SecretSpec's `{project}/{profile}/{key}` naming convention maps onto the
store:

- **`nested`** (the default) keeps the `secretspec/{project}/{profile}` scaffolding, so many
  projects and profiles can share one store without colliding. This is the shape SecretSpec creates.
- **`flat`** drops that scaffolding, so a convention secret is addressed by its **key alone**, at
  the store root — under any provider-native container (a Vault mount) or user-supplied prefix (an
  AWS `?prefix=`, an Infisical `?path=`), but with no project/profile segments. This is the natural
  shape of a **single-project store**, e.g. one migrated from another secret manager where the
  secrets already live at the root.

Because the flat layout no longer puts the project or profile in a name, those names are
unconstrained under it. Two caveats follow from addressing by key alone:

- **Profile separation.** Dropping the profile means distinct profiles no longer separate
  themselves by name. A provider that pins its environment another way (an Infisical `?env=`) can
  still keep profiles apart, but flat plus such a pin collapses every profile onto one key and gives
  up profile separation deliberately — only safe when a single profile is ever resolved against the
  store.
- **The key must fit the store.** With no `secretspec-` rewriting to fall back on, the key itself
  must be a legal name in the backend. Azure Key Vault is the strictest: under flat the key is used
  as the secret name verbatim, so it must match `^[0-9a-zA-Z-]+$` (an underscore, which the nested
  layout would have Base32-encoded away, is refused).

Providers with no hierarchy (`dotenv`, `env`, `bws`) are already flat and ignore the setting.

An unreadable value (anything but `nested` or `flat`) is refused rather than guessed.

## Provider Selection

### Command Line
```bash
# Simple provider names
secretspec get API_KEY --provider keyring
secretspec get API_KEY --provider dotenv
secretspec get API_KEY --provider env

# URIs with configuration
secretspec get API_KEY --provider dotenv:/path/to/.env
secretspec get API_KEY --provider onepassword://vault
secretspec get API_KEY --provider "onepassword://account@vault"
```

### Environment Variables
```bash
export SECRETSPEC_PROVIDER=keyring
export SECRETSPEC_PROVIDER="dotenv:///config/.env"
```


## Security Considerations

| Provider | Encryption | Storage Location | Network Access |
|----------|------------|------------------|----------------|
| DotEnv | ❌ Plain text | Local filesystem | ❌ No |
| Environment | ❌ Plain text | Process memory | ❌ No |
| Keyring | ✅ System encryption | System keychain | ❌ No |
| Pass | ✅ GPG encryption | Local filesystem | ❌ No |
| GoPass | ✅ GPG encryption | Local filesystem | ❌ No |
| Proton Pass | ✅ End-to-end | Cloud (Proton) | ✅ Yes |
| LastPass | ✅ End-to-end | Cloud (LastPass) | ✅ Yes |
| OnePassword | ✅ End-to-end | Cloud (OnePassword) | ✅ Yes |
| GCSM | ✅ Google-managed | Cloud (GCP) | ✅ Yes |
| AWSSM | ✅ AWS KMS | Cloud (AWS) | ✅ Yes |
| Vault | ✅ Vault encryption | Vault server | ✅ Yes |
| OpenBao (0.17+) | ✅ OpenBao encryption | OpenBao server | ✅ Yes |
| BWS | ✅ End-to-end | Cloud (Bitwarden) | ✅ Yes |
| AKV | ✅ Azure-managed | Cloud (Azure) | ✅ Yes |
| Infisical | ✅ Infisical-managed | Cloud (Infisical) or self-hosted | ✅ Yes |
