---
title: Providers Reference
description: Complete reference for SecretSpec storage providers and their URI configurations
---

SecretSpec supports multiple storage backends for secrets. Each provider has its own URI format and configuration options.

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

## Keyring Provider

**URI**: `keyring://` - Uses system keychain/keyring for secure storage

```bash
keyring://                   # System default keychain
```

**Features**: Read/write, secure encryption, profiles, cross-platform
**Storage**: Service `secretspec/{project}`, username `{profile}:{key}`

## LastPass Provider

**URI**: `lastpass://[folder]` - Integrates with LastPass via `lpass` CLI

```bash
lastpass://work              # Store in work folder
lastpass:///personal/projects # Nested folder
lastpass://localhost         # Root (no folder)
```

**Features**: Read/write, cloud sync, profiles via folders, auto-sync
**Prerequisites**: `lpass` CLI, authenticated with `lpass login`
**Storage**: Item name `{folder}/{profile}/{project}/{key}`

## OnePassword Provider

**URI**: `onepassword://[account@]vault` or `onepassword+token://user:token@vault`

```bash
onepassword://MyVault                           # Default account
onepassword://work@CompanyVault                 # Specific account
onepassword+token://user:op_token@SecureVault   # Service account
```

**Features**: Read/write, cloud sync, profiles via vaults, service accounts
**Prerequisites**: `op` CLI, authenticated with `op signin`
**Storage**: Item name `{project}/{key}`, tags `automated`, `{project}`

## Pass Provider

**URI**: `pass://` - Uses Unix password manager with GPG encryption

```bash
pass://                       # Default password store
```

**Features**: Read/write, GPG encryption, profiles, local storage
**Prerequisites**: `pass` CLI, initialized with `pass init <gpg-key-id>`
**Storage**: Path `secretspec/{project}/{profile}/{key}`

## Google Cloud Secret Manager Provider

**URI**: `gcsm://PROJECT_ID` - Stores secrets in Google Cloud Secret Manager

```bash
gcsm://my-gcp-project         # GCP project ID
```

**Features**: Read/write, cloud sync, profiles, service account support
**Prerequisites**: `gcloud` CLI, authenticated, Secret Manager API enabled, build with `--features gcsm`
**Storage**: Secret name `secretspec-{project}-{profile}-{key}`

## AWS Secrets Manager Provider

**URI**: `awssm://[profile@]REGION` - Stores secrets in AWS Secrets Manager

```bash
awssm://us-east-1             # Specific AWS region
awssm://production@us-east-1  # Specific AWS profile and region
awssm://                      # SDK default region and credentials
```

**Features**: Read/write, cloud sync, profiles, IAM/SSO authentication
**Prerequisites**: AWS credentials configured, build with `--features awssm`
**Storage**: Secret name `secretspec/{project}/{profile}/{key}`

## Vault / OpenBao Provider

**URI**: `vault://[namespace@]host[:port][/mount]` or `openbao://[namespace@]host[:port][/mount]` - Stores secrets in HashiCorp Vault or OpenBao KV engine

```bash
vault://vault.example.com:8200/secret       # KV v2 at "secret" mount
vault://vault.example.com:8200              # Default "secret" mount
vault://ns1@vault.example.com:8200/secret   # With namespace
openbao://bao.internal:8200/secret          # OpenBao server
vault://127.0.0.1:8200/secret?kv=1         # KV v1 engine
vault://127.0.0.1:8200/secret?tls=false    # Disable TLS (dev mode)
```

**Features**: Read/write, KV v1 and v2, namespaces, OpenBao compatible
**Prerequisites**: Vault/OpenBao server, `VAULT_TOKEN` env var or `~/.vault-token`, build with `--features vault`
**Storage**: KV path `secretspec/{project}/{profile}/{key}` with a `value` field

## Bitwarden Secrets Manager Provider

**URI**: `bws://PROJECT_UUID` - Stores secrets in Bitwarden Secrets Manager

```bash
bws://a9230ec4-5507-4870-b8b5-b3f500587e4c   # BWS project UUID
```

**Features**: Read/write, cloud sync, project-scoped, end-to-end encryption
**Prerequisites**: BWS subscription, machine account access token, build with `--features bws`
**Storage**: Flat key names in the specified BWS project

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
| LastPass | ✅ End-to-end | Cloud (LastPass) | ✅ Yes |
| OnePassword | ✅ End-to-end | Cloud (OnePassword) | ✅ Yes |
| GCSM | ✅ Google-managed | Cloud (GCP) | ✅ Yes |
| AWSSM | ✅ AWS KMS | Cloud (AWS) | ✅ Yes |
| Vault/OpenBao | ✅ Vault encryption | Vault/OpenBao server | ✅ Yes |
| BWS | ✅ End-to-end | Cloud (Bitwarden) | ✅ Yes |
