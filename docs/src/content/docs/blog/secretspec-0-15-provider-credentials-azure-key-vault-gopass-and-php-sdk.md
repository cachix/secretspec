---
title: "SecretSpec 0.15: Provider credentials, Azure Key Vault / Gopass, and PHP SDK"
description: Authenticate providers from another secret store, use Azure Key Vault or Gopass, export secrets for CI, and resolve them from PHP.
date: 2026-07-16
authors:
  - domen
---

[SecretSpec 0.15](https://github.com/cachix/secretspec/releases/tag/v0.15.0 "SecretSpec 0.15 release")
ships:

- **[Provider credentials](/concepts/providers/#provider-credentials)** —
  authenticate one secret provider with credentials stored in another, without
  exporting them to the application environment.
- **[Azure Key Vault](/providers/akv/)** — store and resolve secrets with
  service-principal, Azure CLI, managed-identity, or AKS workload-identity
  authentication.
- **[Gopass](/providers/gopass/)** — use a GPG-encrypted, git-synchronized
  password store, including multi-user and multi-store setups.
- **[PHP SDK](/sdk/php/)** — use the shared SecretSpec resolver from PHP-FPM,
  Laravel, Symfony, and CLI applications through a native extension or
  `ext-ffi`.
- **[AWS creation guardrails](/providers/awssm/)** — set a customer-managed KMS
  key and required tags when SecretSpec creates an AWS Secrets Manager secret.
- **[`secretspec export`](/reference/cli/#export)** — resolve secrets without
  launching a command, with shell, dotenv, JSON, and GitHub Actions output.
- **[Provider and resolution fixes](/concepts/providers/)** — ordered lazy
  fallback chains, early `ref` validation, correctly merged profile overrides,
  stable output, and broader Node.js Linux compatibility.

## Credentials for the secret store

Suppose [Bitwarden Secrets Manager](/providers/bws/) holds an application's
secrets, but its machine access token is kept in the user's
[OS keyring](/providers/keyring/). Declare the relationship on the provider
alias:

```toml title="secretspec.toml"
[providers]
keyring = "keyring://"

[providers.bws]
uri = "bws://a9230ec4-5507-4870-b8b5-b3f500587e4c"

[providers.bws.credentials]
access_token = "keyring"
```

Before SecretSpec connects to Bitwarden, it reads `access_token` from the
keyring at the normal `{project}/{profile}/access_token` address. The active
[profile](/concepts/profiles/) is part of that address, so production and
development can authenticate as different machines without changing the alias.

When a credential already has a provider-native address, use a `ref`. Here a
[Vault AppRole](/providers/vault/#approle-authentication) is kept as two fields of one
[1Password item](/providers/onepassword/#use-existing-secrets):

```toml title="secretspec.toml"
[providers.vault_prod]
uri = "vault://secret/myapp?auth=approle"

[providers.vault_prod.credentials]
role_id.provider = "onepassword"
role_id.ref.vault = "Infra"
role_id.ref.item = "vault-approle"
role_id.ref.field = "role_id"

secret_id.provider = "onepassword"
secret_id.ref.vault = "Infra"
secret_id.ref.item = "vault-approle"
secret_id.ref.field = "secret_id"
```

The credential source uses the same [`ref` coordinates](/concepts/references/)
as application secrets. The difference is where the value goes: SecretSpec
hands it directly to the destination provider in memory. It is not added to the
environment of a process started by
[`secretspec run`](/reference/cli/#run).

Provider credential names are semantic and checked before a source is opened.
Bitwarden accepts `access_token`; Vault accepts `token`, `role_id`, and
`secret_id`; 1Password accepts `service_account_token`; Azure Key Vault accepts
`tenant_id`, `client_id`, and `client_secret`. A configured credential is
authoritative, while a provider's usual environment fallback remains available
when no credential source is declared.

Credential chains deliberately stop after one hop. The store containing a
provider credential cannot itself depend on another provider credential. This
keeps the bootstrap path finite and makes dependency mistakes fail before any
store is contacted.

## Log in once, without an environment variable

The new
[`config provider login`](/reference/cli/#config-provider-login) command
prompts for every credential an alias declares and writes it to the configured
source:

```console
$ secretspec config provider login bws
Enter access_token for provider 'bws' (source: keyring): ****
✓ stored access_token in keyring at my-app/default/access_token
```

A user-level alias and its credential source can also be declared entirely with
[`config provider add`](/reference/cli/#config-provider-add):

```bash
secretspec config provider add bws "bws://project-uuid" \
  --credential access_token=keyring
secretspec config provider login bws
```

Credentials are fetched once per invocation and profile, then reused for every
secret routed through that alias. Each credential read, and each value stored by
`login`, gets an [audit event](/concepts/audit/) marked with the semantic
credential name and source store. As with every SecretSpec audit event, the
credential value is never recorded.

See [Provider Credentials](/concepts/providers/#provider-credentials) for the
full configuration and resolution rules.

## Azure Key Vault

Azure Key Vault joins the provider list with the `akv://` scheme:

```bash
# Use service-principal credentials, or the current Azure CLI session
secretspec run --provider akv://myvault -- npm start

# Use the platform's managed identity
secretspec check --provider akv://myvault?auth=managed_identity

# Use AKS workload identity federation
secretspec run --provider akv://myvault?auth=workload_identity -- ./deploy
```

The default authentication mode first looks for the `tenant_id`, `client_id`,
and `client_secret` provider credentials introduced above, then their
`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET` environment
fallbacks. If none are present, it uses the signed-in Azure CLI or Azure
Developer CLI session. A partial service principal is an error, rather than a
reason to silently switch identities.

That makes a service principal straightforward to keep in the system keyring:

```toml title="secretspec.toml"
[providers.azure]
uri = "akv://myvault"

[providers.azure.credentials]
tenant_id = "keyring"
client_id = "keyring"
client_secret = "keyring"
```

```bash
secretspec config provider login azure
secretspec run --provider azure -- ./deploy
```

Sovereign clouds can use either a complete vault hostname or an explicit DNS
suffix such as `akv://myvault?suffix=vault.azure.cn`.

Azure restricts secret names to letters, digits, and hyphens and compares them
case-insensitively. SecretSpec encodes the project, profile, and key as
lowercase, unpadded Base32 components. The encoding keeps names that differ by
case or punctuation distinct instead of letting Azure collapse them onto the
same secret. Existing Azure secrets can be addressed with a read-only `ref`.

See the [Azure Key Vault provider guide](/providers/akv/) for authentication,
naming, references, and required permissions.

## Gopass joins the local providers

The new [`gopass://` provider](/providers/gopass/) reads and writes through the
`gopass` CLI. Gopass builds on the Unix [`pass` provider](/providers/pass/) with
multi-user and multi-store support while keeping entries GPG-encrypted and
synchronized through git.

Once Gopass is installed and its password store is initialized, select it like
any other provider:

```bash
secretspec set DATABASE_URL --provider gopass
secretspec run --provider gopass -- npm start
```

By default, entries live under
`secretspec/{project}/{profile}/{key}`. A custom URI can change that layout,
including omitting `{project}` to share secrets between repositories:

```toml title="~/.config/secretspec/config.toml"
[defaults.providers]
shared = "gopass://secretspec/shared/{profile}/{key}"
```

An existing Gopass entry can also be addressed directly with a
[`ref`](/concepts/references/), including the mount-point prefix used by a
multi-store setup. See the [Gopass provider guide](/providers/gopass/) for
installation, shared-store configuration, references, and current limitations.

## PHP joins the SDKs

The new `cachix/secretspec` Composer package brings the shared resolver to PHP:

```bash
composer require cachix/secretspec
```

```php
<?php

use Secretspec\SecretSpec;

$resolved = SecretSpec::builder()
    ->withProfile('production')
    ->withReason('boot web app')
    ->load();

echo $resolved->secrets['DATABASE_URL']->get();
$resolved->setAsEnv();
```

It offers two native backends behind the same PHP API. The recommended native
extension embeds the resolver and works under PHP-FPM without `ffi.enable`, like
`ext-redis`. An `ext-ffi` fallback loads the shared resolver at runtime for CLI
tools and local development. Both use the same Rust core as the CLI and the
other language SDKs, so profiles, providers, fallback chains, generators,
[`as_path`](/reference/configuration/#as_path-option),
[audit reasons](/reference/configuration/#requiring-a-reason-for-secret-access),
and typed missing-secret errors behave the same way.

`setAsEnv()` updates `getenv()`, `$_ENV`, and `$_SERVER`, which lets Laravel's
`env()` helper and Symfony's `%env(...)%` processors consume resolved secrets
during application boot. See the [PHP SDK guide](/sdk/php/) for installation and
framework examples.

## AWS creation guardrails

AWS accounts often require a customer-managed KMS key or specific tags in the
same `CreateSecret` request. The
[AWS Secrets Manager provider](/providers/awssm/) now accepts both on its URI:

```toml title="secretspec.toml"
[providers]
prod = "awssm://prod@us-east-1?kms_key_id=alias/my-key&tag.team=platform&tag.env=prod"
```

`kms_key_id` and repeatable `tag.NAME=VALUE` parameters are applied only when
SecretSpec creates a secret. Updating an existing secret does not alter the key
or tags it was created with. This supports tag-on-create SCP and IAM guardrails
without turning routine secret updates into infrastructure changes.

## Export secrets for shells, tools, and CI

The new `export` command resolves every secret for the active profile without
starting another process. Its default output can be evaluated by a POSIX shell:

```bash
eval "$(secretspec export --profile production)"
```

Use `--format dotenv` to write dotenv syntax or `--format json` to pass the
resolved values to another tool:

```console
$ secretspec export --profile production --format json
{
  "DATABASE_URL": "postgresql://prod.example.com/mydb"
}
```

GitHub and Forgejo Actions can use `--format gha`. SecretSpec masks every value
in the runner log and appends it to `$GITHUB_ENV`, making the secrets available
to later steps and third-party actions:

```yaml
- name: Export secrets
  run: secretspec export --profile production --format gha
- name: Deploy
  run: ./deploy
```

Like non-interactive [`check`](/reference/cli/#check), `export` never prompts
and exits non-zero when a required secret is missing, so it can gate a CI job.
Export attempts are also recorded in the
[audit log](/concepts/audit/). See the
[`export` CLI reference](/reference/cli/#export) for every format and option.

## Provider and resolution fixes

0.15 also tightens the behavior around profiles and fallback chains:

- [Provider chains](/concepts/providers/#how-secretspec-selects-a-provider) are
  now walked strictly in order and resolved lazily. An
  undefined alias or unreachable fallback is skipped with a warning only when a
  read reaches it, so a later working provider can still answer.
- Chain entries accept aliases, bare provider names such as
  [`keyring`](/providers/keyring/), shorthand such as
  [`dotenv:.env`](/providers/dotenv/), and complete provider URIs.
- A single destination provider rejects unsupported
  [`ref` coordinates](/concepts/references/) before contacting the store.
  Multi-provider chains still validate each destination as they reach it,
  because an earlier store may support coordinates a later one does not.
- [Profile overrides](/concepts/profiles/) inherit the base secret's
  `description` and generation `type`. Validation now uses the effective merged
  secret while still catching real conflicts, such as combining
  [`generate`](/concepts/generation/) with a profile default.
- `run` passes non-UTF-8 environment variables through to the child untouched,
  and command output that previously depended on map order is now stable.
- Prebuilt [Node.js addons](/sdk/nodejs/) now target glibc 2.28 and statically
  include libdbus, restoring support for Amazon Linux 2023, RHEL 8/9, and
  similar distributions.

## Upgrading

```bash
cargo install secretspec
```

Existing providers retain their conventional environment authentication when
an alias does not declare credentials. Provider credentials are opt-in, and
credential dependency chains are limited to one hop.

See the [full changelog](https://github.com/cachix/secretspec/blob/main/CHANGELOG.md)
for every change and fix in this release.

Questions or feedback? Join us on [Discord](https://discord.gg/naMgvexb6q).
