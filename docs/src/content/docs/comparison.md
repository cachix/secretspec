---
title: Comparison
description: See how SecretSpec and its providers work together
---

SecretSpec is the application-facing layer of a secrets system. It defines what
an application needs, resolves those requirements across environments, and
delivers the resulting values through its CLI and
[provider-independent SDKs](/sdk/overview/). Providers connect that layer to
concrete value sources. Depending on the backend, they can add secure storage,
identity, access control, availability, and provider-native operations.

This separation keeps [`secretspec.toml`](/concepts/declarative/) portable. A
developer can use the system keyring, CI can supply environment variables, and
production can use Vault or a cloud secret manager without changing the
application's secret contract.

```text
secretspec.toml          SecretSpec                         Provider
what the app needs  →    resolve · check · deliver    ←    provider-backed values
                         route · audit                      source · access
```

## Division of responsibility

| Responsibility | SecretSpec | Providers augment SecretSpec with |
|---|---|---|
| Application secret contract | Declares names, descriptions, [requirements and defaults](/reference/configuration/#secret-variable-options), [generated values](/concepts/generation/), and [composed values](/concepts/composed-secrets/) | Supply provider-backed values named by that contract |
| Environments | Defines portable [profiles](/concepts/profiles/), [configuration inheritance](/concepts/inheritance/), and profile-specific requirements | Add provider-native projects, vaults, paths, or environments |
| Preflight validation | [`check`](/reference/cli/#check) validates required secrets and configuration before the application starts | Report whether a requested value exists or can be accessed |
| Provider selection | Routes each secret independently through [provider aliases and ordered fallback chains](/concepts/providers/#how-secretspec-selects-a-provider) | Supply concrete sources and destinations |
| Existing provider-native secrets | Uses [secret references](/concepts/references/) to give an existing value a stable, application-facing name | Interpret provider-specific coordinates such as vault, item, field, path, or version |
| Application delivery | Resolves secrets through the [CLI](/reference/cli/), [exports environments](/reference/cli/#export), [starts child processes](/reference/cli/#run), and [manages temporary files](/reference/configuration/#as_path-option) | Supply values through provider APIs or clients |
| Application SDKs | Offers one [provider-independent resolver](/sdk/overview/#one-resolver-thin-clients) with a shared [runtime API](/sdk/overview/#the-runtime-api) and [typed access](/sdk/overview/#typed-access) across supported programming languages | Vendor SDKs, when available, remain backend-specific; applications do not need to integrate them directly |
| Audit | Records [local, metadata-only access events](/concepts/audit/) by default, including application context and optional reason | Add centralized, provider-side access records where supported and configured |
| Encryption at rest | Delegates protection of provider-backed values to the selected provider | Protect values when the backend supports encryption; dotenv and environment providers add no at-rest encryption |
| Identity and access policy | Uses the credentials available for the selected provider, including [credentials sourced from another provider](/concepts/providers/#provider-credentials) | Enforce users, roles, service identities, policies, and sharing |
| Availability and retention | Delegates these guarantees for provider-backed values | May provide synchronization, replication, versions, backup, or retention, depending on the provider |
| Dynamic secrets and credential rotation | [Roadmap](https://github.com/cachix/secretspec/issues/11); not currently available and has no assigned target release | Provide native lifecycle features where available; use them outside SecretSpec today |

The distinction is intentional: SecretSpec provides portable application
semantics, while each provider determines how its provider-backed values are
stored, protected, and operated. Some providers, such as dotenv and environment
variables, intentionally provide fewer safeguards. SecretSpec's
[default audit log](/concepts/audit/) complements provider logs by recording the
project, profile, secret name, outcome, actor, and reason seen by the application
workflow. It is a size-bounded, best-effort local log, not a replacement for
central compliance records.

## Supported providers

| Provider | What the provider adds beneath SecretSpec |
|---|---|
| [System keyring](/providers/keyring/) | Native local credential storage through macOS Keychain, Windows Credential Manager, or Linux Secret Service |
| [Dotenv](/providers/dotenv/) | Compatibility with existing local `.env` workflows; values remain plaintext on disk |
| [Environment variables](/providers/env/) | Read-only access to values already injected by CI, containers, or the parent process |
| [Pass](/providers/pass/) | A local GPG-encrypted Unix password store |
| [Gopass (0.15+)](/providers/gopass/) | GPG-encrypted, Git-synchronized, multi-store password management |
| [Proton Pass](/providers/protonpass/) | End-to-end encrypted, synchronized password storage through Proton Pass |
| [1Password](/providers/onepassword/) | Shared vaults, user and service-account access, and 1Password's administrative controls |
| [LastPass](/providers/lastpass/) | Shared password-manager storage and LastPass access controls |
| [Google Cloud Secret Manager](/providers/gcsm/) | Google Cloud IAM, encrypted storage, secret versions, and configured Cloud Audit Logs |
| [AWS Secrets Manager](/providers/awssm/) | AWS IAM, KMS-backed storage, secret versions, and configured CloudTrail records |
| [Vault or OpenBao](/providers/vault/) | Centralized KV storage and policy-based access in a self-managed service |
| [Bitwarden Secrets Manager](/providers/bws/) | Organization and project-based machine-secret storage and access |
| [Azure Key Vault (0.15+)](/providers/akv/) | Microsoft Entra identity, encrypted storage, secret versions, and configured Azure logs |
| [Infisical (0.16+)](/providers/infisical/) | Cloud or self-hosted storage organized by projects, environments, and machine identities |

Providers can be mixed within one project. For example, an application can
read a shared credential from 1Password in the production profile, read the same
secret from the system keyring in the development profile, and accept a
deployment token from the environment in CI. A secret can also define an ordered
fallback chain, which tries the next provider when an earlier provider does not
return the value. SecretSpec keeps those storage decisions outside the
application's code.
