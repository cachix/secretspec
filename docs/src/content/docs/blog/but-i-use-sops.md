---
title: "But I Use SOPS"
description: SOPS encrypts files. SecretSpec gives applications a portable contract for the secrets they need.
date: 2026-07-23
authors:
  - domen
---

Whenever I show someone SecretSpec, I often hear the same response:

> But I use SOPS.

[SOPS](https://getsops.io/docs/) is good. It encrypts files so they can
live in Git without exposing their plaintext values.

But SecretSpec solves a different problem: how applications declare, find, and
consume secrets.

## How does your application use the secret?

Once you have encrypted `secrets.yaml`, how does your Python service consume
it? What about your Go worker or Node.js app?

You still need to decrypt the file, inject its values, select the right file for
each environment, validate required keys, and repeat that integration for every
language.

And if you release the project as open source, that choice does not stay yours.
With SOPS baked into the setup, everyone who runs or contributes to the project
must adopt SOPS and its key management, whatever secrets tooling they already
use.

SecretSpec starts at the other end. The project
[declares what the application needs](/concepts/declarative/) without storing
any values:

```toml title="secretspec.toml"
[project]
name = "payments"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "Postgres connection string" }
STRIPE_API_KEY = { description = "Stripe secret key" }
```

The same secret can come from a developer's
[system keyring](/providers/keyring/) or CI
[environment variables](/providers/env/), while a more sensitive production
environment resolves it from [Vault](/providers/vault/). Applications use the
same declaration through eight SDKs for [Rust](/sdk/rust/),
[Python](/sdk/python/), [Go](/sdk/go/),
[Ruby](/sdk/ruby/), [Node.js/TypeScript](/sdk/nodejs/),
[Haskell](/sdk/haskell/), [PHP](/sdk/php/), and [C#](/sdk/csharp/) without
knowing the provider.

Encrypted files also make the key workflow a project-wide requirement. Adding a
teammate means adding their key to `.sops.yaml` and re-encrypting every file;
removing one means rekeying and rotating the affected secrets, since their key
already saw the plaintext. SecretSpec leaves identity and access to the
provider: onboarding to Vault or a cloud secrets manager is granting a role,
and offboarding is revoking it.

SOPS may be enough today. As your team grows more sensitive to how secrets are
handled, you may want Vault's access policies and centralized audit trail. If
applications know about SOPS, each one needs migrating. If they know only
SecretSpec, you change the [provider configuration](/concepts/providers/); SDK
calls and secret names stay the same.

The same resolver provides [profiles](/concepts/profiles/),
[required-secret checks](/reference/configuration/#secret-variable-options),
[per-secret provider routing and fallback](/concepts/providers/#how-secretspec-selects-a-provider),
[provider-native references](/concepts/references/),
[temporary files](/reference/configuration/#as_path-option), and
[metadata-only audit logs](/concepts/audit/). You build the integration once,
not once per provider and language.

## Different layers, different jobs

SOPS protects a file. SecretSpec gives applications a provider-independent
interface. The selected provider remains responsible for storage, encryption,
identity, access control, and availability.

I wrote a fuller [SecretSpec comparison](/comparison/) showing exactly where
SecretSpec ends, where providers begin, and which responsibilities belong to
each layer.

## Where SecretSpec goes next

Because applications talk to an interface instead of a file, the interface can
grow without touching them. Three open proposals point where it is heading:

- [Project security requirements](https://github.com/cachix/secretspec/issues/188)
  would let a project declare the guarantees a provider must meet, such as
  encryption at rest or an audit trail, and reject providers that fall short.
- [Lease-aware refresh](https://github.com/cachix/secretspec/issues/11) would
  let running applications follow key rotation and short-lived credentials
  instead of restarting for a new value.
- A [native SOPS provider](https://github.com/cachix/secretspec/pull/58) would
  bring SOPS itself behind the same SDK interface, making your encrypted files
  one more place secrets can come from.

Once that provider lands, perhaps “But I use SOPS” just needs two more words:

> But I use SOPS with SecretSpec.

If encrypted files fit your workflow, keep using SOPS. Just recognize the
boundary: encryption at rest is not an application secrets interface.
