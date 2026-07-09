---
title: "SecretSpec 0.17: Scopes, secrets caching, SOPS, age, and systemd credentials"
description: Resolve only the secrets a service needs, cache remote secrets safely, and use age-encrypted files or native systemd credentials alongside new providers.
date: 2026-07-27
authors:
  - domen
---

[SecretSpec 0.17](https://github.com/cachix/secretspec/releases/tag/v0.17.0 "SecretSpec 0.17 release")
ships:

- **[Scopes](/concepts/scopes/)**: let each service or task resolve
  only its declared subset of a profile.
- **[Secrets caching](/concepts/providers/caching/)**: cache a slow fallback
  route in a local secret store with bounded freshness and explicit
  invalidation.
- **[Cross-secret validation](#cross-secret-validation)**:
  declare alternative or mutually exclusive credentials instead of marking
  every value independently required or optional.
- **[GitHub and Forgejo Actions](#github-and-forgejo-actions)**: resolve a
  profile in one workflow step and expose its secrets to the steps that follow.
- **[New providers](#new-providers)**: now with 20 providers, use
  [SOPS](/providers/sops/), [age](/providers/age/), [KeePass
  KDBX](/providers/kdbx/),
  [OpenBao](/providers/openbao/), [Scaleway Secret
  Manager](/providers/scaleway/), and [systemd
  credentials](/providers/systemd-credential/) through the same SecretSpec
  interface, with JWT/OIDC authentication for [Vault](/providers/vault/) and
  [OpenBao](/providers/openbao/).

## Scopes

A profile describes how secrets resolve for an environment. A
[scope](/concepts/scopes/) now describes which of those secrets one consumer
may receive:

```toml title="secretspec.toml"
[profiles.default]
DATABASE_URL = { description = "Database" }
API_KEY = { description = "API key" }
QUEUE_TOKEN = { description = "Queue token" }

[scopes.api]
secrets = ["DATABASE_URL", "API_KEY"]

[scopes.worker]
secrets = ["DATABASE_URL", "QUEUE_TOKEN"]
```

```bash
secretspec run --scope api -- ./api
secretspec run --scope worker -- ./worker
```

Composed secrets may still read hidden dependencies to build a visible value,
but those inputs are not exposed to the child. The same scope selection is
available to `check`, `export`, and the [SDK
builders](/sdk/overview/). Scopes minimize secret delivery; they are not an
authorization boundary when the child itself holds provider credentials.

Carrying the selected scope through resolver requests and results required a
breaking change to
[`secretspec-ffi`](https://github.com/cachix/secretspec/tree/main/secretspec-ffi).
All [SecretSpec SDKs](/sdk/overview/) have been updated for 0.17 to support
scopes, so applications should upgrade their SDK package and bundled native
resolver together.

## Secrets caching

Many cloud providers take long enough to resolve a secret that their latency
becomes part of every development command.

A single **1Password** lookup can take **roughly one second**.

SecretSpec providers implement `get_many` so a backend can resolve several
values together. Relatively few secret stores and CLIs expose a true bulk-read
operation, however, so many providers still have to perform separate lookups.

Waiting on a remote service or its CLI every time makes `check`, `run`, and
application startup feel slow, especially as a project grows.

A provider alias can now combine its authoritative fallback route with a local
cache:

```toml title="secretspec.toml"
[providers]
vault = "vault://vault.example.com:8200/secret"
local = "keyring://secretspec/cache/{project}/{profile}/{key}"

fast_vault = {
  fallback = ["vault"],
  cache = { provider = "local", max_age = "8h" }
}

[profiles.default.defaults]
providers = ["fast_vault"]
```

Fresh entries avoid contacting the remote provider. A miss or expired entry
falls through to [Vault](/providers/vault/) and refreshes the cache; writes
update the authoritative provider first and then refresh or invalidate its
cached copy. Route changes, reference changes, and writes that bypass the
cached alias also invalidate the entry.

The cache is a real copy of the secret, so SecretSpec requires a distinct store
that it can delete from and records ownership before changing an entry.
`secretspec cache clear [NAME]` forces the next read back through the
authoritative route.

[Vault](/providers/vault/) and [OpenBao](/providers/openbao/) KV v2 caches are
the only providers that handle `max_age` as server-side expiry properly.

None of SecretSpec's current local providers has strong native support for
expiry. They can remove an expired entry the next time SecretSpec sees it, but
cannot ensure the local copy disappears at its deadline if SecretSpec never
runs again.

Our planned [FactorSeal](https://github.com/domenkozar/factorseal)
provider in [Future work](#future-work) is intended to close that gap with an
explicit API for credential eviction among the other goals.

## Cross-secret validation

Profiles can now express credential alternatives directly:

```toml title="secretspec.toml"
[profiles.default]
PASSWORD = { description = "Password", required = { at_least_one = "auth" } }
ACCESS_TOKEN = { description = "Token", required = { at_least_one = "auth" } }

GITHUB_TOKEN = { description = "GitHub token", required = { exactly_one = "github_auth" } }
GITHUB_APP_KEY = { description = "GitHub App private key", required = { exactly_one = "github_auth" } }
```

The `auth` group accepts a password, an access token, or both. The
`github_auth` group requires exactly one credential and rejects configurations
that provide both the token and the app key.

## New providers

**[SOPS](/providers/sops/)** brings the encrypted-file workflow from our recent
[SOPS comparison](/blog/but-i-use-sops/) behind SecretSpec's
provider-independent CLI and SDKs. SecretSpec delegates encryption and
decryption to the installed SOPS CLI, so existing SOPS key services and
`.sops.yaml` creation rules remain in control.

The provider reads and writes YAML, JSON, dotenv, and INI files, supports a
single shared file or `{project}` / `{profile}` path templates, and can source
sensitive SOPS inputs such as age keys or cloud credentials through provider
credentials.

```toml title="secretspec.toml"
[providers]
sops = "sops://secrets/{project}/{profile}.enc.yaml"

[profiles.production.defaults]
providers = ["sops"]
```

**[age](/providers/age/)** offers a smaller encrypted-file setup. It stores a
dotenv-style secret set for one or more age recipients, including hybrid
post-quantum recipients.

**[KeePass KDBX](/providers/kdbx/)** reads KDBX 3 and 4 databases and writes
KDBX 4, with master passwords sourced from another provider rather than
embedded in the URI.

**[OpenBao](/providers/openbao/)** gets its own `openbao://` identity and
`BAO_*` configuration while sharing compatible KV, token, AppRole, and JWT
mechanics with [Vault](/providers/vault/). Both Vault and OpenBao can now
exchange a JWT for a short-lived token, including an OIDC token minted
automatically in GitHub Actions and Forgejo Actions with `id-token: write`.

**[Scaleway Secret Manager](/providers/scaleway/)** adds regional,
project-aware cloud storage and read-only references to existing secrets and
revisions.

**[systemd credentials](/providers/systemd-credential/)** is a read-only
provider that resolves values from the current service's
`$CREDENTIALS_DIRECTORY`, including credentials used to bootstrap another
provider.

## GitHub and Forgejo Actions

Alongside 0.17, the new
[`cachix/secretspec-action`](https://github.com/cachix/secretspec-action)
installs SecretSpec, resolves the selected profile, masks every value in the
runner log, and adds the secrets to the environment of later job steps:

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: cachix/secretspec-action@main
        with:
          profile: production
          scope: api
      - run: ./deploy.sh
```

A missing required secret fails the action, so the same step also checks that
the deployment environment is complete. See the [GitHub Actions
guide](/ci/github-actions/) for provider selection and tokenless
[Vault](/providers/vault/) or [OpenBao](/providers/openbao/) authentication
through the runner's OIDC identity.

## Upgrading

[SecretSpec 0.17](https://github.com/cachix/secretspec/releases/tag/v0.17.0)
also brings:

- **[Bitwarden Secrets Manager](/providers/bws/)** — now uses the separately
  installed official `bws` CLI instead of linking its SDK.
- **Non-interactive setup** — `secretspec config global init --provider ...
  --profile ...` configures defaults without prompts.
- **Windows packages** — for the Python, Ruby, and PHP SDKs.
- **Clearer status output** — plus more controlled concurrency and retry
  behavior for Vault and OpenBao.

```bash
cargo install secretspec
```

See the [full changelog](https://github.com/cachix/secretspec/blob/main/CHANGELOG.md)
for every change in this release.

## Future work

The next work brings more control to local secret access:

- **[GUI confirmation
  dialogs](https://github.com/cachix/secretspec/pull/122)** — approve or deny a
  secret request in a native prompt instead of requiring a terminal
  interaction.
- **A [Passbolt provider](https://github.com/cachix/secretspec/pull/127) (0.19+)** —
  bring Passbolt's open-source, collaboration-focused credential manager
  behind the same SecretSpec interface for cloud and self-hosted teams.
- **A [Bitwarden Password Manager
  provider](https://github.com/cachix/secretspec/pull/166)** — resolve regular
  Bitwarden vault items, separately from the Bitwarden Secrets Manager provider
  already available in SecretSpec.
- **A JVM SDK** — work is underway to bring the shared SecretSpec resolver to
  Java, Kotlin, and other JVM languages.
- **A [FactorSeal](https://github.com/domenkozar/factorseal) provider** — we
  have started work on a new Linux provider built around mandatory TPM-backed
  storage and secure defaults. FactorSeal also provides an explicit API for
  credential expiry, which is crucial for the caching work in this release:
  local copies can carry a defined eviction deadline instead of living without
  a retention policy. Still in development.

Questions or feedback? Join us on
[Discord](https://discord.gg/naMgvexb6q).
