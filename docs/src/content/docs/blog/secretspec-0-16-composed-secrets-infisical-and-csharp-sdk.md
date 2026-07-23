---
title: "SecretSpec 0.16: Composed secrets, Infisical, and C# SDK"
description: Derive secrets from other declared values, use Infisical Cloud or self-hosted, and resolve secrets natively from .NET.
date: 2026-07-18
authors:
  - domen
---

[SecretSpec 0.16](https://github.com/cachix/secretspec/releases/tag/v0.16.0 "SecretSpec 0.16 release")
ships:

- **[Composed secrets](/concepts/composed-secrets/)** — derive a read-only
  value, such as a connection string, from other secrets declared in the
  manifest.
- **[Infisical](/providers/infisical/)** — read and write secrets in Infisical
  Cloud or a self-hosted instance, with Universal Auth, access-token, and
  provider-credential authentication.
- **[C# SDK](/sdk/csharp/)** — resolve the same manifests from .NET through the
  shared native resolver, distributed as the `Cachix.SecretSpec` NuGet package.

## Composed secrets

Applications often need a connection string while secret stores work better
with its independently rotated parts. SecretSpec can now keep those parts
separate and assemble the application-facing value when it resolves the
manifest:

```toml title="secretspec.toml"
[profiles.default]
DB_USER = { description = "Database user" }
DB_PASSWORD = { description = "Database password" }
DB_HOST = { description = "Database host" }

DATABASE_URL = {
  description = "PostgreSQL connection string",
  composed = "postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}/app"
}
```

`DB_USER`, `DB_PASSWORD`, and `DB_HOST` still come from their configured
providers. `DATABASE_URL` is assembled in memory and behaves like any other
resolved secret in the CLI and SDKs. Compositions are read-only, may build on
other compositions, and are checked for missing references and cycles before
resolution.

See [Composed Secrets](/concepts/composed-secrets/) for optional values,
escaping, profile inheritance, and validation rules.

## Infisical

The new `infisical://` provider works with Infisical Cloud, its EU service, and
self-hosted instances. Point SecretSpec at an Infisical project and authenticate
with Universal Auth:

```bash
export INFISICAL_CLIENT_ID=...
export INFISICAL_CLIENT_SECRET=...

secretspec run \
  --provider "infisical://app.infisical.com/7e2f1a4c-...?env=prod" \
  -- npm start
```

Access tokens are also supported. Credentials can come from environment
variables or SecretSpec's
[provider credentials](/concepts/providers/#provider-credentials), allowing,
for example, an Infisical machine identity to be kept in the system keyring:

```toml title="secretspec.toml"
[providers.infisical]
uri = "infisical://app.infisical.com/7e2f1a4c-..."

[providers.infisical.credentials]
client_id = "keyring"
client_secret = "keyring"
```

By default, the active SecretSpec profile also names the Infisical environment.
A `production` profile therefore reads from the `production` environment,
while `?env=` can select a different one. The provider supports normal
SecretSpec reads and writes, as well as references to existing Infisical
secrets and versions.

See the [Infisical provider guide](/providers/infisical/) for self-hosting,
authentication, paths, references, and permissions.

## C# SDK

The `Cachix.SecretSpec` NuGet package brings the shared SecretSpec resolver to
.NET 8:

```bash
dotnet add package Cachix.SecretSpec
```

```csharp
using Cachix.SecretSpec;

using var resolved = SecretSpec.Builder()
    .WithProvider("keyring://")
    .WithProfile("production")
    .WithReason("boot web app")
    .Load();

Console.WriteLine(resolved.Secrets["DATABASE_URL"].Get());
resolved.SetAsEnv();
```

It uses the same resolver as the CLI and other language SDKs, so profiles,
providers, fallback chains, references, generators, audit reasons, and composed
secrets work consistently in .NET. Native resolver builds are included in the
NuGet package, with no separate SecretSpec CLI installation required.

See the [C# SDK guide](/sdk/csharp/) for supported platforms, ASP.NET Core
integration, preflight reports, error handling, and typed access.

## Upgrading

```bash
cargo install secretspec
```

All three additions are opt-in: existing manifests and provider configurations
continue to work unchanged. Add `composed` when a value should be derived,
select an `infisical://` provider to use Infisical, or install
`Cachix.SecretSpec` in a .NET application.

See the [full changelog](https://github.com/cachix/secretspec/blob/main/CHANGELOG.md)
for every change in this release.

Questions or feedback? Join us on
[Discord](https://discord.gg/naMgvexb6q).
