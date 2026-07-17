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

## Build one value from several secrets

Applications often need a connection string while secret stores work better
with its independently rotated parts. SecretSpec can now keep those parts
separate and assemble the application-facing value only during resolution:

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
providers. `DATABASE_URL` is rendered in memory and included in `check`, `run`,
`export`, `get`, and SDK resolution like any other secret. It is never read
from or written to a provider.

Composition uses a deliberately small template language. `${UPPERCASE_NAME}`
inserts one declared secret; names must match `[A-Z][A-Z0-9_]*`, and `$$`
produces a literal dollar sign. Ordinary braces remain literal, so JSON, CSS,
and regular-expression syntax does not need brace escaping. There is no ambient
environment lookup, shell fallback syntax, command substitution, or recursive
expansion. Substitution happens once, so reference-looking text inside a secret
value remains ordinary secret bytes rather than becoming new template syntax.
Composition is still raw string concatenation: literal JSON braces are fine,
but use `secretspec export --format json` when values need JSON encoding.

SecretSpec builds and validates the dependency graph before contacting a
provider. Declaration order does not matter, compositions may depend on other
compositions, and unknown names or cycles fail while loading the manifest:

```toml title="secretspec.toml"
[profiles.default]
USER = { description = "Database user" }
PASSWORD = { description = "Database password" }
HOST = { description = "Database host" }

AUTHORITY = {
  description = "Database authority",
  composed = "${USER}:${PASSWORD}"
}
DATABASE_URL = {
  description = "Database URL",
  composed = "postgres://${AUTHORITY}@${HOST}/app"
}
```

Missing and empty values also stay distinct. An empty dependency inserts an
empty string; a missing dependency makes a required composition missing. Set
`required = false` on the composed secret to omit the result when a dependency
is unavailable. SecretSpec never silently turns a missing dependency into
empty text.

Composed secrets are read-only. `set` rejects them and `import` skips them,
because the stored values are their dependencies. A composition also cannot
declare a competing source such as `default`, `providers`, `ref`, or
`generate`. See [Composed Secrets](/concepts/composed-secrets/) for profile
inheritance, `as_path`, escaping, and the full validation rules.

## Infisical joins the provider list

The new `infisical://` provider works with Infisical Cloud, its EU service, and
self-hosted instances. It uses an Infisical project UUID and authenticates as a
machine identity through Universal Auth:

```bash
export INFISICAL_CLIENT_ID=...
export INFISICAL_CLIENT_SECRET=...

secretspec run \
  --provider "infisical://app.infisical.com/7e2f1a4c-...?env=prod" \
  -- npm start
```

A ready-made access token can instead be supplied through `INFISICAL_TOKEN`.
Both authentication forms also integrate with
[provider credentials](/concepts/providers/#provider-credentials), so the
machine identity does not have to pass through the application's environment:

```toml title="secretspec.toml"
[providers.infisical]
uri = "infisical://app.infisical.com/7e2f1a4c-..."

[providers.infisical.credentials]
client_id = "keyring"
client_secret = "keyring"
```

Run `secretspec config provider login infisical` to write those credentials to
their declared source provider. A pre-minted `token` can be sourced the same
way.

By default, the active SecretSpec profile also names the Infisical environment.
A `production` profile reads the `production` environment, while a `dev`
profile reads `dev`. If the two naming schemes do not line up, `?env=` pins the
Infisical environment. Profiles remain isolated because they still occupy
separate folders:

```text
project "myapp", profile "production", key "DATABASE_URL"
  -> environment production
     folder      /secretspec/myapp/production
     key         DATABASE_URL
```

The `?path=` option replaces the `/secretspec` prefix. Secret keys are stored
verbatim, folders are created as needed, and secrets in the same folder are
fetched together in one request. Infisical folder imports and its own secret
references are resolved with Infisical's precedence, matching its CLI.

Existing secrets can be addressed with SecretSpec's provider-independent
[`ref`](/concepts/references/) coordinates. For Infisical, `item` contains the
folder and key, and `version` can pin a revision:

```toml title="secretspec.toml"
[providers]
infisical_prod = "infisical://app.infisical.com/7e2f1a4c-...?env=prod"

[profiles.production]
DATABASE_URL = {
  description = "Postgres DSN",
  ref = { item = "/infra/shared/DB_PASSWORD" },
  providers = ["infisical_prod"]
}
API_KEY = {
  description = "Pinned API key",
  ref = { item = "/infra/API_KEY", version = "3" },
  providers = ["infisical_prod"]
}
```

Version-pinned references are read-only. For self-hosting, put the instance
host in the URI or set `INFISICAL_DOMAIN`; the legacy `INFISICAL_API_URL`
variable remains supported. See the [Infisical provider guide](/providers/infisical/)
for permissions, URI options, approval policies, and limitations.

## Resolve secrets from C# and .NET

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

The SDK is a thin P/Invoke client over the same Rust core as the CLI and the
other language SDKs. Providers, profiles, fallback chains, references,
generators, audit reasons, and composed secrets therefore behave the same way
without C#-specific resolution logic.

The NuGet package includes native resolver builds for Linux x64 and Arm64,
macOS Arm64, and Windows x64. No separate SecretSpec CLI or native-library
installation is required at runtime.

A missing required secret throws `MissingRequiredException`, with the missing
names available on the exception. Other failures use `SecretSpecException` and
a stable error kind. For deployment checks, `Report()` returns the same
value-free inventory as `secretspec check --json`; missing values appear as
statuses instead of exceptions.

`Resolved` implements `IDisposable`. Keeping it in a `using` declaration makes
the lifetime of any `as_path` temporary files explicit and removes them
deterministically:

```csharp
using var resolved = SecretSpec.Builder()
    .WithReason("TLS service boot")
    .Load();

var certificatePath = resolved.Secrets["TLS_CERT"].Get();
// Use the file before resolved is disposed.
```

The SDK can also expose a flat JSON field map for deserializing into a C# model
generated from `secretspec schema`. See the [C# SDK guide](/sdk/csharp/) for
ASP.NET Core integration, one-shot resolution, preflight reports, and typed
access.

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
