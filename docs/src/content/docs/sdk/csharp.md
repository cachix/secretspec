---
title: C# SDK
description: Resolve SecretSpec secrets from C# and .NET
---

> **Version compatibility:** Available since SecretSpec 0.16. The 0.15.0
> NuGet package is an unsupported bootstrap artifact used to reserve the
> package ID; use version 0.16 or later for the API below.

The C# SDK (`Cachix.SecretSpec`) is a thin client over the same Rust resolver as
the CLI. Every provider, fallback chain, profile, generator, reference, and
`as_path` secret therefore works without C#-side resolution logic.

## Install (0.16+)

```bash
dotnet add package Cachix.SecretSpec
```

The package targets .NET 8 and includes native resolvers for glibc and musl
Linux x64/Arm64, macOS x64/Arm64, and Windows x64/Arm64. Windows assets
statically include the C runtime. No separate SecretSpec CLI, native library,
Visual C++ Redistributable, or system `libdbus` installation is needed.

The managed client is safe to trim and supports NativeAOT publishing. A
NativeAOT application still carries the matching SecretSpec native resolver
beside its executable; `dotnet publish` selects and copies that runtime asset
automatically.

```bash
dotnet publish -c Release -r linux-x64 --self-contained \
  -p:PublishAot=true
```

## Quick start

```csharp
using Cachix.SecretSpec;

using var resolved = SecretSpec.Builder()
    .WithProvider("keyring://")
    .WithProfile("production")
    .WithReason("boot web app")
    .Load();

Console.WriteLine($"{resolved.Provider} {resolved.Profile}");
Console.WriteLine(resolved.Secrets["DATABASE_URL"].Get());
resolved.SetAsEnv();
```

`Get()` returns the inline value, or the readable file path for an `as_path`
secret. A missing required secret throws `MissingRequiredException`; its
`Missing` property contains the secret names. Other failures throw
`SecretSpecException`, whose `Kind` property is a stable error category.

A one-shot form is also available:

```csharp
using var resolved = SecretSpec.Resolve(
    provider: "keyring://",
    profile: "production",
    reason: "boot web app");
```

## Scopes (0.17+)

Use `WithScope("api")` to resolve only a named `[scopes.api]` subset. The
selected name is available as `Resolved.Scope` and `ResolutionReport.Scope`:

```csharp
using var resolved = SecretSpec.Builder().WithScope("api").Load();
```

## ASP.NET Core

Resolve and export secrets before creating the application builder, so normal
environment-variable configuration sees them:

```csharp
using Cachix.SecretSpec;

using var secrets = SecretSpec.Builder()
    .WithProfile(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"))
    .WithReason("ASP.NET Core boot")
    .Load();

secrets.SetAsEnv();

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.Run();
```

For longer-lived services, you can instead register `resolved` in dependency
injection and read `ResolvedSecret` objects directly. Keep the result alive for
as long as consumers need any `as_path` file.

## Value-free preflight

`Report()` returns the inventory view exposed by `secretspec check --json`.
It never carries values. Missing required secrets appear with
`Status == "missing_required"` rather than throwing, so incomplete deployments
can still be inspected.

```csharp
var report = SecretSpec.Builder()
    .WithProfile("production")
    .WithReason("deployment preflight")
    .Report();

foreach (var secret in report.Secrets)
    Console.WriteLine($"{secret.Name}: {secret.Status}");
```

## Typed access

Generate an idiomatic C# model from the manifest schema:

```bash
secretspec schema |
  quicktype -s schema --top-level AppSecrets --lang csharp -o AppSecrets.cs
```

Then deserialize the SDK's flat field map:

```csharp
var typed = AppSecrets.FromJson(resolved.FieldsJson());
Console.WriteLine(typed.DatabaseURL);
```

The schema models successful resolution: required, defaulted, and generated
secrets are non-nullable, and profile-specific schemas include inherited
default-profile fields.

## Files (`as_path`)

File-shaped secrets are materialized as mode-0400 temporary files. The returned
path must remain valid after `Load()`, so the caller owns its lifetime.
`Resolved` implements `IDisposable`; use a `using` declaration or call `Close()`
to remove these files deterministically:

```csharp
using var resolved = SecretSpec.Builder().WithReason("TLS boot").Load();
var certificatePath = resolved.Secrets["TLS_CERT"].Get();
// Use the certificate before resolved is disposed.
```

## Native loading

The NuGet runtime asset is selected automatically. For local SDK development,
`SECRETSPEC_FFI_LIB` can point to a particular `libsecretspec_ffi` build. From
a SecretSpec source checkout, the SDK also searches an ancestor Cargo
`target/debug` or `target/release` directory.
