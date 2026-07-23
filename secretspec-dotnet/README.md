# SecretSpec for .NET

> Supported starting with SecretSpec 0.16. A 0.15.0 package was published only
> to reserve the NuGet package ID; it is an unsupported bootstrap artifact and
> is not the C# SDK release.

`Cachix.SecretSpec` is the C# SDK for
[SecretSpec](https://secretspec.dev/), the declarative secrets manager. It is a
thin client over the shared Rust resolver, so every provider, fallback chain,
profile, generator, and `as_path` secret behaves exactly like the CLI and the
other language SDKs.

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

A missing required secret throws `MissingRequiredException`, whose `Missing`
property contains the names. Other failures throw `SecretSpecException`, with a
stable `Kind`.

## Scopes (0.17+)

Use `WithScope("api")` to resolve only a named `[scopes.api]` subset. Both
`Resolved.Scope` and `ResolutionReport.Scope` return the selected scope:

```csharp
using var resolved = SecretSpec.Builder().WithScope("api").Load();
```

## Value-free reports

`Report()` returns the same inventory/preflight view as
`secretspec check --json`. It never exposes values, and a missing required
secret is an entry with `Status == "missing_required"` rather than an exception.

```csharp
var report = SecretSpec.Builder()
    .WithProfile("production")
    .WithReason("deployment preflight")
    .Report();

foreach (var secret in report.Secrets)
    Console.WriteLine($"{secret.Name}: {secret.Status}");
```

## Typed access

Generate a C# type from the manifest, then deserialize `FieldsJson()`:

```bash
secretspec schema |
  quicktype -s schema --top-level AppSecrets --lang csharp -o AppSecrets.cs
```

```csharp
var secrets = AppSecrets.FromJson(resolved.FieldsJson());
```

## Files and cleanup

An `as_path` secret is materialized as a mode-0400 temporary file, and `Get()`
returns its path. `Resolved` implements `IDisposable`; keep the result in a
`using` declaration or call `Close()` to remove those files when finished.

## Native resolver

The NuGet package carries the resolver for glibc and musl Linux x64/Arm64,
macOS x64/Arm64, and Windows x64/Arm64. Windows builds include the C runtime,
so users do not need to install the Visual C++ Redistributable. The managed
client is trimming-safe and supports NativeAOT; the matching native resolver
remains beside the published application as a runtime asset.

```bash
dotnet publish -c Release -r linux-x64 --self-contained \
  -p:PublishAot=true
```

During local SDK development, `SECRETSPEC_FFI_LIB` can point to an explicit
`libsecretspec_ffi` build; the SDK also discovers a Cargo `target` directory
when used from a SecretSpec source checkout.
