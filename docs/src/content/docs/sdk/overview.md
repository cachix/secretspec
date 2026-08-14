---
title: SDK Overview
description: How the Monosecret language SDKs work
---

Monosecret includes SDK source for Rust, Dart, Python, Go, Ruby,
Node.js/TypeScript, Haskell, PHP, C# (0.2+), and Swift (0.2+). PHP, C#, and
Swift registry/binary publication is deferred; their package commands document
planned 0.2+ usage. They all resolve secrets from the same
declarative `monosecret.toml`, and they all behave identically, because they
share one resolver.

> **C# compatibility:** Planned for Monosecret 0.2+; package publication is deferred.

## One resolver, thin clients

Resolution (providers, fallback chains, profiles, generation, `as_path`
materialization) lives in a single Rust core. Each SDK is a thin client over
that core rather than a reimplementation:

- **Rust** uses the library directly, with a compile-time derive macro for
  strongly-typed access.
- **Dart** loads the C ABI through native assets and supports generated typed
  access with `monosecret_builder`.
- **Ruby** (a native C extension) statically links the `monosecret_ffi` C ABI
  at build time; **Go** (purego) loads it at runtime with no cgo. Both exchange
  a small JSON request/response with the core.
- **Haskell** links the same C ABI at build time via the GHC FFI.
- **C# (0.2+)** loads the same C ABI with P/Invoke from a runtime-specific
  native asset in the NuGet package.
- **Swift (0.2+)** imports the same C ABI as a Clang module from a macOS
  XCFramework and maps the shared JSON envelope to `Codable` value types.
- **Python** uses a [pyo3](https://pyo3.rs/) native extension, and
  **Node.js/TypeScript** uses a [napi-rs](https://napi.rs/) native addon; both
  embed the same resolver directly and exchange the same JSON request/response
  shape as the C ABI.
- **PHP** prefers an [ext-php-rs](https://github.com/davidcole1340/ext-php-rs)
  extension that embeds the resolver (working under FPM with no `ffi.enable`),
  and falls back to loading the same C ABI at runtime through `ext-ffi`.

Because resolution happens in one place, every provider, chain, profile, and
generator works the same in every language, and a new provider added to the core
is immediately available everywhere with no per-SDK change. A cross-language
conformance suite asserts that all the SDKs reduce the same inputs to the same
result.

## The runtime API

Each SDK mirrors the Rust derive crate's vocabulary: a builder that takes a
provider, profile, and an access reason, and a `load`/`resolve` that returns the
resolved secrets plus the provider and profile used. A missing required secret
is a typed error, distinct from a transport failure (which carries a stable
`kind`). Secrets exposed `as_path` come back as a readable file path.

```python
from monosecret import Monosecret

resolved = Monosecret.builder().with_provider("keyring://").with_reason("boot").load()
print(resolved.secrets["DATABASE_URL"].get)
```

See each language's page for the idiomatic spelling: [Rust](/sdk/rust),
[Dart](/sdk/dart), [Python](/sdk/python), [Go](/sdk/go), [Ruby](/sdk/ruby),
[Node.js](/sdk/nodejs), [Haskell](/sdk/haskell), [PHP](/sdk/php),
[C# (0.2+)](/sdk/csharp), and [Swift (0.2+)](/sdk/swift).

Every builder also takes a [scope (0.2+)](/concepts/scopes/),
resolving only a named subset of the profile and returning the selected name on
the result. The one exception is Rust's typed loader, which always resolves the
full profile because a generated struct has a field per declared secret; see
[Rust](/sdk/rust#scopes-017).

## Typed access

Beyond the Rust derive macro, typed accessors for the other languages are
generated from the manifest. `monosecret schema` emits a JSON Schema for the
secret shape; [quicktype](https://quicktype.io) turns it into an idiomatic type
and deserializer for any language, which you build from the SDK's `fields()`
map:

```bash
$ monosecret schema | quicktype -s schema --top-level Monosecret --lang <language>
```

This keeps the per-language surface tiny: the SDK only provides `fields()`, and
quicktype owns the type generation.

The schema models successful resolution: required, defaulted, and generated
secrets are non-nullable. A profile schema includes fields inherited from the
`default` profile and is exhaustive.

## Distribution

The resolver ships inside each package, so there is nothing extra to install and
no runtime library path to set:

- **Dart** downloads a checksummed native library through its build hook and
  bundles it as a code asset.
- **Python** builds the resolver into a pyo3 extension shipped as a `cp39-abi3`
  wheel, and **Ruby** statically links the `monosecret_ffi` archive into a
  native C extension in the gem.
- **Haskell** statically links the same archive at build time via the GHC FFI.
- **C# (0.2+)** ships the `cdylib` as runtime-specific native assets in one
  NuGet package and loads the matching asset through P/Invoke. The managed
  client supports trimming and NativeAOT; glibc/musl Linux, Intel/Arm macOS,
  and x64/Arm64 Windows assets are included.
- **Swift (0.2+)** ships Intel and Apple-silicon macOS cdylibs in one
  checksummed XCFramework binary target. SwiftPM selects and embeds the matching
  architecture.
- **Go** embeds the `cdylib` in the module and loads it at runtime via purego
  (no cgo); an opt-in `-tags static` build links it statically instead.
- **Node.js** builds the resolver into a napi-rs addon.
- **PHP** ships as a normal PHP extension (provisioned like `ext-redis`), with an
  `ext-ffi` fallback that dlopens the bundled `cdylib`.

Because the resolver is linked or embedded directly, the SDKs do not depend on a
separately installed `cdylib` or an `LD_LIBRARY_PATH`/`MONOSECRET_FFI_LIB`
override at runtime — the one exception being PHP's optional `ext-ffi` fallback,
where `MONOSECRET_FFI_LIB` can point at a specific library build.

## Platform support

Prebuilt packages cover the following platforms. Windows support for the
Python wheel, the Ruby gem, and the PHP extension binaries is added in
Monosecret 0.2.

| SDK                 | Linux x64 | Linux arm64 | macOS Intel | macOS Apple silicon | Windows x64 | Windows arm64 |
| ------------------- | --------- | ----------- | ----------- | ------------------- | ----------- | ------------- |
| Rust (source crate) | ✓         | ✓           | ✓           | ✓                   | ✓           | ✓             |
| Dart                | ✓         | ✓           | ✓           | ✓                   | ✓           | ✓             |
| Python              | ✓         | ✓           | —           | ✓                   | ✓ (0.2+)    | —             |
| Node.js             | ✓         | ✓           | —           | ✓                   | ✓           | —             |
| Go                  | ✓         | ✓           | —           | ✓                   | ✓           | —             |
| Ruby                | ✓         | ✓           | —           | ✓                   | ✓ (0.2+)    | —             |
| C#                  | ✓         | ✓           | ✓           | ✓                   | ✓           | ✓             |
| Swift (0.2+)        | —         | —           | ✓           | ✓                   | —           | —             |
| PHP                 | ✓         | ✓           | —           | ✓                   | ✓ (0.2+)    | —             |
| Haskell (source)    | ✓         | —           | —           | —                   | ✓ (0.2+)    | —             |

Most Linux packages build against a manylinux_2_28 baseline (glibc 2.28 or
newer); the C# package additionally ships musl Linux assets. Hackage
distributes the Haskell SDK as source, so its row records the platforms CI
builds and tests. Contributors: the [SDK development](/development/sdks) page
documents how these artifacts are built and how to add a platform.
