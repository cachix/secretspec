---
title: SDK Overview
description: How the Monosecret language SDKs work
---

Monosecret ships SDKs for Rust, Dart, Python, Go, Ruby, Node.js/TypeScript, and
Haskell. Every SDK uses the same declarative `monosecret.toml` and delegates
resolution to Monosecret's Rust core through native language bindings.

## One resolver, thin clients

Resolution (providers, fallback chains, profiles, generation, `as_path`
materialization) lives in a single Rust core. Each SDK delegates to that core
rather than reimplementing provider behavior:

- **Rust** uses the library directly, with a compile-time derive macro for
  strongly typed access.
- **Dart** loads the `monosecret_ffi` C ABI as a verified build-hook code asset
  and provides `monosecret_builder` for generated typed access.
- **Ruby** (a native C extension) statically links the `monosecret_ffi` C ABI
  at build time; **Go** (purego) loads it at runtime with no cgo. Both exchange
  a small JSON request/response with the core.
- **Haskell** links the same C ABI at build time via the GHC FFI.
- **Python** uses a [pyo3](https://pyo3.rs/) native extension, and
  **Node.js/TypeScript** uses a [napi-rs](https://napi.rs/) native addon; both
  embed the same resolver directly and exchange the same JSON request/response
  shape as the C ABI.

Because resolution happens in one place, every provider, chain, profile, and
generator works the same in every language, and a new provider added to the core
is immediately available everywhere with no per-SDK change. A cross-language
conformance suite asserts that all the SDKs reduce the same inputs to the same
result.

## The runtime API

The native SDKs mirror the Rust derive crate's vocabulary: a builder that takes
a provider, profile, and an access reason, and a `load`/`resolve` that returns
the resolved secrets plus the provider and profile used. A missing required secret
is a typed error, distinct from a transport failure (which carries a stable
`kind`). Secrets exposed `as_path` come back as a readable file path.

```python
# Distribution: monosecret_py
from monosecret import Monosecret

resolved = Monosecret.builder().with_provider("keyring://").with_reason("boot").load()
print(resolved.secrets["DATABASE_URL"].get)
```

See each language's page for the idiomatic spelling: [Rust](/sdk/rust),
[Dart](/sdk/dart), [Python](/sdk/python), [Go](/sdk/go), [Ruby](/sdk/ruby),
[Node.js](/sdk/nodejs), and [Haskell](/sdk/haskell).

## Typed access

Beyond the Rust derive macro, typed accessors for the other languages are
generated from the manifest. `monosecret schema` emits a JSON Schema for the
secret shape; [quicktype](https://quicktype.io) turns it into an idiomatic type
and deserializer for any language, which you build from the SDK's `fields()`
map:

```bash
monosecret schema | quicktype -s schema --top-level Monosecret --lang <language>
```

This keeps the per-language surface tiny: the SDK only provides `fields()`, and
quicktype owns the type generation.

## Distribution

Each ecosystem packages or locates the shared resolver in its native way:

- **Dart** installs the `monosecret` package, whose build hook downloads and
  verifies the same-version C ABI library; code generation comes from
  `monosecret_builder`.
- **Python** installs the `monosecret_py` distribution (imported as
  `monosecret`) with the resolver embedded in a pyo3 `cp39-abi3` wheel.
- **Ruby** installs the `monosecret_rb` gem (required as `monosecret`), which
  statically links the `monosecret_ffi` archive into its native extension.
- **Haskell** uses the Hackage package `monosecret` and module `Monosecret`,
  statically linked to the same archive through the GHC FFI.
- **Go** imports `github.com/ifiokjr/monosecret/go/monosecret_go` and loads
  `libmonosecret_ffi` via purego by default; `monosecret_embed` and
  `monosecret_static` build tags support staged native artifacts.
- **Node.js** loads a platform-specific napi-rs addon lazily from the canonical
  `@monosecret/client` package.

Dart, Python, Ruby, Haskell, and Node package or download their native artifact.
Go can locate `libmonosecret_ffi` through `MONOSECRET_FFI_LIB` or use a staged
embedded/static artifact.
