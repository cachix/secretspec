---
title: SDK Overview
description: How the SecretSpec language SDKs work
---

SecretSpec ships SDKs for Rust, Python, Go, Ruby, and Node.js/TypeScript. They
all resolve secrets from the same declarative `secretspec.toml`, and they all
behave identically, because they share one resolver.

## One resolver, thin clients

Resolution (providers, fallback chains, profiles, generation, `as_path`
materialization) lives in a single Rust core. Each SDK is a thin client over
that core rather than a reimplementation:

- **Rust** uses the library directly, with a compile-time derive macro for
  strongly-typed access.
- **Python** (cffi), **Go** (purego), and **Ruby** (Fiddle) load the
  `secretspec-ffi` C ABI and exchange a small JSON request/response with it.
- **Node.js/TypeScript** uses a [napi-rs](https://napi.rs/) native addon that
  embeds the same resolver.

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
from secretspec import SecretSpec

resolved = SecretSpec.builder().with_provider("keyring://").with_reason("boot").load()
print(resolved.secrets["DATABASE_URL"].get)
```

See each language's page for the idiomatic spelling: [Rust](/sdk/rust),
[Python](/sdk/python), [Go](/sdk/go), [Ruby](/sdk/ruby), and
[Node.js](/sdk/nodejs).

## Typed access

Beyond the Rust derive macro, typed accessors for the other languages are
generated from the manifest. `secretspec schema` emits a JSON Schema for the
secret shape; [quicktype](https://quicktype.io) turns it into an idiomatic type
and deserializer for any language, which you build from the SDK's `fields()`
map:

```bash
secretspec schema | quicktype -s schema --top-level SecretSpec --lang <language>
```

This keeps the per-language surface tiny: the SDK only provides `fields()`, and
quicktype owns the type generation.

## Distribution

The SDKs are designed to install with no native build: the C ABI library is
bundled in the Python wheel and the Ruby gem, embedded in the Go module, and
built as a napi-rs addon for Node (prebuilt per-platform npm packages are a
follow-up). The native library is otherwise discovered from the
`SECRETSPEC_FFI_LIB` environment variable or a Cargo `target` directory, which
is how it works from a source checkout.
