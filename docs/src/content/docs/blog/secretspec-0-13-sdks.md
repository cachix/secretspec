---
title: "SecretSpec 0.13: SDKs for Python, Node.js, Go, Ruby, and Haskell"
description: Native Python, Node.js, Go, Ruby, and Haskell bindings over the same Rust resolver as the CLI.
date: 2026-07-03
authors:
  - domen
---

SecretSpec separates *what* secrets an application needs, declared in
`secretspec.toml`, from *where* the values live, a provider like your system
keyring, 1Password, or Vault. Until now, reading those resolved secrets at
runtime meant the CLI or the Rust SDK. If your service was written in Python or
Go, you shelled out to `secretspec run` or reimplemented resolution yourself.

[SecretSpec 0.13](https://github.com/cachix/secretspec/releases/tag/v0.13.0 "SecretSpec 0.13 release")
closes that gap. It ships native SDKs for five languages: Python,
Node.js / TypeScript, Go, Ruby, and Haskell. Each resolves the exact secrets your
manifest declares, through the same providers, profiles, fallback chains, and
generators as the CLI, with no per-language configuration.

## Native bindings over one resolver

Every SDK is a thin client over the same Rust core that powers the CLI. No
provider logic, profile resolution, chain fallback, `as_path` materialization, or
secret generation lives in the binding. A provider added to SecretSpec works in
every language the day it lands, and every SDK behaves identically.

The binding strategy is chosen per ecosystem:

- **Python**: a pyo3 extension, statically linked, shipped as a self-contained
  `cp39-abi3` wheel.
- **Node.js**: a napi-rs addon with prebuilt per-platform packages.
- **Ruby**: a native C extension (mkmf) with the resolver statically linked into
  a platform gem.
- **Go**: the `secretspec-ffi` C ABI loaded at runtime via
  [purego](https://github.com/ebitengine/purego) (no cgo).
- **Haskell**: the same C ABI, linked at build time through the Haskell FFI.

## The same three steps, in your language

Each SDK mirrors the vocabulary of the Rust derive crate: a builder that takes a
provider, a profile, and an access reason, then `load()` to resolve, then a map
of secrets you can read or export into the environment.

```python
# Python
from secretspec import SecretSpec

resolved = (
    SecretSpec.builder()
    .with_provider("keyring://")
    .with_profile("production")
    .with_reason("boot web app")
    .load()
)
print(resolved.secrets["DATABASE_URL"].get)  # value, or file path for as_path
resolved.set_as_env()                         # export into os.environ
```

```js
// Node.js / TypeScript
const { SecretSpec } = require('secretspec');

const resolved = SecretSpec.builder()
  .withProvider('keyring://')
  .withProfile('production')
  .withReason('boot web app')
  .load();
console.log(resolved.secrets.DATABASE_URL.get()); // value, or as_path file path
resolved.setAsEnv();                              // export into process.env
```

```go
// Go
resolved, err := secretspec.New().
    WithProvider("keyring://").
    WithProfile("production").
    WithReason("boot web app").
    Load()
fmt.Println(resolved.Secrets["DATABASE_URL"].Get()) // value, or as_path file path
resolved.SetAsEnv()                                 // export into the environment
```

```ruby
# Ruby
resolved = Secretspec::SecretSpec.builder
                                 .with_provider("keyring://")
                                 .with_profile("production")
                                 .with_reason("boot web app")
                                 .load
puts resolved.secrets["DATABASE_URL"].get # value, or as_path file path
resolved.set_as_env!                      # export into ENV
```

```haskell
-- Haskell
resolved <-
  S.load
    ( S.builder
        & S.withProvider "keyring://"
        & S.withProfile "production"
        & S.withReason "boot web app"
    )
S.setAsEnv resolved -- export into the environment
```

Across all of them, `load()` resolves every declared secret, a missing required
secret raises a typed `MissingRequiredError`, and `as_path` secrets come back as
a readable file path with a cleanup that removes the backing temp file. The
access reason feeds the same audit log and `require_reason` policy from
[0.12](/blog/secretspec-0-12-audit-logs-and-coding-agents/), so a Go service is
as accountable as the CLI.

## Write your own binding

Under all five SDKs sits a new crate, `secretspec-ffi`: a small, versioned C ABI
for resolving secrets. If we do not ship your language yet, you can bind to it
directly. It also exposes the public Rust building blocks the SDKs share,
`Secrets::resolve()` and `Secrets::report()`, so a Rust program reaches the same
value-carrying and value-free entry points.

## Typed secrets, one schema for every language

`secretspec.toml` already knows the shape of your secrets, so 0.13 can hand that
shape to your type system. `secretspec schema` emits a JSON Schema for your
manifest, the union of all profiles or one profile with `--profile`. Pipe it
through [quicktype](https://quicktype.io) to generate idiomatic typed classes in
any language, then populate them from each SDK's `fields()` map:

```bash
secretspec schema | quicktype -s schema --top-level SecretSpec --lang python -o secrets_gen.py
```

```python
typed = Secrets.from_dict(resolved.fields())
print(typed.database_url)  # typed str
```

One schema drives every language's type system, with no hand-written emitter per
language.

## Install

```bash
pip install secretspec                              # Python
npm install secretspec                              # Node.js / TypeScript
gem install secretspec                              # Ruby
go get github.com/cachix/secretspec/secretspec-go   # Go
```

For Haskell, add `secretspec` from Hackage to your `build-depends`. The CLI and
Rust SDK upgrade as usual:

```bash
cargo install secretspec
```

See the [SDK overview](/sdk/overview/) for the per-language guides. Questions or
feedback? Join us on [Discord](https://discord.gg/naMgvexb6q).
