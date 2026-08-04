---
title: Ruby SDK
description: Resolve SecretSpec secrets from Ruby
---

The Ruby SDK (`secretspec`) is a thin client over the `secretspec-ffi` C ABI,
linked into a native C extension at build time. Resolution happens in the Rust
core, so the SDK inherits every provider with no Ruby-side logic.

## Quick start

```ruby
require "secretspec"

resolved = Secretspec::SecretSpec.builder
                                 .with_provider("keyring://")
                                 .with_profile("production")
                                 .with_reason("boot web app")
                                 .load

puts resolved.provider, resolved.profile
db = resolved.secrets["DATABASE_URL"]
puts db.get             # the value, or the file path for as_path secrets
resolved.set_as_env!    # export everything into ENV
```

A missing required secret raises `Secretspec::MissingRequiredError`; any other
failure raises `Secretspec::Error` (with a stable `#kind`).

## Scopes (0.17+)

Use `.with_scope("api")` to resolve only a named `[scopes.api]` subset. The
selected name is available as `resolved.scope` and `report.scope`:

```ruby
resolved = Secretspec::SecretSpec.builder.with_scope("api").load
```

## Typed access (codegen)

Generate typed classes with `secretspec schema` plus
[quicktype](https://quicktype.io), then build them from `resolved.fields`:

```bash
secretspec schema | quicktype -s schema --top-level SecretSpec --lang ruby -o secrets_gen.rb
```

```ruby
typed = SecretSpec.from_dynamic!(resolved.fields) # typed, generated
puts typed.database_url
```

## Native library

The published platform gems bundle the `secretspec-ffi` archive and statically
link it into the mkmf extension at install time.

### pkg-config (0.19+)

To build against your own `secretspec-ffi` install instead, install it with
[cargo-c](https://github.com/lu-zero/cargo-c) and pass `--enable-pkg-config`:

```bash
cargo cinstall -p secretspec-ffi --library-type staticlib --prefix "$PREFIX"
PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" gem install secretspec -- --enable-pkg-config
```

### Dynamic linking (0.19+)

Drop `--library-type staticlib` from the install and the extension links the
shared library instead.
