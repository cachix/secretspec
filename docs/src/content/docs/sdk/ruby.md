---
title: Ruby SDK
description: Resolve SecretSpec secrets from Ruby
---

The Ruby SDK (`secretspec`) is a thin client over the `secretspec-ffi` C ABI,
statically linked into a native C extension at build time (no runtime library to
locate). Resolution happens in the Rust core, so the SDK inherits every provider
with no Ruby-side logic.

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

## Library discovery

The native library is found via the `SECRETSPEC_FFI_LIB` environment variable,
or a Cargo `target` directory found by searching up from the working directory.
