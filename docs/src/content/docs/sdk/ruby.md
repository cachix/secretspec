---
title: Ruby SDK
description: Resolve Monosecret secrets from Ruby
---

The Ruby gem (`monosecret_rb`, required as `monosecret`) is a thin client over the `monosecret_ffi` C ABI,
statically linked into a native C extension at build time (no runtime library to
locate). Resolution happens in the Rust core, so the SDK inherits every provider
with no Ruby-side logic.

## Install

```sh
gem install monosecret_rb
```

## Quick start

```ruby
require "monosecret"

resolved = Monosecret.builder
                                 .with_provider("keyring://")
                                 .with_profile("production")
                                 .with_reason("boot web app")
                                 .load

puts resolved.provider, resolved.profile
db = resolved.secrets["DATABASE_URL"]
puts db.get             # the value, or the file path for as_path secrets
resolved.set_as_env!    # export everything into ENV
```

A missing required secret raises `Monosecret::MissingRequiredError`; any other
failure raises `Monosecret::Error` (with a stable `#kind`).

## Typed access (codegen)

Generate typed classes with `monosecret schema` plus
[quicktype](https://quicktype.io), then build them from `resolved.fields`:

```bash
monosecret schema | quicktype -s schema --top-level Monosecret --lang ruby -o secrets_gen.rb
```

```ruby
typed = Monosecret.from_dynamic!(resolved.fields) # typed, generated
puts typed.database_url
```

## Native library

The resolver is statically linked into a native C extension built by mkmf, so the
published platform gem is self-contained — there is no separate `cdylib` to
locate and no `MONOSECRET_FFI_LIB` to set at runtime.
