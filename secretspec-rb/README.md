# secretspec (Ruby SDK)

Ruby bindings for [SecretSpec](https://secretspec.dev/), a declarative secrets
manager. A thin client over the `secretspec-ffi` C ABI, statically linked into a
native C extension at build time (no runtime library to locate). Resolution
happens in the Rust core, so the SDK inherits every provider with no Ruby-side
logic.

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

## Cleanup

`as_path` secrets are materialized to temp files that outlive the call. Pass a
block to `load` (which closes automatically) or call `resolved.close` when done
so the secret files do not accumulate in the temp dir.

## Value-free report

`report` returns the inventory/preflight view: per-secret status and provenance,
never a value. Unlike `load`, it does not raise when a required secret is missing
— it appears as a `SecretReport` with status `"missing_required"`.

```ruby
report = Secretspec::SecretSpec.builder.with_profile("production").report
report.secrets.each { |s| puts [s.name, s.status, s.required].join(" ") }
```

## Library discovery

The native library is found via the `SECRETSPEC_FFI_LIB` environment variable,
or a Cargo `target` directory found by searching up from the working directory.
