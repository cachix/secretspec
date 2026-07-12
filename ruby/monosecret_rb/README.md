# monosecret_rb (Ruby SDK)

The `monosecret_rb` gem (required as `monosecret`) provides Ruby bindings for [Monosecret](https://ifiokjr.github.io/monosecret/), a declarative secrets
manager. A thin client over the `monosecret_ffi` C ABI, statically linked into a
native C extension at build time (no runtime library to locate). Resolution
happens in the Rust core, so the SDK inherits every provider with no Ruby-side
logic.

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

## Cleanup

`as_path` secrets are materialized to temp files that outlive the call. Pass a
block to `load` (which closes automatically) or call `resolved.close` when done
so the secret files do not accumulate in the temp dir.

## Value-free report

`report` returns the inventory/preflight view: per-secret status and provenance,
never a value. Unlike `load`, it does not raise when a required secret is missing
— it appears as a `SecretReport` with status `"missing_required"`.

```ruby
report = Monosecret.builder.with_profile("production").report
report.secrets.each { |s| puts [s.name, s.status, s.required].join(" ") }
```

## Native extension

The resolver is statically linked into the gem's native C extension for local
source builds. Future platform gems will be self-contained: requiring
`monosecret` will not load a separate `cdylib`, and `MONOSECRET_FFI_LIB` will not
be used at runtime.

Platform-gem assembly, smoke installation, and publication are deferred. The
current package check validates only source-gem metadata and source inclusion;
it does not claim that the unstaged source gem is independently installable.
