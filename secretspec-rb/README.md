# secretspec (Ruby SDK)

Ruby bindings for [SecretSpec](https://secretspec.dev/), a declarative secrets
manager. A thin client over the `secretspec-ffi` C ABI, linked into a native C
extension at build time. Resolution happens in the Rust core, so the SDK
inherits every provider with no Ruby-side logic.

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

Use `.with_scope("api")` to resolve only a named `[scopes.api]` subset. Both
`resolved.scope` and `report.scope` return the selected scope:

```ruby
resolved = Secretspec::SecretSpec.builder.with_scope("api").load
```

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

## Building

The extension links the `secretspec-ffi` archive statically. In a development
checkout:

```bash
bash scripts/build-ext.sh
```

### pkg-config (0.19+)

Install the library with [cargo-c](https://github.com/lu-zero/cargo-c) and pass
`--enable-pkg-config` to the build:

```bash
bash secretspec-ffi/scripts/cinstall.sh "$PREFIX"
PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" gem install secretspec -- --enable-pkg-config
```

The same flag works in a checkout: `bash scripts/build-ext.sh --enable-pkg-config`.

### Dynamic linking (0.19+)

Drop `--library-type staticlib` from the install and the extension links the
shared library instead.
