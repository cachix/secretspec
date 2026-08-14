# monosecret_rb (Ruby SDK)

Ruby bindings for [Monosecret](https://monosecret.dev/), a declarative secrets
manager. A thin client over the `monosecret_ffi` C ABI, linked into a native C
extension at build time. Resolution happens in the Rust core, so the SDK
inherits every provider with no Ruby-side logic.

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

## Scopes (0.17+)

Use `.with_scope("api")` to resolve only a named `[scopes.api]` subset. Both
`resolved.scope` and `report.scope` return the selected scope:

```ruby
resolved = Monosecret::Monosecret.builder.with_scope("api").load
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
report = Monosecret.builder.with_profile("production").report
report.secrets.each { |s| puts [s.name, s.status, s.required].join(" ") }
```

## Building

The extension links the `monosecret_ffi` archive statically. In a development
checkout:

```bash
bash scripts/build-ext.sh
```

### Linking with pkg-config (0.19+)

Install one library type with [cargo-c](https://github.com/lu-zero/cargo-c):

```bash
# Use "static" (the default) or "shared"; use separate prefixes for both.
bash crates/monosecret_ffi/scripts/cinstall.sh "$PREFIX" static
```

Then use the same extension flag for either type:

```bash
PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" gem install monosecret -- --enable-pkg-config
```

The same flag works in a checkout: `bash scripts/build-ext.sh --enable-pkg-config`.
A shared install in a non-system prefix also requires `PREFIX/lib` in the
platform's runtime library search path.
