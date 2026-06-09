# secretspec (Ruby SDK)

Ruby bindings for [SecretSpec](https://secretspec.dev/), a declarative secrets
manager. A thin client over the `secretspec-ffi` C ABI, loaded at runtime via
the stdlib [Fiddle](https://docs.ruby-lang.org/en/master/Fiddle.html) (dlopen,
no native gem). Resolution happens in the Rust core, so the SDK inherits every
provider with no Ruby-side logic.

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

## Library discovery

The native library is found via the `SECRETSPEC_FFI_LIB` environment variable,
or a Cargo `target` directory found by searching up from the working directory.
