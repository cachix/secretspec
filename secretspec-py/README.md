# secretspec (Python SDK)

Python bindings for [SecretSpec](https://secretspec.dev/), a declarative secrets
manager. This package is a thin client over the `secretspec-ffi` C ABI:
resolution (providers, chains, profiles, generation, `as_path`) happens in the
Rust core, so the SDK inherits every provider with no Python-side logic.

```python
from secretspec import SecretSpec

resolved = (
    SecretSpec.builder()
    .with_provider("keyring://")
    .with_profile("production")
    .with_reason("boot web app")
    .load()
)

print(resolved.provider, resolved.profile)
db = resolved.secrets["DATABASE_URL"]
print(db.get)              # the value, or the file path for as_path secrets
resolved.set_as_env()      # export everything into os.environ
```

A missing required secret raises `MissingRequiredError`; any other failure
raises `SecretSpecError` (with a stable `.kind`).

## Library discovery

The SDK loads the native library from, in order: the `SECRETSPEC_FFI_LIB`
environment variable, a copy bundled in the installed wheel, or a Cargo `target`
directory found by searching up from the working directory (useful in a source
checkout).
