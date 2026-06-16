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

## Cleanup

`as_path` secrets are materialized to temp files that outlive the call. Use the
result as a context manager (`with SecretSpec.builder()...load() as resolved:`)
or call `resolved.close()` when done so the secret files do not accumulate.

## Value-free report

`report()` returns the inventory/preflight view: per-secret status and
provenance, never a value. Unlike `load()`, it does not raise when a required
secret is missing — it appears as a `SecretReport` with status
`"missing_required"`.

```python
report = SecretSpec.builder().with_profile("production").report()
for s in report.secrets:
    print(s.name, s.status, s.required)
```

## Native library

The Rust resolver is statically linked into a compiled extension
(`secretspec._secretspec_cffi`) inside the installed wheel, so there is nothing
to locate at runtime and no `SECRETSPEC_FFI_LIB` to set. The prebuilt `abi3`
wheels are self-contained (`pip install secretspec`). From a source checkout the
extension is compiled on demand by the test harness, which needs a Rust
toolchain and a C compiler on `PATH`.
