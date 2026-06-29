---
title: Python SDK
description: Resolve SecretSpec secrets from Python
---

The Python SDK (`secretspec`) is a thin client over the `secretspec-ffi` C ABI,
loaded via cffi. Resolution (providers, chains, profiles, generation, `as_path`)
happens in the Rust core, so the SDK inherits every provider with no Python-side
logic.

## Quick start

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

## Typed access (codegen)

Generate typed classes with `secretspec schema` plus
[quicktype](https://quicktype.io), then build them from `resolved.fields()`:

```bash
secretspec schema | quicktype -s schema --top-level SecretSpec --lang python -o secrets_gen.py
```

```python
from secrets_gen import SecretSpec as Secrets  # typed

typed = Secrets.from_dict(resolved.fields())
print(typed.database_url)  # typed str
```

## Native library

The resolver is statically linked into the extension module via cffi's API mode,
so the published `cp39-abi3` wheel is self-contained — there is no separate
`cdylib` to locate and no `SECRETSPEC_FFI_LIB` to set at runtime.
