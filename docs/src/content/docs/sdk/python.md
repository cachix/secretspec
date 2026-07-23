---
title: Python SDK
description: Resolve SecretSpec secrets from Python
---

The Python SDK (`secretspec`) is a thin client over a pyo3 extension that calls
`secretspec::resolve_json` directly. Resolution (providers, chains, profiles,
generation, `as_path`) happens in the Rust core, so the SDK inherits every
provider with no Python-side logic.

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

## Scopes (0.17+)

Use `.with_scope("api")` to resolve only a named `[scopes.api]` subset. The
selected name is available as `resolved.scope` and `report.scope`:

```python
resolved = SecretSpec.builder().with_scope("api").load()
```

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

The resolver is statically linked into a pyo3 extension (`secretspec._native`,
built from the `secretspec-py-native` crate) using pyo3's `abi3-py39` feature,
so the published `cp39-abi3` wheel is self-contained — there is no separate
`cdylib` to locate and no runtime dlopen.
