---
title: Python SDK
description: Resolve Monosecret secrets from Python
---

The Python distribution (`monosecret_py`, imported as `monosecret`) is a thin client over a pyo3 extension that calls
`monosecret::resolve_json` directly. Resolution (providers, chains, profiles,
generation, `as_path`) happens in the Rust core, so the SDK inherits every
provider with no Python-side logic.

## Install

```sh
python -m pip install monosecret_py
```

## Quick start

```python
from monosecret import Monosecret

resolved = (
    Monosecret.builder()
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
raises `MonosecretError` (with a stable `.kind`).

## Typed access (codegen)

Generate typed classes with `monosecret schema` plus
[quicktype](https://quicktype.io), then build them from `resolved.fields()`:

```bash
monosecret schema | quicktype -s schema --top-level Monosecret --lang python -o secrets_gen.py
```

```python
from secrets_gen import Monosecret as Secrets  # typed

typed = Secrets.from_dict(resolved.fields())
print(typed.database_url)  # typed str
```

## Native library

The resolver is statically linked into a pyo3 extension (`monosecret._native`,
built from the `monosecret_py_native` crate) using pyo3's `abi3-py39` feature,
so the published `cp39-abi3` wheel is self-contained — there is no separate
`cdylib` to locate and no runtime dlopen.
