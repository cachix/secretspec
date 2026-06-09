---
title: Go SDK
description: Resolve SecretSpec secrets from Go
---

The Go SDK (`secretspec-go`) is a thin client over the `secretspec-ffi` C ABI,
loaded via [purego](https://github.com/ebitengine/purego) (dlopen, no cgo).
Resolution happens in the Rust core, so the SDK inherits every provider with no
Go-side logic.

## Quick start

```go
import secretspec "github.com/cachix/secretspec/secretspec-go"

resolved, err := secretspec.New().
    WithProvider("keyring://").
    WithProfile("production").
    WithReason("boot web app").
    Load()
if err != nil {
    log.Fatal(err)
}

fmt.Println(resolved.Provider, resolved.Profile)
db := resolved.Secrets["DATABASE_URL"]
fmt.Println(db.Get()) // the value, or the file path for as_path secrets
resolved.SetAsEnv()   // export everything into the process environment
```

A missing required secret returns `*MissingRequiredError`; any other failure
returns `*Error` (with a stable `.Kind`).

## Typed access (codegen)

Generate typed structs with `secretspec schema` plus
[quicktype](https://quicktype.io), then unmarshal `resolved.FieldsJSON()`:

```bash
secretspec schema | quicktype -s schema --top-level SecretSpec --lang go -o secrets_gen.go
```

```go
data, _ := resolved.FieldsJSON()
typed, _ := UnmarshalSecretSpec(data) // typed, generated
fmt.Println(typed.DatabaseURL)
```

## Library discovery

The native library is found via the `SECRETSPEC_FFI_LIB` environment variable,
or a Cargo `target` directory found by searching up from the working directory.
