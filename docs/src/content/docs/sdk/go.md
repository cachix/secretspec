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

The native `secretspec-ffi` cdylib is resolved at runtime, in order:

1. The `SECRETSPEC_FFI_LIB` environment variable (an explicit path).
2. A library embedded at build time with `-tags embed_lib`.
3. A Cargo `target` directory found by searching up from the working directory
   (the development path).

The SDK uses [purego](https://github.com/ebitengine/purego), so the cdylib is
loaded at runtime, not linked. Either install/build `libsecretspec_ffi` and set
`SECRETSPEC_FFI_LIB`, or stage the per-platform library into `lib/` and build
with `-tags embed_lib` for a self-contained binary. The embedded library is
extracted to a per-user, owner-only cache directory at first use, and is not
distributed through the Go module proxy.
