---
title: Go SDK
description: Resolve Monosecret secrets from Go
---

The Go SDK (`github.com/ifiokjr/monosecret/go/monosecret_go`) is a thin client over the `monosecret_ffi` C ABI,
loaded via [purego](https://github.com/ebitengine/purego) (dlopen, no cgo).
Resolution happens in the Rust core, so the SDK inherits every provider with no
Go-side logic.

## Install

```sh
go get github.com/ifiokjr/monosecret/go/monosecret_go
```

## Quick start

```go
import monosecret "github.com/ifiokjr/monosecret/go/monosecret_go"

resolved, err := monosecret.New().
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

Generate typed structs with `monosecret schema` plus
[quicktype](https://quicktype.io), then unmarshal `resolved.FieldsJSON()`:

```bash
monosecret schema | quicktype -s schema --top-level Monosecret --lang go -o secrets_gen.go
```

```go
data, _ := resolved.FieldsJSON()
typed, _ := UnmarshalMonosecret(data) // typed, generated
fmt.Println(typed.DatabaseURL)
```

## Library discovery

The native `monosecret_ffi` cdylib is resolved at runtime, in order:

1. The `MONOSECRET_FFI_LIB` environment variable (an explicit path).
2. A library embedded at build time with `-tags monosecret_embed`.
3. A Cargo `target` directory found by searching up from the working directory
   (the development path).

The SDK uses [purego](https://github.com/ebitengine/purego), so the cdylib is
loaded at runtime, not linked. Either install/build `libmonosecret_ffi` and set
`MONOSECRET_FFI_LIB`, or stage the per-platform library into `lib/` and build
with `-tags monosecret_embed` for a self-contained binary. The embedded library is
extracted to a per-user, owner-only cache directory at first use, and is not
distributed through the Go module proxy.
