# monosecret (Go SDK)

Go bindings for [Monosecret](https://ifiokjr.github.io/monosecret/), a declarative secrets
manager. A thin client over the `monosecret_ffi` C ABI. Resolution happens in the
Rust core, so the SDK inherits every provider with no Go-side logic. By default
the resolver is loaded at runtime via
[purego](https://github.com/ebitengine/purego) (dlopen, no cgo), keeping `go get`
toolchain-free; `-tags monosecret_static` instead links it in statically (see below).

```go
package main

import (
	"fmt"
	"log"

	monosecret "github.com/ifiokjr/monosecret/go/monosecret_go"
)

func main() {
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
}
```

A missing required secret returns `*MissingRequiredError`; any other failure
returns `*Error` (with a stable `.Kind`).

## Cleanup

`as_path` secrets are materialized to temp files that outlive the call. Call
`resolved.Close()` (e.g. `defer resolved.Close()`) when done so the secret files
do not accumulate in the temp dir.

## Value-free report

`Report()` returns the inventory/preflight view: per-secret status and
provenance, never a value. Unlike `Load()`, it does not fail when a required
secret is missing — it appears as a `SecretReport` with `Status`
`"missing_required"`.

```go
report, _ := monosecret.New().WithProfile("production").Report()
for _, s := range report.Secrets {
	fmt.Println(s.Name, s.Status, s.Required)
}
```

## Binding the native resolver

### Default: purego (dlopen, no cgo)

The `monosecret_ffi` cdylib is resolved at runtime, in order:

1. The `MONOSECRET_FFI_LIB` environment variable (an explicit path).
2. A library embedded at build time with `-tags monosecret_embed`.
3. A Cargo `target` directory found by searching up from the working directory
   (the development path).

This keeps `go get` toolchain-free; the cdylib is loaded at runtime rather than
linked. Provide it via `MONOSECRET_FFI_LIB` / a Cargo checkout, or stage the
per-platform library into `lib/` and build `-tags monosecret_embed` (embedded via
`go:embed`, extracted to a per-user, owner-only cache directory at first use).
Neither the cdylib nor the archive is shipped through the Go module proxy (which
does not carry binary assets). Automated distribution of prebuilt native
artifacts through GitHub releases is deferred.

### `-tags monosecret_static`: cgo, statically linked

For a self-contained binary with no runtime library to locate, link the resolver
statically. This uses **cgo** (a C toolchain is required) and links
`libmonosecret_ffi.a` directly into the Go binary:

```bash
# Stage the archive + header + generated cgo LDFLAGS, then build with cgo.
bash scripts/stage-staticlib.sh
CGO_ENABLED=1 go build -tags monosecret_static ./...
```

On Linux this can be made **fully static** (no dynamic libraries at all) by
building the archive for a musl target and passing the static link flags:

```bash
MONOSECRET_FFI_TARGET=x86_64-unknown-linux-musl \
  MONOSECRET_FFI_PROFILE=release bash scripts/stage-staticlib.sh
CGO_ENABLED=1 go build -tags monosecret_static \
  -ldflags '-linkmode external -extldflags "-static"' ./...
```

macOS links the archive in but stays self-contained-except-system-frameworks (no
static libSystem). Windows stays on the default purego path. Prebuilt archive
distribution automation is deferred.
