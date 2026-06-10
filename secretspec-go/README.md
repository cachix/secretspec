# secretspec (Go SDK)

Go bindings for [SecretSpec](https://secretspec.dev/), a declarative secrets
manager. A thin client over the `secretspec-ffi` C ABI, loaded at runtime via
[purego](https://github.com/ebitengine/purego) (dlopen, no cgo). Resolution
happens in the Rust core, so the SDK inherits every provider with no Go-side
logic.

```go
package main

import (
	"fmt"
	"log"

	secretspec "github.com/cachix/secretspec/secretspec-go"
)

func main() {
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
report, _ := secretspec.New().WithProfile("production").Report()
for _, s := range report.Secrets {
	fmt.Println(s.Name, s.Status, s.Required)
}
```

## Library discovery

The native library is found via the `SECRETSPEC_FFI_LIB` environment variable,
or a Cargo `target` directory found by searching up from the working directory.
