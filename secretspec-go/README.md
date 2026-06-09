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

## Library discovery

The native library is found via the `SECRETSPEC_FFI_LIB` environment variable,
or a Cargo `target` directory found by searching up from the working directory.
