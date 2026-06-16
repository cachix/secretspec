//go:build static

package secretspec

// Static binding: cgo links libsecretspec_ffi.a directly into the Go binary, so
// the Rust resolver is embedded (fully static on Linux/musl with
// `-ldflags '-linkmode external -extldflags "-static"'`). The archive path and
// its transitive native deps come from the generated, per-platform
// cgo_ldflags_<os>_<arch>.go (produced by scripts/stage-staticlib.sh); the header
// is vendored under include/.

/*
#cgo CFLAGS: -I${SRCDIR}/include
#include <stdlib.h>
#include "secretspec.h"
*/
import "C"

import "unsafe"

// ensureLoaded is a no-op: the resolver is linked in, nothing to load.
func ensureLoaded() error { return nil }

// nativeResolve calls secretspec_resolve and returns the owned response, freeing
// both the C request copy and the returned allocation.
func nativeResolve(payload string) (string, error) {
	req := C.CString(payload)
	defer C.free(unsafe.Pointer(req))

	res := C.secretspec_resolve(req)
	if res == nil {
		return "", &Error{Kind: "ffi", Message: "secretspec_resolve returned null"}
	}
	out := C.GoString(res)
	C.secretspec_free(res)
	return out, nil
}

// nativeABIVersion returns the ABI version string (a static C string, not freed).
func nativeABIVersion() (string, error) {
	return C.GoString(C.secretspec_abi_version()), nil
}
