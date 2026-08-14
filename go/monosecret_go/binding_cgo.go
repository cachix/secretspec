//go:build monosecret_static || pkgconfig

package monosecret

// Linked binding: cgo links the Rust resolver at build time. The link inputs
// come from files staged by scripts/stage-staticlib.sh (`-tags monosecret_static`) or from
// monosecret_ffi.pc (`-tags pkgconfig`). The installed library selected by the
// latter may be static or shared.

/*
#include <stdlib.h>
#include "monosecret.h"
*/
import "C"

import "unsafe"

// ensureLoaded is a no-op: the platform linker loads the resolver.
func ensureLoaded() error { return nil }

// nativeResolve calls monosecret_resolve and returns the owned response, freeing
// both the C request copy and the returned allocation.
func nativeResolve(payload string) (string, error) {
	req := C.CString(payload)
	defer C.free(unsafe.Pointer(req))

	res := C.monosecret_resolve(req)
	if res == nil {
		return "", &Error{Kind: "ffi", Message: "monosecret_resolve returned null"}
	}
	out := C.GoString(res)
	C.monosecret_free(res)
	return out, nil
}

// nativeABIVersion returns the ABI version string (a static C string, not freed).
func nativeABIVersion() (string, error) {
	return C.GoString(C.monosecret_abi_version()), nil
}
