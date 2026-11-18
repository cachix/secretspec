//go:build static || pkgconfig

package secretspec

// Linked binding: cgo links the Rust resolver at build time. The link inputs
// come from files staged by scripts/stage-staticlib.sh (`-tags static`) or from
// libsecretspec.pc (`-tags pkgconfig`). The installed library selected by the
// latter may be static or shared.

/*
#include <stdlib.h>
#include "secretspec.h"

// Older headers still support Load. These stubs let cgo compile against them.
#ifndef SECRETSPEC_HAS_CANCELLATION
#define SECRETSPEC_HAS_CANCELLATION 0
static inline void *secretspec_cancel_new(void) { return NULL; }
static inline void secretspec_cancel(const void *h) { (void)h; }
static inline void secretspec_cancel_free(void *h) { (void)h; }
static inline char *secretspec_call_with_cancel(const char *req, const void *h) {
    (void)req;
    (void)h;
    return NULL;
}
#endif
*/
import "C"

import "unsafe"

// ensureLoaded is a no-op: the platform linker loads the resolver.
func ensureLoaded() error     { return nil }
func ensureCallLoaded() error { return nil }

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

func nativeCall(payload string) (string, error) {
	req := C.CString(payload)
	defer C.free(unsafe.Pointer(req))

	res := C.secretspec_call(req)
	if res == nil {
		return "", &Error{Kind: "ffi", Message: "secretspec_call returned null"}
	}
	out := C.GoString(res)
	C.secretspec_free(res)
	return out, nil
}

func newNativeCancellation() (*nativeCancellation, error) {
	if C.SECRETSPEC_HAS_CANCELLATION == 0 {
		return nil, &Error{Kind: "capability", Message: cancellationUnavailable}
	}
	handle := C.secretspec_cancel_new()
	if handle == nil {
		return nil, &Error{Kind: "ffi", Message: "secretspec_cancel_new returned null"}
	}
	return &nativeCancellation{
		cancel: func() { C.secretspec_cancel(handle) },
		free:   func() { C.secretspec_cancel_free(handle) },
		call: func(payload string) (string, error) {
			req := C.CString(payload)
			defer C.free(unsafe.Pointer(req))
			res := C.secretspec_call_with_cancel(req, handle)
			if res == nil {
				return "", &Error{Kind: "ffi", Message: "secretspec_call_with_cancel returned null"}
			}
			defer C.secretspec_free(res)
			return C.GoString(res), nil
		},
	}, nil
}

// nativeABIVersion returns the ABI version string (a static C string, not freed).
func nativeABIVersion() (string, error) {
	return C.GoString(C.secretspec_abi_version()), nil
}
