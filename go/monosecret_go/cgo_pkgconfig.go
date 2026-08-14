//go:build pkgconfig

package monosecret

// Every link input comes from an installed monosecret_ffi.pc. The install may
// contain either the static or shared library.

/*
#cgo pkg-config: monosecret_ffi
*/
import "C"
