//go:build pkgconfig

package secretspec

// Every link input comes from an installed secretspec_ffi.pc. The install may
// contain either the static or shared library.

/*
#cgo pkg-config: secretspec_ffi
*/
import "C"
