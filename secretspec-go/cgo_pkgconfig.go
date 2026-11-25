//go:build pkgconfig

package secretspec

// Every link input comes from an installed libsecretspec.pc. The install may
// contain either the static or shared library.

/*
#cgo pkg-config: libsecretspec
*/
import "C"
