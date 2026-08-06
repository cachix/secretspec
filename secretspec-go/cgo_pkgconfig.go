//go:build static && pkgconfig

package secretspec

// Every link input comes from secretspec_ffi.pc (installed by
// `cargo cinstall -p secretspec-ffi --library-type staticlib`).

/*
#cgo pkg-config: secretspec_ffi
*/
import "C"
