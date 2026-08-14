//go:build monosecret_static && !pkgconfig

package monosecret

// Vendored header staged by scripts/stage-staticlib.sh.

/*
#cgo CFLAGS: -I${SRCDIR}/include
*/
import "C"
