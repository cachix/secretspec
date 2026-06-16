//go:build unix && !static

package secretspec

import "github.com/ebitengine/purego"

// openLibrary loads the shared library at path and returns an opaque handle
// usable with purego.RegisterLibFunc.
func openLibrary(path string) (uintptr, error) {
	return purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
}
