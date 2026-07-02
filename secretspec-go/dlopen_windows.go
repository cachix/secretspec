//go:build windows && !static

package secretspec

import "syscall"

// openLibrary loads the DLL at path and returns an opaque handle usable with
// purego.RegisterLibFunc (purego resolves symbols via GetProcAddress on
// Windows; purego.Dlopen only exists on Unix).
func openLibrary(path string) (uintptr, error) {
	handle, err := syscall.LoadLibrary(path)
	return uintptr(handle), err
}
