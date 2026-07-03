//go:build !static

package secretspec

// Default binding: purego (dlopen, no cgo). The Rust resolver lives in a shared
// library located at runtime via SECRETSPEC_FFI_LIB, an embedded copy, or a Cargo
// target directory, so `go get` needs no native toolchain. The `-tags static`
// build (binding_cgo.go) replaces this with a statically linked archive.

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

var (
	loadOnce sync.Once
	loadErr  error
	cResolve func(string) uintptr
	cFree    func(uintptr)
	cABI     func() uintptr
)

func libNames() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{"libsecretspec_ffi.dylib"}
	case "windows":
		return []string{"secretspec_ffi.dll"}
	default:
		return []string{"libsecretspec_ffi.so"}
	}
}

func findLibrary() (string, error) {
	if p := os.Getenv("SECRETSPEC_FFI_LIB"); p != "" {
		return p, nil
	}
	// A library embedded at build time (go:embed, per platform) is extracted to
	// a temp file and used, so `go get` works with no native build.
	if len(embeddedLib) > 0 {
		return extractEmbedded()
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		// Within the nearest ancestor target/, pick the most recently built
		// library rather than always preferring release: a stale release build
		// must not shadow the debug build the developer just produced.
		var bestPath string
		var best os.FileInfo
		for _, profile := range []string{"release", "debug"} {
			for _, name := range libNames() {
				candidate := filepath.Join(dir, "target", profile, name)
				if info, err := os.Stat(candidate); err == nil {
					if best == nil || info.ModTime().After(best.ModTime()) {
						best, bestPath = info, candidate
					}
				}
			}
		}
		if bestPath != "" {
			return bestPath, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", &Error{
		Kind:    "load",
		Message: "could not locate the secretspec-ffi library; set SECRETSPEC_FFI_LIB",
	}
}

func ensureLoaded() error {
	loadOnce.Do(func() {
		// purego.RegisterLibFunc panics (it does not return an error) when a
		// symbol is missing. Recover so an incompatible library yields a returned
		// *Error instead of a panic that escapes the Once — which would otherwise
		// mark it done with loadErr nil and the function pointers nil, turning
		// every later call into a nil-pointer panic for the process lifetime.
		defer func() {
			if r := recover(); r != nil {
				loadErr = &Error{
					Kind:    "load",
					Message: fmt.Sprintf("failed to bind secretspec-ffi symbols (incompatible library?): %v", r),
				}
			}
		}()
		path, err := findLibrary()
		if err != nil {
			loadErr = err
			return
		}
		handle, err := openLibrary(path)
		if err != nil {
			loadErr = err
			return
		}
		purego.RegisterLibFunc(&cResolve, handle, "secretspec_resolve")
		purego.RegisterLibFunc(&cFree, handle, "secretspec_free")
		purego.RegisterLibFunc(&cABI, handle, "secretspec_abi_version")
	})
	return loadErr
}

// nativeResolve calls secretspec_resolve and returns the owned response, freeing
// the C allocation.
func nativeResolve(payload string) (string, error) {
	ptr := cResolve(payload)
	if ptr == 0 {
		return "", &Error{Kind: "ffi", Message: "secretspec_resolve returned null"}
	}
	raw := goString(ptr)
	cFree(ptr)
	return raw, nil
}

// nativeABIVersion returns the ABI version string (a static C string, not freed).
func nativeABIVersion() (string, error) {
	return goString(cABI()), nil
}

// goString copies a NUL-terminated C string at ptr into a Go string. The
// pointer comes from the C ABI (a Rust allocation), not Go's heap, so this is a
// legitimate FFI read; `go vet`'s unsafeptr check flags it as a false positive
// (it is not part of the `go test` vet subset).
func goString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	base := unsafe.Pointer(ptr)
	length := 0
	for *(*byte)(unsafe.Add(base, length)) != 0 {
		length++
	}
	return string(unsafe.Slice((*byte)(base), length))
}
