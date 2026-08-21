//go:build !static && !pkgconfig

package secretspec

import (
	"runtime"
	"testing"
)

func TestLibraryNamesPreferLibsecretspecAndRetainPre020Fallback(t *testing.T) {
	names := libNames()
	want := []string{"libsecretspec.so", "libsecretspec_ffi.so"}
	switch runtime.GOOS {
	case "darwin":
		want = []string{"libsecretspec.dylib", "libsecretspec_ffi.dylib"}
	case "windows":
		// Windows carries a third name: cargo emits secretspec.dll into
		// target/, while the shipped artifact is libsecretspec.dll, so a
		// developer running against a build directory still resolves.
		want = []string{"libsecretspec.dll", "secretspec.dll", "secretspec_ffi.dll"}
	}
	if len(names) != len(want) {
		t.Fatalf("library names = %v, want %v", names, want)
	}
	for i, name := range want {
		if names[i] != name {
			t.Fatalf("library names = %v, want %v", names, want)
		}
	}
}
