//go:build !static && !pkgconfig

package secretspec

import (
	"runtime"
	"testing"
)

func TestLibraryNamesPreferLibsecretspecAndRetainPre020Fallback(t *testing.T) {
	names := libNames()
	if len(names) != 2 {
		t.Fatalf("library names = %v", names)
	}
	wantCurrent := "libsecretspec.so"
	wantLegacy := "libsecretspec_ffi.so"
	if runtime.GOOS == "darwin" {
		wantCurrent = "libsecretspec.dylib"
		wantLegacy = "libsecretspec_ffi.dylib"
	} else if runtime.GOOS == "windows" {
		wantCurrent = "secretspec.dll"
		wantLegacy = "secretspec_ffi.dll"
	}
	if names[0] != wantCurrent || names[1] != wantLegacy {
		t.Fatalf("library names = %v, want [%q %q]", names, wantCurrent, wantLegacy)
	}
}
