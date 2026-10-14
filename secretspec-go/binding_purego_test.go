//go:build !static && !pkgconfig

package secretspec

import (
	"errors"
	"runtime"
	"testing"
)

func TestRestrictionsDoNotFallBackToLegacyResolver(t *testing.T) {
	if err := ensureCallLoaded(); err != nil {
		t.Fatal(err)
	}
	previousErr, previousResolve := callErr, cResolve
	t.Cleanup(func() { callErr, cResolve = previousErr, previousResolve })
	callErr = &Error{Kind: "capability", Message: "missing secretspec_call"}
	cResolve = func(string) uintptr {
		t.Fatal("restricted request used the legacy resolver")
		return 0
	}
	for _, builder := range []*Builder{New().WithReadOnly(true), New().WithNoFiles(true)} {
		_, err := builder.Load()
		if !errors.Is(err, callErr) {
			t.Fatalf("expected capability error, got %v", err)
		}
	}
	cResolve = previousResolve
	manifestPath, provider := writeProject(t, "DATABASE_URL=postgres://db\n")
	resolved, err := New().WithPath(manifestPath).WithProvider(provider).
		WithReadOnly(false).WithNoFiles(false).WithReason("compatibility test").Load()
	if err != nil {
		t.Fatalf("disabled restrictions must still work without secretspec_call: %v", err)
	}
	defer resolved.Close()
}

func TestLibraryNamesPreferLibsecretspecAndRetainPre020Fallback(t *testing.T) {
	names := libNames()
	want := []string{"libsecretspec.so", "libsecretspec_ffi.so"}
	switch runtime.GOOS {
	case "darwin":
		want = []string{"libsecretspec.dylib", "libsecretspec_ffi.dylib"}
	case "windows":
		// Cargo emits secretspec.dll into target/, while packaged assets use
		// libsecretspec.dll. The final name preserves pre-0.20 compatibility.
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
