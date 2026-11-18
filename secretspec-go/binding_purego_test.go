//go:build !static && !pkgconfig

package secretspec

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

func TestMissingCancellationSymbolsKeepLegacyLoad(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("C fixture uses the Unix compiler driver")
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}
	for _, partial := range []bool{false, true} {
		name := "absent"
		if partial {
			name = "partial"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "legacy.c")
			library := filepath.Join(dir, libNames()[0])
			code := `#include <stdlib.h>
#include <string.h>
const char *secretspec_abi_version(void) { return "0.21"; }
void secretspec_free(char *p) { free(p); }
char *secretspec_resolve(const char *p) {
    (void)p;
    return strdup("{\"ok\":true,\"response\":{\"schema_version\":2,\"secrets\":{}}}");
}
char *secretspec_call(const char *p) { return secretspec_resolve(p); }
`
			if partial {
				code += "void *secretspec_cancel_new(void) { return NULL; }\n"
			}
			if err := os.WriteFile(source, []byte(code), 0600); err != nil {
				t.Fatal(err)
			}
			compiler := exec.Command(cc, "-shared", "-fPIC", source, "-o", library)
			if output, err := compiler.CombinedOutput(); err != nil {
				t.Fatalf("fixture compile: %v: %s", err, output)
			}
			helper := exec.Command(os.Args[0], "-test.run=^TestLegacyBindingHelper$")
			helper.Env = append(os.Environ(), "SECRETSPEC_CANCEL_BINDING_HELPER=1", "SECRETSPEC_FFI_LIB="+library)
			if output, err := helper.CombinedOutput(); err != nil {
				t.Fatalf("binding fixture: %v: %s", err, output)
			}
			if !partial {
				t.Run("pkgconfig", func(t *testing.T) {
					if _, err := exec.LookPath("pkg-config"); err != nil {
						t.Skip("pkg-config unavailable")
					}
					const header = `char *secretspec_resolve(const char *);
char *secretspec_call(const char *);
void secretspec_free(char *);
const char *secretspec_abi_version(void);
`
					const pc = `Name: libsecretspec
Description: Legacy binding fixture
Version: 0.21
Cflags: -I${pcfiledir}
Libs: -L${pcfiledir} -Wl,-rpath,${pcfiledir} -lsecretspec
`
					if err := os.WriteFile(filepath.Join(dir, "secretspec.h"), []byte(header), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, "libsecretspec.pc"), []byte(pc), 0600); err != nil {
						t.Fatal(err)
					}
					linked := exec.Command("go", "test", "-count=1", "-tags=pkgconfig", "-run=^TestLegacyBindingHelper$", ".")
					// Go's cgo build cache does not track PKG_CONFIG_PATH. Include
					// the fixture directory in the compiler flags for this build.
					linked.Env = append(os.Environ(),
						"SECRETSPEC_CANCEL_BINDING_HELPER=1",
						"CGO_ENABLED=1",
						"PKG_CONFIG_PATH="+dir,
						"CGO_CPPFLAGS="+os.Getenv("CGO_CPPFLAGS")+" "+strconv.Quote("-I"+dir),
					)
					if output, err := linked.CombinedOutput(); err != nil {
						t.Fatalf("legacy pkg-config binding: %v: %s", err, output)
					}
				})
			}
		})
	}
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
