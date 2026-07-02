//go:build embed_lib && linux && arm64

package secretspec

import _ "embed"

//go:embed lib/secretspec_ffi_linux_arm64.so
var embeddedLib []byte

const embeddedLibName = "libsecretspec_ffi.so"
