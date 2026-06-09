//go:build embed_lib && darwin && arm64

package secretspec

import _ "embed"

//go:embed lib/secretspec_ffi_darwin_arm64.dylib
var embeddedLib []byte

const embeddedLibName = "libsecretspec_ffi.dylib"
