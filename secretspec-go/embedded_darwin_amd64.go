//go:build embed_lib && darwin && amd64

package secretspec

import _ "embed"

//go:embed lib/secretspec_ffi_darwin_amd64.dylib
var embeddedLib []byte

const embeddedLibName = "libsecretspec_ffi.dylib"
