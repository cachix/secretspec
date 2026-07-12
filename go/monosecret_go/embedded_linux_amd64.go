//go:build monosecret_embed && linux && amd64

package monosecret

import _ "embed"

//go:embed lib/monosecret_ffi_linux_amd64.so
var embeddedLib []byte

const embeddedLibName = "libmonosecret_ffi.so"
