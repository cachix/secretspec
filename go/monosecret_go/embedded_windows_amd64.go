//go:build monosecret_embed && windows && amd64

package monosecret

import _ "embed"

//go:embed lib/monosecret_ffi_windows_amd64.dll
var embeddedLib []byte

const embeddedLibName = "monosecret_ffi.dll"
