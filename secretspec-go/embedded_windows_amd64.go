//go:build embed_lib && windows && amd64

package secretspec

import _ "embed"

//go:embed lib/secretspec_windows_amd64.dll
var embeddedLib []byte

const embeddedLibName = "libsecretspec.dll"
