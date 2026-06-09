//go:build !embed_lib

package secretspec

// Built without the `embed_lib` tag: no embedded library, so the SDK uses
// SECRETSPEC_FFI_LIB or a Cargo target directory. Release/distribution builds
// pass `-tags embed_lib` (with the per-platform libraries staged into lib/).
var embeddedLib []byte

const embeddedLibName = ""
