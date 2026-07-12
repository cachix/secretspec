//go:build !monosecret_embed

package monosecret

// Built without the `monosecret_embed` tag: no embedded library, so the SDK uses
// MONOSECRET_FFI_LIB or a Cargo target directory. Release/distribution builds
// pass `-tags monosecret_embed` (with the per-platform libraries staged into lib/).
var embeddedLib []byte

const embeddedLibName = ""
