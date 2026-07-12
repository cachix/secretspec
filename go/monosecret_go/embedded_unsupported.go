//go:build monosecret_embed && !(linux && amd64) && !(linux && arm64) && !(darwin && arm64) && !(windows && amd64)

package monosecret

var embeddedLib []byte

const embeddedLibName = ""
