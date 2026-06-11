//go:build embed_lib && !(linux && amd64) && !(linux && arm64) && !(darwin && arm64) && !(windows && amd64)

package secretspec

var embeddedLib []byte

const embeddedLibName = ""
