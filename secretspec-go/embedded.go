package secretspec

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
)

// extractEmbedded writes the build-time-embedded cdylib to a content-addressed
// temp file (reused across runs and processes) and returns its path, so purego
// can dlopen it. The per-platform `embeddedLib` and `embeddedLibName` are
// defined in the build-tagged embedded_<os>_<arch>.go files (or zeroed by
// embedded_unsupported.go).
func extractEmbedded() (string, error) {
	sum := sha256.Sum256(embeddedLib)
	dir := filepath.Join(os.TempDir(), "secretspec-ffi-"+hex.EncodeToString(sum[:8]))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	path := filepath.Join(dir, embeddedLibName)
	if info, err := os.Stat(path); err == nil && info.Size() == int64(len(embeddedLib)) {
		return path, nil
	}

	tmp, err := os.CreateTemp(dir, "lib-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(embeddedLib); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", err
	}

	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		// A concurrent process may have published it first.
		if _, statErr := os.Stat(path); statErr == nil {
			return path, nil
		}
		return "", err
	}
	return path, nil
}
