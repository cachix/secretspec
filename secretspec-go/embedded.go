package secretspec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// extractEmbedded writes the build-time-embedded cdylib to a content-addressed
// file under a per-user, owner-only directory and returns its path, so purego
// can dlopen it. The per-platform `embeddedLib` and `embeddedLibName` are
// defined in the build-tagged embedded_<os>_<arch>.go files (or zeroed by
// embedded_unsupported.go).
//
// Security: the extraction directory must be one no other user can write to,
// otherwise a local attacker on a shared host could pre-create the
// predictably-named directory or swap the file between extraction and dlopen
// (a TOCTOU that yields code execution in this process). We therefore extract
// under the per-user cache directory (inside $HOME), create the leaf 0700, and
// verify it is genuinely private — owned by us, not a symlink, no group/other
// access — before trusting anything inside it.
func extractEmbedded() (string, error) {
	// A git-LFS pointer (or any non-library blob) embedded by a botched release
	// is not a loadable library; fail loudly here instead of handing pointer
	// text to dlopen and getting a cryptic "invalid ELF header".
	if isLFSPointer(embeddedLib) {
		return "", &Error{
			Kind: "load",
			Message: "embedded library is a git-LFS pointer, not a shared library; " +
				"the build embedded an unresolved LFS file — set SECRETSPEC_FFI_LIB " +
				"to a real cdylib or rebuild without git-LFS",
		}
	}

	sum := sha256.Sum256(embeddedLib)

	base, err := extractBaseDir()
	if err != nil {
		return "", err
	}
	// Content-addressed by the full digest: a different library never collides.
	dir := filepath.Join(base, "secretspec-ffi", hex.EncodeToString(sum[:]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	// MkdirAll is a no-op on a pre-existing directory regardless of its owner or
	// mode, so verify the leaf is private before writing into or reading from it.
	if err := verifyPrivateDir(dir); err != nil {
		return "", err
	}

	path := filepath.Join(dir, embeddedLibName)
	// Reuse the cached file only if its contents hash to the embedded library's
	// digest. A size-only check would reuse a truncated/corrupted file; verifying
	// the content rejects those and re-extracts the genuine bytes below. (The
	// directory is private, so the file cannot have been planted by another user.)
	if existing, err := os.ReadFile(path); err == nil && sha256.Sum256(existing) == sum {
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

// extractBaseDir returns the per-user base directory to extract under. The user
// cache directory ($XDG_CACHE_HOME or ~/.cache, %LocalAppData% on Windows) is
// inside the user's own home, so no other user can write to it — unlike the
// shared system temp dir. It is also usually not mounted `noexec`, which the
// system temp dir sometimes is. Falls back to a euid-scoped temp directory only
// when no cache dir is resolvable; `verifyPrivateDir` still guards either way.
func extractBaseDir() (string, error) {
	if cache, err := os.UserCacheDir(); err == nil && cache != "" {
		return cache, nil
	}
	tmp := os.TempDir()
	if tmp == "" {
		return "", &Error{
			Kind:    "load",
			Message: "no user cache or temp directory available to extract the embedded library",
		}
	}
	// euid-scope the fallback name so a foreign-owned squat on a shared temp dir
	// does not permanently block us; verifyPrivateDir rejects the foreign dir.
	return filepath.Join(tmp, "secretspec-"+strconv.Itoa(geteuid())), nil
}

// isLFSPointer reports whether b is a git-LFS pointer file rather than a real
// library. Pointer files are small text blobs that begin with this version line.
func isLFSPointer(b []byte) bool {
	return bytes.HasPrefix(b, []byte("version https://git-lfs.github.com/spec/"))
}

func cacheDirError(dir string, reason string) error {
	return &Error{
		Kind:    "load",
		Message: fmt.Sprintf("refusing to use library cache directory %q: %s", dir, reason),
	}
}
