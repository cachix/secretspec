//go:build unix

package secretspec

import (
	"os"
	"syscall"
)

func geteuid() int { return os.Geteuid() }

// verifyPrivateDir ensures dir is a real directory (not a symlink) owned by the
// current user with no group/other access, so no other user on the host can
// plant or swap a file inside it between extraction and dlopen.
func verifyPrivateDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		return cacheDirError(dir, "is a symlink")
	}
	if !mode.IsDir() {
		return cacheDirError(dir, "is not a directory")
	}
	if mode.Perm()&0o077 != 0 {
		return cacheDirError(dir, "is writable or readable by group or others")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return cacheDirError(dir, "ownership could not be determined")
	}
	if int(st.Uid) != os.Geteuid() {
		return cacheDirError(dir, "is owned by another user")
	}
	return nil
}
