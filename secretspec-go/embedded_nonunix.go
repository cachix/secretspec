//go:build !unix

package secretspec

import "os"

func geteuid() int {
	if uid := os.Getuid(); uid >= 0 {
		return uid
	}
	return 0
}

// verifyPrivateDir is a no-op off unix: the per-user cache directory
// (%LocalAppData% on Windows) is already user-scoped and the POSIX ownership
// model checked on unix does not apply.
func verifyPrivateDir(string) error { return nil }
