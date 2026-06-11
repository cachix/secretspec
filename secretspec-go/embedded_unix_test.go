//go:build unix

package secretspec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyPrivateDirAcceptsOwnerOnlyDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivateDir(dir); err != nil {
		t.Fatalf("owner-only 0700 dir should be accepted, got: %v", err)
	}
}

func TestVerifyPrivateDirRejectsGroupOrWorldAccess(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A directory other users can write to is exactly the TOCTOU/file-swap risk
	// the check exists to reject.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivateDir(dir); err == nil {
		t.Fatal("world-writable dir must be rejected")
	}
}

func TestVerifyPrivateDirRejectsSymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivateDir(link); err == nil {
		t.Fatal("a symlinked cache dir must be rejected")
	}
}

func TestIsLFSPointer(t *testing.T) {
	pointer := []byte("version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 34000000\n")
	if !isLFSPointer(pointer) {
		t.Fatal("git-LFS pointer text should be detected")
	}
	// A real ELF starts with 0x7f 'E' 'L' 'F'; never a pointer.
	if isLFSPointer([]byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0}) {
		t.Fatal("an ELF header must not be treated as an LFS pointer")
	}
	if isLFSPointer(nil) {
		t.Fatal("empty embedded lib is not an LFS pointer")
	}
}
