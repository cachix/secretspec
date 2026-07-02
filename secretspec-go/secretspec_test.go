package secretspec

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

const manifest = `
[project]
name = "go-test"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "DB", required = true }
LOG_LEVEL = { description = "log", required = false, default = "info" }
SENTRY_DSN = { description = "sentry", required = false }
`

// TestMain builds the secretspec-ffi cdylib and points the SDK at it, unless
// SECRETSPEC_FFI_LIB is already set.
func TestMain(m *testing.M) {
	if err := ensureLib(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func ensureLib() error {
	if os.Getenv("SECRETSPEC_FFI_LIB") != "" {
		return nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	repo := filepath.Dir(wd) // secretspec-go lives directly under the repo root

	build := exec.Command("cargo", "build", "-p", "secretspec-ffi")
	build.Dir = repo
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return err
	}

	meta := exec.Command("cargo", "metadata", "--no-deps", "--format-version", "1")
	meta.Dir = repo
	out, err := meta.Output()
	if err != nil {
		return err
	}
	var parsed struct {
		TargetDirectory string `json:"target_directory"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return err
	}
	name := "libsecretspec_ffi.so"
	if runtime.GOOS == "darwin" {
		name = "libsecretspec_ffi.dylib"
	}
	return os.Setenv("SECRETSPEC_FFI_LIB", filepath.Join(parsed.TargetDirectory, "debug", name))
}

func writeProject(t *testing.T, dotenv string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "secretspec.toml")
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envPath, []byte(dotenv), 0o600); err != nil {
		t.Fatal(err)
	}
	return manifestPath, "dotenv://" + envPath
}

func TestABIVersion(t *testing.T) {
	version, err := ABIVersion()
	if err != nil {
		t.Fatal(err)
	}
	if version == "" {
		t.Fatal("empty ABI version")
	}
}

func TestLoadValuesAndProvenance(t *testing.T) {
	manifestPath, provider := writeProject(t, "DATABASE_URL=postgres://db\n")

	resolved, err := New().
		WithPath(manifestPath).
		WithProvider(provider).
		WithReason("go test").
		Load()
	if err != nil {
		t.Fatal(err)
	}

	if resolved.Profile != "default" {
		t.Fatalf("profile = %q", resolved.Profile)
	}
	db := resolved.Secrets["DATABASE_URL"]
	if db.Get() != "postgres://db" {
		t.Fatalf("DATABASE_URL = %q", db.Get())
	}
	if db.Source != "provider" || db.SourceProvider == nil {
		t.Fatalf("DATABASE_URL provenance: source=%q provider=%v", db.Source, db.SourceProvider)
	}

	log := resolved.Secrets["LOG_LEVEL"]
	if log.Get() != "info" || log.Source != "default" {
		t.Fatalf("LOG_LEVEL = %q source=%q", log.Get(), log.Source)
	}

	if len(resolved.MissingOptional) != 1 || resolved.MissingOptional[0] != "SENTRY_DSN" {
		t.Fatalf("missing_optional = %v", resolved.MissingOptional)
	}
	if _, ok := resolved.Secrets["SENTRY_DSN"]; ok {
		t.Fatal("missing optional should not appear in secrets")
	}
}

func TestMissingRequired(t *testing.T) {
	manifestPath, provider := writeProject(t, "") // DATABASE_URL absent

	_, err := New().WithPath(manifestPath).WithProvider(provider).WithReason("go test").Load()
	var missing *MissingRequiredError
	if !errors.As(err, &missing) {
		t.Fatalf("expected MissingRequiredError, got %v", err)
	}
	if len(missing.Missing) != 1 || missing.Missing[0] != "DATABASE_URL" {
		t.Fatalf("missing = %v", missing.Missing)
	}
}

func TestAsPath(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "secretspec.toml")
	envPath := filepath.Join(dir, ".env")
	os.WriteFile(manifestPath, []byte(`
[project]
name = "go-test"
revision = "1.0"

[profiles.default]
TLS_CERT = { description = "cert", required = true, as_path = true }
`), 0o600)
	os.WriteFile(envPath, []byte("TLS_CERT=----cert----\n"), 0o600)

	resolved, err := New().
		WithPath(manifestPath).
		WithProvider("dotenv://" + envPath).
		WithReason("go test").
		Load()
	if err != nil {
		t.Fatal(err)
	}
	// as_path materializes a 0400 temp file the caller owns; remove it so the
	// test does not leave secret-bearing files behind in the temp dir.
	defer resolved.Close()

	cert := resolved.Secrets["TLS_CERT"]
	if !cert.AsPath || cert.Value != nil {
		t.Fatalf("expected as_path with nil value, got %+v", cert)
	}
	contents, err := os.ReadFile(cert.Get())
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "----cert----" {
		t.Fatalf("cert contents = %q", contents)
	}
}

// A zero-value Builder (not constructed via New) must not panic on a nil-map
// write in the setters.
func TestZeroValueBuilderDoesNotPanic(t *testing.T) {
	var b Builder
	got := b.WithPath("x").WithProvider("env://").WithProfile("p")
	if got.req["path"] != "x" || got.req["provider"] != "env://" || got.req["profile"] != "p" {
		t.Fatalf("zero-value builder did not record fields: %+v", got.req)
	}
}

func TestInvalidManifest(t *testing.T) {
	_, err := New().
		WithPath("/definitely/does/not/exist/secretspec.toml").
		WithReason("go test").
		Load()
	var sErr *Error
	if !errors.As(err, &sErr) {
		t.Fatalf("expected *Error, got %v", err)
	}
	var missing *MissingRequiredError
	if errors.As(err, &missing) {
		t.Fatal("should not be a MissingRequiredError")
	}
}
