package secretspec

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func hasNpx() bool {
	return exec.Command("bash", "-lc", "command -v npx").Run() == nil
}

func run(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %v: %v", name, args, err)
	}
}

// TestCodegen drives the full pipeline: secretspec schema -> quicktype --lang go
// -> UnmarshalSecretSpec(resolved.FieldsJSON()), compiling the generated code
// against this SDK.
func TestCodegen(t *testing.T) {
	if !hasNpx() {
		t.Skip("npx (quicktype) not available")
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	goSDK := wd
	repo := filepath.Dir(wd)

	// Build + locate the secretspec CLI.
	build := exec.Command("cargo", "build", "-p", "secretspec")
	build.Dir = repo
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatal(err)
	}
	metaOut, err := func() ([]byte, error) {
		c := exec.Command("cargo", "metadata", "--no-deps", "--format-version", "1")
		c.Dir = repo
		return c.Output()
	}()
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		TargetDirectory string `json:"target_directory"`
	}
	if err := json.Unmarshal(metaOut, &meta); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(meta.TargetDirectory, "debug", "secretspec")

	dir := t.TempDir()
	manifest := filepath.Join(dir, "secretspec.toml")
	env := filepath.Join(dir, ".env")
	os.WriteFile(manifest, []byte(`
[project]
name = "go-codegen"
revision = "1.0"

[profiles.default]
DATABASE_URL = { required = true }
LOG_LEVEL = { required = false, default = "info" }
`), 0o600)
	os.WriteFile(env, []byte("DATABASE_URL=postgres://db\n"), 0o600)

	schema := filepath.Join(dir, "schema.json")
	run(t, dir, bin, "-f", manifest, "schema", "-o", schema)

	os.MkdirAll(filepath.Join(dir, "secrets"), 0o755)
	run(t, dir, "npx", "--yes", "quicktype", "-s", "schema", schema,
		"--top-level", "SecretSpec", "--lang", "go", "--package", "secrets",
		"-o", filepath.Join(dir, "secrets", "secrets.go"))

	main := `package main

import (
	"encoding/json"
	"fmt"

	secretspec "github.com/cachix/secretspec/secretspec-go"
	"tmpcg/secrets"
)

func main() {
	r, err := secretspec.New().
		WithPath(` + jsonString(manifest) + `).
		WithProvider("dotenv://" + ` + jsonString(env) + `).
		WithReason("go codegen").
		Load()
	if err != nil {
		panic(err)
	}
	data, err := r.FieldsJSON()
	if err != nil {
		panic(err)
	}
	s, err := secrets.UnmarshalSecretSpec(data)
	if err != nil {
		panic(err)
	}
	out, _ := json.Marshal(s)
	fmt.Println(string(out))
}
`
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(main), 0o600)
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(
		"module tmpcg\n\ngo 1.23\n\nrequire github.com/cachix/secretspec/secretspec-go v0.0.0\n\nreplace github.com/cachix/secretspec/secretspec-go => "+goSDK+"\n",
	), 0o600)

	run(t, dir, "go", "mod", "tidy")
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = dir
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, "postgres://db") || !strings.Contains(got, "info") {
		t.Fatalf("unexpected generated-code output: %s", got)
	}
}

// jsonString renders s as a Go double-quoted string literal.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
