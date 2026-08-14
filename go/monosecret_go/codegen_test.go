package monosecret

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

// TestCodegen drives the full pipeline: monosecret schema -> quicktype --lang go
// -> UnmarshalMonosecret(resolved.FieldsJSON()), compiling the generated code
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
	repo := filepath.Dir(filepath.Dir(wd))

	// Build + locate the monosecret CLI.
	build := exec.Command("cargo", "build", "-p", "monosecret")
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
	bin := filepath.Join(meta.TargetDirectory, "debug", "monosecret")

	dir := t.TempDir()
	manifest := filepath.Join(dir, "monosecret.toml")
	env := filepath.Join(dir, ".env")
	os.WriteFile(manifest, []byte(`
[project]
name = "go-codegen"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "Database connection URL", required = true }
DEV_SESSION_SECRET = { description = "Development-only session secret", required = false, default = "development-only-secret" }
`), 0o600)
	os.WriteFile(env, []byte("DATABASE_URL=postgres://db\n"), 0o600)

	schema := filepath.Join(dir, "schema.json")
	run(t, dir, bin, "-f", manifest, "schema", "-o", schema)

	os.MkdirAll(filepath.Join(dir, "secrets"), 0o755)
	run(t, dir, "npx", "--yes", "quicktype", "-s", "schema", schema,
		"--top-level", "Monosecret", "--lang", "go", "--package", "secrets",
		"-o", filepath.Join(dir, "secrets", "secrets.go"))

	main := `package main

import (
	"encoding/json"
	"fmt"

	monosecret "github.com/ifiokjr/monosecret/go/monosecret_go"
	"tmpcg/secrets"
)

func main() {
	r, err := monosecret.New().
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
	s, err := secrets.UnmarshalMonosecret(data)
	if err != nil {
		panic(err)
	}
	out, _ := json.Marshal(s)
	fmt.Println(string(out))
}
`
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(main), 0o600)
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(
		"module tmpcg\n\ngo 1.23\n\nrequire github.com/ifiokjr/monosecret/go/monosecret_go v0.0.0\n\nreplace github.com/ifiokjr/monosecret/go/monosecret_go => "+goSDK+"\n",
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
	if !strings.Contains(got, "postgres://db") || !strings.Contains(got, "development-only-secret") {
		t.Fatalf("unexpected generated-code output: %s", got)
	}
}

// jsonString renders s as a Go double-quoted string literal.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
