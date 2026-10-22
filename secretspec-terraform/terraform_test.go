package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests run the actual Terraform protocol and inspect saved plans/state.
// Set TF_ACC=1, SECRETSPEC_FFI_LIB and optionally TF_ACC_TERRAFORM_PATH.
func TestTerraform(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("set TF_ACC=1 to run Terraform CLI tests")
	}
	terraform := os.Getenv("TF_ACC_TERRAFORM_PATH")
	if terraform == "" {
		var err error
		terraform, err = exec.LookPath("terraform")
		if err != nil {
			t.Fatal(err)
		}
	}
	lib, err := filepath.Abs(os.Getenv("SECRETSPEC_FFI_LIB"))
	if err != nil || os.Getenv("SECRETSPEC_FFI_LIB") == "" {
		t.Fatal("set SECRETSPEC_FFI_LIB to the freshly built native library")
	}
	t.Setenv("SECRETSPEC_FFI_LIB", lib)
	for _, key := range []string{"SECRETSPEC_PROFILE", "SECRETSPEC_PROVIDER", "SECRETSPEC_SCOPE", "TF_LOG", "TF_LOG_PATH", "TF_CLI_ARGS", "TF_DATA_DIR"} {
		t.Setenv(key, "")
	}
	t.Setenv("CHECKPOINT_DISABLE", "1")
	t.Setenv("TF_IN_AUTOMATION", "1")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	binDir := t.TempDir()
	build := exec.Command("go", "build", "-o", filepath.Join(binDir, "terraform-provider-secretspec"), ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build provider: %v\n%s", err, out)
	}
	cliConfig := filepath.Join(t.TempDir(), "terraform.tfrc")
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(cliConfig, fmt.Sprintf("provider_installation {\n dev_overrides {\n  \"cachix/secretspec\" = %q\n }\n direct {}\n}\n", filepath.ToSlash(binDir)))
	t.Setenv("TF_CLI_CONFIG_FILE", cliConfig)

	for _, kind := range []string{"data", "ephemeral"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			run := func(wantSuccess bool, args ...string) []byte {
				t.Helper()
				cmd := exec.Command(terraform, args...)
				cmd.Dir = dir
				out, err := cmd.CombinedOutput()
				if (err == nil) != wantSuccess {
					t.Fatalf("terraform %v: %v\n%s", args, err, out)
				}
				return out
			}
			const token = "terraform-test-secret-7c64a2"
			const unused = "terraform-test-unused-secret-509fc3"
			store := "TOKEN=" + token + "\nUNUSED=" + unused + "\n"
			write(filepath.Join(dir, ".env"), store)
			write(filepath.Join(dir, "expected.txt"), token)
			manifest := `[project]
name = "terraform-cli-test"
revision = "1.0"
[providers]
store = "dotenv://.env"
[defaults]
providers = ["store"]
[profiles.default]
OUTSIDE_SCOPE = { description = "must not be read", as_path = true }
[profiles.production]
TOKEN = { description = "token", type = "password", generate = true }
UNUSED = { description = "returned but never referenced" }
OPTIONAL = { description = "optional", required = false }
[scopes.terraform]
secrets = ["TOKEN", "UNUSED", "OPTIONAL"]
`
			write(filepath.Join(dir, "secretspec.toml"), manifest)
			config := fmt.Sprintf(`terraform {
  required_providers {
    secretspec = { source = "cachix/secretspec" }
  }
}
%s "secretspec_secrets" "test" {
  path    = "${path.module}/secretspec.toml"
  profile = "production"
  scope   = "terraform"
  reason  = "Terraform acceptance test"
}
`, kind)
			if kind == "data" {
				config += `resource "terraform_data" "consumer" {
  input = data.secretspec_secrets.test.values["TOKEN"]
}
`
			} else {
				config += `resource "terraform_data" "consumer" {
  provisioner "local-exec" {
    command = "test \"$TOKEN\" = \"$(cat expected.txt)\""
    environment = { TOKEN = ephemeral.secretspec_secrets.test.values["TOKEN"] }
  }
}
`
			}
			write(filepath.Join(dir, "main.tf"), config)
			run(true, "validate", "-no-color")
			planOutput := run(true, "plan", "-input=false", "-no-color", "-out=plan")
			applyOutput := run(true, "apply", "-input=false", "-no-color", "plan")
			for _, output := range [][]byte{planOutput, applyOutput} {
				if bytes.Contains(output, []byte(token)) || bytes.Contains(output, []byte(unused)) {
					t.Fatal("CLI output exposed a sensitive value")
				}
			}
			for _, target := range []string{"plan", "terraform.tfstate"} {
				output := run(true, "show", "-json", target)
				var document map[string]any
				if err := json.Unmarshal(output, &document); err != nil {
					t.Fatalf("invalid Terraform JSON: %v\n%s", err, output)
				}
				if kind == "ephemeral" {
					if bytes.Contains(output, []byte(token)) || bytes.Contains(output, []byte(unused)) {
						t.Fatalf("ephemeral value persisted in %s", target)
					}
					continue
				}
				var resources []any
				appendResources := func(value any) {
					if values, ok := value.(map[string]any); ok {
						root := values["root_module"].(map[string]any)
						resources = append(resources, root["resources"].([]any)...)
					}
				}
				appendResources(document["values"])
				appendResources(document["planned_values"])
				// Plan-time data reads may be recorded in the refreshed prior state.
				if prior, ok := document["prior_state"].(map[string]any); ok {
					appendResources(prior["values"])
				}
				found := false
				for _, item := range resources {
					resource := item.(map[string]any)
					if resource["address"] != "data.secretspec_secrets.test" {
						continue
					}
					found = true
					values := resource["values"].(map[string]any)["values"].(map[string]any)
					if len(values) != 2 || values["TOKEN"] != token || values["UNUSED"] != unused {
						t.Fatal("data source must persist the entire resolved map")
					}
					if resource["sensitive_values"].(map[string]any)["values"] != true {
						t.Fatal("data source values must be sensitive")
					}
				}
				if !found {
					t.Fatalf("data source missing from %s: %s", target, output)
				}
			}
			contents, err := os.ReadFile(filepath.Join(dir, ".env"))
			if err != nil || string(contents) != store {
				t.Fatal("reading existing values changed the store")
			}

			// A profile supplied by another resource is unknown until apply.
			deferred := strings.Replace(config, `profile = "production"`, `profile = terraform_data.profile.output`, 1)
			deferred += `resource "terraform_data" "profile" {
  input = "production"
}
`
			write(filepath.Join(dir, "main.tf"), deferred)
			run(true, "plan", "-input=false", "-no-color", "-replace=terraform_data.consumer", "-out=deferred.plan")
			run(true, "apply", "-input=false", "-no-color", "deferred.plan")
			write(filepath.Join(dir, "main.tf"), config)

			write(filepath.Join(dir, ".env"), "UNUSED="+unused+"\n")
			output := run(false, "plan", "-input=false", "-no-color")
			if !strings.Contains(string(output), "may not write") {
				t.Fatalf("expected read-only error: %s", output)
			}
			contents, err = os.ReadFile(filepath.Join(dir, ".env"))
			if err != nil || string(contents) != "UNUSED="+unused+"\n" {
				t.Fatal("generation refusal changed the store")
			}

			write(filepath.Join(dir, "secretspec.toml"), strings.Replace(manifest, "generate = true", "generate = true, as_path = true", 1))
			output = run(false, "plan", "-input=false", "-no-color")
			if !strings.Contains(string(output), "as_path") {
				t.Fatalf("expected as_path refusal: %s", output)
			}
		})
	}
}
