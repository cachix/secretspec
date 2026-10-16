package provider

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	secretspec "github.com/cachix/secretspec/secretspec-go"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestValuesAreSensitive(t *testing.T) {
	var data datasource.SchemaResponse
	(&secretsDataSource{}).Schema(context.Background(), datasource.SchemaRequest{}, &data)
	if !data.Schema.Attributes["values"].IsSensitive() {
		t.Fatal("data source values must be sensitive")
	}
	var temporary ephemeral.SchemaResponse
	(&secretsEphemeralResource{}).Schema(context.Background(), ephemeral.SchemaRequest{}, &temporary)
	if !temporary.Schema.Attributes["values"].IsSensitive() {
		t.Fatal("ephemeral values must be sensitive")
	}
}

func TestResolveReadOnly(t *testing.T) {
	for _, key := range []string{"SECRETSPEC_PROFILE", "SECRETSPEC_PROVIDER", "SECRETSPEC_SCOPE"} {
		t.Setenv(key, "")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	dir := t.TempDir()
	manifest := `[project]
name = "terraform-test"
revision = "1.0"
[providers]
store = "dotenv://.env"
[defaults]
providers = ["store"]
[profiles.default]
TOKEN = { description = "token", type = "password", generate = true }
OPTIONAL = { description = "optional", required = false }
`
	for name, contents := range map[string]string{"secretspec.toml": manifest, ".env": "TOKEN=stored-token\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	model := secretsModel{Path: types.StringValue(filepath.Join(dir, "secretspec.toml")), Reason: types.StringValue("test")}
	if diags := model.resolve(context.Background(), "test"); diags.HasError() {
		t.Fatal(diags)
	}
	if len(model.Values.Elements()) != 1 || !model.Values.Elements()["TOKEN"].Equal(types.StringValue("stored-token")) {
		t.Fatal("expected stored value and omitted optional value")
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("# unchanged\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if diags := model.resolve(context.Background(), "test"); !diags.HasError() {
		t.Fatal("expected generation to be refused")
	}
	contents, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil || string(contents) != "# unchanged\n" {
		t.Fatalf("store changed: %q, %v", contents, err)
	}
}

func TestResolutionErrorDoesNotExposeProviderValues(t *testing.T) {
	for _, err := range []error{
		&secretspec.Error{Kind: "provider", Message: "failed to parse secret-value"},
		&secretspec.Error{Kind: "invalid_request", Message: "secret-value"},
		errors.New("secret-value"),
	} {
		if strings.Contains(resolutionError(err), "secret-value") {
			t.Fatal("diagnostic exposed a value from an underlying error")
		}
	}
}
