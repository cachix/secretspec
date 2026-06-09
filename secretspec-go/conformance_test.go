package secretspec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestConformance resolves the shared cross-language fixtures and asserts this
// SDK produces the canonical result every other SDK must also produce.
func TestConformance(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	fixtures := filepath.Join(filepath.Dir(wd), "conformance", "fixtures")

	entries, err := os.ReadDir(fixtures)
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			dir := filepath.Join(fixtures, entry.Name())

			resolved, err := New().
				WithPath(filepath.Join(dir, "secretspec.toml")).
				WithProvider("dotenv://" + filepath.Join(dir, ".env")).
				WithReason("conformance").
				Load()
			if err != nil {
				t.Fatal(err)
			}

			actual := canonical(t, resolved)

			expectedBytes, err := os.ReadFile(filepath.Join(dir, "expected.json"))
			if err != nil {
				t.Fatal(err)
			}
			var expected any
			if err := json.Unmarshal(expectedBytes, &expected); err != nil {
				t.Fatal(err)
			}

			// Round-trip actual through JSON so both sides are the same generic
			// shape (map[string]any, []any) for DeepEqual.
			actualBytes, err := json.Marshal(actual)
			if err != nil {
				t.Fatal(err)
			}
			var actualGeneric any
			if err := json.Unmarshal(actualBytes, &actualGeneric); err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(actualGeneric, expected) {
				t.Fatalf("canonical mismatch\n got: %s\nwant: %s", actualBytes, expectedBytes)
			}
		})
	}
}

func canonical(t *testing.T, resolved *Resolved) map[string]any {
	t.Helper()
	secrets := map[string]any{}
	for name, secret := range resolved.Secrets {
		var value string
		if secret.AsPath {
			contents, err := os.ReadFile(secret.Get())
			if err != nil {
				t.Fatal(err)
			}
			value = string(contents)
		} else if secret.Value != nil {
			value = *secret.Value
		}
		secrets[name] = map[string]any{
			"value":   value,
			"source":  secret.Source,
			"as_path": secret.AsPath,
		}
	}
	missingOptional := resolved.MissingOptional
	if missingOptional == nil {
		missingOptional = []string{}
	}
	return map[string]any{
		"profile":          resolved.Profile,
		"secrets":          secrets,
		"missing_required": []string{},
		"missing_optional": missingOptional,
	}
}
