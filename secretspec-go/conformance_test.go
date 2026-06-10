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

// TestConformanceNoValues asserts that under no_values every SDK emits the same
// all-null fields map: a value-less secret must serialize to JSON null, not "".
func TestConformanceNoValues(t *testing.T) {
	forEachFixture(t, func(t *testing.T, dir string) {
		resolved, err := New().
			WithPath(filepath.Join(dir, "secretspec.toml")).
			WithProvider("dotenv://" + filepath.Join(dir, ".env")).
			WithReason("conformance").
			WithNoValues(true).
			Load()
		if err != nil {
			t.Fatal(err)
		}
		defer resolved.Close()

		fieldsBytes, err := resolved.FieldsJSON()
		if err != nil {
			t.Fatal(err)
		}
		assertJSONEqualsFile(t, fieldsBytes, filepath.Join(dir, "expected_no_values.json"))
	})
}

// TestConformanceReport asserts the value-free report (status + provenance,
// including whether a source_provider is present) is identical across SDKs.
func TestConformanceReport(t *testing.T) {
	forEachFixture(t, func(t *testing.T, dir string) {
		report, err := New().
			WithPath(filepath.Join(dir, "secretspec.toml")).
			WithProvider("dotenv://" + filepath.Join(dir, ".env")).
			WithReason("conformance").
			Report()
		if err != nil {
			t.Fatal(err)
		}
		actualBytes, err := json.Marshal(canonicalReport(report))
		if err != nil {
			t.Fatal(err)
		}
		assertJSONEqualsFile(t, actualBytes, filepath.Join(dir, "expected_report.json"))
	})
}

func canonicalReport(report *Report) map[string]any {
	secrets := map[string]any{}
	for _, s := range report.Secrets {
		secrets[s.Name] = map[string]any{
			"status":          s.Status,
			"required":        s.Required,
			"as_path":         s.AsPath,
			"generated":       s.Generated,
			"default_applied": s.DefaultApplied,
			// Present-or-not (not the path-dependent value) so the vector is
			// machine-independent yet still catches a dropped source_provider.
			"source_provider": s.SourceProvider != nil,
		}
	}
	return map[string]any{"profile": report.Profile, "secrets": secrets}
}

func forEachFixture(t *testing.T, fn func(*testing.T, string)) {
	t.Helper()
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
		t.Run(entry.Name(), func(t *testing.T) { fn(t, filepath.Join(fixtures, entry.Name())) })
	}
}

func assertJSONEqualsFile(t *testing.T, actual []byte, file string) {
	t.Helper()
	expectedBytes, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var expected, actualGeneric any
	if err := json.Unmarshal(expectedBytes, &expected); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(actual, &actualGeneric); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actualGeneric, expected) {
		t.Fatalf("mismatch for %s\n got: %s\nwant: %s", filepath.Base(file), actual, expectedBytes)
	}
}
