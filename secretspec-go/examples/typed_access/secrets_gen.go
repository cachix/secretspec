package main

import "encoding/json"

// SecretSpec represents the generated quicktype model used by this example.
type SecretSpec struct {
	DatabaseURL string `json:"DATABASE_URL"`
}

// UnmarshalSecretSpec mirrors quicktype's generated entry point.
func UnmarshalSecretSpec(data []byte) (SecretSpec, error) {
	var result SecretSpec
	err := json.Unmarshal(data, &result)
	return result, err
}
