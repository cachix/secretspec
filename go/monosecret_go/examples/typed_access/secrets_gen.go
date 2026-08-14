package main

import "encoding/json"

// Monosecret represents the generated quicktype model used by this example.
type Monosecret struct {
	DatabaseURL string `json:"DATABASE_URL"`
}

// UnmarshalMonosecret mirrors quicktype's generated entry point.
func UnmarshalMonosecret(data []byte) (Monosecret, error) {
	var result Monosecret
	err := json.Unmarshal(data, &result)
	return result, err
}
