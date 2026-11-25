package main

import (
	"fmt"
	"log"

	secretspec "github.com/cachix/secretspec/secretspec-go"
)

func main() {
	resolved, err := secretspec.New().Load()
	if err != nil {
		log.Fatal(err)
	}
	defer resolved.Close()

	data, _ := resolved.FieldsJSON()
	typed, _ := UnmarshalSecretSpec(data) // typed, generated
	fmt.Println(typed.DatabaseURL)
}
