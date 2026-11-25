package main

import (
	"log"

	secretspec "github.com/cachix/secretspec/secretspec-go"
)

func main() {
	resolved, err := secretspec.New().WithScope("api").Load()
	if err != nil {
		log.Fatal(err)
	}
	defer resolved.Close()
}
