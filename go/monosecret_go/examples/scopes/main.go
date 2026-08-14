package main

import (
	"log"

	monosecret "github.com/ifiokjr/monosecret/go/monosecret_go"
)

func main() {
	resolved, err := monosecret.New().WithScope("api").Load()
	if err != nil {
		log.Fatal(err)
	}
	defer resolved.Close()
}
