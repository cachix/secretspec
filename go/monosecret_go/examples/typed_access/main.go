package main

import (
	"fmt"
	"log"

	monosecret "github.com/ifiokjr/monosecret/go/monosecret_go"
)

func main() {
	resolved, err := monosecret.New().Load()
	if err != nil {
		log.Fatal(err)
	}
	defer resolved.Close()

	data, _ := resolved.FieldsJSON()
	typed, _ := UnmarshalMonosecret(data) // typed, generated
	fmt.Println(typed.DatabaseURL)
}
