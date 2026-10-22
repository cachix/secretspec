package main

import (
	"context"
	"log"

	"github.com/cachix/secretspec/secretspec-terraform/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

func main() {
	if err := providerserver.Serve(context.Background(), provider.New, providerserver.ServeOpts{
		Address: "registry.terraform.io/cachix/secretspec",
	}); err != nil {
		log.Fatal(err)
	}
}
