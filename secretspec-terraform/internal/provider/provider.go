package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var _ provider.ProviderWithEphemeralResources = &secretSpecProvider{}

type secretSpecProvider struct{}

func New() provider.Provider { return &secretSpecProvider{} }

func (p *secretSpecProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "secretspec"
	resp.Version = "dev"
}

func (p *secretSpecProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Read secrets from an existing SecretSpec manifest (unreleased prototype).",
	}
}

func (p *secretSpecProvider) Configure(context.Context, provider.ConfigureRequest, *provider.ConfigureResponse) {
}

func (p *secretSpecProvider) Resources(context.Context) []func() resource.Resource { return nil }

func (p *secretSpecProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		func() datasource.DataSource { return &secretsDataSource{} },
	}
}

func (p *secretSpecProvider) EphemeralResources(context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{
		func() ephemeral.EphemeralResource { return &secretsEphemeralResource{} },
	}
}
