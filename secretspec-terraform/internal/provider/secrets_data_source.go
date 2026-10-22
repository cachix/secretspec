package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &secretsDataSource{}

type secretsDataSource struct{}

func (d *secretsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secrets"
}

func (d *secretsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Read a SecretSpec profile/scope without writing back to its providers (unreleased prototype). All returned values are stored in Terraform state and saved plans, including unused map entries. Use a scope to limit them. as_path is unsupported.",
		Attributes: map[string]schema.Attribute{
			"path":    schema.StringAttribute{Required: true, Description: pathDescription},
			"profile": schema.StringAttribute{Optional: true, Description: profileDescription},
			"scope":   schema.StringAttribute{Optional: true, Description: scopeDescription},
			"reason":  schema.StringAttribute{Optional: true, Description: reasonDescription},
			"values": schema.MapAttribute{
				Computed: true, Sensitive: true, ElementType: types.StringType,
				Description: "Resolved inline values. Sensitive hides their display; the entire map is persisted in state and saved plans.",
			},
		},
	}
}

func (d *secretsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data secretsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(data.resolve(ctx, "data_read")...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
