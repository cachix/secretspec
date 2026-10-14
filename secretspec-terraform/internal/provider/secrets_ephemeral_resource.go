package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ ephemeral.EphemeralResource = &secretsEphemeralResource{}

type secretsEphemeralResource struct{}

func (e *secretsEphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secrets"
}

func (e *secretsEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Read a SecretSpec profile/scope without writing back to its providers (unreleased prototype, Terraform 1.10+). Values are omitted from state and plans and can only be used in ephemeral contexts. as_path is unsupported.",
		Attributes: map[string]schema.Attribute{
			"path":    schema.StringAttribute{Required: true, Description: pathDescription},
			"profile": schema.StringAttribute{Optional: true, Description: profileDescription},
			"scope":   schema.StringAttribute{Optional: true, Description: scopeDescription},
			"reason":  schema.StringAttribute{Optional: true, Description: reasonDescription},
			"values": schema.MapAttribute{
				Computed: true, Sensitive: true, ElementType: types.StringType,
				Description: "Resolved inline values, available only during the current Terraform operation.",
			},
		},
	}
}

func (e *secretsEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data secretsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(data.resolve(ctx, "ephemeral_open")...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
