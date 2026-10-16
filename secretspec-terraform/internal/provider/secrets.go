package provider

import (
	"context"
	"errors"
	"fmt"

	secretspec "github.com/cachix/secretspec/secretspec-go"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type secretsModel struct {
	Path    types.String `tfsdk:"path"`
	Profile types.String `tfsdk:"profile"`
	Scope   types.String `tfsdk:"scope"`
	Reason  types.String `tfsdk:"reason"`
	Values  types.Map    `tfsdk:"values"`
}

const (
	pathDescription    = "Path to secretspec.toml. Relative paths are resolved from Terraform's working directory."
	profileDescription = "SecretSpec profile. When omitted, SecretSpec's normal profile selection applies."
	scopeDescription   = "Named manifest scope restricting which secrets are returned. Dependencies may also be read."
	reasonDescription  = "Access reason passed to SecretSpec, required when the manifest's access policy requires one."
)

func (m *secretsModel) resolve(ctx context.Context, operation string) diag.Diagnostics {
	var diags diag.Diagnostics
	for _, attr := range []struct {
		name  string
		value types.String
	}{{"path", m.Path}, {"profile", m.Profile}, {"scope", m.Scope}, {"reason", m.Reason}} {
		if attr.value.IsUnknown() {
			diags.AddAttributeError(path.Root(attr.name), "Unknown SecretSpec configuration", "The value must be known before secrets can be resolved.")
		}
	}
	if m.Path.IsNull() || m.Path.ValueString() == "" {
		diags.AddAttributeError(path.Root("path"), "Missing manifest path", "Provide a non-empty path to secretspec.toml.")
	}
	if diags.HasError() {
		return diags
	}
	if err := ctx.Err(); err != nil {
		diags.AddError("SecretSpec read cancelled", err.Error())
		return diags
	}

	builder := secretspec.New().WithPath(m.Path.ValueString()).
		WithReadOnly(true).WithNoFiles(true).
		WithCaller(secretspec.CallerContext{Name: "terraform", Operation: operation})
	if !m.Profile.IsNull() {
		builder.WithProfile(m.Profile.ValueString())
	}
	if !m.Scope.IsNull() {
		builder.WithScope(m.Scope.ValueString())
	}
	if !m.Reason.IsNull() {
		builder.WithReason(m.Reason.ValueString())
	}
	resolved, err := builder.Load()
	if err != nil {
		diags.AddError("Unable to resolve SecretSpec secrets", resolutionError(err))
		return diags
	}
	defer resolved.Close()
	m.Values, diags = types.MapValueFrom(ctx, types.StringType, resolved.Fields())
	return diags
}

func resolutionError(err error) string {
	var missing *secretspec.MissingRequiredError
	if errors.As(err, &missing) {
		return missing.Error()
	}
	var native *secretspec.Error
	if errors.As(err, &native) {
		switch native.Kind {
		case "produced_value_write_refused", "file_value_refused":
			return native.Message
		case "load", "capability", "version", "invalid_request":
			return "This prototype requires a libsecretspec build with read-only and no-files support. Check SECRETSPEC_FFI_LIB and build the library from the same checkout."
		default:
			// Provider and conversion errors can contain secret values.
			return fmt.Sprintf("SecretSpec failed (%s). Check the manifest, provider credentials, profile, scope and access reason.", native.Kind)
		}
	}
	return "SecretSpec could not resolve the requested secrets. Check the native library and manifest configuration."
}
