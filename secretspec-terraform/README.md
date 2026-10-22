# SecretSpec Terraform provider (unreleased prototype)

Read an existing `secretspec.toml` through the SecretSpec Go SDK and Rust
resolver. The prototype offers `secretspec_secrets` as both an ephemeral
resource and a data source. It has no managed resources. The target release
has not been assigned.

| | Ephemeral resource | Data source |
| --- | --- | --- |
| Terraform | 1.10+ | 1.0+ |
| Result | Sensitive `map(string)` in `values` | Sensitive `map(string)` in `values` |
| Persistence | Values omitted from state and saved plans | Entire map saved, including unused entries |
| References | Ephemeral contexts, such as provider configuration, write-only arguments, or provisioners | Ordinary resource arguments and other Terraform expressions |

Both accept a required `path` and optional `profile`, `scope`, and `reason`.
Relative paths are resolved from Terraform's working directory. Set `reason`
when the manifest's access policy requires it. Write-only arguments require
Terraform 1.11+ and support from the consuming provider.
Profile and scope selection otherwise follows SecretSpec's defaults. Provider
selection comes from the manifest and SecretSpec configuration. Missing optional
secrets are omitted. Values remain strings, including values with a SecretSpec
type declaration. There is no single-secret lookup; use a manifest scope to
limit the returned map.

Existing values can be read even when their declarations enable generation.
Both refuse resolution that requires saving a generated or prompted value
before generation or prompting. `as_path` is rejected before file creation,
including hidden dependencies of composed or derived values. Local caches,
auditing and provider commands remain enabled; generators that do not persist
values may still run. This is not a sandbox for those commands.
Generic provider errors are summarized because their text can contain secret
values.

## Run the prototype locally

Requires Go 1.25+, the repository's Rust toolchain, and Terraform. Build the
provider and native library from the **same checkout**.

From the repository root:

```sh
cargo build -p libsecretspec
mkdir -p "$PWD/target/terraform-provider"
(cd secretspec-terraform && go build -o ../target/terraform-provider/terraform-provider-secretspec .)

# Linux; on macOS use libsecretspec.dylib.
export SECRETSPEC_FFI_LIB="$PWD/target/debug/libsecretspec.so"
```

Create a Terraform CLI configuration file with the **absolute** provider
directory:

```hcl
provider_installation {
  dev_overrides {
    "cachix/secretspec" = "/absolute/path/to/secretspec/target/terraform-provider"
  }
  direct {}
}
```

`cachix/secretspec` is the local development address. These examples use
[development overrides](https://developer.hashicorp.com/terraform/cli/config/config-file#development-overrides-for-provider-developers)
and run without `terraform init`, which would still look for a published
provider in the Registry.

The [ephemeral example](examples/ephemeral/main.tf) consumes a token in a
provisioner without persisting it. The [data source example](examples/data-source/main.tf)
uses it in an ordinary resource argument and persists it; that example requires
Terraform 1.4+ because it uses `terraform_data`. Both use the shared
[example manifest](examples/secretspec.toml), which reads `API_TOKEN` from the
environment.

From the repository root, try the ephemeral example with a dummy token. Set
`TF_CLI_CONFIG_FILE` to the absolute path of the CLI configuration created above:

```sh
export TF_CLI_CONFIG_FILE="/absolute/path/to/terraform.tfrc"
export API_TOKEN="example-token"
terraform -chdir=secretspec-terraform/examples/ephemeral plan
terraform -chdir=secretspec-terraform/examples/ephemeral apply
```

`plan` checks secret resolution; the first `apply` also runs the provisioner,
which checks that the token is non-empty. To try the data source, use
`secretspec-terraform/examples/data-source` as the `-chdir` path instead.

## Tests

From the repository root, with `SECRETSPEC_FFI_LIB` pointing to the freshly built
library:

```sh
cd secretspec-terraform
go test ./...
TF_ACC=1 go test ./...
```

The second command also runs real Terraform plan/apply operations using only
temporary dotenv stores and the built-in `terraform_data` resource. It verifies
sensitive output, ephemeral omission from saved plans/state, full-map data
source persistence, scope/profile selection, and refusal before provider
writeback. Terraform 1.10+ must be on `PATH`, or set `TF_ACC_TERRAFORM_PATH`.
