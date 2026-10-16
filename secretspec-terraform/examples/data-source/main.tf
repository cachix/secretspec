# Unreleased SecretSpec prototype: configure the local dev_overrides first.
terraform {
  required_version = ">= 1.4"
  required_providers {
    secretspec = { source = "cachix/secretspec" }
  }
}

data "secretspec_secrets" "app" {
  path   = "${path.module}/../secretspec.toml"
  scope  = "terraform"
  reason = "Configure application"
}

# The entire data source map and this input are persisted in state.
resource "terraform_data" "app" {
  input = data.secretspec_secrets.app.values["API_TOKEN"]
}
