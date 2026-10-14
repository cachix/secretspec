# Unreleased SecretSpec prototype: configure the local dev_overrides first.
terraform {
  required_version = ">= 1.10"
  required_providers {
    secretspec = { source = "cachix/secretspec" }
  }
}

ephemeral "secretspec_secrets" "app" {
  path   = "${path.module}/../secretspec.toml"
  scope  = "terraform"
  reason = "Configure application"
}

resource "terraform_data" "app" {
  provisioner "local-exec" {
    command = "test -n \"$API_TOKEN\""
    environment = {
      API_TOKEN = ephemeral.secretspec_secrets.app.values["API_TOKEN"]
    }
  }
}
