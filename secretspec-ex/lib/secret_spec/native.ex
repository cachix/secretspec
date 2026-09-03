defmodule SecretSpec.Native do
  @moduledoc false

  version = Mix.Project.config()[:version]

  # local_checkout? =
  #   File.exists?(Path.expand("../../native/secretspec_native/Cargo.toml", __DIR__))

  use RustlerPrecompiled,
    otp_app: :secretspec,
    crate: "secretspec_native",
    targets: [
      "x86_64-unknown-linux-gnu",
      "aarch64-unknown-linux-gnu",
      "aarch64-apple-darwin",
      "x86_64-pc-windows-msvc"
    ],
    base_url: "https://github.com/cachix/secretspec/releases/download/v#{version}",
    # force_build: local_checkout?,
    version: version

  def resolve(_request), do: :erlang.nif_error(:nif_not_loaded)
  def call(_request), do: :erlang.nif_error(:nif_not_loaded)
  def abi_version, do: :erlang.nif_error(:nif_not_loaded)
end
