defmodule SecretSpec.Native do
  @moduledoc false

  version = Mix.Project.config()[:version]

  # Prebuilt consumers (Nix) provide the compiled NIF at
  # priv/native/secretspec_native.so and skip both the cargo build and the
  # precompiled-artifact download, which are unavailable in a build sandbox.
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
    force_build: System.get_env("SECRETSPEC_EX_FORCE_BUILD") in ~w[1 true],
    version: version

  def resolve(_request) do
    :erlang.nif_error(:nif_not_loaded)
  end

  # Rustler replaces this fallback when the loaded NIF exports `call/1`.
  def call(_request) do
    raise %SecretSpec.Error{
      kind: "capability",
      message: "loaded libsecretspec does not support inline specs (missing secretspec_call)"
    }
  end

  def abi_version, do: :erlang.nif_error(:nif_not_loaded)
end
