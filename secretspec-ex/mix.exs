defmodule SecretSpec.MixProject do
  use Mix.Project

  @source_url "https://github.com/cachix/secretspec"

  def project do
    [
      app: :secretspec,
      version: "0.19.1",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      description: "Elixir SDK for SecretSpec",
      source_url: @source_url,
      homepage_url: @source_url,
      docs: [main: "SecretSpec", extras: ["README.md"]],
      package: package(),
      deps: deps(),
      compilers: Mix.compilers()
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp package do
    [
      files: ["lib", "native", "checksum-*.exs", "mix.exs", "README.md"],
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url}
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.4"},
      {:rustler_precompiled, "~> 0.9.0"},
      {:ex_doc, "~> 0.40.3", only: :dev, runtime: false},
      {:rustler, ">= 0.0.0", optional: true}
    ]
  end
end
