defmodule SecretSpec.Subprocess do
  @moduledoc """
  Detects whether a native request may reach a provider that spawns a
  subprocess.

  The BEAM starts with SIGCHLD ignored, which breaks Rust's `waitpid`-based
  CLI providers (`lpass`, `op`, `bw`, …). The NIF bridge restores SIGCHLD
  before such calls, but that flip is a VM-wide signal mutation, so it must
  only run when a subprocess-backed provider is actually in play. This module
  inspects the request the way the builder built it: the explicit provider
  spec, the inline spec's provider aliases, per-secret provider chains, and
  profile defaults.

  The scheme lists below mirror the core's provider registrations
  (`secretspec/src/provider/*.rs`); a new CLI-backed registration must be
  added to `@subprocess_schemes` here.
  """

  @subprocess_schemes [
    "akv",
    "bw",
    "bws",
    "cloudflare",
    "dashlane",
    "ejson",
    "fly",
    "gopass",
    "lastpass",
    "onepassword",
    "onepassword+token",
    "op",
    "pass",
    "passbolt",
    "protonpass",
    "sops"
  ]

  @in_process_schemes [
    "aac",
    "age",
    "awsps",
    "awssm",
    "cloudflarekvs",
    "dotenv",
    "env",
    "file",
    "gcsm",
    "infisical",
    "kdbx",
    "keeper",
    "keyring",
    "k8s+configmap",
    "k8s+secret",
    "kubernetes",
    "openbao",
    "scaleway",
    "systemd-credential",
    "vault"
  ]

  @doc """
  Returns true when the request may reach a subprocess-spawning provider.

  Fail-safe: any provider spec the SDK cannot prove subprocess-free (an
  alias name, a bare provider name, a scheme missing from both lists, an
  unknown shape) engages the wrapper. Only a URI whose scheme names a known
  in-process provider skips it.
  """
  @spec engaged_by?(map()) :: boolean()
  def engaged_by?(request) when is_map(request) do
    request
    |> provider_specs()
    |> Enum.any?(&subprocess_possible?/1)
  end

  defp provider_specs(%{"provider" => provider}) when is_binary(provider) do
    [provider]
  end

  defp provider_specs(%{"source" => %{"kind" => "inline"} = source} = request) do
    option =
      case request do
        %{"options" => %{"provider" => provider}} when is_binary(provider) -> [provider]
        _ -> []
      end

    specs = alias_specs(source) ++ chain_specs(source) ++ default_specs(source) ++ option

    case specs do
      [] -> [nil]
      specs -> specs
    end
  end

  # A path-based request without an explicit provider: the core falls back to
  # the user config default provider, which the SDK cannot inspect. The
  # manifest's own aliases could name a subprocess provider, so stay safe.
  defp provider_specs(_), do: [nil]

  defp alias_specs(%{"spec" => %{"providers" => providers}}) when is_map(providers) do
    Enum.map(providers, fn {_name, spec} -> spec end)
  end

  defp alias_specs(_), do: []

  defp chain_specs(%{"spec" => %{"profiles" => profiles}}) when is_map(profiles) do
    Enum.flat_map(profiles, fn
      {_name, %{"secrets" => secrets}} when is_map(secrets) ->
        Enum.flat_map(secrets, fn
          {_name, %{"providers" => chain}} when is_list(chain) -> chain
          _ -> []
        end)

      _ ->
        []
    end)
  end

  defp chain_specs(_), do: []

  defp default_specs(%{"spec" => %{"defaults" => %{"providers" => providers}}})
       when is_list(providers) do
    providers
  end

  defp default_specs(_), do: []

  defp subprocess_possible?(spec) when is_binary(spec) do
    case URI.parse(spec).scheme do
      scheme when scheme in @subprocess_schemes -> true
      scheme when scheme in @in_process_schemes -> false
      scheme when is_binary(scheme) -> true
      nil -> true
    end
  end

  defp subprocess_possible?(_), do: true
end
