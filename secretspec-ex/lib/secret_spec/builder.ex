defmodule SecretSpec.Builder do
  @moduledoc "Fluent request builder for SecretSpec resolution."

  alias SecretSpec.CallerContext
  defstruct request: %{}, inline: nil

  @doc "Creates an empty builder."
  def new, do: %__MODULE__{}
  @doc "Sets the manifest path."
  def with_path(%__MODULE__{} = builder, path),
    do: %{builder | request: Map.put(builder.request, "path", path), inline: nil}

  @doc "Sets the provider URI or name."
  def with_provider(%__MODULE__{} = builder, provider), do: put(builder, "provider", provider)
  @doc "Sets the profile."
  def with_profile(%__MODULE__{} = builder, profile), do: put(builder, "profile", profile)
  @doc "Sets the manifest scope."
  def with_scope(%__MODULE__{} = builder, scope), do: put(builder, "scope", scope)
  @doc "Sets the audit reason."
  def with_reason(%__MODULE__{} = builder, reason), do: put(builder, "reason", reason)
  @doc "Sets caller audit context."
  def with_caller(%__MODULE__{} = builder, caller),
    do: put(builder, "caller", CallerContext.to_request(caller))

  @doc "Controls whether values are omitted."
  def with_no_values(%__MODULE__{} = builder, value \\ true), do: put(builder, "no_values", value)
  @doc "Sets an inline specification and its logical base directory."
  def with_inline_spec(%__MODULE__{} = builder, spec, base_dir),
    do: %{builder | request: Map.delete(builder.request, "path"), inline: {spec, base_dir}}

  @doc "Applies one-shot options to a builder."
  def configure(builder, opts) do
    Enum.reduce(opts, builder, fn
      {:path, value}, builder -> with_path(builder, value)
      {:provider, value}, builder -> with_provider(builder, value)
      {:profile, value}, builder -> with_profile(builder, value)
      {:scope, value}, builder -> with_scope(builder, value)
      {:reason, value}, builder -> with_reason(builder, value)
      {:caller, value}, builder -> with_caller(builder, value)
      {:no_values, value}, builder -> with_no_values(builder, value)
    end)
  end

  @doc "Resolves and returns a `SecretSpec.Resolved`."
  def load(%__MODULE__{} = builder),
    do:
      builder
      |> native_request()
      |> SecretSpec.checked_response("resolve", 2)
      |> SecretSpec.to_resolved()

  @doc "Resolves without returning secret values."
  def report(%__MODULE__{} = builder),
    do:
      builder
      |> native_request("report")
      |> SecretSpec.checked_response("report", 1)
      |> SecretSpec.to_report()

  defp put(builder, key, value), do: %{builder | request: Map.put(builder.request, key, value)}
  defp native_request(%__MODULE__{request: request, inline: nil}), do: {request, false}

  defp native_request(%__MODULE__{request: request, inline: {spec, base_dir}}),
    do:
      {%{
         "request_version" => 1,
         "operation" => "resolve",
         "source" => %{
           "kind" => "inline",
           "spec_version" => 1,
           "base_dir" => base_dir,
           "spec" => spec
         },
         "options" => request
       }, true}

  defp native_request(builder, mode) do
    {request, versioned} = native_request(builder)
    {Map.put(request, "mode", mode), versioned}
  end
end
