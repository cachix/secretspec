defmodule SecretSpec do
  @moduledoc """
  Elixir SDK for SecretSpec.

  The Rustler native module calls the shared Rust resolver directly. This layer
  builds requests and maps the JSON response into Elixir structs.
  """

  alias SecretSpec.{
    Builder,
    Error,
    MissingRequiredError,
    Native,
    Report,
    Resolved,
    ResolvedSecret,
    SecretReport
  }

  @doc "Starts a fluent SecretSpec builder."
  def builder, do: Builder.new()

  @doc "Resolves secrets using the supplied options."
  def resolve(opts \\ []) do
    builder()
    |> Builder.configure(opts)
    |> Builder.load()
  end

  @doc "Returns a value-free resolution report."
  def report(opts \\ []) do
    builder()
    |> Builder.configure(opts)
    |> Builder.report()
  end

  @doc "Returns the native bridge version."
  def abi_version, do: Native.abi_version()

  @doc false
  def checked_response({request, versioned}, kind, expected_version) do
    request_json = Jason.encode!(request)

    # Rust's LastPass provider uses waitpid, which fails while OTP ignores SIGCHLD.
    raw =
      with_default_sigchld(fn ->
        if versioned, do: Native.call(request_json), else: Native.resolve(request_json)
      end)

    envelope = Jason.decode!(raw)

    case envelope do
      %{"ok" => true, "response" => %{"schema_version" => ^expected_version} = response} ->
        response

      %{"ok" => true, "response" => response} ->
        raise %Error{
          kind: "version",
          message:
            "unsupported #{kind} schema version #{response["schema_version"]} (expected #{expected_version})"
        }

      %{"ok" => false, "error" => %{"kind" => error_kind, "message" => message}} ->
        raise %Error{kind: error_kind, message: message}
    end
  end

  @doc false
  defp with_default_sigchld(fun) do
    :global.trans({__MODULE__, :sigchld}, fn ->
      :ok = :os.set_signal(:sigchld, :default)

      try do
        fun.()
      after
        # OTP normally starts with SIGCHLD ignored, but the public Erlang API has no
        # getter, so restore that assumed original disposition.
        :ok = :os.set_signal(:sigchld, :ignore)
      end
    end)
  end

  def to_resolved(%{"missing_required" => [_ | _] = missing}),
    do: raise(%MissingRequiredError{missing: missing})

  def to_resolved(response) do
    secrets =
      Map.new(response["secrets"] || %{}, fn {name, entry} ->
        {name,
         %ResolvedSecret{
           value: entry["value"],
           path: entry["path"],
           as_path: entry["as_path"],
           source: entry["source"],
           source_provider: entry["source_provider"]
         }}
      end)

    %Resolved{
      provider: response["provider"],
      profile: response["profile"],
      secrets: secrets,
      missing_optional: response["missing_optional"] || [],
      scope: response["scope"]
    }
  end

  @doc false
  def to_report(response) do
    secrets =
      Enum.map(response["secrets"] || [], fn entry ->
        %SecretReport{
          name: entry["name"],
          status: entry["status"],
          required: entry["required"],
          source_provider: entry["source_provider"],
          default_applied: entry["default_applied"],
          generated: entry["generated"],
          as_path: entry["as_path"]
        }
      end)

    %Report{
      provider: response["provider"],
      profile: response["profile"],
      secrets: secrets,
      scope: response["scope"]
    }
  end
end
