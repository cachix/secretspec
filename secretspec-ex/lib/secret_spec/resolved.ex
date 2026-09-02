defmodule SecretSpec.Resolved do
  @moduledoc "A successful SecretSpec resolution."

  alias SecretSpec.ResolvedSecret
  defstruct [:provider, :profile, :secrets, missing_optional: [], scope: nil]

  @doc "Exports usable secrets into the Erlang VM environment."
  def set_as_env(%__MODULE__{secrets: secrets}) do
    Enum.each(secrets, fn {name, secret} ->
      case ResolvedSecret.get(secret) do
        nil -> :ok
        value -> System.put_env(name, value)
      end
    end)
  end

  @doc "Returns a flat map of secret names to usable values."
  def fields(%__MODULE__{secrets: secrets}),
    do: Map.new(secrets, fn {name, secret} -> {name, ResolvedSecret.get(secret)} end)

  @doc "Removes materialized files belonging to this resolution."
  def close(%__MODULE__{secrets: secrets}) do
    first_error =
      secrets
      |> Map.values()
      |> Enum.filter(&(&1.as_path && is_binary(&1.path)))
      |> Enum.reduce(nil, fn secret, first_error ->
        case File.rm(secret.path) do
          :ok -> first_error
          {:error, :enoent} -> first_error
          {:error, reason} when is_nil(first_error) -> reason
          {:error, _reason} -> first_error
        end
      end)

    case first_error do
      nil -> :ok
      reason -> raise File.Error, reason: reason
    end
  end
end
