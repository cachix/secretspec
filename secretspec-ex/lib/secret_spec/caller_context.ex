defmodule SecretSpec.CallerContext do
  @moduledoc "Caller information sent to SecretSpec's audit policy."

  defstruct [:name, :version, :operation, :resource]

  @doc "Converts the caller context to the native request shape."
  def to_request(%__MODULE__{} = caller) do
    caller
    |> Map.from_struct()
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new(fn {key, value} -> {Atom.to_string(key), value} end)
  end
end
