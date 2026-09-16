defmodule SecretSpec.ResolvedSecret do
  @moduledoc "One resolved secret and its provenance."

  defstruct [:value, :path, :as_path, :source, :source_provider]

  @doc "Returns the usable value or materialized file path."
  def get(%__MODULE__{as_path: true, path: path}), do: path
  def get(%__MODULE__{value: value}), do: value
end
