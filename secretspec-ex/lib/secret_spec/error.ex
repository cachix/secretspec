defmodule SecretSpec.Error do
  @moduledoc "A resolver protocol error."
  defexception [:kind, :message, :data]

  @impl true
  def message(%__MODULE__{kind: kind, message: message}), do: "#{message} (kind: #{kind})"

  def from_response(%{"error" => %{"message" => message, "data" => %{"kind" => kind}} = error}),
    do: %__MODULE__{kind: kind, message: message, data: error}

  def from_response(_), do: %__MODULE__{kind: "protocol", message: "malformed error response"}
end
