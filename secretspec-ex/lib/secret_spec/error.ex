defmodule SecretSpec.Error do
  @moduledoc "A SecretSpec resolution or native bridge error."

  defexception [:kind, :message]

  @impl true
  def message(%__MODULE__{kind: kind, message: message}), do: "#{message} (kind: #{kind})"
end
