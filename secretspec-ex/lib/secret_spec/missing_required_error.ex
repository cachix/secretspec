defmodule SecretSpec.MissingRequiredError do
  @moduledoc "Raised when required secrets are missing."

  defexception [:missing]

  @impl true
  def message(%__MODULE__{missing: missing}),
    do: "missing required secret(s): #{Enum.join(missing, ", ")}"
end
