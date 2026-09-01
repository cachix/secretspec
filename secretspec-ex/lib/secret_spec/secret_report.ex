defmodule SecretSpec.SecretReport do
  @moduledoc "Value-free outcome for one declared secret."

  defstruct [:name, :status, :required, :source_provider, :default_applied, :generated, :as_path]
end
