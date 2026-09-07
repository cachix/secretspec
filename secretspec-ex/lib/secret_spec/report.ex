defmodule SecretSpec.Report do
  @moduledoc "A value-free resolution snapshot."

  defstruct [:provider, :profile, :secrets, scope: nil, constraint_violations: []]
end
