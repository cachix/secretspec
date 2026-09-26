defmodule SecretSpec.Secret do
  @moduledoc "A single result returned by `resolver.get`."
  defstruct [
    :name,
    :representation,
    :value,
    :path,
    :lease_id,
    :source,
    :source_provider,
    :revision,
    :expires_at,
    :refresh_at
  ]
end
