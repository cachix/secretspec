defmodule SecretSpec do
  @moduledoc "Pure Elixir client for the SecretSpec resolver IPC protocol."

  alias SecretSpec.Session

  def with_session(options, fun) when is_function(fun, 1) do
    with {:ok, session} <- Session.start_link(options) do
      try do
        fun.(session)
      after
        Session.close(session)
      end
    end
  end
end
