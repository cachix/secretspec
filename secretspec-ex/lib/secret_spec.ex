defmodule SecretSpec do
  @moduledoc "Pure Elixir client for the SecretSpec resolver IPC protocol."

  alias SecretSpec.Session

  def with_session(options, fun) when is_function(fun, 1) do
    with {:ok, session} <- Session.start(options) do
      try do
        fun.(session)
      after
        try do
          Session.close(session)
        catch
          :exit, {:noproc, _} -> :ok
          :exit, :noproc -> :ok
          :exit, _reason -> :ok
        end
      end
    end
  end
end
