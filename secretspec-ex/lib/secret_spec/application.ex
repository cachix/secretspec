defmodule SecretSpec.Application do
  use Application

  @impl true
  def start(_type, _args) do
    children = [{Task.Supervisor, name: SecretSpec.TaskSupervisor}]
    Supervisor.start_link(children, strategy: :one_for_one, name: SecretSpec.Supervisor)
  end
end
