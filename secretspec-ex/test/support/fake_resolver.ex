defmodule SecretSpec.Test.FakeResolver do
  @moduledoc "Isolated executable resolver endpoints for deterministic IPC tests."

  def build(tmp_dir, opts \\ []) do
    id = opts[:id] || "#{System.unique_integer([:positive])}"
    transcript = Path.join(tmp_dir, "#{id}.transcript")
    ready = Path.join(tmp_dir, "#{id}.ready")
    endpoint = Path.join(tmp_dir, "#{id}.exs")
    config = Keyword.merge([transcript: transcript, ready: ready, methods: ["resolver.get", "resolver.release", "rpc.shutdown"]], opts)
    File.write!(endpoint, script(config))
    %{endpoint: endpoint, transcript: transcript, ready: ready, marker: opts[:marker], executable: System.find_executable("elixir"), arguments: [endpoint]}
  end

  def session_options(fake, opts \\ []), do: [executable: fake.executable, arguments: fake.arguments] ++ opts

  def messages(fake) do
    case File.read(fake.transcript) do
      {:ok, body} -> body |> String.split("\n", trim: true) |> Enum.map(&JSON.decode!/1)
      {:error, :enoent} -> []
    end
  end

  def wait_ready(fake, timeout \\ 2_000), do: wait_for(fake, fn _ -> File.exists?(fake.ready) end, timeout)

  def wait_for(fake, fun, timeout \\ 1_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_wait(fake, fun, deadline)
  end

  defp do_wait(fake, fun, deadline) do
    if fun.(messages(fake)) or (fake.ready && File.exists?(fake.ready) && fun.([])) do
      :ok
    else
      if System.monotonic_time(:millisecond) < deadline do
        Process.sleep(10)
        do_wait(fake, fun, deadline)
      else
        {:error, :timeout}
      end
    end
  end

  def marked_processes(marker) do
    case System.cmd("ps", ["-eo", "args"], stderr_to_stdout: true) do
      {output, 0} -> output |> String.split("\n") |> Enum.filter(&String.contains?(&1, marker))
      _ -> []
    end
  end

  defp script(config) do
    """
    config = #{inspect(config, limit: :infinity, printable_limit: :infinity)}
    transcript = config[:transcript]
    write = fn message -> File.write!(transcript, JSON.encode!(message) <> <<10>>, [:append]) end
    frame = fn message -> JSON.encode!(message) <> <<10>> end
    response = fn request ->
      id = request["id"]
      case request["method"] do
        "rpc.initialize" ->
          result = config[:init] || %{"protocol" => "secretspec.resolver", "version" => 1,
            "server" => %{"name" => "fake", "version" => "1"}, "methods" => config[:methods],
            "limits" => %{"max_frame_bytes" => 32_768, "max_in_flight" => 1},
            "application" => %{"manifest_kind" => "path"}}
          %{"jsonrpc" => "2.0", "id" => id, "result" => result}
        "resolver.get" ->
          case config[:get] || :resolved do
            :missing -> %{"jsonrpc" => "2.0", "id" => id, "result" => %{"status" => "missing", "required" => true}}
            :optional_missing -> %{"jsonrpc" => "2.0", "id" => id, "result" => %{"status" => "missing", "required" => false}}
            :undeclared -> %{"jsonrpc" => "2.0", "id" => id, "result" => %{"status" => "undeclared"}}
            :malformed -> %{"jsonrpc" => "2.0", "id" => id, "result" => %{"status" => "resolved", "representation" => "unknown"}}
            :path -> %{"jsonrpc" => "2.0", "id" => id, "result" => %{"status" => "resolved", "representation" => "path", "path" => "/tmp/secret", "lease_id" => "lease-1"}}
            value when is_binary(value) -> %{"jsonrpc" => "2.0", "id" => id, "result" => %{"status" => "resolved", "representation" => "value", "value" => value}}
            _ -> %{"jsonrpc" => "2.0", "id" => id, "result" => %{"status" => "resolved", "representation" => "value", "value" => "secret"}}
          end
        "resolver.release" -> %{"jsonrpc" => "2.0", "id" => id, "result" => %{}}
        "rpc.shutdown" -> %{"jsonrpc" => "2.0", "id" => id, "result" => %{}}
        _ -> %{"jsonrpc" => "2.0", "id" => id, "error" => %{"code" => -32601, "message" => "method not found", "data" => %{"kind" => "capability"}}}
      end
    end
    emit = fn message -> IO.binwrite(:stdio, frame.(message)) end
    emit_coalesced = fn messages -> IO.binwrite(:stdio, Enum.map_join(messages, "", frame)) end
    if config[:marker] do
      Port.open({:spawn_executable, "/bin/sh"}, [:binary, {:args, ["-c", "exec -a #{config[:marker]} sleep 60"]}])
    end
    loop = fn loop, buffer, waiting ->
      case IO.read(:stdio, 1) do
        :eof -> :ok
        data ->
          buffer = buffer <> data
          case String.split(buffer, <<10>>, parts: 2) do
            [rest] -> loop.(loop, rest, waiting)
            [line, rest] ->
              request = JSON.decode!(line)
              write.(request)
              cond do
                request["method"] == "rpc.cancel" ->
                  loop.(loop, rest, waiting)
                waiting && request["id"] == waiting.callback_id && Map.has_key?(request, "result") ->
                  emit.(response.(waiting.parent))
                  loop.(loop, rest, nil)
                config[:hang] == request["method"] -> Process.sleep(:infinity)
                config[:exit] == request["method"] -> System.halt(0)
                true ->
                  if is_integer(config[:delay]) and config[:delay] > 0, do: Process.sleep(config[:delay])
                  if request["method"] == "rpc.initialize" do
                    File.write!(config[:ready], "ready")
                    if config[:coalesced] do
                      emit_coalesced.([response.(request), %{"jsonrpc" => "2.0", "method" => "resolver.ready", "params" => %{}}])
                    else
                      emit.(response.(request))
                    end
                    loop.(loop, rest, waiting)
                  else
                    if config[:send_callback] && request["method"] == "resolver.get" do
                      callback = %{"jsonrpc" => "2.0", "id" => config[:callback_id] || 100, "method" => "client.prompt", "_meta" => %{"parent_request_id" => request["id"], "deadline_unix_ms" => System.system_time(:millisecond) + 1_000}, "params" => %{"name" => "TOKEN", "profile" => "default"}}
                      emit.(callback)
                      loop.(loop, rest, %{parent: request, callback_id: config[:callback_id] || 100})
                    else
                      if config[:no_response] != request["method"], do: emit.(response.(request))
                      loop.(loop, rest, waiting)
                    end
                  end
              end
          end
      end
    end
    loop.(loop, "", nil)
    """
  end
end
