defmodule SecretSpec.Test.FakeResolver do
  @moduledoc "Small, isolated resolver endpoint used by the SDK tests."

  def build(tmp_dir, opts \\ []) do
    id = opts[:id] || "#{System.unique_integer([:positive])}"
    transcript = Path.join(tmp_dir, "#{id}.transcript")
    endpoint = Path.join(tmp_dir, "#{id}.exs")
    config = Keyword.merge([transcript: transcript, methods: ["resolver.get", "resolver.release", "rpc.shutdown"]], opts)
    File.write!(endpoint, script(config))
    %{endpoint: endpoint, transcript: transcript, executable: System.find_executable("elixir"), arguments: [endpoint]}
  end

  def session_options(fake, opts \\ []) do
    [executable: fake.executable, arguments: fake.arguments] ++ opts
  end

  def messages(fake) do
    case File.read(fake.transcript) do
      {:ok, body} -> body |> String.split("\n", trim: true) |> Enum.map(&JSON.decode!/1)
      {:error, :enoent} -> []
    end
  end

  def wait_for(fake, fun, timeout \\ 1_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_wait(fake, fun, deadline)
  end

  defp do_wait(fake, fun, deadline) do
    if fun.(messages(fake)) do
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

  defp script(config) do
    """
    config = #{inspect(config, limit: :infinity, printable_limit: :infinity)}
    transcript = config[:transcript]
    write = fn message -> File.write!(transcript, JSON.encode!(message) <> <<10>>, [:append]) end
    response = fn request ->
      id = request["id"]
      method = request["method"]
      params = request["params"] || %{}
      case {method, config[:behavior]} do
        {"rpc.initialize", _} ->
          result = config[:init] || %{"protocol" => "secretspec.resolver", "version" => 1,
            "server" => %{"name" => "fake", "version" => "1"}, "methods" => config[:methods],
            "limits" => %{"max_frame_bytes" => 32_768, "max_in_flight" => 1},
            "application" => %{"manifest_kind" => "path"}}
          %{"jsonrpc" => "2.0", "id" => id, "result" => result}
        {"resolver.get", _} ->
          case config[:get] || :resolved do
            :missing -> %{"jsonrpc" => "2.0", "id" => id, "result" => %{"status" => "missing", "required" => true}}
            :optional_missing -> %{"jsonrpc" => "2.0", "id" => id, "result" => %{"status" => "missing", "required" => false}}
            :undeclared -> %{"jsonrpc" => "2.0", "id" => id, "result" => %{"status" => "undeclared"}}
            :malformed -> %{"jsonrpc" => "2.0", "id" => id, "result" => %{"status" => "resolved", "representation" => "unknown"}}
            :path -> %{"jsonrpc" => "2.0", "id" => id, "result" => %{"status" => "resolved", "representation" => "path", "path" => "/tmp/secret", "lease_id" => "lease-1"}}
            value when is_binary(value) -> %{"jsonrpc" => "2.0", "id" => id, "result" => %{"status" => "resolved", "representation" => "value", "value" => value}}
            _ -> %{"jsonrpc" => "2.0", "id" => id, "result" => %{"status" => "resolved", "representation" => "value", "value" => "secret"}}
          end
        {"resolver.release", _} -> %{"jsonrpc" => "2.0", "id" => id, "result" => %{}}
        {"rpc.shutdown", _} -> %{"jsonrpc" => "2.0", "id" => id, "result" => %{}}
        _ -> %{"jsonrpc" => "2.0", "id" => id, "error" => %{"code" => -32601, "message" => "method not found", "data" => %{"kind" => "capability"}}}
      end
    end
    emit = fn message ->
      frame = JSON.encode!(message) <> <<10>>
      case config[:chunks] do
        nil -> IO.binwrite(:stdio, frame)
        chunks ->
          remaining =
            Enum.reduce(chunks, frame, fn n, remaining ->
              {chunk, rest} =
                if byte_size(remaining) <= n,
                  do: {remaining, <<>>},
                  else: :erlang.split_binary(remaining, n)

              IO.binwrite(:stdio, chunk)
              rest
            end)

          IO.binwrite(:stdio, remaining)
      end
    end
    loop = fn loop, buffer ->
      case IO.read(:stdio, 1) do
        :eof -> :ok
        data ->
          buffer = buffer <> data
          case String.split(buffer, <<10>>, parts: 2) do
            [rest] -> loop.(loop, rest)
            [line, rest] ->
              request = JSON.decode!(line)
              write.(request)
              if config[:hang] == request["method"], do: Process.sleep(:infinity)
              if config[:exit] == request["method"], do: System.halt(0)
              if is_integer(config[:delay]) and config[:delay] > 0, do: Process.sleep(config[:delay])
              if config[:send_callback] && request["method"] == "resolver.get" do
                  emit.(%{"jsonrpc" => "2.0", "id" => config[:callback_id] || 100, "method" => "client.prompt", "_meta" => %{"parent_request_id" => request["id"], "deadline_unix_ms" => System.system_time(:millisecond) + 1_000}, "params" => %{"name" => "TOKEN", "profile" => "default"}})
              end
              if config[:no_response] != request["method"], do: emit.(response.(request))
              loop.(loop, rest)
          end
      end
    end
    loop.(loop, "")
    """
  end
end
