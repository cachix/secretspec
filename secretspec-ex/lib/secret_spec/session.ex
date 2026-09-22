defmodule SecretSpec.Session do
  use GenServer

  alias SecretSpec.{Codec, Error, Secret}
  @default_startup 5_000
  @default_timeout 30_000
  @default_max_frame_bytes 32 * 1024
  @protocol "secretspec.resolver"
  @version 1

  defstruct port: nil,
            executable: nil,
            methods: MapSet.new(),
            limits: %{max_frame_bytes: @default_max_frame_bytes, max_in_flight: 1},
            next_id: 1,
            pending: %{},
            callers: %{},
            waiters: [],
            leases: MapSet.new(),
            prompt: nil,
            status: :starting,
            options: [],
            buffer: <<>>,
            abandoned: MapSet.new(),
            callbacks: %{},
            last_callback_id: 0

  def start_link(options), do: GenServer.start_link(__MODULE__, options)

  def get(session, name, options \\ []),
    do:
      GenServer.call(
        session,
        {:get, name, options},
        Keyword.get(options, :timeout, @default_timeout) + 1_000
      )

  def release(session, lease_id),
    do: GenServer.call(session, {:release, lease_id}, @default_timeout + 1_000)

  def close(session), do: GenServer.call(session, :close, @default_timeout + 1_000)

  @impl true
  def init(options) do
    executable = Keyword.get(options, :executable) || System.find_executable("secretspec")

    if is_nil(executable) do
      {:stop, {:error, :executable_not_found}}
    else
      args = Keyword.get(options, :arguments, ["serve"])

      port =
        Port.open({:spawn_executable, Path.expand(executable)}, [
          :binary,
          :exit_status,
          {:args, args}
        ])

      state = %__MODULE__{
        port: port,
        executable: executable,
        options: options,
        prompt: Keyword.get(options, :prompt)
      }

      {:ok, state, {:continue, :initialize}}
    end
  end

  @impl true
  def handle_continue(:initialize, state) do
    application = initialize_application(state.options)
    id = state.next_id

    message = %{
      "jsonrpc" => "2.0",
      "id" => id,
      "method" => "rpc.initialize",
      "_meta" => %{"deadline_unix_ms" => System.system_time(:millisecond) + @default_startup},
      "params" => %{
        "protocol" => @protocol,
        "versions" => [@version],
        "client" => %{
          "name" => "secretspec-elixir",
          "version" => Application.spec(:secretspec, :vsn) |> to_string()
        },
        "limits" => state.limits,
        "client_methods" => if(state.prompt, do: ["client.prompt"], else: []),
        "application" => application
      }
    }

    with :ok <- send_message(state, message) do
      timer = Process.send_after(self(), {:deadline, id}, @default_startup)
      pending = Map.put(state.pending, id, {:initialize, nil, timer})
      {:noreply, %{state | next_id: id + 1, pending: pending}}
    else
      {:error, reason} -> {:stop, reason, state}
    end
  end

  @impl true
  def handle_call({:get, name, options}, from, %{status: :starting} = state),
    do: {:noreply, %{state | waiters: [{from, {:get, name, options}} | state.waiters]}}

  def handle_call({:get, name, options}, from, state) do
    with :ok <- validate_get(name, options),
         {:ok, state, _id} <-
           request(
             state,
             "resolver.get",
             get_params(name, options),
             from,
             Keyword.get(options, :timeout, @default_timeout)
           ) do
      {:noreply, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:release, lease_id}, from, state) do
    case request(
           state,
           "resolver.release",
           %{"path_lease_ids" => [lease_id]},
           from,
           @default_timeout
         ) do
      {:ok, state, _} -> {:noreply, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:close, _from, %{status: :closed} = state), do: {:reply, :ok, state}

  def handle_call(:close, from, state) do
    case request(state, "rpc.shutdown", %{}, from, @default_timeout) do
      {:ok, state, _} -> {:noreply, %{state | status: :closing}}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_info({port, {:data, data}}, %{port: port} = state) do
    handle_data(state.buffer <> data, %{state | buffer: <<>>})
  end

  def handle_info({port, {:exit_status, status}}, %{port: port} = state),
    do: fail_all({:error, {:child_exit, status}}, state)

  def handle_info({:deadline, id}, state) do
    case Map.pop(state.pending, id) do
      {nil, _} ->
        {:noreply, state}

      {{kind, from, timer}, pending} ->
        if timer, do: Process.cancel_timer(timer)
        send_cancel(state, id)

        reply_if_present(
          from,
          {:error, %Error{kind: "deadline_exceeded", message: "request deadline exceeded"}}
        )

        if kind == :initialize do
          fail_all(
            {:error,
             %Error{
               kind: "deadline_exceeded",
               message: "session initialization deadline exceeded"
             }},
            %{state | pending: pending}
          )
        else
          state = remove_caller(state, id)
          {:noreply, %{state | pending: pending, abandoned: MapSet.put(state.abandoned, id)}}
        end
    end
  end

  def handle_info({:prompt_result, id, answer}, state) do
    case Map.pop(state.callbacks, id) do
      {nil, _callbacks} ->
        {:noreply, state}

      {_parent_id, callbacks} ->
        send_message(state, prompt_response(id, answer))
        {:noreply, %{state | callbacks: callbacks}}
    end
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    case Map.pop(state.callers, ref) do
      {nil, _callers} ->
        {:noreply, state}

      {id, callers} ->
        case Map.pop(state.pending, id) do
          {nil, _pending} ->
            {:noreply, %{state | callers: callers}}

          {{_kind, _from, timer}, pending} ->
            if timer, do: Process.cancel_timer(timer)
            send_cancel(state, id)
            {:noreply, %{state | pending: pending, callers: callers}}
        end
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp handle_data(data, state) do
    case :binary.match(data, "\n") do
      :nomatch ->
        if byte_size(data) > state.limits.max_frame_bytes do
          fail_all(
            {:error, %Error{kind: "protocol", message: "frame exceeds negotiated limit"}},
            state
          )
        else
          {:noreply, %{state | buffer: data}}
        end

      {offset, 1} ->
        body = binary_part(data, 0, offset)
        tail = binary_part(data, offset + 1, byte_size(data) - offset - 1)

        case Codec.decode(<<body::binary, ?\n>>, state.limits.max_frame_bytes) do
          {:ok, message} ->
            case handle_message(message, state) do
              {:noreply, state} -> handle_data(tail, state)
              other -> other
            end

          {:error, reason} ->
            fail_all(
              {:error, %Error{kind: "protocol", message: "invalid frame: #{reason}"}},
              state
            )
        end
    end
  end

  defp handle_message(%{"id" => id, "result" => result}, state) when is_integer(id) do
    case Map.pop(state.pending, id) do
      {nil, _} ->
        if MapSet.member?(state.abandoned, id) do
          {:noreply, %{state | abandoned: MapSet.delete(state.abandoned, id)}}
        else
          fail_all({:error, %Error{kind: "protocol", message: "unexpected response id"}}, state)
        end

      {{:initialize, _from, timer}, pending} ->
        if timer, do: Process.cancel_timer(timer)

        with :ok <- validate_initialize(result, state) do
          state = %{
            state
            | pending: pending,
              status: :ready,
              methods: MapSet.new(result["methods"] || []),
              limits: normalize_limits(result["limits"], state.limits)
          }

          waiters = Enum.reverse(state.waiters)
          state = %{state | waiters: []}

          Enum.each(waiters, fn {from, {:get, name, options}} ->
            GenServer.cast(self(), {:retry, from, name, options})
          end)

          {:noreply, state}
        else
          {:error, reason} -> fail_all({:error, reason}, state)
        end

      {{:request, from, timer}, pending} ->
        if timer, do: Process.cancel_timer(timer)
        reply = decode_result(result)
        GenServer.reply(from, reply)

        state = remove_caller(state, id)

        if state.status == :closing do
          Port.close(state.port)
          {:stop, :normal, %{state | pending: pending, status: :closed}}
        else
          {:noreply, %{state | pending: pending}}
        end
    end
  end

  defp handle_message(%{"id" => id, "error" => error}, state) when is_integer(id) do
    case Map.pop(state.pending, id) do
      {nil, _} ->
        if MapSet.member?(state.abandoned, id) do
          {:noreply, %{state | abandoned: MapSet.delete(state.abandoned, id)}}
        else
          fail_all({:error, %Error{kind: "protocol", message: "unexpected response id"}}, state)
        end

      {{:initialize, nil, timer}, pending} ->
        if timer, do: Process.cancel_timer(timer)
        fail_all({:error, Error.from_response(%{"error" => error})}, %{state | pending: pending})

      {{_kind, from, timer}, pending} ->
        if timer, do: Process.cancel_timer(timer)
        reply_if_present(from, {:error, Error.from_response(%{"error" => error})})
        state = remove_caller(state, id)
        {:noreply, %{state | pending: pending}}
    end
  end

  defp handle_message(
         %{"method" => "client.prompt", "id" => id, "_meta" => meta, "params" => params},
         state
       )
       when is_integer(id) and is_map(meta) and is_map(params) and is_function(state.prompt, 1) do
    with {:ok, parent_id} <- validate_callback(meta, id, state),
         :ok <- validate_prompt_params(params),
         true <- Map.has_key?(state.pending, parent_id) do
      parent = self()

      Task.Supervisor.start_child(SecretSpec.TaskSupervisor, fn ->
        send(parent, {:prompt_result, id, state.prompt.(params)})
      end)

      {:noreply,
       %{state | callbacks: Map.put(state.callbacks, id, parent_id), last_callback_id: id}}
    else
      _ ->
        fail_all({:error, %Error{kind: "protocol", message: "invalid callback request"}}, state)
    end
  end

  defp handle_message(%{"method" => method} = message, state)
       when is_binary(method) and not is_map_key(message, "id"),
       do: {:noreply, state}

  defp handle_message(_, state),
    do: fail_all({:error, %Error{kind: "protocol", message: "invalid message"}}, state)

  @impl true
  def handle_cast({:retry, from, name, options}, state),
    do: handle_call({:get, name, options}, from, state)

  defp request(state, method, params, from, timeout) do
    cond do
      method != "rpc.shutdown" and not MapSet.member?(state.methods, method) ->
        {:error, %Error{kind: "capability_required", message: "method not advertised"}}

      map_size(state.pending) >= state.limits.max_in_flight ->
        {:error, %Error{kind: "busy", message: "maximum in-flight requests reached"}}

      true ->
        send_request(state, method, params, from, timeout)
    end
  end

  defp send_request(state, method, params, from, timeout) do
    id = state.next_id
    deadline = System.system_time(:millisecond) + timeout

    message = %{
      "jsonrpc" => "2.0",
      "id" => id,
      "method" => method,
      "_meta" => %{"deadline_unix_ms" => deadline},
      "params" => params
    }

    with :ok <- send_message(state, message) do
      timer = Process.send_after(self(), {:deadline, id}, timeout)
      caller_ref = Process.monitor(elem(from, 0))
      pending = Map.put(state.pending, id, {:request, from, timer})

      {:ok,
       %{
         state
         | next_id: id + 1,
           pending: pending,
           callers: Map.put(state.callers, caller_ref, id)
       }, id}
    end
  end

  defp remove_caller(state, id) do
    case Enum.find(state.callers, fn {_ref, caller_id} -> caller_id == id end) do
      {ref, _id} ->
        Process.demonitor(ref, [:flush])
        %{state | callers: Map.delete(state.callers, ref)}

      nil ->
        state
    end
  end

  defp reply_if_present(nil, _reply), do: :ok
  defp reply_if_present(from, reply), do: GenServer.reply(from, reply)

  defp send_message(state, message) do
    case Codec.encode(message, state.limits.max_frame_bytes) do
      {:ok, frame} ->
        Port.command(state.port, frame)
        :ok

      error ->
        error
    end
  end

  defp send_cancel(state, id),
    do:
      send_message(state, %{
        "jsonrpc" => "2.0",
        "method" => "rpc.cancel",
        "params" => %{"id" => id}
      })

  defp fail_all(reply, state) do
    Enum.each(state.pending, fn
      {_id, {_kind, nil, timer}} ->
        if timer, do: Process.cancel_timer(timer)

      {_id, {_kind, from, timer}} ->
        if timer, do: Process.cancel_timer(timer)
        reply_if_present(from, reply)
    end)

    Enum.each(state.waiters, fn {from, _request} -> reply_if_present(from, reply) end)
    Enum.each(state.callers, fn {ref, _id} -> Process.demonitor(ref, [:flush]) end)
    safe_close_port(state.port)
    {:stop, :normal, %{state | pending: %{}, callers: %{}, waiters: [], callbacks: %{}}}
  end

  defp initialize_application(options) do
    manifest = Keyword.get(options, :manifest)

    %{
      "manifest" => manifest_value(manifest),
      "provider" => Keyword.get(options, :provider),
      "profile" => Keyword.get(options, :profile),
      "scope" => Keyword.get(options, :scope),
      "reason" => Keyword.get(options, :reason)
    }
  end

  defp manifest_value(path) when is_binary(path),
    do: %{"kind" => "path", "path" => Path.expand(path)}

  defp manifest_value(%{toml: toml, base_dir: base_dir}),
    do: %{"kind" => "inline", "toml" => toml, "base_dir" => Path.expand(base_dir)}

  defp manifest_value(_), do: nil

  defp get_params(name, options),
    do: %{
      "name" => name,
      "representation" => Atom.to_string(Keyword.get(options, :representation, :auto)),
      "purpose" => Keyword.get(options, :purpose) |> normalize_purpose()
    }

  defp normalize_purpose(purpose) when is_map(purpose),
    do: Map.new(purpose, fn {k, v} -> {to_string(k), v} end)

  defp validate_get(name, options) when is_binary(name) and byte_size(name) <= 4096 do
    case Keyword.get(options, :purpose) do
      %{consumer: consumer, operation: operation}
      when is_binary(consumer) and is_binary(operation) and byte_size(consumer) > 0 and
             byte_size(operation) > 0 ->
        :ok

      %{"consumer" => consumer, "operation" => operation}
      when is_binary(consumer) and is_binary(operation) ->
        :ok

      _ ->
        {:error,
         %Error{
           kind: "invalid_request",
           message: "purpose with consumer and operation is required"
         }}
    end
  end

  defp validate_get(_, _),
    do: {:error, %Error{kind: "invalid_request", message: "secret name is invalid"}}

  defp normalize_limits(limits, defaults) when is_map(limits) do
    %{
      max_frame_bytes:
        Map.get(
          limits,
          "max_frame_bytes",
          Map.get(limits, :max_frame_bytes, defaults.max_frame_bytes)
        ),
      max_in_flight:
        Map.get(limits, "max_in_flight", Map.get(limits, :max_in_flight, defaults.max_in_flight))
    }
  end

  defp normalize_limits(_, defaults), do: defaults

  defp validate_initialize(
         %{
           "protocol" => @protocol,
           "version" => @version,
           "methods" => methods,
           "limits" => limits
         },
         _state
       )
       when is_list(methods) and is_map(limits),
       do:
         if(Enum.all?(methods, &is_binary/1),
           do: :ok,
           else: {:error, %Error{kind: "protocol", message: "invalid methods"}}
         )

  defp validate_initialize(_, _),
    do: {:error, %Error{kind: "protocol", message: "invalid initialization response"}}

  defp decode_result(%{"status" => "undeclared"}), do: :undeclared
  defp decode_result(%{"status" => "missing", "required" => required}), do: {:missing, required}
  defp decode_result(%{"released" => released}) when is_integer(released), do: :ok
  defp decode_result(%{} = result) when map_size(result) == 0, do: :ok

  defp decode_result(%{"status" => "resolved"} = result),
    do:
      {:ok,
       struct(Secret, %{
         representation: result["representation"],
         value: result["value"],
         path: result["path"],
         lease_id: result["path_lease_id"] || result["lease_id"],
         source: result["source"],
         source_provider: result["source_provider"],
         revision: result["revision"],
         expires_at: result["expires_at_unix_ms"],
         refresh_at: result["refresh_at_unix_ms"]
       })}

  defp prompt_response(id, value) when is_binary(value) and byte_size(value) > 0,
    do: %{"jsonrpc" => "2.0", "id" => id, "result" => %{"value" => value}}

  defp prompt_response(id, :decline), do: prompt_error(id, "prompt declined")
  defp prompt_response(id, _), do: prompt_error(id, "invalid prompt response")

  defp prompt_error(id, message),
    do: %{
      "jsonrpc" => "2.0",
      "id" => id,
      "error" => %{
        "code" => -32008,
        "message" => "operation failed",
        "data" => %{"kind" => "declined", "message" => message}
      }
    }

  defp validate_callback(
         %{"parent_request_id" => parent_id, "deadline_unix_ms" => deadline},
         id,
         state
       ) do
    cond do
      not is_integer(parent_id) or not is_integer(deadline) -> {:error, :invalid_callback}
      id <= state.last_callback_id -> {:error, :invalid_callback}
      deadline < System.system_time(:millisecond) -> {:error, :invalid_callback}
      map_size(state.callbacks) >= state.limits.max_in_flight -> {:error, :invalid_callback}
      true -> {:ok, parent_id}
    end
  end

  defp validate_callback(_, _, _), do: {:error, :invalid_callback}

  defp validate_prompt_params(%{"name" => name, "profile" => profile})
       when is_binary(name) and byte_size(name) > 0 and is_binary(profile) and
              byte_size(profile) > 0,
       do: :ok

  defp validate_prompt_params(_), do: {:error, :invalid_prompt_params}

  defp safe_close_port(port) do
    if is_port(port),
      do:
        (try do
           Port.close(port)
         catch
           _, _ -> :ok
         end)
  end

  defp decode_result(result),
    do: {:error, %Error{kind: "protocol", message: "invalid resolver result: #{inspect(result)}"}}
end
