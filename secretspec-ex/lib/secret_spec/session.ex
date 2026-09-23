defmodule SecretSpec.Session do
  use GenServer

  alias SecretSpec.{Codec, Error, Secret}
  @default_startup 5_000
  @default_timeout 30_000
  @max_request_timeout 300_000
  @default_max_frame_bytes 32 * 1024
  @absolute_max_frame_bytes 1_048_576
  @protocol "secretspec.resolver"
  @version 1
  @process_group_poll_ms 25
  @process_group_wait_attempts 200

  defstruct port: nil,
            process_grouped: false,
            process_groups: [],
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
            deadlines: %{},
            last_callback_id: 0,
            owner_ref: nil

  def start(options), do: GenServer.start(__MODULE__, Keyword.put(options, :owner, self()))

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
    Process.flag(:trap_exit, true)
    executable = Keyword.get(options, :executable) || System.find_executable("secretspec")

    if is_nil(executable) do
      {:stop, {:error, :executable_not_found}}
    else
      args = Keyword.get(options, :arguments, ["serve"])

      {spawn_executable, spawn_args} = spawn_command(executable, args)

      port =
        Port.open({:spawn_executable, spawn_executable}, [
          :binary,
          :exit_status,
          {:args, spawn_args}
        ])

      owner_ref =
        case Keyword.get(options, :owner) do
          owner when is_pid(owner) -> Process.monitor(owner)
          _ -> nil
        end

      process_grouped = is_binary(System.find_executable("setsid"))
      process_groups = if process_grouped, do: process_groups_for_port(port), else: []

      state = %__MODULE__{
        port: port,
        process_grouped: process_grouped,
        process_groups: process_groups,
        executable: executable,
        options: options,
        prompt: Keyword.get(options, :prompt),
        owner_ref: owner_ref
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

      deadlines =
        Map.put(state.deadlines, id, System.system_time(:millisecond) + @default_startup)

      {:noreply, %{state | next_id: id + 1, pending: pending, deadlines: deadlines}}
    else
      {:error, :port_closed} -> {:stop, :normal, state}
      {:error, reason} -> {:stop, reason, state}
    end
  end

  @impl true
  def handle_call({:get, name, options}, from, %{status: :starting} = state) do
    deadline = System.system_time(:millisecond) + Keyword.get(options, :timeout, @default_timeout)
    {:noreply, %{state | waiters: [{from, {:get, name, options}, deadline} | state.waiters]}}
  end

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

  def handle_call(:close, _from, %{status: :starting} = state) do
    safe_close_port(state.port, state.process_groups, state.process_grouped)
    {:stop, :normal, :ok, %{state | status: :closed}}
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

  def handle_info({:EXIT, port, reason}, %{port: port} = state),
    do: fail_all({:error, {:child_exit, reason}}, state)

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

        state = cancel_callbacks_for_parent(state, id)

        if kind == :initialize or state.status == :closing do
          fail_all(
            {:error,
             %Error{
               kind: "deadline_exceeded",
               message:
                 if(kind == :initialize,
                   do: "session initialization deadline exceeded",
                   else: "shutdown deadline exceeded"
                 )
             }},
            %{state | pending: pending, deadlines: Map.delete(state.deadlines, id)}
          )
        else
          state = remove_caller(state, id)

          {:noreply,
           %{
             state
             | pending: pending,
               deadlines: Map.delete(state.deadlines, id),
               abandoned: MapSet.put(state.abandoned, id)
           }}
        end
    end
  end

  def handle_info({:prompt_result, id, answer}, state) do
    case Map.pop(state.callbacks, id) do
      {nil, _callbacks} ->
        {:noreply, state}

      {callback, callbacks} ->
        if callback.timer, do: Process.cancel_timer(callback.timer)

        response =
          if callback.deadline > System.system_time(:millisecond) do
            prompt_response(id, answer)
          else
            prompt_error(id, "prompt deadline exceeded")
          end

        case send_message(state, response) do
          :ok ->
            {:noreply, %{state | callbacks: callbacks}}

          {:error, :frame_too_large} ->
            send_message(state, prompt_too_large_error(id))
            {:noreply, %{state | callbacks: callbacks}}

          {:error, _reason} ->
            fail_all(
              {:error, %Error{kind: "protocol", message: "unable to send prompt response"}},
              %{state | callbacks: callbacks}
            )
        end
    end
  end

  def handle_info({:callback_deadline, id}, state) do
    case Map.pop(state.callbacks, id) do
      {nil, _callbacks} ->
        {:noreply, state}

      {callback, callbacks} ->
        Process.exit(callback.pid, :kill)
        send_message(state, prompt_error(id, "prompt deadline exceeded"))
        {:noreply, %{state | callbacks: callbacks}}
    end
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{owner_ref: ref} = state),
    do: fail_all({:error, :owner_down}, state)

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
            state = cancel_callbacks_for_parent(state, id)

            {:noreply,
             %{
               state
               | pending: pending,
                 callers: callers,
                 deadlines: Map.delete(state.deadlines, id),
                 abandoned: MapSet.put(state.abandoned, id)
             }}
        end
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp handle_data(data, state) do
    frame_limit = frame_limit(state)

    case :binary.match(data, "\n") do
      :nomatch ->
        if byte_size(data) > frame_limit do
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

        case Codec.decode(<<body::binary, ?\n>>, frame_limit) do
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
              deadlines: Map.delete(state.deadlines, id),
              status: :ready,
              methods: MapSet.new(result["methods"] || []),
              limits: normalize_limits(result["limits"], state.limits)
          }

          waiters = Enum.reverse(state.waiters)
          state = %{state | waiters: []}

          Enum.each(waiters, fn {from, {:get, name, options}, deadline} ->
            if deadline > System.system_time(:millisecond) do
              GenServer.cast(self(), {:retry, from, name, options, deadline})
            else
              GenServer.reply(
                from,
                {:error, %Error{kind: "deadline_exceeded", message: "request deadline exceeded"}}
              )
            end
          end)

          {:noreply, state}
        else
          {:error, reason} -> fail_all({:error, reason}, state)
        end

      {{:request, from, timer}, pending} ->
        if timer, do: Process.cancel_timer(timer)
        reply = decode_result(result)
        GenServer.reply(from, reply)
        state = cancel_callbacks_for_parent(state, id)
        state = remove_caller(state, id)
        state = %{state | pending: pending, deadlines: Map.delete(state.deadlines, id)}

        if state.status == :closing do
          safe_close_port(state.port, state.process_groups, state.process_grouped)
          {:stop, :normal, %{state | status: :closed}}
        else
          {:noreply, state}
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

        fail_all(
          {:error, Error.from_response(%{"error" => error})},
          %{state | pending: pending, deadlines: Map.delete(state.deadlines, id)}
        )

      {{_kind, from, timer}, pending} ->
        if timer, do: Process.cancel_timer(timer)
        reply_if_present(from, {:error, Error.from_response(%{"error" => error})})
        state = cancel_callbacks_for_parent(state, id)
        state = remove_caller(state, id)
        {:noreply, %{state | pending: pending, deadlines: Map.delete(state.deadlines, id)}}
    end
  end

  defp handle_message(
         %{
           "jsonrpc" => "2.0",
           "method" => "client.prompt",
           "id" => id,
           "_meta" => meta,
           "params" => params
         } = message,
         state
       )
       when is_integer(id) and is_map(meta) and is_map(params) and map_size(message) == 5 and
              map_size(meta) == 2 and is_function(state.prompt, 1) do
    with {:ok, parent_id, deadline} <- validate_callback(meta, id, state),
         :ok <- validate_prompt_params(params) do
      parent = self()

      case Task.Supervisor.start_child(SecretSpec.TaskSupervisor, fn ->
             send(parent, {:prompt_result, id, state.prompt.(params)})
           end) do
        {:ok, pid} ->
          timer =
            Process.send_after(
              self(),
              {:callback_deadline, id},
              max(deadline - System.system_time(:millisecond), 0)
            )

          {:noreply,
           %{
             state
             | callbacks:
                 Map.put(state.callbacks, id, %{
                   parent_id: parent_id,
                   pid: pid,
                   deadline: deadline,
                   timer: timer
                 }),
               last_callback_id: id
           }}

        {:error, _reason} ->
          fail_all({:error, %Error{kind: "internal", message: "unable to start prompt"}}, state)
      end
    else
      _ ->
        fail_all({:error, %Error{kind: "protocol", message: "invalid callback request"}}, state)
    end
  end

  defp handle_message(%{"jsonrpc" => "2.0", "method" => method} = message, state)
       when is_binary(method) do
    if valid_notification?(message) do
      {:noreply, state}
    else
      fail_all({:error, %Error{kind: "protocol", message: "invalid notification"}}, state)
    end
  end

  defp handle_message(_, state),
    do: fail_all({:error, %Error{kind: "protocol", message: "invalid message"}}, state)

  @impl true
  def handle_cast({:retry, from, name, options, deadline}, state) do
    if deadline > System.system_time(:millisecond) do
      case validate_get(name, options) do
        :ok ->
          timeout = deadline - System.system_time(:millisecond)

          case request(state, "resolver.get", get_params(name, options), from, timeout) do
            {:ok, state, _id} ->
              {:noreply, state}

            {:error, reason} ->
              GenServer.reply(from, {:error, reason})
              {:noreply, state}
          end

        {:error, reason} ->
          GenServer.reply(from, {:error, reason})
          {:noreply, state}
      end
    else
      GenServer.reply(
        from,
        {:error, %Error{kind: "deadline_exceeded", message: "request deadline exceeded"}}
      )

      {:noreply, state}
    end
  end

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
    with {:ok, timeout} <- normalize_timeout(timeout) do
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
        deadlines = Map.put(state.deadlines, id, deadline)

        {:ok,
         %{
           state
           | next_id: id + 1,
             pending: pending,
             deadlines: deadlines,
             callers: Map.put(state.callers, caller_ref, id)
         }, id}
      end
    end
  end

  defp normalize_timeout(timeout) when is_integer(timeout) and timeout <= 0,
    do: {:error, %Error{kind: "deadline_exceeded", message: "request deadline exceeded"}}

  defp normalize_timeout(timeout) when is_integer(timeout),
    do: {:ok, min(timeout, @max_request_timeout)}

  defp normalize_timeout(_),
    do: {:error, %Error{kind: "invalid_request", message: "request timeout is invalid"}}

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
    case Codec.encode(message, frame_limit(state)) do
      {:ok, frame} ->
        try do
          Port.command(state.port, frame)
          :ok
        catch
          :error, :badarg -> {:error, :port_closed}
        end

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

    Enum.each(state.waiters, fn {from, _request, _deadline} -> reply_if_present(from, reply) end)
    Enum.each(state.callers, fn {ref, _id} -> Process.demonitor(ref, [:flush]) end)
    if state.owner_ref, do: Process.demonitor(state.owner_ref, [:flush])
    Enum.each(state.callbacks, fn {_id, %{pid: pid}} -> Process.exit(pid, :kill) end)
    safe_close_port(state.port, state.process_groups, state.process_grouped)

    {:stop, :normal,
     %{state | pending: %{}, callers: %{}, waiters: [], callbacks: %{}, deadlines: %{}}}
  end

  defp cancel_callbacks_for_parent(state, parent_id) do
    callbacks =
      Enum.reduce(state.callbacks, state.callbacks, fn {callback_id, callback}, callbacks ->
        if callback.parent_id == parent_id do
          Process.exit(callback.pid, :kill)
          Map.delete(callbacks, callback_id)
        else
          callbacks
        end
      end)

    %{state | callbacks: callbacks}
  end

  defp valid_notification?(message) do
    MapSet.new(Map.keys(message)) == MapSet.new(["jsonrpc", "method", "params"]) and
      message["jsonrpc"] == "2.0" and is_binary(message["method"]) and
      byte_size(message["method"]) in 1..256 and is_map(message["params"])
  end

  defp frame_limit(%{status: :starting}), do: @absolute_max_frame_bytes
  defp frame_limit(state), do: state.limits.max_frame_bytes

  defp spawn_command(executable, args) do
    executable = Path.expand(executable)

    case {System.find_executable("setsid"), System.find_executable("sh")} do
      {setsid, shell} when is_binary(setsid) and is_binary(shell) ->
        {shell,
         ["-c", "exec setsid --wait \"$@\" 2>/dev/null", "secretspec-resolver", executable | args]}

      {setsid, _} when is_binary(setsid) ->
        {setsid, ["--wait", executable | args]}

      _ ->
        {executable, args}
    end
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

  defp normalize_limits(limits, _defaults) do
    %{
      max_frame_bytes: limits["max_frame_bytes"],
      max_in_flight: limits["max_in_flight"]
    }
  end

  defp validate_initialize(
         %{
           "protocol" => @protocol,
           "version" => @version,
           "methods" => methods,
           "limits" => limits
         },
         state
       )
       when is_list(methods) and is_map(limits) do
    cond do
      not Enum.all?(methods, &is_binary/1) ->
        {:error, %Error{kind: "protocol", message: "invalid methods"}}

      validate_limits(limits, state.limits) != :ok ->
        {:error, %Error{kind: "protocol", message: "invalid negotiated limits"}}

      true ->
        :ok
    end
  end

  defp validate_initialize(_, _),
    do: {:error, %Error{kind: "protocol", message: "invalid initialization response"}}

  defp validate_limits(%{"max_frame_bytes" => frame_bytes, "max_in_flight" => in_flight}, offered)
       when is_integer(frame_bytes) and is_integer(in_flight) and
              frame_bytes >= 4096 and frame_bytes <= @absolute_max_frame_bytes and
              in_flight >= 1 and in_flight <= 32 and
              frame_bytes <= offered.max_frame_bytes and in_flight <= offered.max_in_flight,
       do: :ok

  defp validate_limits(_, _), do: {:error, :invalid_limits}

  defp decode_result(%{"status" => "undeclared"}), do: :undeclared
  defp decode_result(%{"status" => "missing", "required" => required}), do: {:missing, required}
  defp decode_result(%{"released" => released}) when is_integer(released), do: :ok
  defp decode_result(%{} = result) when map_size(result) == 0, do: :ok

  defp decode_result(
         %{"status" => "resolved", "representation" => "value", "value" => value} = result
       )
       when is_binary(value) do
    {:ok, resolved_secret(result, value: value)}
  end

  defp decode_result(
         %{"status" => "resolved", "representation" => "path", "path" => path} = result
       )
       when is_binary(path) do
    lease_id = result["path_lease_id"] || result["lease_id"]

    if is_binary(lease_id) do
      {:ok, resolved_secret(result, path: path, lease_id: lease_id)}
    else
      {:error, %Error{kind: "protocol", message: "invalid resolver result: missing path lease"}}
    end
  end

  defp decode_result(_result),
    do: {:error, %Error{kind: "protocol", message: "invalid resolver result"}}

  defp resolved_secret(result, fields) do
    struct(
      Secret,
      Map.merge(Map.new(fields), %{
        representation: result["representation"],
        source: result["source"],
        source_provider: result["source_provider"],
        revision: result["revision"],
        expires_at: result["expires_at_unix_ms"],
        refresh_at: result["refresh_at_unix_ms"]
      })
    )
  end

  defp prompt_response(id, value) when is_binary(value) and byte_size(value) > 0,
    do: %{"jsonrpc" => "2.0", "id" => id, "result" => %{"value" => value}}

  defp prompt_response(id, :decline), do: prompt_error(id, "prompt declined")
  defp prompt_response(id, _), do: prompt_error(id, "invalid prompt response")

  defp prompt_error(id, _message),
    do: %{
      "jsonrpc" => "2.0",
      "id" => id,
      "error" => %{
        "code" => -32008,
        "message" => "operation failed",
        "data" => %{"kind" => "operation_failed", "retryable" => false}
      }
    }

  defp prompt_too_large_error(id),
    do: %{
      "jsonrpc" => "2.0",
      "id" => id,
      "error" => %{
        "code" => -32009,
        "message" => "message too large",
        "data" => %{"kind" => "message_too_large", "retryable" => false}
      }
    }

  defp validate_callback(
         %{"parent_request_id" => parent_id, "deadline_unix_ms" => deadline} = meta,
         id,
         state
       ) do
    parent_deadline = Map.get(state.deadlines, parent_id)

    if map_size(meta) != 2 do
      {:error, :invalid_callback}
    else
      cond do
        not is_integer(parent_deadline) or not is_integer(deadline) -> {:error, :invalid_callback}
        id <= state.last_callback_id -> {:error, :invalid_callback}
        deadline < System.system_time(:millisecond) -> {:error, :invalid_callback}
        deadline > parent_deadline -> {:error, :invalid_callback}
        map_size(state.callbacks) >= state.limits.max_in_flight -> {:error, :invalid_callback}
        true -> {:ok, parent_id, deadline}
      end
    end
  end

  defp validate_prompt_params(params) when is_map(params) do
    keys = MapSet.new(Map.keys(params))
    required = MapSet.new(["name", "profile"])
    allowed = MapSet.new(["name", "profile", "target_provider"])

    with true <- MapSet.subset?(required, keys),
         true <- MapSet.subset?(keys, allowed),
         name when is_binary(name) and byte_size(name) in 1..4096 <- params["name"],
         profile when is_binary(profile) and byte_size(profile) in 1..4096 <- params["profile"],
         target when is_binary(target) and byte_size(target) <= 32768 <-
           Map.get(params, "target_provider", "") do
      if Map.has_key?(params, "target_provider") or target == "",
        do: :ok,
        else: {:error, :invalid_prompt_params}
    else
      _ -> {:error, :invalid_prompt_params}
    end
  end

  defp validate_prompt_params(_), do: {:error, :invalid_prompt_params}

  defp process_groups_for_port(port) do
    case :erlang.port_info(port, :os_pid) do
      {:os_pid, root} ->
        {_pids, groups} = await_process_group(root, @process_group_wait_attempts)
        groups

      nil ->
        []
    end
  end

  defp safe_close_port(port, groups, grouped) when is_port(port) do
    case :erlang.port_info(port, :os_pid) do
      {:os_pid, pid} -> terminate_process(pid, groups, grouped)
      nil -> :ok
      :undefined -> :ok
    end

    try do
      Port.close(port)
    catch
      _, _ -> :ok
    end
  end

  defp safe_close_port(_, _, _), do: :ok

  defp terminate_process(root, known_groups, grouped) when is_integer(root) do
    {pids, groups} =
      if known_groups == [] do
        if grouped,
          do: await_process_group(root, @process_group_wait_attempts),
          else: process_tree(root)
      else
        {[], known_groups}
      end

    descendants = List.delete(pids, root)

    with kill when is_binary(kill) <- System.find_executable("kill") do
      if groups == [] do
        terminate_pids(kill, descendants, "TERM")
        terminate_pids(kill, [root], "TERM")
        Process.sleep(75)

        {remaining, remaining_groups} = process_tree(root)
        terminate_groups(kill, remaining_groups, "KILL")
        terminate_pids(kill, List.delete(remaining, root), "KILL")
      else
        terminate_groups(kill, groups, "TERM")
        Process.sleep(75)
        terminate_groups(kill, groups, "KILL")
      end

      terminate_pids(kill, [root], "KILL")
      wait_for_groups(kill, groups, 20)
      wait_for_process_tree(kill, root, 20)
    end
  rescue
    _ -> :ok
  end

  defp terminate_process(_, _, _), do: :ok

  defp await_process_group(root, attempts) do
    {pids, groups} = process_tree(root)

    cond do
      groups != [] ->
        {pids, groups}

      pids == [] ->
        {pids, groups}

      attempts == 0 ->
        {pids, groups}

      true ->
        Process.sleep(25)
        await_process_group(root, attempts - 1)
    end
  end

  defp process_tree(root) do
    case System.find_executable("ps") do
      nil ->
        {[root], []}

      ps ->
        with {output, 0} <- System.cmd(ps, ["-eo", "pid=,ppid=,pgid="], stderr_to_stdout: true) do
          rows =
            output
            |> String.split("\n", trim: true)
            |> Enum.flat_map(fn line ->
              case String.split(String.trim(line), ~r/\s+/) do
                [pid, ppid, pgid] ->
                  [{String.to_integer(pid), String.to_integer(ppid), String.to_integer(pgid)}]

                _ ->
                  []
              end
            end)

          root_group =
            case Enum.find(rows, fn {pid, _ppid, _pgid} -> pid == root end) do
              {_pid, _ppid, pgid} -> pgid
              nil -> nil
            end

          pids =
            if Enum.any?(rows, fn {pid, _ppid, _pgid} -> pid == root end) do
              collect_descendants(root, rows, [])
            else
              []
            end

          groups =
            rows
            |> Enum.filter(fn {pid, _ppid, _pgid} -> pid in pids end)
            |> Enum.map(fn {_pid, _ppid, pgid} -> pgid end)
            |> Enum.uniq()
            |> Enum.reject(&(&1 == root_group))

          {pids, groups}
        else
          _ -> {[root], []}
        end
    end
  rescue
    _ -> {[root], []}
  end

  defp collect_descendants(parent, rows, found) do
    children =
      for {pid, ^parent, _pgid} <- rows, pid not in found, do: pid

    case children do
      [] -> [parent | found]
      _ -> Enum.reduce(children, [parent | found], &collect_descendants(&1, rows, &2))
    end
  end

  defp terminate_groups(kill, groups, signal) do
    Enum.each(groups, &run_kill(kill, ["-#{signal}", "--", "-#{&1}"]))
  end

  defp terminate_pids(kill, pids, signal) do
    Enum.each(pids, &run_kill(kill, ["-#{signal}", Integer.to_string(&1)]))
  end

  defp wait_for_groups(_kill, [], _attempts), do: :ok

  defp wait_for_groups(_kill, _groups, 0), do: :ok

  defp wait_for_groups(kill, groups, attempts) do
    if Enum.any?(groups, &process_group_alive?(kill, &1)) do
      Process.sleep(@process_group_poll_ms)
      wait_for_groups(kill, groups, attempts - 1)
    else
      :ok
    end
  end

  defp process_group_alive?(kill, group) do
    case System.cmd(kill, ["-0", "--", "-#{group}"], stderr_to_stdout: true) do
      {_output, 0} -> true
      _ -> false
    end
  rescue
    _ -> false
  end

  defp wait_for_process_tree(_kill, _root, 0), do: :ok

  defp wait_for_process_tree(kill, root, attempts) do
    {pids, groups} = process_tree(root)

    if pids == [] do
      :ok
    else
      terminate_groups(kill, groups, "KILL")
      terminate_pids(kill, pids, "KILL")
      Process.sleep(25)
      wait_for_process_tree(kill, root, attempts - 1)
    end
  end

  defp run_kill(kill, args) do
    System.cmd(kill, args, stderr_to_stdout: true)
    :ok
  rescue
    _ -> :ok
  end
end
