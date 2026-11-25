defmodule SecretSpec.SessionDeadlineCallbackTest do
  use ExUnit.Case, async: true
  alias SecretSpec.{Error, Session}
  alias SecretSpec.Test.FakeResolver

  defp request_seen?(messages, method), do: Enum.any?(messages, &(&1["method"] == method))
  defp cancel_count(messages), do: Enum.count(messages, &(&1["method"] == "rpc.cancel"))

  @tag :tmp_dir
  test "deadline sends one cancellation after initialization", %{tmp_dir: dir} do
    fake = FakeResolver.build(dir, no_response: "resolver.get")
    {:ok, session} = Session.start_link(FakeResolver.session_options(fake))
    assert :ok = FakeResolver.wait_ready(fake)

    assert {:error, %Error{kind: "deadline_exceeded"}} =
             Session.get(session, "TOKEN",
               timeout: 50,
               purpose: %{consumer: "test", operation: "read"}
             )

    assert :ok =
             FakeResolver.wait_for(
               fake,
               &(request_seen?(&1, "resolver.get") and cancel_count(&1) == 1)
             )

    assert Process.alive?(session)
    assert :ok = Session.close(session)
  end

  @tag :tmp_dir
  test "caller death cancels only its pending request", %{tmp_dir: dir} do
    fake = FakeResolver.build(dir, no_response: "resolver.get")
    {:ok, session} = Session.start_link(FakeResolver.session_options(fake))
    assert :ok = FakeResolver.wait_ready(fake)
    parent = self()

    caller =
      spawn(fn ->
        send(parent, {:caller, self()})

        Session.get(session, "TOKEN",
          timeout: 5_000,
          purpose: %{consumer: "test", operation: "read"}
        )
      end)

    assert_receive {:caller, ^caller}, 1_000
    assert :ok = FakeResolver.wait_for(fake, &request_seen?(&1, "resolver.get"))
    ref = Process.monitor(caller)
    Process.exit(caller, :kill)
    assert_receive {:DOWN, ^ref, :process, ^caller, _}, 1_000
    assert :ok = FakeResolver.wait_for(fake, &(cancel_count(&1) == 1))
    assert Process.alive?(session)
    assert :ok = Session.close(session)
  end

  @tag :tmp_dir
  test "late responses do not satisfy another caller", %{tmp_dir: dir} do
    fake = FakeResolver.build(dir, delay: 150)
    {:ok, session} = Session.start_link(FakeResolver.session_options(fake))
    assert :ok = FakeResolver.wait_ready(fake)

    assert {:error, %Error{kind: "deadline_exceeded"}} =
             Session.get(session, "ONE",
               timeout: 30,
               purpose: %{consumer: "test", operation: "read"}
             )

    assert :ok =
             FakeResolver.wait_for(
               fake,
               &(request_seen?(&1, "resolver.get") and cancel_count(&1) == 1)
             )

    assert {:ok, _} = Session.get(session, "TWO", purpose: %{consumer: "test", operation: "read"})
    assert :ok = Session.close(session)
  end

  @tag :tmp_dir
  test "prompt callback is consumed before the parent request completes", %{tmp_dir: dir} do
    fake = FakeResolver.build(dir, send_callback: true)
    parent = self()

    prompt = fn params ->
      send(parent, {:prompt, params})
      "yes"
    end

    {:ok, session} = Session.start_link(FakeResolver.session_options(fake, prompt: prompt))
    assert :ok = FakeResolver.wait_ready(fake)

    assert {:ok, _} =
             Session.get(session, "TOKEN", purpose: %{consumer: "test", operation: "read"})

    assert_receive {:prompt, %{"name" => "TOKEN", "profile" => "default"}}, 1_000
    messages = FakeResolver.messages(fake)
    assert Enum.any?(messages, &(&1["id"] == 100 and get_in(&1, ["result", "value"]) == "yes"))
    assert :ok = Session.close(session)
  end
end
