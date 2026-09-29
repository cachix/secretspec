defmodule SecretSpec.SessionLifecycleTest do
  use ExUnit.Case, async: true
  alias SecretSpec.Session
  alias SecretSpec.Test.FakeResolver

  @tag :tmp_dir
  test "close during initialization terminates the session", %{tmp_dir: dir} do
    fake = FakeResolver.build(dir, hang: "rpc.initialize")
    {:ok, session} = Session.start_link(FakeResolver.session_options(fake))
    assert :ok = Session.close(session)
    assert :ok = wait_until(fn -> not Process.alive?(session) end, 2_000)
  end

  @tag :tmp_dir
  test "resolver crash fails pending callers", %{tmp_dir: dir} do
    fake = FakeResolver.build(dir, exit: "resolver.get")
    {:ok, session} = Session.start_link(FakeResolver.session_options(fake))

    assert {:error, _} =
             Session.get(session, "TOKEN", purpose: %{consumer: "test", operation: "read"})

    assert :ok = wait_until(fn -> not Process.alive?(session) end, 2_000)
  end

  @tag :tmp_dir
  test "sessions remain isolated", %{tmp_dir: dir} do
    fake_a = FakeResolver.build(dir, id: "a", get: "a")
    fake_b = FakeResolver.build(dir, id: "b", get: "b")
    {:ok, a} = Session.start_link(FakeResolver.session_options(fake_a))
    {:ok, b} = Session.start_link(FakeResolver.session_options(fake_b))

    assert {:ok, %{value: "a"}} =
             Session.get(a, "A", purpose: %{consumer: "test", operation: "read"})

    assert {:ok, %{value: "b"}} =
             Session.get(b, "B", purpose: %{consumer: "test", operation: "read"})

    Session.close(a)
    assert Process.alive?(b)
    Session.close(b)
  end

  @tag :tmp_dir
  test "owner termination closes an unlinked session", %{tmp_dir: dir} do
    fake = FakeResolver.build(dir, hang: "rpc.initialize")
    parent = self()

    owner =
      spawn(fn ->
        {:ok, session} = Session.start(FakeResolver.session_options(fake))
        send(parent, {:session, session})
        Process.sleep(:infinity)
      end)

    session =
      receive do
        {:session, pid} -> pid
      after
        2_000 -> flunk("session not started")
      end

    ref = Process.monitor(session)
    Process.exit(owner, :kill)
    assert_receive {:DOWN, ^ref, :process, ^session, _}, 2_000
  end

  @tag :os_process
  @tag timeout: 120_000
  @tag :tmp_dir
  test "repeated session cycles leave no marked descendants", %{tmp_dir: dir} do
    marker = "secretspec-test-#{System.unique_integer([:positive])}"

    for n <- 1..25 do
      fake = FakeResolver.build(dir, id: "cycle-#{n}", marker: marker)
      {:ok, session} = Session.start_link(FakeResolver.session_options(fake))

      assert {:ok, _} =
               Session.get(session, "TOKEN", purpose: %{consumer: "test", operation: "read"})

      assert :ok = Session.close(session)
    end

    assert :ok = wait_until(fn -> FakeResolver.marked_processes(marker) == [] end, 5_000)
  end

  defp wait_until(fun, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout
    poll_until(fun, deadline)
  end

  defp poll_until(fun, deadline) do
    if fun.() do
      :ok
    else
      if System.monotonic_time(:millisecond) < deadline do
        Process.sleep(25)
        poll_until(fun, deadline)
      else
        {:error, :timeout}
      end
    end
  end
end
