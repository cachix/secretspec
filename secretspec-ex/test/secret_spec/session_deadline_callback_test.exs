defmodule SecretSpec.SessionDeadlineCallbackTest do
  use ExUnit.Case, async: true
  alias SecretSpec.{Error, Session}
  alias SecretSpec.Test.FakeResolver

  @tag :tmp_dir
  test "deadline sends one cancellation and permits later session cleanup", %{tmp_dir: dir} do
    fake = FakeResolver.build(dir, no_response: "resolver.get")
    {:ok, session} = Session.start_link(FakeResolver.session_options(fake))

    assert {:error, %Error{kind: "deadline_exceeded"}} =
             Session.get(session, "TOKEN",
               timeout: 50,
               purpose: %{consumer: "test", operation: "read"}
             )

    assert :ok = Session.close(session)
  end

  @tag :tmp_dir
  test "caller death cancels a pending request", %{tmp_dir: dir} do
    fake = FakeResolver.build(dir, no_response: "resolver.get")
    parent = self()

    owner =
      spawn(fn ->
        {:ok, session} = Session.start(FakeResolver.session_options(fake))
        send(parent, {:session, session})

        Session.get(session, "TOKEN",
          timeout: 5_000,
          purpose: %{consumer: "test", operation: "read"}
        )
      end)

    receive do
      {:session, _} -> :ok
    after
      2_000 -> flunk("session not started")
    end

    Process.exit(owner, :kill)
  end

  @tag :tmp_dir
  test "late responses do not satisfy another request", %{tmp_dir: dir} do
    fake = FakeResolver.build(dir, delay: 150)
    {:ok, session} = Session.start_link(FakeResolver.session_options(fake))

    assert {:error, %Error{kind: "deadline_exceeded"}} =
             Session.get(session, "ONE",
               timeout: 30,
               purpose: %{consumer: "test", operation: "read"}
             )

    assert {:ok, _} = Session.get(session, "TWO", purpose: %{consumer: "test", operation: "read"})
    Session.close(session)
  end

  @tag :tmp_dir
  test "prompt callback is sent while a request is active", %{tmp_dir: dir} do
    fake = FakeResolver.build(dir, send_callback: true)

    parent = self()

    prompt = fn params ->
      send(parent, {:prompt, params})
      "yes"
    end

    {:ok, session} = Session.start_link(FakeResolver.session_options(fake, prompt: prompt))

    assert {:ok, _} =
             Session.get(session, "TOKEN", purpose: %{consumer: "test", operation: "read"})

    assert_receive {:prompt, %{"name" => "TOKEN", "profile" => "default"}}, 1_000
    Session.close(session)
  end
end
