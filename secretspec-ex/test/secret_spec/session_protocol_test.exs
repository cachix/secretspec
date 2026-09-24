defmodule SecretSpec.SessionProtocolTest do
  use ExUnit.Case, async: true
  alias SecretSpec.{Error, Secret, Session}
  alias SecretSpec.Test.FakeResolver

  defp start(tmp_dir, opts) do
    fake = FakeResolver.build(tmp_dir, opts)
    {:ok, session} = Session.start_link(FakeResolver.session_options(fake))
    {session, fake}
  end

  @tag :tmp_dir
  test "initializes and resolves inline, path, missing, and undeclared results", %{tmp_dir: dir} do
    {session, fake} = start(dir, get: "value")

    assert {:ok, %Secret{representation: "value", value: "value"}} =
             Session.get(session, "TOKEN", purpose: %{consumer: "test", operation: "read"})

    assert :ok = Session.close(session)

    assert [
             %{"method" => "rpc.initialize"},
             %{"method" => "resolver.get"},
             %{"method" => "rpc.shutdown"}
           ] = FakeResolver.messages(fake)

    for result <- [:path, :missing, :optional_missing, :undeclared] do
      fake = FakeResolver.build(dir, id: "#{result}", get: result)
      {:ok, session} = Session.start_link(FakeResolver.session_options(fake))

      expected =
        case result do
          :path ->
            {:ok,
             %Secret{
               name: "TOKEN",
               representation: "path",
               path: "/tmp/secret",
               lease_id: "lease-1"
             }}

          :missing ->
            {:missing, true}

          :optional_missing ->
            {:missing, false}

          :undeclared ->
            :undeclared
        end

      assert expected ==
               Session.get(session, "TOKEN", purpose: %{consumer: "test", operation: "read"})

      Session.close(session)
    end
  end

  @tag :tmp_dir
  test "requires purpose and reports malformed results", %{tmp_dir: dir} do
    {session, _} = start(dir, get: :malformed)
    assert {:error, %Error{kind: "invalid_request"}} = Session.get(session, "TOKEN")

    assert {:error, %Error{kind: "protocol"}} =
             Session.get(session, "TOKEN", purpose: %{consumer: "test", operation: "read"})

    Session.close(session)
  end

  @tag :tmp_dir
  test "supports fragmented and coalesced protocol frames", %{tmp_dir: dir} do
    {session, _fake} = start(dir, chunks: [1, 2, 3, 5, 8, 13])

    assert {:ok, %Secret{value: "secret"}} =
             Session.get(session, "TOKEN", purpose: %{consumer: "test", operation: "read"})

    assert :ok = Session.close(session)
  end

  @tag :tmp_dir
  test "processes a fatal second frame from one port write", %{tmp_dir: dir} do
    {session, fake} = start(dir, coalesced: true, coalesced_fatal: true)
    assert :ok = FakeResolver.wait_ready(fake)
    ref = Process.monitor(session)
    assert_receive {:DOWN, ^ref, :process, ^session, _}, 2_000
  end

  @tag :tmp_dir
  test "negotiated limits and methods are accepted", %{tmp_dir: dir} do
    init = %{
      "protocol" => "secretspec.resolver",
      "version" => 1,
      "server" => %{"name" => "fake", "version" => "1"},
      "methods" => ["resolver.get"],
      "limits" => %{"max_frame_bytes" => 32_768, "max_in_flight" => 1},
      "application" => %{"manifest_kind" => "path"}
    }

    {session, _} = start(dir, init: init)

    assert {:ok, %Secret{}} =
             Session.get(session, "TOKEN", purpose: %{consumer: "test", operation: "read"})

    Session.close(session)
  end

  @tag :tmp_dir
  test "invalid initialization response closes the session", %{tmp_dir: dir} do
    for init <- [
          %{"protocol" => "wrong"},
          %{"protocol" => "secretspec.resolver", "version" => 99},
          %{"protocol" => "secretspec.resolver", "version" => 1, "server" => "bad"}
        ] do
      fake = FakeResolver.build(dir, id: "bad#{System.unique_integer()}", init: init)
      {:ok, session} = Session.start_link(FakeResolver.session_options(fake))
      assert eventually_dead?(session)
    end
  end

  defp eventually_dead?(pid) do
    ref = Process.monitor(pid)

    receive do
      {:DOWN, ^ref, :process, ^pid, _} -> true
    after
      2_000 -> false
    end
  end
end
