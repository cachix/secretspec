defmodule SecretSpecTest do
  use ExUnit.Case, async: true

  alias SecretSpec.{Codec, Error, Secret}

  test "encodes and decodes framed JSON" do
    {:ok, frame} = Codec.encode(%{"jsonrpc" => "2.0", "id" => 1})
    assert {:ok, %{"jsonrpc" => "2.0", "id" => 1}} = Codec.decode(frame)
  end

  test "rejects duplicate object keys" do
    body = ~s({"jsonrpc":"2.0","jsonrpc":"2.0"})
    frame = <<body::binary, ?\n>>
    assert {:error, :duplicate_key} = Codec.decode(frame)
  end

  test "rejects oversized frames" do
    body = ~s({"value":"x"})
    frame = <<body::binary, ?\n>>
    assert {:error, :frame_too_large} = Codec.decode(frame, 4)
  end

  test "requires purpose attribution" do
    assert {:error, %Error{kind: "invalid_request"}} =
             SecretSpec.Session.get(self(), "TOKEN")
  catch
    :exit, _ -> :ok
  end

  @tag :tmp_dir
  test "runs initialize, get, and shutdown over a direct port", %{tmp_dir: tmp_dir} do
    endpoint = Path.join(tmp_dir, "endpoint.exs")

    File.write!(endpoint, """
    defmodule FakeEndpoint do
      def run do
        case IO.read(:stdio, :line) do
          :eof -> :ok
          line ->
            request = line |> String.trim_trailing(<<10>>) |> JSON.decode!()
            response = response(request)
            body = JSON.encode!(response)
            IO.binwrite(:stdio, body <> <<10>>)
            run()
        end
      end

      defp response(%{"id" => id, "method" => "rpc.initialize"}) do
        %{"jsonrpc" => "2.0", "id" => id, "result" => %{
          "protocol" => "secretspec.resolver", "version" => 1,
          "server" => %{"name" => "fake", "version" => "0"},
          "methods" => ["resolver.get", "resolver.release", "rpc.shutdown"],
          "limits" => %{"max_frame_bytes" => 8388608, "max_in_flight" => 1},
          "application" => %{"manifest_kind" => "path"}
        }}
      end

      defp response(%{"id" => id, "method" => "resolver.get"}) do
        %{"jsonrpc" => "2.0", "id" => id, "result" => %{
          "status" => "resolved", "representation" => "value", "value" => "secret",
          "source" => "provider", "source_provider" => "env://",
          "expires_at_unix_ms" => nil, "refresh_at_unix_ms" => nil
        }}
      end

      defp response(%{"id" => id, "method" => "rpc.shutdown"}), do: %{"jsonrpc" => "2.0", "id" => id, "result" => %{}}
    end

    FakeEndpoint.run()
    """)

    {:ok, session} =
      SecretSpec.Session.start_link(
        executable: System.find_executable("elixir"),
        arguments: [endpoint],
        manifest: Path.join(tmp_dir, "secretspec.toml")
      )

    assert {:ok, %Secret{name: nil, value: "secret", representation: "value"}} =
             SecretSpec.Session.get(session, "TOKEN",
               purpose: %{consumer: "test", operation: "read"}
             )

    assert :ok = SecretSpec.Session.close(session)
  end
end
