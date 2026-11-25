defmodule SecretSpec.CodecTest do
  use ExUnit.Case, async: true
  alias SecretSpec.{Codec, Error}

  test "encodes UTF-8 JSON with exactly one LF" do
    assert {:ok, frame} = Codec.encode(%{"message" => "café"})
    assert String.ends_with?(frame, "\n")
    refute String.ends_with?(frame, "\n\n")
    assert {:ok, %{"message" => "café"}} = Codec.decode(frame)
  end

  test "validates framing boundaries" do
    assert {:error, :truncated_frame} = Codec.decode(<<>>)
    assert {:error, :frame_too_large} = Codec.decode("\n")
    assert {:error, :truncated_frame} = Codec.decode("{}")
    assert {:error, :invalid_json} = Codec.decode("{}\n{}\n")
    assert {:error, :carriage_return} = Codec.decode("{}\r\n")
    assert {:error, :carriage_return} = Codec.decode("{\"x\":\"a\rb\"}\n")
    assert {:error, :carriage_return} = Codec.decode("{\"x\":\"a\\rb\"}\r\n")
    assert {:error, :invalid_json} = Codec.decode("{\"x\":\"a\nb\"}\n")
    assert {:error, :truncated_frame} = Codec.decode(:not_binary)
  end

  test "enforces body limits and the absolute ceiling" do
    body = ~s({"x":"12345"})
    assert {:ok, _} = Codec.decode(body <> "\n", byte_size(body))
    assert {:error, :frame_too_large} = Codec.decode(body <> "x\n", byte_size(body))
    huge = "{" <> "\"x\":\"" <> String.duplicate("x", 1_048_576) <> "\"}\n"
    assert {:error, :frame_too_large} = Codec.decode(huge, 9_999_999)
  end

  test "rejects duplicate keys, invalid JSON and invalid UTF-8" do
    cases = [
      {~s({"x":1,"x":2}), :duplicate_key},
      {~s({"x":{"y":1,"y":2}}), :invalid_json},
      {~s({"x":1,}), :invalid_json},
      {~s({"x":true), :invalid_json},
      {~s({"x":true), :invalid_json},
      {<<"{\"x\":\"", 0xFF, "\"}">>, :invalid_utf8}
    ]

    for {body, error} <- cases, do: assert({:error, ^error} = Codec.decode(body <> "\n"))
    assert {:ok, _} = Codec.decode(~s({"a":1,"b":{"a":2}}) <> "\n")
    assert {:error, :duplicate_key} = Codec.decode(~s({"a":1,"\\u0061":2}) <> "\n")
  end

  test "accepts nesting depth 64 and rejects depth 65" do
    accepted = String.duplicate("[", 64) <> "0" <> String.duplicate("]", 64)
    rejected = String.duplicate("[", 65) <> "0" <> String.duplicate("]", 65)
    assert {:ok, _} = Codec.decode(accepted <> "\n")
    assert {:error, :nesting_too_deep} = Codec.decode(rejected <> "\n")
  end

  test "decodes structured and fallback errors" do
    response = %{
      "error" => %{"message" => "deadline", "data" => %{"kind" => "deadline_exceeded", "x" => 1}}
    }

    assert %Error{
             kind: "deadline_exceeded",
             message: "deadline",
             data: %{
               "message" => "deadline",
               "data" => %{"kind" => "deadline_exceeded", "x" => 1}
             }
           } =
             Error.from_response(response)

    assert %Error{kind: "protocol"} = Error.from_response(%{})
  end
end
