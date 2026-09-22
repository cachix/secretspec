defmodule SecretSpec.Codec do
  @moduledoc false
  @absolute_max 8 * 1024 * 1024
  @max_depth 64

  def encode(message, max_frame_bytes \\ @absolute_max) do
    body = JSON.encode!(message)
    size = byte_size(body)

    if size < 2 or size > min(max_frame_bytes, @absolute_max) do
      {:error, :frame_too_large}
    else
      {:ok, <<body::binary, ?\n>>}
    end
  end

  def decode(frame, max_frame_bytes \\ @absolute_max)

  def decode(frame, max_frame_bytes) when is_binary(frame) do
    if frame != <<>> and :binary.last(frame) == ?\n do
      decode_body(binary_part(frame, 0, byte_size(frame) - 1), max_frame_bytes)
    else
      {:error, :truncated_frame}
    end
  end

  def decode(_, _), do: {:error, :truncated_frame}
  def max_frame_bytes, do: @absolute_max

  defp decode_body(body, max_frame_bytes) do
    size = byte_size(body)

    cond do
      size < 2 or size > min(max_frame_bytes, @absolute_max) ->
        {:error, :frame_too_large}

      not String.valid?(body) ->
        {:error, :invalid_utf8}

      true ->
        with :ok <- duplicate_and_nesting_check(body),
             {:ok, value} <- JSON.decode(body) do
          {:ok, value}
        else
          {:error, reason} when reason in [:duplicate_key, :nesting_too_deep] -> {:error, reason}
          _ -> {:error, :invalid_json}
        end
    end
  end

  defp duplicate_and_nesting_check(body) do
    with {:ok, rest, _depth} <- parse_value(skip_ws(body), 0),
         <<>> <- skip_ws(rest) do
      :ok
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_json}
    end
  end

  defp parse_value(<<char, rest::binary>>, depth) when char == ?{ and depth < @max_depth,
    do: parse_object(skip_ws(rest), depth + 1)

  defp parse_value(<<char, rest::binary>>, depth) when char == ?[ and depth < @max_depth,
    do: parse_array(skip_ws(rest), depth + 1)

  defp parse_value(<<char, _rest::binary>>, depth)
       when char in [?{, ?[] and depth >= @max_depth,
       do: {:error, :nesting_too_deep}

  defp parse_value(<<?\", _rest::binary>> = value, depth) do
    with {:ok, encoded, rest} <- take_string(value),
         {:ok, _string} <- JSON.decode(encoded) do
      {:ok, rest, depth}
    else
      _ -> {:error, :invalid_json}
    end
  end

  defp parse_value(value, depth) do
    {atom, rest} = take_atom(value)
    if atom == "", do: {:error, :invalid_json}, else: {:ok, rest, depth}
  end

  defp parse_object(<<"}"::binary, rest::binary>>, depth), do: {:ok, rest, depth}
  defp parse_object(value, depth), do: parse_object_members(value, depth, MapSet.new())

  defp parse_object_members(value, depth, keys) do
    with {:ok, encoded_key, rest} <- take_string(skip_ws(value)),
         {:ok, key} <- JSON.decode(encoded_key),
         {:ok, rest} <- consume_colon(rest),
         false <- MapSet.member?(keys, key),
         {:ok, rest, _} <- parse_value(skip_ws(rest), depth) do
      case skip_ws(rest) do
        <<",", tail::binary>> -> parse_object_members(tail, depth, MapSet.put(keys, key))
        <<"}", tail::binary>> -> {:ok, tail, depth}
        _ -> {:error, :invalid_json}
      end
    else
      true -> {:error, :duplicate_key}
      _ -> {:error, :invalid_json}
    end
  end

  defp parse_array(<<"]"::binary, rest::binary>>, depth), do: {:ok, rest, depth}

  defp parse_array(value, depth) do
    with {:ok, rest, _} <- parse_value(skip_ws(value), depth) do
      case skip_ws(rest) do
        <<",", tail::binary>> -> parse_array(tail, depth)
        <<"]", tail::binary>> -> {:ok, tail, depth}
        _ -> {:error, :invalid_json}
      end
    end
  end

  defp consume_colon(binary) do
    case skip_ws(binary) do
      <<":", rest::binary>> -> {:ok, rest}
      _ -> {:error, :invalid_json}
    end
  end

  defp take_string(<<?\", rest::binary>>), do: take_string_chars(rest, <<?\">>)
  defp take_string(_), do: {:error, :invalid_json}

  defp take_string_chars(<<?\", rest::binary>>, acc), do: {:ok, <<acc::binary, ?\">>, rest}

  defp take_string_chars(<<?\\, char, rest::binary>>, acc),
    do: take_string_chars(rest, <<acc::binary, ?\\, char>>)

  defp take_string_chars(<<char, rest::binary>>, acc),
    do: take_string_chars(rest, <<acc::binary, char>>)

  defp take_string_chars(<<>>, _acc), do: {:error, :invalid_json}

  defp take_atom(binary), do: take_atom(binary, <<>>)

  defp take_atom(<<char, rest::binary>>, acc) when char in [32, 9, 10, 13, ?,, ?}, ?]],
    do: {acc, <<char, rest::binary>>}

  defp take_atom(<<char, rest::binary>>, acc), do: take_atom(rest, <<acc::binary, char>>)
  defp take_atom(<<>>, acc), do: {acc, <<>>}

  defp skip_ws(<<char, rest::binary>>) when char in [32, 9, 10, 13], do: skip_ws(rest)
  defp skip_ws(binary), do: binary
end
