defmodule SecretSpec.ConformanceTest do
  use ExUnit.Case, async: true

  @fixtures Path.expand("../../conformance/fixtures", __DIR__)

  test "matches the canonical basic fixture" do
    fixture = Path.join(@fixtures, "basic")
    expected = fixture |> Path.join("expected.json") |> File.read!() |> Jason.decode!()
    manifest = Path.join(fixture, "secretspec.toml")
    provider = "dotenv://#{Path.join(fixture, ".env")}"

    resolved =
      SecretSpec.builder()
      |> SecretSpec.Builder.with_path(manifest)
      |> SecretSpec.Builder.with_provider(provider)
      |> SecretSpec.Builder.with_reason("conformance")
      |> SecretSpec.Builder.load()

    assert canonical(resolved) == expected
  end

  defp canonical(resolved) do
    secrets =
      Map.new(resolved.secrets, fn {name, secret} ->
        value = if secret.as_path, do: File.read!(secret.path), else: secret.value
        {name, %{"value" => value, "source" => secret.source, "as_path" => secret.as_path}}
      end)

    %{
      "profile" => resolved.profile,
      "secrets" => secrets,
      "missing_required" => [],
      "missing_optional" => Enum.sort(resolved.missing_optional)
    }
  end
end
