defmodule SecretSpec.ConformanceTest do
  use ExUnit.Case, async: true

  @fixtures Path.expand("../../conformance/fixtures", __DIR__)

  fixtures =
    @fixtures |> File.ls!() |> Enum.filter(&File.dir?(Path.join(@fixtures, &1))) |> Enum.sort()

  for fixture <- fixtures do
    @fixture fixture

    test "matches the canonical #{@fixture} fixture" do
      fixture_path = Path.join(@fixtures, @fixture)
      expected = fixture_path |> Path.join("expected.json") |> File.read!() |> Jason.decode!()
      resolved = fixture_path |> builder() |> SecretSpec.Builder.load()

      try do
        assert canonical(resolved) == expected
      after
        :ok = SecretSpec.Resolved.close(resolved)
      end
    end

    test "matches the no-values #{@fixture} fixture" do
      fixture_path = Path.join(@fixtures, @fixture)

      expected =
        fixture_path
        |> Path.join("expected_no_values.json")
        |> File.read!()
        |> Jason.decode!()

      resolved =
        fixture_path
        |> builder()
        |> SecretSpec.Builder.with_no_values()
        |> SecretSpec.Builder.load()

      try do
        assert SecretSpec.Resolved.fields(resolved) == expected
      after
        :ok = SecretSpec.Resolved.close(resolved)
      end
    end

    test "matches the report #{@fixture} fixture" do
      fixture_path = Path.join(@fixtures, @fixture)

      expected =
        fixture_path
        |> Path.join("expected_report.json")
        |> File.read!()
        |> Jason.decode!()

      report = fixture_path |> builder() |> SecretSpec.Builder.report()

      assert canonical_report(report) == expected
    end
  end

  defp builder(fixture_path) do
    SecretSpec.builder()
    |> SecretSpec.Builder.with_path(Path.join(fixture_path, "secretspec.toml"))
    |> SecretSpec.Builder.with_provider("dotenv://#{Path.join(fixture_path, ".env")}")
    |> SecretSpec.Builder.with_reason("conformance")
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

  defp canonical_report(report) do
    %{
      "profile" => report.profile,
      "secrets" =>
        Map.new(report.secrets, fn secret ->
          {secret.name,
           %{
             "status" => secret.status,
             "required" => secret.required,
             "as_path" => secret.as_path,
             "generated" => secret.generated,
             "default_applied" => secret.default_applied,
             "source_provider" => not is_nil(secret.source_provider)
           }}
        end)
    }
  end
end
