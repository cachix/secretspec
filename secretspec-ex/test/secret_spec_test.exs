defmodule SecretSpecTest do
  use ExUnit.Case, async: true

  test "builder stores request options" do
    builder =
      SecretSpec.builder()
      |> SecretSpec.Builder.with_path("secretspec.toml")
      |> SecretSpec.Builder.with_provider("dotenv://.env")
      |> SecretSpec.Builder.with_profile("development")
      |> SecretSpec.Builder.with_reason("test")

    assert builder.request == %{
             "path" => "secretspec.toml",
             "provider" => "dotenv://.env",
             "profile" => "development",
             "reason" => "test"
           }
  end

  test "caller context omits unset fields" do
    caller = %SecretSpec.CallerContext{name: "test", operation: "resolve"}

    assert SecretSpec.CallerContext.to_request(caller) == %{
             "name" => "test",
             "operation" => "resolve"
           }
  end

  test "abi version is non-empty" do
    assert SecretSpec.Native.abi_version() != ""
  end

  test "load returns values and provenance" do
    {manifest, provider} = project("DATABASE_URL=postgres://db\n")

    resolved =
      SecretSpec.builder()
      |> SecretSpec.Builder.with_path(manifest)
      |> SecretSpec.Builder.with_provider(provider)
      |> SecretSpec.Builder.with_reason("elixir test")
      |> SecretSpec.Builder.load()

    assert resolved.profile == "default"
    assert resolved.secrets["DATABASE_URL"].value == "postgres://db"
    assert resolved.secrets["DATABASE_URL"].source == "provider"
    assert resolved.secrets["DATABASE_URL"].source_provider != nil
    assert resolved.secrets["DEV_SESSION_SECRET"].value == "development-only-secret"
    assert resolved.secrets["DEV_SESSION_SECRET"].source == "default"
    assert resolved.missing_optional == ["SENTRY_DSN"]
    refute Map.has_key?(resolved.secrets, "SENTRY_DSN")
  end

  test "inline spec resolves at its logical base directory" do
    {manifest, _provider} = project("")
    base_dir = Path.dirname(manifest)
    File.write!(Path.join(base_dir, "inline.env"), "TOKEN=inline-elixir\n")

    resolved =
      SecretSpec.builder()
      |> SecretSpec.Builder.with_inline_spec(
        %{
          "project" => %{"name" => "elixir-inline"},
          "providers" => %{"env" => "dotenv://inline.env"},
          "profiles" => %{
            "default" => %{
              "secrets" => %{
                "TOKEN" => %{"description" => "token", "providers" => ["env"]}
              }
            }
          }
        },
        base_dir
      )
      |> SecretSpec.Builder.with_reason("inline test")
      |> SecretSpec.Builder.load()

    assert resolved.secrets["TOKEN"].value == "inline-elixir"
  end

  test "scope is selected and returned" do
    {manifest, provider} = project("DATABASE_URL=postgres://db\nSENTRY_DSN=https://sentry\n")

    builder =
      SecretSpec.builder()
      |> SecretSpec.Builder.with_path(manifest)
      |> SecretSpec.Builder.with_provider(provider)
      |> SecretSpec.Builder.with_scope("database")
      |> SecretSpec.Builder.with_reason("scoped test")

    resolved = SecretSpec.Builder.load(builder)
    report = SecretSpec.Builder.report(builder)

    assert resolved.scope == "database"
    assert Map.keys(resolved.secrets) == ["DATABASE_URL"]
    assert report.scope == "database"
    assert Enum.map(report.secrets, & &1.name) == ["DATABASE_URL"]
  end

  test "report preserves status metadata" do
    {manifest, provider} = project("DATABASE_URL=postgres://db\n")

    report =
      SecretSpec.builder()
      |> SecretSpec.Builder.with_path(manifest)
      |> SecretSpec.Builder.with_provider(provider)
      |> SecretSpec.Builder.report()

    assert report.profile == "default"

    database = Enum.find(report.secrets, &(&1.name == "DATABASE_URL"))
    assert database.name == "DATABASE_URL"
    assert database.status == "resolved"
    assert database.required
    assert database.source_provider =~ "dotenv:"
    refute database.default_applied
    refute database.generated
    refute database.as_path

    assert Enum.find(report.secrets, &(&1.name == "DEV_SESSION_SECRET")).default_applied
    assert Enum.find(report.secrets, &(&1.name == "SENTRY_DSN")).status == "missing_optional"
  end

  test "no_values returns nil fields" do
    {manifest, provider} = project("DATABASE_URL=postgres://db\n")

    resolved =
      SecretSpec.builder()
      |> SecretSpec.Builder.with_path(manifest)
      |> SecretSpec.Builder.with_provider(provider)
      |> SecretSpec.Builder.with_no_values()
      |> SecretSpec.Builder.load()

    assert SecretSpec.Resolved.fields(resolved) == %{
             "DATABASE_URL" => nil,
             "DEV_SESSION_SECRET" => nil
           }
  end

  test "missing required raises MissingRequiredError" do
    {manifest, provider} = project("")

    assert_raise SecretSpec.MissingRequiredError, ~r/DATABASE_URL/, fn ->
      SecretSpec.builder()
      |> SecretSpec.Builder.with_path(manifest)
      |> SecretSpec.Builder.with_provider(provider)
      |> SecretSpec.Builder.load()
    end
  end

  test "as_path returns a readable file and close removes it" do
    manifest = """
    [project]
    name = "elixir-test"
    revision = "1.0"

    [profiles.default]
    TLS_CERT = { description = "cert", required = true, as_path = true }
    """

    {manifest_path, provider} = project("TLS_CERT=----cert----\n", manifest)

    resolved =
      SecretSpec.builder()
      |> SecretSpec.Builder.with_path(manifest_path)
      |> SecretSpec.Builder.with_provider(provider)
      |> SecretSpec.Builder.load()

    secret = resolved.secrets["TLS_CERT"]
    assert secret.as_path
    assert secret.value == nil
    assert File.read!(secret.path) == "----cert----"

    SecretSpec.Resolved.close(resolved)
    refute File.exists?(secret.path)
  end

  @tag :tmp_dir
  test "close removes later materialized files after a removal error", %{tmp_dir: tmp_dir} do
    blocked_path = Path.join(tmp_dir, "blocked")
    later_path = Path.join(tmp_dir, "later")
    File.mkdir!(blocked_path)
    File.write!(later_path, "later")

    resolved = %SecretSpec.Resolved{
      secrets: %{
        "BLOCKED" => %SecretSpec.ResolvedSecret{as_path: true, path: blocked_path},
        "LATER" => %SecretSpec.ResolvedSecret{as_path: true, path: later_path}
      }
    }

    assert_raise File.Error, fn -> SecretSpec.Resolved.close(resolved) end
    refute File.exists?(later_path)
  end

  test "invalid manifest raises SecretSpec.Error" do
    assert_raise SecretSpec.Error, fn ->
      SecretSpec.builder()
      |> SecretSpec.Builder.with_path("/definitely/does/not/exist/secretspec.toml")
      |> SecretSpec.Builder.load()
    end
  end

  test "set_as_env exports resolved secrets" do
    {manifest, provider} = project("DATABASE_URL=postgres://db\n")
    System.delete_env("DATABASE_URL")

    resolved =
      SecretSpec.builder()
      |> SecretSpec.Builder.with_path(manifest)
      |> SecretSpec.Builder.with_provider(provider)
      |> SecretSpec.Builder.load()

    SecretSpec.Resolved.set_as_env(resolved)
    assert System.get_env("DATABASE_URL") == "postgres://db"
    System.delete_env("DATABASE_URL")
  end

  defp project(dotenv, manifest \\ manifest()) do
    directory =
      Path.join(System.tmp_dir!(), "secretspec-ex-#{System.unique_integer([:positive])}")

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf(directory) end)

    manifest_path = Path.join(directory, "secretspec.toml")
    env_path = Path.join(directory, ".env")
    File.write!(manifest_path, manifest)
    File.write!(env_path, dotenv)
    {manifest_path, "dotenv://#{env_path}"}
  end

  defp manifest do
    """
    [project]
    name = "elixir-test"
    revision = "1.0"

    [profiles.default]
    DATABASE_URL = { description = "DB", required = true }
    DEV_SESSION_SECRET = { description = "Development-only session secret", required = false, default = "development-only-secret" }
    SENTRY_DSN = { description = "sentry", required = false }

    [scopes.database]
    secrets = ["DATABASE_URL"]
    """
  end
end
