defmodule SecretSpec.SubprocessTest do
  use ExUnit.Case, async: true

  # A provider spec the gate cannot prove in-process (an alias, a bare name,
  # or any non-URI string) must engage the wrapper; only a URI whose scheme
  # names a known in-process provider may skip it.

  test "a URI with an in-process scheme does not engage" do
    refute SecretSpec.Subprocess.engaged_by?(%{"provider" => "dotenv://.env"})
    refute SecretSpec.Subprocess.engaged_by?(%{"provider" => "keyring://"})
    refute SecretSpec.Subprocess.engaged_by?(%{"provider" => "env://"})
    refute SecretSpec.Subprocess.engaged_by?(%{"provider" => "file:///tmp/secrets"})
    refute SecretSpec.Subprocess.engaged_by?(%{"provider" => "vault://cluster"})
    refute SecretSpec.Subprocess.engaged_by?(%{"provider" => "awssm://us-east-1/name"})
  end

  test "a URI with a CLI-backed scheme engages" do
    assert SecretSpec.Subprocess.engaged_by?(%{"provider" => "lastpass://Work"})
    assert SecretSpec.Subprocess.engaged_by?(%{"provider" => "op://Team"})
    assert SecretSpec.Subprocess.engaged_by?(%{"provider" => "sops://config.yaml"})
    assert SecretSpec.Subprocess.engaged_by?(%{"provider" => "pass://"})
    # Azure CLI credential shells out to `az` via azure_identity.
    assert SecretSpec.Subprocess.engaged_by?(%{"provider" => "akv://my-vault"})
  end

  test "the single-colon shorthand carries its scheme, matching the core's split_spec" do
    refute SecretSpec.Subprocess.engaged_by?(%{"provider" => "dotenv:.env"})
    assert SecretSpec.Subprocess.engaged_by?(%{"provider" => "sops:config.yaml"})
  end

  test "a scheme missing from both lists engages (fail-safe)" do
    assert SecretSpec.Subprocess.engaged_by?(%{"provider" => "futureprovider://x"})
  end

  test "an alias or bare provider name engages" do
    # Aliases resolve through manifest and user config the SDK cannot see;
    # the gate stays fail-safe.
    assert SecretSpec.Subprocess.engaged_by?(%{"provider" => "prod_vault"})
    assert SecretSpec.Subprocess.engaged_by?(%{"provider" => "keyring"})
  end

  test "a path request without an explicit provider engages" do
    # The core then consults the user config default provider, invisible to
    # the SDK.
    assert SecretSpec.Subprocess.engaged_by?(%{"path" => "secretspec.toml"})
  end

  test "an inline spec is judged by its own provider declarations" do
    inline = fn providers ->
      %{
        "request_version" => 1,
        "operation" => "resolve",
        "source" => %{
          "kind" => "inline",
          "spec_version" => 2,
          "base_dir" => "/tmp",
          "spec" => providers
        },
        "options" => %{}
      }
    end

    dotenv_only = %{
      "providers" => %{"env" => "dotenv://inline.env"},
      "profiles" => %{
        "default" => %{
          "secrets" => %{
            "TOKEN" => %{"description" => "t", "providers" => ["dotenv://inline.env"]}
          }
        }
      }
    }

    refute SecretSpec.Subprocess.engaged_by?(inline.(dotenv_only))

    with_lastpass_alias = put_in(dotenv_only, ["providers", "vault"], "lastpass://Work")
    assert SecretSpec.Subprocess.engaged_by?(inline.(with_lastpass_alias))

    with_fallback_chain =
      put_in(dotenv_only, ["profiles", "default", "secrets", "TOKEN", "providers"], [
        "env",
        "op://Team"
      ])

    assert SecretSpec.Subprocess.engaged_by?(inline.(with_fallback_chain))

    with_subprocess_default =
      put_in(dotenv_only, ["defaults"], %{"providers" => ["sops://secrets.yaml"]})

    assert SecretSpec.Subprocess.engaged_by?(inline.(with_subprocess_default))

    # The provider can also ride in options alongside an inline spec
    # (Builder.with_inline_spec |> with_provider puts it there).
    with_option =
      put_in(inline.(dotenv_only), ["options", "provider"], "lastpass://Work")

    assert SecretSpec.Subprocess.engaged_by?(with_option)
  end

  test "an inline spec without any provider declaration engages" do
    # The core then uses the user config default provider.
    request = %{
      "request_version" => 1,
      "operation" => "resolve",
      "source" => %{
        "kind" => "inline",
        "spec_version" => 2,
        "base_dir" => "/tmp",
        "spec" => %{"project" => %{"name" => "x"}}
      },
      "options" => %{}
    }

    assert SecretSpec.Subprocess.engaged_by?(request)
  end

  test "an unexpected request shape engages" do
    assert SecretSpec.Subprocess.engaged_by?(%{})
    assert SecretSpec.Subprocess.engaged_by?(%{"provider" => 42})
  end
end
