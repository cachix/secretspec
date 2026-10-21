SecretSpec.with_session([manifest: "secretspec.toml", reason: "boot web app"], fn session ->
  case SecretSpec.Session.get(session, "DATABASE_URL",
         representation: :value,
         purpose: %{consumer: "my_app", operation: "connect"}
       ) do
    {:ok, %SecretSpec.Secret{value: value}} ->
      {:ok, value}

    {:missing, true} ->
      {:error, :missing_required}

    {:missing, false} ->
      {:ok, nil}

    :undeclared ->
      {:error, :undeclared}

    {:error, %SecretSpec.Error{kind: kind}} ->
      {:error, kind}
  end
end)
