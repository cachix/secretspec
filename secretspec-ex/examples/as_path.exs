SecretSpec.with_session([manifest: "secretspec.toml", reason: "configure TLS"], fn session ->
  {:ok, %SecretSpec.Secret{path: path, lease_id: lease_id}} =
    SecretSpec.Session.get(session, "TLS_CERT",
      representation: :path,
      purpose: %{consumer: "my_app", operation: "configure_tls"}
    )

  try do
    # Read the file while its lease is active.
    certificate = File.read!(path)
    byte_size(certificate)
  after
    :ok = SecretSpec.Session.release(session, lease_id)
  end
end)
