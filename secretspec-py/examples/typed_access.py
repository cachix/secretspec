from secrets_gen import SecretSpec as Secrets  # typed

typed = Secrets.from_dict(resolved.fields())
print(typed.database_url)  # typed str
