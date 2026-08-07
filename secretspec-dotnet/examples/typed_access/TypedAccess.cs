using Cachix.SecretSpec;

using var resolved = SecretSpec.Builder().Load();
var typed = AppSecrets.FromJson(resolved.FieldsJson());
Console.WriteLine(typed.DatabaseURL);
