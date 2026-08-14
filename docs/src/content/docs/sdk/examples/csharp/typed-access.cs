using Monosecret;

using var resolved = Monosecret.Builder().Load();
var typed = AppSecrets.FromJson(resolved.FieldsJson());
Console.WriteLine(typed.DatabaseURL);
