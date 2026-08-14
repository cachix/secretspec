using Monosecret;

using var resolved = Monosecret.Builder().WithReason("TLS boot").Load();
var certificatePath = resolved.Secrets["TLS_CERT"].Get();
// Use the certificate before resolved is disposed.
