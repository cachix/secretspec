using Cachix.SecretSpec;

using var resolved = SecretSpec.Builder().WithReason("TLS boot").Load();
var certificatePath = resolved.Secrets["TLS_CERT"].Get();
// Use the certificate before resolved is disposed.
