using Cachix.SecretSpec;

using var resolved = SecretSpec.Resolve(
    provider: "keyring://",
    profile: "production",
    reason: "boot web app");
