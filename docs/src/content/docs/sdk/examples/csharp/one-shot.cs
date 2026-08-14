using Monosecret;

using var resolved = Monosecret.Resolve(
    provider: "keyring://",
    profile: "production",
    reason: "boot web app");
