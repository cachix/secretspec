using Cachix.SecretSpec;

using var resolved = SecretSpec.Builder().WithScope("api").Load();
