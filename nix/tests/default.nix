# NixOS VM tests for the SecretSpec integration.
#
# Run one test with:
#   nix-build nix/tests -A systemd-creds
#   nix-build nix/tests -A module-activation
#
# The systemd-creds test uses the host credential key, not TPM2, so it works on
# ordinary CI hardware. TPM2 validation is separate.
{
  pkgs ? import <nixpkgs> { },
}:

let
  fakeSecretspec = pkgs.writeShellScriptBin "secretspec" ''
    if [ "$1" = "nixos" ] && [ "$2" = "refresh" ]; then
      mkdir -p /run/secretspec/current/secrets /run/secretspec/current/templates
      printf 'fake-value' > /run/secretspec/current/secrets/TOKEN
      chmod 0400 /run/secretspec/current/secrets/TOKEN
      printf 'token=fake-value' > /run/secretspec/current/templates/config
      chmod 0400 /run/secretspec/current/templates/config
      exit 0
    fi
    echo "unexpected arguments: $*" >&2
    exit 1
  '';

  manifest = pkgs.writeText "secretspec.toml" ''
    [project]
    name = "nixos-test"
    revision = "1.0"
    require_reason = false

    [profiles.default]
    TOKEN = { description = "test" }
  '';

  nixosTest = if pkgs ? testers then pkgs.testers.nixosTest else pkgs.nixosTest;
in
{
  # Real systemd-creds encryption/decryption with the host key. This validates
  # that LoadCredentialEncrypted can consume the cache format on a NixOS guest
  # without requiring physical TPM hardware.
  systemd-creds = nixosTest {
    name = "secretspec-systemd-creds";
    nodes.machine = { config, pkgs, ... }: {
      systemd.services.credential-setup = {
        wantedBy = [ "multi-user.target" ];
        before = [ "secret.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${pkgs.bash}/bin/bash -c 'printf secret-value | ${config.systemd.package}/bin/systemd-creds encrypt --with-key=host --name test - /run/secret.cred'";
        };
      };
      systemd.services.secret = {
        wantedBy = [ "multi-user.target" ];
        after = [ "credential-setup.service" ];
        requires = [ "credential-setup.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          LoadCredentialEncrypted = [ "test:/run/secret.cred" ];
          ExecStart = "${pkgs.bash}/bin/bash -c 'cat \"$CREDENTIALS_DIRECTORY/test\" > /run/secret.out'";
        };
      };
    };
    testScript = ''
      machine.wait_for_unit("secret.service")
      machine.succeed("test \"$(cat /run/secret.out)\" = secret-value")
    '';
  };

  # Module wiring: activation mode creates the runtime files before consumers.
  # The package is a stub so this test does not depend on a released binary;
  # Rust behavior is covered by the crate tests.
  module-activation = nixosTest {
    name = "secretspec-module-activation";
    nodes.machine = { config, pkgs, ... }: {
      imports = [ ../../nix/nixos.nix ];
      system.stateVersion = "26.05";
      services.secretspec = {
        enable = true;
        package = fakeSecretspec;
        manifest = manifest;
        profile = "default";
        secrets.TOKEN = { };
        templates.config.content = "token=@secretspec:TOKEN@";
      };
      systemd.services.consumer = {
        wantedBy = [ "multi-user.target" ];
        after = [ "secretspec.service" ];
        requires = [ "secretspec.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${pkgs.bash}/bin/bash -c 'cat /run/secretspec/current/secrets/TOKEN > /run/secret.out; cat /run/secretspec/current/templates/config >> /run/secret.out'";
        };
      };
    };
    testScript = ''
      machine.wait_for_unit("consumer.service")
      machine.succeed("test \"$(cat /run/secret.out)\" = fake-valuetoken=fake-value")
    '';
  };
}
