# NixOS VM tests for the SecretSpec integration.
#
# Run one test with:
#   nix-build nix/tests -A systemd-creds
#   nix-build nix/tests -A module-activation
#   nix-build nix/tests -A module-refresh
#
# These are NixOS VM tests and can run on non-NixOS Linux hosts. The
# systemd-creds test uses the host credential key, not TPM2.
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

  secretspecPackage = pkgs.callPackage ../package.nix {
    buildFeatures = [
      "cli"
      "bws"
    ];
  };

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

  # Exercise the actual CLI and NixOS module together. The environment provider
  # supplies a deterministic test value, avoiding external provider services.
  module-refresh = nixosTest {
    name = "secretspec-module-refresh";
    nodes.machine = { pkgs, ... }: {
      imports = [ ../../nix/nixos.nix ];
      system.stateVersion = "26.05";

      services.secretspec = {
        enable = true;
        package = secretspecPackage;
        manifest = pkgs.writeText "secretspec-refresh-test.toml" ''
          [project]
          name = "nixos-refresh-test"
          revision = "1.0"
          require_reason = false

          [providers]
          test-env = "env://"

          [profiles.default]
          TOKEN = { description = "test token", providers = ["test-env"] }
          OPTIONAL = { description = "optional test value", providers = ["test-env"], required = false }
        '';
        profile = "default";
        useSystemdActivation = true;
        secrets.TOKEN = {
          cache = false;
          units = [ "consumer.service" ];
        };
        secrets.OPTIONAL = {
          cache = false;
          required = false;
        };
        templates.config = {
          content = "token=@secretspec:TOKEN@";
          units = [ "consumer.service" ];
        };
      };

      # Keep the test deterministic and local: the real SecretSpec CLI resolves
      # TOKEN through its environment provider inside the oneshot service.
      systemd.services.secretspec.environment.TOKEN = "vm-secret";

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
      machine.succeed("test \"$(cat /run/secret.out)\" = vm-secrettoken=vm-secret")
      machine.succeed("test ! -e /run/secretspec/current/secrets/OPTIONAL")
      machine.succeed("test \"$(systemctl show secretspec.service --property=Result --value)\" = success")
    '';
  };
}
