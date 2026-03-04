{ pkgs, ... }:
{
  # For development of SOPS provider
  languages.go.enable = true;

  languages.rust.enable = true;

  languages.javascript = {
    enable = true;
    npm = {
      enable = true;
      install.enable = true;
    };
  };

  packages = [
    # keyring
    pkgs.dbus
    # coverage testing
    pkgs.cargo-tarpaulin
    # installers
    pkgs.cargo-dist
    # For managing test secrets of the SOPS provider
    pkgs.sops
  ];

  git-hooks.hooks = {
    rustfmt.enable = true;
    clippy.enable = true;
    # TODO: this should be done by devenv
    clippy.settings.offline = false;
  };

  enterTest = ''
    cargo test --all
  '';

  scripts.test-cli-integration.exec = ''
    # Build the CLI for integration tests
    cargo build --release
    export PATH="$PWD/target/release:$PATH"

    # Run CLI integration tests
    bash tests/cli-integration.sh
  '';

  processes.docs.exec = ''
    cd docs && npm run dev
  '';
}
