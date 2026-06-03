{ pkgs, lib, ... }: {
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
    pkgs.pkg-config
    # formatting
    pkgs.dprint
    pkgs.taplo
    # Dart SDK
    pkgs.dart
    # installers
    pkgs.cargo-dist
  ] ++ lib.optionals pkgs.stdenv.isLinux [
    # coverage testing
    pkgs.cargo-llvm-cov
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

  scripts."fix:all".exec = ''
    dprint fmt
    taplo fmt
    cargo +nightly fmt --all
    dart format sdk/dart
    monochange step:validate
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
