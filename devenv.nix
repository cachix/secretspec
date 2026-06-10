{ pkgs, ... }: {
  languages.rust = {
    enable = true;
    # Pinned to >= 1.92 for the detect-coding-agent dependency's MSRV.
    channel = "stable";
    version = "1.92.0";
  };
  languages.javascript = {
    enable = true;
    npm = {
      enable = true;
      install.enable = true;
    };
  };
  # Python is used by the reference SDK (secretspec-py), which binds the
  # secretspec-ffi C ABI via cffi (dlopen) over the prebuilt cdylib.
  languages.python = {
    enable = true;
    venv = {
      enable = true;
      requirements = ''
        cffi
        pytest
      '';
    };
  };
  # Go SDK (secretspec-go) binds the C ABI via purego (dlopen, no cgo).
  languages.go.enable = true;
  # Ruby SDK (secretspec-rb) binds the C ABI via stdlib Fiddle (dlopen).
  languages.ruby.enable = true;
  # Haskell SDK (secretspec-hs) links the C ABI at build time via the FFI.
  languages.haskell.enable = true;

  packages = [
    # keyring
    pkgs.dbus
    # coverage testing
    pkgs.cargo-tarpaulin
    # installers
    pkgs.cargo-dist
    # packaging the Python SDK wheel that bundles the cdylib
    pkgs.maturin
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
