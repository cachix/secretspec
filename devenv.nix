{ pkgs, ... }: {
  languages.rust = {
    enable = true;
    # The Rust version is pinned in rust-toolchain.toml, which the native CI
    # runners (artifact workflows that cannot use devenv) read via rustup.
    # The musl targets for the fully-static Go binary are declared in
    # rust-toolchain.toml (read automatically via toolchainFile).
    toolchainFile = ./rust-toolchain.toml;
  };
  languages.javascript = {
    enable = true;
    # Node 22 (the plain nixpkgs default) bundles npm 10.x, which mishandles
    # npm Trusted Publishing's OIDC handshake and can even misreport a brand
    # new package's first publish as a 404. Node 24 bundles npm >= 11.5.1.
    package = pkgs.nodejs_24;
    npm = {
      enable = true;
      install.enable = true;
    };
  };
  # Python is used by the reference SDK (secretspec-py), a pyo3 extension
  # (secretspec-py-native) that statically links the resolver in directly.
  languages.python = {
    enable = true;
    venv = {
      enable = true;
      requirements = ''
        maturin
        pytest
      '';
    };
  };
  # Go SDK (secretspec-go): default binding is purego (dlopen, no cgo); the
  # `-tags static` binding uses cgo to statically link libsecretspec_ffi.a, and on
  # Linux is built fully static against musl (see the env block below).
  languages.go.enable = true;
  # Ruby SDK (secretspec-rb) compiles an mkmf C extension that statically links
  # libsecretspec_ffi.a.
  languages.ruby.enable = true;
  # Haskell SDK (secretspec-hs) links the C ABI at build time via the FFI.
  languages.haskell.enable = true;
  # PHP SDK (secretspec-php) has two native backends over the same resolver:
  #   * secretspec-php-native, an ext-php-rs extension that embeds the resolver
  #     (the production path: no ffi.enable, works in FPM like ext-redis); and
  #   * a runtime ext-ffi fallback that dlopens the secretspec-ffi cdylib.
  # The pure-PHP client prefers the extension when loaded. ext-ffi (enabled here)
  # covers the fallback + dev; composer (bundled with languages.php) manages the
  # dev-only phpunit dependency.
  languages.php = {
    enable = true;
    extensions = [ "ffi" ];
    ini = ''
      ffi.enable = true;
    '';
  };

  packages = [
    # keyring
    pkgs.dbus
    # coverage testing
    pkgs.cargo-tarpaulin
    # installers
    pkgs.cargo-dist
    # Building the secretspec-php-native extension (ext-php-rs) needs php-config +
    # the PHP dev headers, and bindgenHook wires libclang/clang system headers so
    # ext-php-rs's bindgen step can parse php.h.
    pkgs.php.unwrapped.dev
    pkgs.rustPlatform.bindgenHook
  ];

  # Fully-static musl build of the Go SDK (-tags static + -extldflags -static).
  # The musl C cross-toolchain and static libdbus/libunwind are referenced HERE by
  # absolute path only -- NOT added to `packages`, because devenv `packages` inject
  # their lib dirs into the host NIX_LDFLAGS, which would make the ordinary glibc
  # build pick up the musl-static libdbus (a libc ABI mismatch -> __register_atfork
  # link errors). Referenced by path, they realise into the store without polluting
  # the host build environment. The CC_/linker vars are musl-target-scoped, so host
  # (glibc) cargo builds are unaffected; MUSL_CC / MUSL_STATIC_LDFLAGS feed the cgo
  # step so the final binary statically links libdbus + libunwind.
  env =
    let
      muslcc = "${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc";
    in
    {
      CC_x86_64_unknown_linux_musl = muslcc;
      CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = muslcc;
      MUSL_CC = muslcc;
      MUSL_STATIC_LDFLAGS = "-L${pkgs.pkgsStatic.dbus.lib}/lib -L${pkgs.pkgsStatic.libunwind}/lib";
    };

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
