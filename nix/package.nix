{
  lib,
  rustPlatform,
  pkg-config,
  cmake,
  perl,
  # Providers compiled into the CLI. Override this to add SDK-backed
  # providers without rebuilding the whole default feature set.
  buildFeatures ? [
    "cli"
    "bws"
  ],
}:

let
  cargo = lib.importTOML ../Cargo.toml;
in
rustPlatform.buildRustPackage {
  pname = "secretspec";
  version = cargo.workspace.package.version;

  src = lib.cleanSourceWith {
    src = ../.;
    filter =
      path: type:
      let
        base = baseNameOf (toString path);
      in
      !(builtins.elem base [
        "target"
        "result"
      ])
      && lib.cleanSourceFilter path type;
  };

  cargoLock.lockFile = ../Cargo.lock;
  cargoBuildFlags = [
    "-p"
    "secretspec"
    "--no-default-features"
    "--features"
    (lib.concatStringsSep "," buildFeatures)
  ];
  doCheck = false;

  nativeBuildInputs = [
    pkg-config
    cmake
    perl
  ];

  env = {
    # nixpkgs' aws-lc-sys setup expects a system AWS-LC; build the vendored
    # copy instead so the package is self-contained.
    AWS_LC_SYS_USE_SYSTEM = "0";
  };

  preBuild = ''
    export AWS_LC_SYS_USE_SYSTEM=0
  '';

  meta = {
    description = "A declarative interface for every secret provider";
    homepage = "https://secretspec.dev";
    license = lib.licenses.asl20;
    mainProgram = "secretspec";
  };
}
