{
  description = "SecretSpec NixOS integration";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      nixosModules.default = import ./nix/nixos.nix;
      nixosModules.secretspec = self.nixosModules.default;

      packages = forAllSystems (pkgs: {
        default = pkgs.callPackage ./nix/package.nix { };
      });
    };
}
