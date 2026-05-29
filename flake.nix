{
  description = "network-renderer-wireguard";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self
    , nixpkgs
    , ...
    }:
    let
      lib = nixpkgs.lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = lib.genAttrs systems;

      mkSystemLib =
        system:
        {
          renderer = {
            buildWireGuardProviderRuntimeModule =
              providerContract:
              {
                imports = [ self.nixosModules.default ];
                services.network-renderer-wireguard.providerRuntime = {
                  enable = true;
                  inherit providerContract;
                };
              };
          };
        };
    in
    {
      nixosModules.default = import ./modules/wireguard-provider-runtime.nix;
      nixosModules.wireguard-provider-runtime = self.nixosModules.default;

      libBySystem = forAllSystems mkSystemLib;
      lib = mkSystemLib "x86_64-linux";
    };
}
