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
        let
          providerContractCm = import ./s88/ControlModule/provider-contract.nix { inherit lib; };
          renderResultCm = import ./s88/ControlModule/render-result.nix { };
          validateProviderContract =
            providerContract:
            let
              providerState = providerContractCm.normalize providerContract;
              failedAssertions =
                builtins.filter (assertion: assertion.assertion == false) (
                  providerContractCm.assertions providerState
                );
            in
            if failedAssertions != [ ] then
              throw (
                "network-renderer-wireguard provider contract rejected before render-result projection: "
                + builtins.concatStringsSep "; " (map (assertion: assertion.message) failedAssertions)
              )
            else
              providerContract;
        in
        {
          renderer = rec {
            buildWireGuardProviderRenderResult =
              providerRequest:
              let
                providerContract =
                  if builtins.isAttrs providerRequest && providerRequest ? providerContract then
                    providerRequest.providerContract
                  else
                    providerRequest;
                validatedProviderContract = validateProviderContract providerContract;
                validationToken = builtins.seq validatedProviderContract true;
                requiredCapabilities =
                  if builtins.isAttrs providerRequest && builtins.isList (providerRequest.requiredCapabilities or null) then
                    providerRequest.requiredCapabilities
                  else
                    [ ];
                providerRuntimeModule = {
                  imports = [ self.nixosModules.default ];
                  services.network-renderer-wireguard.providerRuntime = {
                    enable = true;
                    providerContract = validatedProviderContract;
                  };
                };
              in
              builtins.seq validationToken (renderResultCm.build {
                providerContract = validatedProviderContract;
                inherit requiredCapabilities;
                nixosModule = providerRuntimeModule;
              });

            buildWireGuardProviderRuntimeModule =
              providerContract:
              (buildWireGuardProviderRenderResult providerContract).artifacts.nixosModules.providerRuntime;
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
