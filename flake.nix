{
  description = "network-renderer-wireguard";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    network-control-plane-model.url = "github:esp0xdeadbeef/network-control-plane-model";
    network-control-plane-model.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { self
    , nixpkgs
    , network-control-plane-model
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
          cpmLib = network-control-plane-model.libBySystem.${system};

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
            hostModule =
              rendererInput:
              { config, lib, pkgs, ... }:
              let
                controlPlane = cpmLib.compileAndBuildFromPaths {
                  inputPath = rendererInput.intent;
                  inventoryPath = rendererInput.inventory;
                };
                inventory = cpmLib.readInput rendererInput.inventory;

                # Find WireGuard overlay nodes from CPM output
                cpmData = controlPlane.control_plane_model.data or { };
                wgNodes = lib.concatLists (
                  lib.mapAttrsToList
                    (_enterprise: enterpriseData:
                      lib.concatLists (
                        lib.mapAttrsToList
                          (_site: siteData:
                            let
                              overlays = siteData.overlays or { };
                              wgOverlayNodes = lib.concatLists (
                                lib.mapAttrsToList
                                  (_overlayName: overlay:
                                    let
                                      nodes = overlay.terminateOn or [ ];
                                      nodeAddrs = overlay.nodes or { };
                                    in
                                    map
                                      (nodeName:
                                        let
                                          nodeAddr = nodeAddrs.${nodeName} or { };
                                        in
                                        {
                                          inherit nodeName;
                            overlayName = _overlayName;
                                          addr4 = nodeAddr.addr4 or null;
                                          addr6 = nodeAddr.addr6 or null;
                                          inherit (overlay) providerBootstrapDns;
                                        }
                                      )
                                      nodes
                                  )
                                  overlays
                              );
                            in
                            wgOverlayNodes
                          )
                          enterpriseData
                      )
                    )
                    cpmData
                );

                # Get wireguard-specific data from inventory
                inventoryData = inventory.controlPlane or { };
                inventorySites = inventoryData.sites or { };
                inventoryOverlays = lib.concatLists (
                  lib.mapAttrsToList
                    (_enterprise: enterpriseSites:
                      lib.concatLists (
                        lib.mapAttrsToList
                          (_site: siteData:
                            let
                              overlays = siteData.overlays or { };
                            in
                            lib.mapAttrsToList
                              (_overlayName: overlayData:
                                {
                                  overlayName = _overlayName;
                                  wgData = overlayData.wireguard or overlayData.wg or { };
                                  provider = overlayData.provider or null;
                                }
                              )
                              overlays
                          )
                          enterpriseSites
                      )
                    )
                    inventorySites
                );

                # Filter wgNodes to only those with wireguard data in inventory.
                # Overlays without wireguard data (e.g., nebula east-west) are
                # present in CPM wgNodes but have empty wgData in inventory.
                wgNodesWithWgData = lib.filter
                  (node:
                    let
                      invOverlay = lib.findFirst
                        (o: o.overlayName == node.overlayName)
                        null
                        inventoryOverlays;
                    in
                    invOverlay != null && invOverlay.wgData != { }
                  )
                  wgNodes;

                # Combine CPM nodes with inventory WG data
                nodeConfigs = map
                  (node:
                    let
                      invOverlay = lib.findFirst
                        (o: o.overlayName == node.overlayName)
                        { wgData = { }; provider = null; }
                        inventoryOverlays;
                      wgData = invOverlay.wgData;
                      peers = wgData.peers or [ ];
                      wgIface =
                        if wgData ? interface && builtins.isString wgData.interface && wgData.interface != "" then
                          wgData.interface
                        else
                          throw "network-renderer-wireguard: inventory overlay ${node.overlayName} wireguard data requires explicit interface name";
                      privateKeyFile =
                        if wgData ? privateKeyFile
                           && builtins.isString wgData.privateKeyFile
                           && wgData.privateKeyFile != "" then
                          wgData.privateKeyFile
                        else
                          throw "network-renderer-wireguard: inventory overlay ${node.overlayName} wireguard data requires explicit privateKeyFile";
                      listenPort = wgData.listenPort or null;
                      netdevName = "40-${wgIface}";
                    in
                    {
                      container = node.nodeName;
                      overlayName = node.overlayName;
                      config = {
                        boot.kernelModules = [ "wireguard" ];

                        environment.systemPackages = [ pkgs.wireguard-tools ];

                        systemd.network.netdevs.${netdevName} = {
                          netdevConfig = {
                            Kind = "wireguard";
                            Name = wgIface;
                            Description = "WireGuard provider egress interface (s88)";
                          };
                          wireguardConfig = {
                            PrivateKeyFile = privateKeyFile;
                          }
                          // lib.optionalAttrs (listenPort != null) {
                            ListenPort = listenPort;
                          };
                          wireguardPeers = map
                            (peer: {
                              wireguardPeerConfig = {
                                PublicKey = peer.publicKey or "";
                                Endpoint = peer.endpoint or "";
                                AllowedIPs = peer.allowedIPs or [ ];
                              }
                              // lib.optionalAttrs (peer ? presharedKeyFile
                                                   && builtins.isString peer.presharedKeyFile
                                                   && peer.presharedKeyFile != "") {
                                                     PresharedKeyFile = peer.presharedKeyFile;
                                                   }
                              // lib.optionalAttrs (peer ? persistentKeepalive
                                                   && builtins.isInt peer.persistentKeepalive) {
                                                     PersistentKeepalive = peer.persistentKeepalive;
                                                   };
                            })
                            peers;
                        };

                        systemd.network.networks.${netdevName} = {
                          matchConfig.Name = wgIface;
                          networkConfig = {
                            ConfigureWithoutCarrier = true;
                          }
                          // lib.optionalAttrs (node.addr4 != null) {
                            Address = [ node.addr4 ];
                          }
                          // lib.optionalAttrs (node.addr6 != null) {
                            Address = (lib.optionals (node.addr4 != null) [ node.addr4 ])
                                    ++ (lib.optionals (node.addr6 != null) [ node.addr6 ]);
                          };
                        };

                        systemd.services.s88-provider-interface-wg-egress = {
                          description = "S88 WireGuard Provider Egress Interface";
                          wantedBy = [ "multi-user.target" ];
                          after = [ "network.target" "systemd-networkd.service" ];
                          requires = [ "systemd-networkd.service" ];
                          path = with pkgs; [ wireguard-tools iproute2 ];
                          serviceConfig = {
                            Type = "oneshot";
                            RemainAfterExit = true;
                            ExecStart = pkgs.writeShellScript
                              "s88-provider-interface-wg-egress-start" ''
                                set -euo pipefail
                                IFACE=${lib.escapeShellArg wgIface}
                                for i in $(seq 1 30); do
                                  if ip link show "$IFACE" >/dev/null 2>&1; then
                                    ip link set "$IFACE" up 2>/dev/null || true
                                    echo "WireGuard egress interface $IFACE is up"
                                    exit 0
                                  fi
                                  sleep 1
                                done
                                echo "WireGuard egress interface $IFACE did not appear" >&2
                                exit 1
                              '';
                            ExecStop = pkgs.writeShellScript
                              "s88-provider-interface-wg-egress-stop" ''
                                set -euo pipefail
                                IFACE=${lib.escapeShellArg wgIface}
                                ip link set "$IFACE" down 2>/dev/null || true
                              '';
                          };
                        };
                      };
                    }
                  )
                  wgNodesWithWgData;

                grouped = lib.foldl
                  (acc: { container, config, ... }:
                    acc // {
                      ${container} = (acc.${container} or [ ]) ++ [ config ];
                    }
                  )
                  { }
                  nodeConfigs;
              in
              lib.mkIf (nodeConfigs != [ ]) {
                containers = lib.mapAttrs
                  (containerName: cfgs: {
                    config = lib.mkMerge cfgs;
                  })
                  grouped;
              };

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
