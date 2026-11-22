{
  description = "network-renderer-wireguard";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    network-control-plane-model.url =
      "github:esp0xdeadbeef/network-control-plane-model";
    network-control-plane-model.inputs.nixpkgs.follows = "nixpkgs";

    network-realization-model.url =
      "github:esp0xdeadbeef/network-realization-model";
    network-realization-model.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, network-control-plane-model
    , network-realization-model, ... }:
    let
      lib = nixpkgs.lib;

      systems = [ "x86_64-linux" "aarch64-linux" ];

      forAllSystems = lib.genAttrs systems;

      mkSystemLib = system:
        let
          sms022TraceId = "FS-470-HDS-010-SDS-010-SMS-022";
          sms022Diagnostic = message: "${sms022TraceId}: ${message}";
          providerContractCm =
            import ./s88/ControlModule/provider-contract.nix { inherit lib; };
          renderResultCm = import ./s88/ControlModule/render-result.nix { };
          validateProviderContract = providerContract:
            let
              providerState = providerContractCm.normalize providerContract;
              failedAssertions =
                builtins.filter (assertion: assertion.assertion == false)
                (providerContractCm.assertions providerState);
            in if failedAssertions != [ ] then
              throw
              ("network-renderer-wireguard provider contract rejected before render-result projection: "
                + builtins.concatStringsSep "; "
                (map (assertion: assertion.message) failedAssertions))
            else
              providerContract;

          # Build per-overlay WG node configs from CPM model.
          # Accepts pre-compiled CPM output (controlPlane) and
          # WG overlay data (wgInventory, extracted from CPM model) — satisfies SMS-021.
          buildWireGuardNodeConfigs =
            { canonicalSites, wgInventory, providerRuntimeModuleFor, pkgs, lib, providerContracts ? null, }:
            let
              wireguardProviderContracts =
                if providerContracts != null then
                  (providerContracts.wireguard or { })
                else
                  { };
              wgNodes = lib.concatLists (map
                (entry:
                  let
                    nodeNames = entry.terminateOn or [ ];
                    nodeAddrs = entry.nodes or { };
                  in map
                    (nodeName:
                      let nodeAddr = nodeAddrs.${nodeName} or { };
                      in {
                        inherit nodeName;
                        overlayName = entry.overlay;
                        addr4 = nodeAddr.addr4 or null;
                        addr6 = nodeAddr.addr6 or null;
                        inherit (entry) providerBootstrapDns;
                      })
                    nodeNames)
                (canonicalSites.overlays or [ ]));

              # Filter wgNodes to only those with wireguard data in wgInventory.
              # Overlays without wireguard data (e.g., nebula east-west) are
              # present in CPM wgNodes but have empty wgData in wgInventory.
              wgNodesWithWgData = lib.filter (node:
                let wgData = wgInventory.${node.overlayName} or { };
                in wgData != { }) wgNodes;

              secretPathOrNull = path:
                if builtins.isString path
                && lib.hasPrefix "/run/secrets/" path then
                  path
                else
                  null;

              providerContractSecretPaths = providerContract:
                let
                  generatedPeer = providerContract.profile.generatedPeer or { };
                  generatedPeers =
                    if builtins.isList (generatedPeer.peers or null) then
                      generatedPeer.peers
                    else
                      [ ];
                in [
                  (secretPathOrNull (generatedPeer.privateKeyFile or null))
                  (secretPathOrNull (generatedPeer.addressesFile or null))
                  (secretPathOrNull (generatedPeer.dnsFile or null))
                ]
                ++ map (peer: secretPathOrNull (peer.endpointFile or null))
                generatedPeers
                ++ map (peer: secretPathOrNull (peer.presharedKeyFile or null))
                generatedPeers
                ++ map (peer: secretPathOrNull (peer.publicKeyFile or null))
                generatedPeers;

              nodeConfigs = map (node:
                let
                  wgData = wgInventory.${node.overlayName} or { };
                  providerContract =
                    wireguardProviderContracts.${node.overlayName} or null;
                  peers = if providerContract != null then [ ] else if wgData ? peers && builtins.isList wgData.peers
                  && wgData.peers != [ ] then
                    wgData.peers
                  else
                    throw (sms022Diagnostic
                      "WireGuard peers required by CPM-preserved wgInventory for inventory overlay ${node.overlayName}");
                  wgIface = if providerContract != null then
                    (providerContract.interfaces.vpn or "wg0")
                  else if wgData ? interface
                  && builtins.isString wgData.interface && wgData.interface
                  != "" then
                    if builtins.stringLength wgData.interface <= 15 then
                      wgData.interface
                    else
                      throw (sms022Diagnostic
                        "WireGuard interface name from CPM-preserved wgInventory must be <= 15 characters for Linux, got ${wgData.interface}")
                  else
                    throw (sms022Diagnostic ''
                      WireGuard interface name required by CPM-preserved wgInventory, cannot default to "wg-egress" for inventory overlay ${node.overlayName}'');
                  privateKeyFile = if providerContract != null then
                    ""
                  else if wgData ? privateKeyFile
                  && builtins.isString wgData.privateKeyFile
                  && wgData.privateKeyFile != "" then
                    wgData.privateKeyFile
                  else
                    throw (sms022Diagnostic
                      "WireGuard private key path required by CPM-preserved wgInventory for inventory overlay ${node.overlayName}, cannot construct a default private key path");
                  listenPort = if providerContract != null then
                    null
                  else if wgData ? listenPort
                  && builtins.isInt wgData.listenPort then
                    wgData.listenPort
                  else
                    throw (sms022Diagnostic
                      "WireGuard listenPort required by CPM-preserved wgInventory for inventory overlay ${node.overlayName}, cannot default to 51820");
                  netdevName = "40-${wgIface}";
                  secretPaths = lib.unique (builtins.filter (path: path != null)
                    ([ (secretPathOrNull privateKeyFile) ] ++ map
                      (peer: secretPathOrNull (peer.presharedKeyFile or null))
                      peers ++ lib.optionals (providerContract != null)
                      (providerContractSecretPaths providerContract)));
                  duplicateAllowedIP =
                    let
                      claims = lib.concatMap
                        (peer: if builtins.isList (peer.allowedIPs or null) then peer.allowedIPs else [ ])
                        peers;
                      counts = builtins.foldl'
                        (acc: ip: acc // { ${ip} = (acc.${ip} or 0) + 1; })
                        { }
                        claims;
                      duplicates = builtins.filter
                        (ip: counts.${ip} > 1)
                        (builtins.attrNames counts);
                    in
                    if duplicates == [ ] then null else builtins.head duplicates;
                  wireguardNetdevConfig = {
                    boot.kernelModules = [ "wireguard" ];

                    environment.systemPackages = [ pkgs.wireguard-tools ];

                    systemd.network.netdevs.${netdevName} = {
                      netdevConfig = {
                        Kind = "wireguard";
                        Name = wgIface;
                        Description =
                          "WireGuard provider egress interface (s88)";
                      };
                      wireguardConfig = {
                        PrivateKeyFile = privateKeyFile;
                      } // lib.optionalAttrs (listenPort != null) {
                        ListenPort = listenPort;
                      };
                      # FS-315 / FS-310-HDS-020-SDS-010-SMS-060: one route
                      # authority carries ONE modelled next-hop set. Two peers of
                      # the same interface claiming the same prefix (in practice
                      # 0.0.0.0/0) is one authority with two next hops, and
                      # `ip route replace` keys on (table, destination) -- so the
                      # survivor depends on write order. The model names one
                      # member; a peer set that names two is refused here rather
                      # than emitted.
                      wireguardPeers = if duplicateAllowedIP != null then
                        throw (sms022Diagnostic
                          "WireGuard interface ${wgIface} has more than one peer claiming ${duplicateAllowedIP} (one route authority, one next-hop set)")
                      else map (peer: {
                        wireguardPeerConfig = {
                          PublicKey = if peer ? publicKey
                          && builtins.isString peer.publicKey && peer.publicKey
                          != "" then
                            peer.publicKey
                          else
                            throw (sms022Diagnostic
                              "WireGuard peer requires publicKey from CPM-preserved wgInventory for inventory overlay ${node.overlayName}");
                          Endpoint = if peer ? endpoint
                          && builtins.isString peer.endpoint && peer.endpoint
                          != "" then
                            peer.endpoint
                          else
                            throw (sms022Diagnostic
                              "WireGuard peer requires endpoint from CPM-preserved wgInventory for inventory overlay ${node.overlayName}");
                          AllowedIPs = if peer ? allowedIPs
                          && builtins.isList peer.allowedIPs && peer.allowedIPs
                          != [ ] then
                            peer.allowedIPs
                          else
                            throw (sms022Diagnostic
                              "WireGuard peer requires allowedIPs from CPM-preserved wgInventory for inventory overlay ${node.overlayName}");
                        } // lib.optionalAttrs (peer ? presharedKeyFile
                          && builtins.isString peer.presharedKeyFile
                          && peer.presharedKeyFile
                          != "") { PresharedKeyFile = peer.presharedKeyFile; }
                          // lib.optionalAttrs (peer ? persistentKeepalive
                            && builtins.isInt peer.persistentKeepalive) {
                              PersistentKeepalive = peer.persistentKeepalive;
                            };
                      }) peers;
                    };

                    systemd.network.networks.${netdevName} = {
                      matchConfig.Name = wgIface;
                      networkConfig = {
                        ConfigureWithoutCarrier = true;
                      } // lib.optionalAttrs (node.addr4 != null) {
                        Address = [ node.addr4 ];
                      } // lib.optionalAttrs (node.addr6 != null) {
                        Address =
                          (lib.optionals (node.addr4 != null) [ node.addr4 ])
                          ++ (lib.optionals (node.addr6 != null)
                            [ node.addr6 ]);
                      };
                    };

                    systemd.services."s88-provider-interface-${wgIface}-egress" =
                      {
                        description = "S88 WireGuard Provider Egress Interface";
                        wantedBy = [ "multi-user.target" ];
                        after = [ "network.target" "systemd-networkd.service" ];
                        requires = [ "systemd-networkd.service" ];
                        path = with pkgs; [ wireguard-tools iproute2 ];
                        serviceConfig = {
                          Type = "oneshot";
                          RemainAfterExit = true;
                          ExecStart = pkgs.writeShellScript
                            "s88-provider-interface-${wgIface}-egress-start" ''
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
                            "s88-provider-interface-${wgIface}-egress-stop" ''
                              set -euo pipefail
                              IFACE=${lib.escapeShellArg wgIface}
                              ip link set "$IFACE" down 2>/dev/null || true
                            '';
                        };
                      };
                  };
                  providerRuntimeConfig =
                    providerRuntimeModuleFor providerContract;
                in {
                  container = node.nodeName;
                  overlayName = node.overlayName;
                  inherit secretPaths;
                  config = if providerContract == null then
                    wireguardNetdevConfig
                  else
                    providerRuntimeConfig;
                }) wgNodesWithWgData;
            in nodeConfigs;
        in {
          renderer = rec {
            # FS-470-HDS-010-SDS-010-SMS-021: Accepts only CPM output (controlPlane).
            # wgInventory is extracted from controlPlane internally — no separate
            # parameter, no path-based API, no inventory tree walking.
            # When CPM output omits wgInventory, this renderer has no WireGuard
            # authority for that host and creates no containers.

            hostModule = rendererInput:
              { config, lib, pkgs, ... }:
              let
                canonicalSites = rendererInput.canonicalSites or (throw
                  "${sms022TraceId}: WireGuard hostModule requires the bundle's canonicalSites");
                canonicalWireGuard = rendererInput.canonicalWireGuard or (throw
                  "${sms022TraceId}: WireGuard hostModule requires the bundle's canonicalWireGuard");
                wgInventory = rendererInput.wgInventory or (canonicalWireGuard.providers or { });
                providerContracts = rendererInput.providerContracts or (canonicalWireGuard.contracts or null);
                nodeConfigs = buildWireGuardNodeConfigs {
                  inherit canonicalSites;
                  providerRuntimeModuleFor =
                    buildWireGuardProviderRuntimeModule;
                  inherit wgInventory providerContracts pkgs lib;
                };

                groupedConfigs = lib.foldl (acc:
                  { container, config, ... }:
                  acc // {
                    ${container} = (acc.${container} or [ ]) ++ [ config ];
                  }) { } nodeConfigs;

                groupedSecretPaths = lib.foldl (acc:
                  { container, secretPaths ? [ ], ... }:
                  acc // {
                    ${container} =
                      lib.unique ((acc.${container} or [ ]) ++ secretPaths);
                  }) { } nodeConfigs;

                secretNspawnBindFlags = paths:
                  map (path: "--bind-ro=${path}:${path}") paths;

              in lib.mkIf (nodeConfigs != [ ]) {
                containers = lib.mapAttrs (containerName: cfgs:
                  {
                    additionalCapabilities = [ "CAP_NET_ADMIN" "CAP_NET_RAW" ];
                    autoStart = true;
                    config.imports = cfgs;
                    privateNetwork = true;
                  } // lib.optionalAttrs
                  ((groupedSecretPaths.${containerName} or [ ]) != [ ]) {
                    extraFlags =
                      secretNspawnBindFlags groupedSecretPaths.${containerName};
                  }) groupedConfigs;
              };

            canonical = {
              validateInput = { bundle, platformBinding ? null, }:
                network-realization-model.lib.validateRendererInput {
                  inherit bundle platformBinding;
                  expectedTarget = "wireguard";
                };
              hostModule =
                { bundle, platformBinding ? null, ... }@rendererInput:
                let
                  validated =
                    canonical.validateInput { inherit bundle platformBinding; };
                  forwarded = builtins.removeAttrs rendererInput [
                    "bundle"
                    "platformBinding"
                  ];
                in hostModule (forwarded // {
                  # The bundle's canonical section, which
                  # network-realization-model projects from the producer. Reading
                  # `bundle.network.data.canonicalSites` assumed the producer put
                  # its collections on the artifact's top level; a producer that
                  # wraps them (a build result that nests the envelope) publishes
                  # them one level down, and the read found nothing.
                  # The bundle section is the same value, normalized, and is the
                  # contract a renderer is supposed to map.
                  canonicalSites = (bundle.canonical.canonicalSites or (throw
                    "WireGuard renderer requires the bundle's canonicalSites"));
                  canonicalWireGuard = (bundle.canonical.canonicalWireGuard or (throw
                    "WireGuard renderer requires the bundle's canonicalWireGuard"));
                  canonicalBundleIdentity = validated.bundleIdentity;
                  canonicalBindingIdentity = validated.bindingIdentity;
                });
            };

            buildWireGuardProviderRenderResult = providerRequest:
              let
                providerContract = if builtins.isAttrs providerRequest
                && providerRequest ? providerContract then
                  providerRequest.providerContract
                else
                  providerRequest;

                validatedProviderContract =
                  validateProviderContract providerContract;
                validationToken = builtins.seq validatedProviderContract true;

                requiredCapabilities = if builtins.isAttrs providerRequest
                && builtins.isList
                (providerRequest.requiredCapabilities or null) then
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
              in builtins.seq validationToken (renderResultCm.build {
                providerContract = validatedProviderContract;
                inherit requiredCapabilities;
                nixosModule = providerRuntimeModule;
              });

            buildWireGuardProviderRuntimeModule = providerContract:
              (buildWireGuardProviderRenderResult
                providerContract).artifacts.nixosModules.providerRuntime;
          };
        };
    in {
      nixosModules.default = import ./modules/wireguard-provider-runtime.nix;
      nixosModules.wireguard-provider-runtime = self.nixosModules.default;

      packages = forAllSystems (system: {
        wg-conf-to-secrets = (import nixpkgs { inherit system; }).callPackage ./pkgs/wg-conf-to-secrets { };
      });

      libBySystem = forAllSystems mkSystemLib;
      lib = mkSystemLib "x86_64-linux";

      checks = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          renderer = self.libBySystem.${system}.renderer;
          bundle = network-realization-model.lib.realize {
            input =
              import "${network-realization-model}/examples/cpm-result.nix";
            requestScope = {
              kind = "complete-artifact";
              identity = "wireguard-renderer-boundary";
            };
            rootLockIdentity = "network-renderer-wireguard-flake-lock";
            producerRevision = network-realization-model.rev;
          };
          accepted = renderer.canonical.validateInput { inherit bundle; };
          rawRejected = !(builtins.tryEval (builtins.deepSeq
            (renderer.canonical.validateInput {
              bundle = { rawProducerPayload = { }; };
            }) true)).success;
        in assert accepted.bundleIdentity == bundle.bundleIdentity;
        assert rawRejected; {
          canonical-renderer-input =
            pkgs.runCommand "network-renderer-wireguard-canonical-input" { } ''
              touch "$out"
            '';
        });
    };
}
