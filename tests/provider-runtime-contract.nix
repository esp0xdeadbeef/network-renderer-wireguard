# FS-470-HDS-010-SDS-010-SMS-041 and FS-310-HDS-020-SDS-010-SMS-040:
# provider runtime test fixture binds eth0 as an explicit ingress/WAN interface
# fact and verifies the WireGuard renderer contract around it.
{ repoRoot ? toString ./..
, system ? builtins.currentSystem
}:

let
  flake = builtins.getFlake repoRoot;
  pkgs = import flake.inputs.nixpkgs { inherit system; };
  lib = pkgs.lib;
  providerContractCm = import ../s88/ControlModule/provider-contract.nix { inherit lib; };

  baseContract = {
    id = "test-provider";
    provider = {
      class = "commercial-imported";
      mode = "egress-only";
      prefixAuthority = "none";
    };
    interfaces = {
      wan = "eth0";
      lan = "lan0";
      vpn = "wg0";
    };
    profile = {
      mode = "profile-import";
      path = "/run/test-provider/wg.conf";
      format = "wireguard";
    };
    dns.mode = "default";
    firewall = {
      mode = "dedicated-gateway";
      allowLanToVpn = true;
      denyLanToWan = true;
      denyWanToLan = true;
    };
    runtime.uuidFile = "/run/network-renderer-wireguard/test-provider.uuid";
    publicIngress = [ ];
    portForwards = [ ];
    lan = {
      ipv4.address = "10.66.0.1/24";
      ipv6.address = "fd42:66::1/64";
    };
    nat = {
      ipv4 = {
        enable = true;
        sourceCidrs = [ "10.66.0.0/24" ];
      };
      ipv6 = {
        enable = true;
        sourceCidrs = [ "fd42:66::/64" ];
      };
    };
    services = {
      dhcp4 = {
        enable = true;
        subnet = "10.66.0.0/24";
        pool = "10.66.0.100 - 10.66.0.200";
        gateway = "10.66.0.1";
        dns = [ "10.66.0.1" ];
        leaseFile = "/var/lib/kea/dhcp4.leases";
      };
      ra = {
        enable = true;
        prefix = "fd42:66::/64";
        rdnss = [ "fd42:66::1" ];
      };
      healthCheck.enable = false;
    };
  };

  evalWith =
    providerContract:
    import (flake.inputs.nixpkgs + "/nixos/lib/eval-config.nix") {
      inherit system;
      modules = [
        flake.nixosModules.default
        {
          services.network-renderer-wireguard.providerRuntime = {
            enable = true;
            inherit providerContract;
          };
        }
      ];
    };

  falseAssertionMessages =
    evaluated:
    map (assertion: assertion.message) (
      builtins.filter (assertion: assertion.assertion == false) evaluated.config.assertions
    );

  forceEval =
    providerContract:
    let
      state = providerContractCm.normalize providerContract;
    in
    {
      inherit (state)
        dnsMode
        nat44Enable
        prefixAuthority
        profileMode
        publicIngress
        portForwards
        providerClass
        providerMode
        uuidFile
        ;
    };

  valid = evalWith baseContract;
  routedWithNat66 = evalWith (
    lib.recursiveUpdate baseContract {
      provider = {
        class = "self-hosted";
        mode = "routed-prefix";
        publicEndpoint = {
          address = "203.0.113.10";
          port = 51820;
          transport = "udp";
        };
      };
      routes.ipv6.routedClientPrefixes = [ "2001:db8:66::/64" ];
      nat.ipv6 = {
        enable = true;
        sourceCidrs = [ "fd42:66::/64" ];
      };
    }
  );
  publicIngressMissing = evalWith (
    lib.recursiveUpdate baseContract {
      provider = {
        class = "self-hosted";
        mode = "public-ingress";
        publicEndpoint = {
          address = "203.0.113.10";
          port = 51820;
          transport = "udp";
        };
      };
      nat.ipv6.enable = false;
    }
  );
  selfHostedMissingEndpoint = evalWith (
    lib.recursiveUpdate baseContract {
      provider = {
        class = "self-hosted";
        mode = "egress-only";
      };
      nat.ipv6.enable = false;
    }
  );
  selfHostedExposureContract =
    lib.recursiveUpdate baseContract {
      provider = {
        class = "self-hosted";
        mode = "public-ingress";
        publicEndpoint = {
          address = "203.0.113.10";
          port = 51820;
          transport = "udp";
        };
      };
      routes = {
        ipv6.providerOwnedPrefixes = [ "2001:db8:70::/64" ];
        returnRoutes = [
          {
            destination = "2001:db8:70:10::/64";
            gateway = "fd42:66::2";
            interface = "lan0";
          }
        ];
      };
      publicIngress = [
        {
          id = "https-ingress";
          protocol = "tcp";
          listenPort = 443;
          targetAddress = "10.66.0.10";
          targetPort = 443;
          targetInterface = "lan0";
        }
      ];
      portForwards = [
        {
          id = "wg-game";
          protocol = "udp";
          listenPort = 51821;
          ingressInterface = "eth0";
          targetAddress = "10.66.0.20";
          targetPort = 51820;
          targetInterface = "lan0";
        }
      ];
      nat.ipv6.enable = false;
    };
  selfHostedExposureValid = evalWith selfHostedExposureContract;
  selfHostedBadReturnRoute = evalWith (
    lib.recursiveUpdate selfHostedExposureContract {
      routes.returnRoutes = [
        {
          destination = "2001:db8:70:10::/64";
          interface = "lan0";
        }
      ];
    }
  );
  selfHostedBadPublicIngress = evalWith (
    lib.recursiveUpdate selfHostedExposureContract {
      publicIngress = [
        {
          id = "bad-public-ingress";
          protocol = "tcp";
          listenPort = 443;
          targetAddress = "10.66.0.10";
          targetInterface = "lan0";
        }
      ];
    }
  );
  selfHostedBadPortForward = evalWith (
    lib.recursiveUpdate selfHostedExposureContract {
      portForwards = [
        {
          id = "bad-port-forward";
          protocol = "udp";
          listenPort = 51821;
          ingressInterface = "eth0";
          targetAddress = "10.66.0.20";
          targetInterface = "lan0";
        }
      ];
    }
  );
  commercialPortForwardContract =
    lib.recursiveUpdate baseContract {
      provider.mode = "public-ingress";
      portForwards = [
        {
          id = "commercial-forward";
          protocol = "tcp";
          listenPort = 8443;
          ingressInterface = "wg0";
          targetAddress = "10.66.0.30";
          targetPort = 443;
          targetInterface = "lan0";
        }
      ];
    };
  commercialPortForwardValid = evalWith commercialPortForwardContract;
  commercialPublicIngressWithoutAuthority = evalWith (
    lib.recursiveUpdate baseContract {
      provider.mode = "public-ingress";
      publicIngress = [
        {
          id = "commercial-public-ingress";
          protocol = "tcp";
          listenPort = 443;
          targetAddress = "10.66.0.40";
          targetPort = 443;
          targetInterface = "lan0";
        }
      ];
    }
  );
  commercialPublicIngressAuthorityContract =
    lib.recursiveUpdate baseContract {
      provider = {
        mode = "public-ingress";
        publicIngressAuthority = true;
      };
      publicIngress = [
        {
          id = "commercial-public-ingress";
          protocol = "tcp";
          listenPort = 443;
          targetAddress = "10.66.0.40";
          targetPort = 443;
          targetInterface = "lan0";
        }
      ];
    };
  commercialPublicIngressAuthorityValid = evalWith commercialPublicIngressAuthorityContract;
  commercialRoutedWithoutAuthority = evalWith (
    lib.recursiveUpdate baseContract {
      provider.mode = "routed-prefix";
      routes.ipv6.routedClientPrefixes = [ "2001:db8:80::/64" ];
      nat.ipv6.enable = false;
    }
  );
  commercialRoutedAuthorityContract =
    lib.recursiveUpdate baseContract {
      provider = {
        mode = "routed-prefix";
        routedClientPrefixAuthority = true;
      };
      routes = {
        ipv6.routedClientPrefixes = [ "2001:db8:80::/64" ];
        returnRoutes = [
          {
            destination = "2001:db8:80::/64";
            gateway = "fd42:66::80";
            interface = "lan0";
          }
        ];
      };
      nat.ipv6.enable = false;
    };
  commercialRoutedAuthorityValid = evalWith commercialRoutedAuthorityContract;
  routedPrefixContract =
    lib.recursiveUpdate baseContract {
      provider = {
        class = "self-hosted";
        mode = "routed-prefix";
        prefixAuthority = "routed-prefix";
        publicEndpoint = {
          address = "203.0.113.11";
          port = 51820;
          transport = "udp";
        };
      };
      routes = {
        ipv6.routedClientPrefixes = [ "2001:db8:91::/64" ];
        returnRoutes = [
          {
            destination = "2001:db8:91::/64";
            gateway = "fd42:66::91";
            interface = "lan0";
          }
        ];
      };
      nat.ipv6.enable = false;
    };
  routedPrefixValid = evalWith routedPrefixContract;
  providerOwnedPrefixContract =
    lib.recursiveUpdate baseContract {
      provider = {
        class = "self-hosted";
        mode = "routed-prefix";
        prefixAuthority = "provider-owned-prefix";
        publicEndpoint = {
          address = "203.0.113.12";
          port = 51820;
          transport = "udp";
        };
      };
      routes = {
        ipv6.providerOwnedPrefixes = [ "2001:db8:92::/64" ];
        returnRoutes = [
          {
            destination = "2001:db8:92::/64";
            gateway = "fd42:66::92";
            interface = "lan0";
          }
        ];
      };
      nat.ipv6.enable = false;
    };
  providerOwnedPrefixValid = evalWith providerOwnedPrefixContract;
  clientPrefixMissingReturnRoute = evalWith (
    lib.recursiveUpdate routedPrefixContract {
      routes.returnRoutes = [ ];
    }
  );
  clientPrefixNat66 = evalWith (
    lib.recursiveUpdate routedPrefixContract {
      nat.ipv6 = {
        enable = true;
        sourceCidrs = [ "fd42:66::/64" ];
      };
    }
  );
  clientPrefixRouterGua = evalWith (
    lib.recursiveUpdate routedPrefixContract {
      lan.ipv6.address = "2001:db8:91::1/64";
    }
  );
  hostOnlyContract =
    lib.recursiveUpdate baseContract {
      provider.prefixAuthority = "host-only-128";
    };
  hostOnlyValid = evalWith hostOnlyContract;
  hostOnlySnatContract =
    lib.recursiveUpdate hostOnlyContract {
      nat = {
        ipv4.toAddress = "198.51.100.44";
        ipv6.toAddress = "2001:db8:44::1";
      };
    };
  hostOnlySnatValid = evalWith hostOnlySnatContract;
  hostOnlyNat44MissingSource = evalWith (
    lib.recursiveUpdate hostOnlyContract {
      nat.ipv4.sourceCidrs = [ ];
    }
  );
  hostOnlyNat66MissingSource = evalWith (
    lib.recursiveUpdate hostOnlyContract {
      nat.ipv6.sourceCidrs = [ ];
    }
  );
  hostOnlyDownstreamGua = evalWith (
    lib.recursiveUpdate hostOnlyContract {
      provider.routedClientPrefixAuthority = true;
      routes.ipv6.routedClientPrefixes = [ "2001:db8:90::/64" ];
    }
  );
  tooLongVpnInterface = evalWith (
    lib.recursiveUpdate baseContract {
      interfaces.vpn = "wg-remote-egress0";
    }
  );
  badProviderClassRenderResult =
    flake.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult (
      lib.recursiveUpdate baseContract {
        provider.class = "guessed-provider-name";
      }
    );
  badProviderModeRenderResult =
    flake.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult (
      lib.recursiveUpdate baseContract {
        provider.mode = "assume-public-ingress";
      }
    );
  badPrefixAuthorityRenderResult =
    flake.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult (
      lib.recursiveUpdate baseContract {
        provider.prefixAuthority = "assume-routed-gua";
      }
    );
  missingDnsModeResult = forceEval (baseContract // { dns = { }; });
  missingPrefixAuthorityResult = forceEval (
    baseContract
    // {
      provider = builtins.removeAttrs baseContract.provider [ "prefixAuthority" ];
    }
  );
  missingRuntimePathResult = forceEval (baseContract // { runtime = { }; });
  missingPublicIngressListResult = forceEval (builtins.removeAttrs baseContract [ "publicIngress" ]);
  missingPortForwardsListResult = forceEval (builtins.removeAttrs baseContract [ "portForwards" ]);
  missingNat44ModeResult = forceEval (
    baseContract
    // {
      nat = baseContract.nat // {
        ipv4 = builtins.removeAttrs baseContract.nat.ipv4 [ "enable" ];
      };
    }
  );
  missingProfileModeResult = forceEval (
    baseContract
    // {
      profile = builtins.removeAttrs baseContract.profile [ "mode" ];
    }
  );
  healthCheckMissingTarget = evalWith (
    lib.recursiveUpdate baseContract {
      services.healthCheck = {
        enable = true;
        interval = "30s";
      };
    }
  );
  firewallMissingAction = evalWith (
    baseContract
    // {
      firewall = builtins.removeAttrs baseContract.firewall [ "allowLanToVpn" ];
    }
  );
  generatedPeerContract =
    lib.recursiveUpdate baseContract {
      profile = {
        mode = "generated-peer";
        generatedPeer = {
          privateKeyFile = "/run/keys/wg-private";
          addresses = [
            "10.70.0.2/32"
            "2001:db8:70::2/128"
          ];
          dns = [ "10.70.0.1" ];
          mtu = 1420;
          peers = [
            {
              publicKey = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc=";
              endpoint = "198.51.100.10:51820";
              allowedIPs = [
                "0.0.0.0/0"
                "::/0"
              ];
              presharedKeyFile = "/run/keys/wg-psk";
              persistentKeepalive = 25;
            }
          ];
        };
      };
      runtime = {
        generatedConfigPath = "/run/network-renderer-wireguard/generated-test-provider.conf";
        uuidFile = "/run/network-renderer-wireguard/test-provider.uuid";
      };
    };
  generatedPeerValid = evalWith generatedPeerContract;
  nameInferenceContract =
    lib.recursiveUpdate baseContract {
      id = "public-ingress-routed-gua-dns-nat66-hostile";
      profile.path = "/run/public-ingress-routed-gua-dns-nat66-hostile.conf";
      dns.mode = "none";
      runtime.ownNetworkStack = true;
      nat = {
        ipv4 = {
          enable = false;
          sourceCidrs = [ ];
        };
        ipv6 = {
          enable = false;
          sourceCidrs = [ ];
        };
      };
    };
  nameInferenceValid = evalWith nameInferenceContract;
  generatedPeerMissingEndpoint = evalWith (
    lib.recursiveUpdate generatedPeerContract {
      profile.generatedPeer.peers = [
        {
          publicKey = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc=";
          allowedIPs = [ "0.0.0.0/0" ];
        }
      ];
    }
  );
  generatedPeerMissingPrivateKey = evalWith (
    generatedPeerContract
    // {
      profile = generatedPeerContract.profile // {
        generatedPeer =
          builtins.removeAttrs generatedPeerContract.profile.generatedPeer [ "privateKeyFile" ];
      };
    }
  );
  fs100ProvenanceContract =
    lib.recursiveUpdate baseContract {
      id = "fs100-renderer-output-provenance-provider";
      provenance = {
        path = "provider-contracts/fs100-wireguard-provider.json";
        sourceClasses = {
          userIntent = {
            path = "examples/fs100/intent.nix";
            narHash = "sha256-intent";
          };
          publicInventory = {
            path = "examples/fs100/inventory-nixos.nix";
            narHash = "sha256-public-inventory";
          };
          protectedInventory = {
            ref = "sops://examples/fs100/protected.yaml";
            secretValue = "PLAINTEXT-PROTECTED-VALUE";
          };
          runtimeFacts = {
            ref = "runtime://provider/public-addresses";
          };
          validationContext = {
            profile = "renderer-construction";
          };
        };
        requested = {
          scope = {
            site = "nixos";
            host = "s-router-nixos";
          };
          target = {
            renderer = "wireguard";
            role = "renderer-output";
          };
        };
        locks = {
          "network-control-plane-model" = {
            rev = "1111222233334444555566667777888899990000";
            narHash = "sha256-cpm";
          };
        };
        controlledBaseline = "fs100-renderer-output-provenance";
      };
    };
  renderResult = flake.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult baseContract;
  fs100ProvenanceRenderResult =
    flake.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult fs100ProvenanceContract;
  selfHostedRenderResult =
    flake.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult selfHostedExposureContract;
  commercialPortForwardRenderResult =
    flake.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult commercialPortForwardContract;
  commercialPublicIngressAuthorityRenderResult =
    flake.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult commercialPublicIngressAuthorityContract;
  commercialRoutedAuthorityRenderResult =
    flake.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult commercialRoutedAuthorityContract;
  routedPrefixRenderResult =
    flake.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult routedPrefixContract;
  providerOwnedPrefixRenderResult =
    flake.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult providerOwnedPrefixContract;
  hostOnlyRenderResult =
    flake.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult hostOnlyContract;
  hostOnlySnatRenderResult =
    flake.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult hostOnlySnatContract;
  nameInferenceRenderResult =
    flake.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult nameInferenceContract;
  generatedPeerRenderResult =
    flake.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult generatedPeerContract;
  renderResultWithRequiredCapabilities =
    flake.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult {
      providerContract = baseContract;
      requiredCapabilities = [
        "provider-runtime"
        "source-scoped-nat44"
      ];
    };
  missingRequiredCapabilityResult =
    flake.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult {
      providerContract = baseContract;
      requiredCapabilities = [
        "provider-runtime"
        "future-public-ingress"
      ];
    };
in
{
  valid = {
    dispatcherDescription = valid.config.systemd.services.wireguard-provider-dispatcher.description;
    nftables = valid.config.networking.nftables.ruleset;
    dhcp4Config = valid.config.environment.etc."kea/kea-dhcp4.conf".text;
    radvdConfig = valid.config.environment.etc."radvd.conf".text;
  };

  routedWithNat66Errors = falseAssertionMessages routedWithNat66;
  publicIngressMissingErrors = falseAssertionMessages publicIngressMissing;
  selfHostedMissingEndpointErrors = falseAssertionMessages selfHostedMissingEndpoint;
  selfHostedBadReturnRouteErrors = falseAssertionMessages selfHostedBadReturnRoute;
  selfHostedBadPublicIngressErrors = falseAssertionMessages selfHostedBadPublicIngress;
  selfHostedBadPortForwardErrors = falseAssertionMessages selfHostedBadPortForward;
  commercialPublicIngressWithoutAuthorityErrors = falseAssertionMessages commercialPublicIngressWithoutAuthority;
  commercialRoutedWithoutAuthorityErrors = falseAssertionMessages commercialRoutedWithoutAuthority;
  clientPrefixMissingReturnRouteErrors = falseAssertionMessages clientPrefixMissingReturnRoute;
  clientPrefixNat66Errors = falseAssertionMessages clientPrefixNat66;
  clientPrefixRouterGuaErrors = falseAssertionMessages clientPrefixRouterGua;
  hostOnlyNat44MissingSourceErrors = falseAssertionMessages hostOnlyNat44MissingSource;
  hostOnlyNat66MissingSourceErrors = falseAssertionMessages hostOnlyNat66MissingSource;
  hostOnlyDownstreamGuaErrors = falseAssertionMessages hostOnlyDownstreamGua;
  tooLongVpnInterfaceErrors = falseAssertionMessages tooLongVpnInterface;
  selfHostedExposure = {
    publicEndpoint = selfHostedExposureContract.provider.publicEndpoint;
    nftables = selfHostedExposureValid.config.networking.nftables.ruleset;
    lanRoutes = selfHostedExposureValid.config.systemd.network.networks."20-lan0".routes;
    providerSurfaces = selfHostedRenderResult.artifacts.providerSurfaces;
    capabilities = selfHostedRenderResult.capabilities;
    trace = selfHostedRenderResult.trace;
  };
  commercialPortForward = {
    nftables = commercialPortForwardValid.config.networking.nftables.ruleset;
    providerSurfaces = commercialPortForwardRenderResult.artifacts.providerSurfaces;
    capabilities = commercialPortForwardRenderResult.capabilities;
    trace = commercialPortForwardRenderResult.trace;
  };
  commercialPublicIngressAuthority = {
    nftables = commercialPublicIngressAuthorityValid.config.networking.nftables.ruleset;
    providerSurfaces = commercialPublicIngressAuthorityRenderResult.artifacts.providerSurfaces;
    capabilities = commercialPublicIngressAuthorityRenderResult.capabilities;
    trace = commercialPublicIngressAuthorityRenderResult.trace;
  };
  commercialRoutedAuthority = {
    providerSurfaces = commercialRoutedAuthorityRenderResult.artifacts.providerSurfaces;
    capabilities = commercialRoutedAuthorityRenderResult.capabilities;
    trace = commercialRoutedAuthorityRenderResult.trace;
    hasProviderRuntimeModule =
      builtins.hasAttr "providerRuntime" commercialRoutedAuthorityRenderResult.artifacts.nixosModules;
  };
  routedPrefix = {
    lanRoutes = routedPrefixValid.config.systemd.network.networks."20-lan0".routes;
    providerSurfaces = routedPrefixRenderResult.artifacts.providerSurfaces;
    capabilities = routedPrefixRenderResult.capabilities;
    trace = routedPrefixRenderResult.trace;
  };
  providerOwnedPrefix = {
    lanRoutes = providerOwnedPrefixValid.config.systemd.network.networks."20-lan0".routes;
    providerSurfaces = providerOwnedPrefixRenderResult.artifacts.providerSurfaces;
    capabilities = providerOwnedPrefixRenderResult.capabilities;
    trace = providerOwnedPrefixRenderResult.trace;
  };
  hostOnly = {
    nftables = hostOnlyValid.config.networking.nftables.ruleset;
    providerSurfaces = hostOnlyRenderResult.artifacts.providerSurfaces;
    capabilities = hostOnlyRenderResult.capabilities;
    trace = hostOnlyRenderResult.trace;
  };
  hostOnlySnat = {
    nftables = hostOnlySnatValid.config.networking.nftables.ruleset;
    providerSurfaces = hostOnlySnatRenderResult.artifacts.providerSurfaces;
    capabilities = hostOnlySnatRenderResult.capabilities;
    trace = hostOnlySnatRenderResult.trace;
  };
  generatedPeer = {
    dispatcherDescription = generatedPeerValid.config.systemd.services.wireguard-provider-dispatcher.description;
    generatedConfigPath = generatedPeerContract.runtime.generatedConfigPath;
    uuidFile = generatedPeerContract.runtime.uuidFile;
    profileMode = generatedPeerContract.profile.mode;
    privateKeyFile = generatedPeerContract.profile.generatedPeer.privateKeyFile;
    endpoint = (builtins.elemAt generatedPeerContract.profile.generatedPeer.peers 0).endpoint;
    allowedIPs = (builtins.elemAt generatedPeerContract.profile.generatedPeer.peers 0).allowedIPs;
    presharedKeyFile = (builtins.elemAt generatedPeerContract.profile.generatedPeer.peers 0).presharedKeyFile;
    mtu = generatedPeerContract.profile.generatedPeer.mtu;
    hasProviderRuntimeModule =
      builtins.hasAttr "providerRuntime" generatedPeerRenderResult.artifacts.nixosModules;
    trace = generatedPeerRenderResult.trace;
  };
  nameInference = {
    networkmanagerDns = nameInferenceValid.config.networking.networkmanager.dns;
    nftables = nameInferenceValid.config.networking.nftables.ruleset;
    providerSurfaces = nameInferenceRenderResult.artifacts.providerSurfaces;
    capabilities = nameInferenceRenderResult.capabilities;
    trace = nameInferenceRenderResult.trace;
  };
  generatedPeerMissingEndpointErrors = falseAssertionMessages generatedPeerMissingEndpoint;
  generatedPeerMissingPrivateKeyErrors = falseAssertionMessages generatedPeerMissingPrivateKey;
  healthCheckMissingTargetErrors = falseAssertionMessages healthCheckMissingTarget;
  firewallMissingActionErrors = falseAssertionMessages firewallMissingAction;

  renderResultShape = {
    inherit (renderResult)
      rendererClass
      targetRenderer
      scope
      capabilities
      diagnostics
      unsupportedContracts
      validationHints
      trace
      ;
    providerSurfaces = renderResult.artifacts.providerSurfaces;
    hasProviderRuntimeModule =
      builtins.hasAttr "providerRuntime" renderResult.artifacts.nixosModules;
  };

  renderResultWithRequiredCapabilitiesShape = {
    inherit (renderResultWithRequiredCapabilities) capabilities targetRenderer;
    hasProviderRuntimeModule =
      builtins.hasAttr "providerRuntime" renderResultWithRequiredCapabilities.artifacts.nixosModules;
  };
  fs100RendererOutputProvenance = fs100ProvenanceRenderResult.metadata.provenance;

  inherit
    missingDnsModeResult
    missingPrefixAuthorityResult
    missingRuntimePathResult
    missingPublicIngressListResult
    missingPortForwardsListResult
    missingNat44ModeResult
    missingProfileModeResult
    badProviderClassRenderResult
    badProviderModeRenderResult
    badPrefixAuthorityRenderResult
    missingRequiredCapabilityResult
    ;
}
