{ repoRoot ? toString ./..
, system ? builtins.currentSystem
}:

let
  flake = builtins.getFlake repoRoot;
  pkgs = import flake.inputs.nixpkgs { inherit system; };
  lib = pkgs.lib;

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

  remoteEgressContract = {
    id = "fs470-remote-egress";
    provider = {
      class = "commercial-imported";
      mode = "egress-only";
      prefixAuthority = "host-only-128";
    };
    interfaces = {
      wan = "uplink0";
      lan = "edge-lan0";
      vpn = "wg-remote-egress0";
    };
    profile = {
      mode = "generated-peer";
      generatedPeer = {
        privateKeyFile = "/run/keys/fs470-wg-private";
        addresses = [
          "10.47.0.2/32"
          "fd47:470::2/128"
        ];
        dns = [ "10.47.0.1" ];
        mtu = 1420;
        peers = [
          {
            publicKey = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc=";
            endpoint = "198.51.100.47:51820";
            allowedIPs = [
              "0.0.0.0/0"
              "::/0"
            ];
            presharedKeyFile = "/run/keys/fs470-wg-psk";
            persistentKeepalive = 25;
          }
        ];
      };
    };
    runtime = {
      generatedConfigPath = "/run/network-renderer-wireguard/fs470-generated.conf";
      uuidFile = "/run/network-renderer-wireguard/fs470.uuid";
    };
    dns.mode = "default";
    publicIngress = [ ];
    portForwards = [ ];
    lan = {
      ipv4.address = "10.147.0.1/24";
      ipv6.address = "fd47:147::1/64";
    };
    nat = {
      ipv4 = {
        enable = true;
        sourceCidrs = [ "10.147.0.0/24" ];
      };
      ipv6 = {
        enable = true;
        sourceCidrs = [ "fd47:147::/64" ];
      };
    };
    services = {
      dhcp4 = {
        enable = true;
        subnet = "10.147.0.0/24";
        pool = "10.147.0.100 - 10.147.0.180";
        gateway = "10.147.0.1";
        dns = [ "10.147.0.1" ];
      };
      ra = {
        enable = true;
        prefix = "fd47:147::/64";
        rdnss = [ "fd47:147::1" ];
      };
      healthCheck.enable = false;
    };
  };

  remoteEgressEval = evalWith remoteEgressContract;
  remoteEgressRender =
    flake.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult remoteEgressContract;
  remoteEgressDhcp4 =
    builtins.fromJSON remoteEgressEval.config.environment.etc."kea/kea-dhcp4.conf".text;

  unrelatedPoolDenied = evalWith (
    lib.recursiveUpdate remoteEgressContract {
      routes.ipv6.routedClientPrefixes = [ "2001:db8:470::/64" ];
    }
  );

  bootstrapPayloadMissingEndpoint = evalWith (
    lib.recursiveUpdate remoteEgressContract {
      profile.generatedPeer.peers = [
        {
          publicKey = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc=";
          allowedIPs = [ "0.0.0.0/0" ];
        }
      ];
    }
  );
in
{
  remoteEgress = {
    dispatcherDescription =
      remoteEgressEval.config.systemd.services.wireguard-provider-dispatcher.description;
    nftables = remoteEgressEval.config.networking.nftables.ruleset;
    dhcp4Config = remoteEgressDhcp4;
    radvdConfig = remoteEgressEval.config.environment.etc."radvd.conf".text;
    lanRoutes = remoteEgressEval.config.systemd.network.networks."20-edge-lan0".routes;
    providerSurfaces = remoteEgressRender.artifacts.providerSurfaces;
    capabilities = remoteEgressRender.capabilities;
    trace = remoteEgressRender.trace;
    profileMode = remoteEgressContract.profile.mode;
    generatedConfigPath = remoteEgressContract.runtime.generatedConfigPath;
    generatedPeer = remoteEgressContract.profile.generatedPeer;
    hasProviderRuntimeModule =
      builtins.hasAttr "providerRuntime" remoteEgressRender.artifacts.nixosModules;
  };

  unrelatedPoolDeniedErrors = falseAssertionMessages unrelatedPoolDenied;
  bootstrapPayloadMissingEndpointErrors = falseAssertionMessages bootstrapPayloadMissingEndpoint;
}
