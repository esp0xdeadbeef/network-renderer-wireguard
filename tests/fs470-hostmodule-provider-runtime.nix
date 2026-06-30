{ repoRoot ? toString ./..
, system ? builtins.currentSystem
}:

let
  flake = builtins.getFlake repoRoot;
  pkgs = import flake.inputs.nixpkgs { inherit system; };
  lib = pkgs.lib;
  hostModule = flake.libBySystem.${system}.renderer.hostModule;

  wgData = {
    interface = "wg-re-egress0";
    privateKeyFile = "/run/secrets/wireguard-mini-provider-private-key";
    listenPort = 51820;
    peers = [
      {
        publicKey = "lulaH/DcSwly2+BTasbAx4hNtXuA3J5K9pXjPesXJlo=";
        endpoint = "198.51.100.47:51820";
        allowedIPs = [
          "0.0.0.0/0"
          "::/0"
        ];
        persistentKeepalive = 25;
      }
    ];
  };

  providerContract = {
    id = "fs470-remote-egress";
    provider = {
      class = "commercial-imported";
      mode = "egress-only";
      prefixAuthority = "host-only-128";
    };
    interfaces = {
      wan = "uplink0";
      lan = "edge-lan0";
      vpn = "wg-re-egress0";
    };
    profile = {
      mode = "generated-peer";
      generatedPeer = {
        privateKeyFile = "/run/secrets/wireguard-mini-provider-private-key";
        addresses = [
          "10.47.0.2/32"
          "fd47:470::2/128"
        ];
        dns = [ "10.47.0.1" ];
        mtu = 1420;
        peers = [
          {
            publicKey = "lulaH/DcSwly2+BTasbAx4hNtXuA3J5K9pXjPesXJlo=";
            endpoint = "198.51.100.47:51820";
            allowedIPs = [
              "0.0.0.0/0"
              "::/0"
            ];
            persistentKeepalive = 25;
          }
        ];
      };
    };
    runtime = {
      generatedConfigPath = "/run/network-renderer-wireguard/fs470-generated.conf";
      uuidFile = "/run/network-renderer-wireguard/fs470.uuid";
      ownNetworkStack = true;
    };
    dns.mode = "default";
    wan = {
      ipv4.method = "disabled";
      ipv6.method = "ignore";
    };
    firewall = {
      mode = "dedicated-gateway";
      allowLanToVpn = true;
      denyLanToWan = true;
      denyWanToLan = true;
    };
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
        leaseFile = "/var/lib/kea/dhcp4.leases";
      };
      ra = {
        enable = true;
        prefix = "fd47:147::/64";
        rdnss = [ "fd47:147::1" ];
      };
      healthCheck.enable = false;
    };
  };

  mkControlPlane =
    withProviderContract:
    {
      meta.traceId = "FS-470-HDS-010-SDS-010-SMS-010__hostmodule-provider-runtime";
      data.acme.lab.overlays.wg-remote-egress = {
        terminateOn = [ "wireguard-remote-egress" ];
        providerBootstrapDns = [ ];
        nodes.wireguard-remote-egress = {
          addr4 = "10.47.0.2/32";
          addr6 = "fd47:470::2/128";
        };
      };
      wgInventory.wg-remote-egress = wgData;
    }
    // lib.optionalAttrs withProviderContract {
      providerContracts.wireguard.wg-remote-egress = providerContract;
    };

  evalContainer =
    withProviderContract:
    let
      rendererInput = {
        hostName = "s-router-nixos";
        controlPlane.control_plane_model = mkControlPlane withProviderContract;
      };
      hostOutput = (hostModule rendererInput { config = { }; inherit lib pkgs; }).content;
      container = hostOutput.containers.wireguard-remote-egress;
      evaluated = import (flake.inputs.nixpkgs + "/nixos/lib/eval-config.nix") {
        inherit system;
        modules = [ container.config ];
      };
    in
    {
      inherit hostOutput container;
      config = evaluated.config;
    };

  withRuntime = evalContainer true;
  withoutRuntime = evalContainer false;
in
{
  providerRuntime = {
    extraFlags = withRuntime.container.extraFlags;
    containerUnitAfter = withRuntime.hostOutput.systemd.services."container@wireguard-remote-egress".after;
    containerUnitRequires = withRuntime.hostOutput.systemd.services."container@wireguard-remote-egress".requires;
    providerRuntimeEnabled =
      withRuntime.config.services.network-renderer-wireguard.providerRuntime.enable;
    providerContractId =
      withRuntime.config.services.network-renderer-wireguard.providerRuntime.providerContract.id;
    dispatcherDescription =
      withRuntime.config.systemd.services.wireguard-provider-dispatcher.description;
    hasNetdevService =
      withRuntime.config.systemd.services ? "s88-provider-interface-wg-re-egress0-egress";
    nftables = withRuntime.config.networking.nftables.ruleset;
    dhcp4Config =
      builtins.fromJSON withRuntime.config.environment.etc."kea/kea-dhcp4.conf".text;
    radvdConfig = withRuntime.config.environment.etc."radvd.conf".text;
  };

  withoutProviderRuntime = {
    hasDispatcher =
      withoutRuntime.config.systemd.services ? wireguard-provider-dispatcher;
    hasProviderRuntimeOption =
      withoutRuntime.config.services ? network-renderer-wireguard;
    hasNetdevService =
      withoutRuntime.config.systemd.services ? "s88-provider-interface-wg-re-egress0-egress";
  };
}
