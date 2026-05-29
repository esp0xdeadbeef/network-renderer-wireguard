{ repoRoot ? toString ./..
, system ? builtins.currentSystem
}:

let
  flake = builtins.getFlake repoRoot;
  pkgs = import flake.inputs.nixpkgs { inherit system; };
  lib = pkgs.lib;

  baseContract = {
    id = "test-provider";
    provider = {
      class = "commercial-imported";
      mode = "egress-only";
    };
    interfaces = {
      wan = "eth0";
      lan = "lan0";
      vpn = "wg0";
    };
    profile = {
      path = "/run/test-provider/wg.conf";
      format = "wireguard";
    };
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

  valid = evalWith baseContract;
  routedWithNat66 = evalWith (
    lib.recursiveUpdate baseContract {
      provider = {
        class = "self-hosted";
        mode = "routed-prefix";
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
      };
      nat.ipv6.enable = false;
    }
  );
  renderResult = flake.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult baseContract;
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

  renderResultShape = {
    inherit (renderResult) rendererClass targetRenderer scope validationHints trace;
    hasProviderRuntimeModule =
      builtins.hasAttr "providerRuntime" renderResult.artifacts.nixosModules;
  };
}
