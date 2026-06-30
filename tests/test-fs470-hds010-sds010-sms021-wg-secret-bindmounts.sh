#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

nix eval --impure --expr '
let
  system = builtins.currentSystem;
  flake = builtins.getFlake ("path:" + "'"${repo_root}"'");
  pkgs = import flake.inputs.nixpkgs { inherit system; };
  lib = pkgs.lib;
  hostModule = flake.libBySystem.${system}.renderer.hostModule;
  evalModule =
    wgInventory:
    let
      rendererInput = {
        hostName = "s-router-nixos";
        controlPlane.control_plane_model = {
          inherit wgInventory;
          data.acme.lab.overlays.wg-mini = {
            terminateOn = [ "wg-mini-node" ];
            providerBootstrapDns = [ ];
            nodes.wg-mini-node = {
              addr4 = "10.66.90.2/32";
              addr6 = "fd42:66:90::2/128";
            };
          };
        };
      };
    in
      (hostModule rendererInput { config = { }; inherit lib pkgs; }).content;
  secretOutput = evalModule {
    wg-mini = {
      interface = "wg-mini";
      privateKeyFile = "/run/secrets/wireguard-mini-provider-private-key";
      listenPort = 51820;
      peers = [
        {
          publicKey = "uK6fX6Hg5MR6pQOSRPFKCFH5hvQ5R8ymMjZtUsua3Qg=";
          endpoint = "198.51.100.1:51820";
          allowedIPs = [ "0.0.0.0/0" "::/0" ];
          presharedKeyFile = "/run/secrets/wireguard-mini-provider-psk";
        }
      ];
    };
  };
  nonSecretOutput = evalModule {
    wg-mini = {
      interface = "wg-mini";
      privateKeyFile = "/etc/wireguard/wg-mini.key";
      listenPort = 51820;
      peers = [
        {
          publicKey = "uK6fX6Hg5MR6pQOSRPFKCFH5hvQ5R8ymMjZtUsua3Qg=";
          endpoint = "198.51.100.1:51820";
          allowedIPs = [ "0.0.0.0/0" "::/0" ];
          presharedKeyFile = "/etc/wireguard/wg-mini.psk";
        }
      ];
    };
  };
  systemdServicesOf = output: (output.systemd or { }).services or { };
  require = cond: msg: if cond then true else throw msg;
in
  require (builtins.elem "--bind-ro=/run/secrets/wireguard-mini-provider-private-key:/run/secrets/wireguard-mini-provider-private-key" secretOutput.containers.wg-mini-node.extraFlags)
    "hostModule must bind the explicit sops privateKeyFile into the generated WG container"
  && require (builtins.elem "--bind-ro=/run/secrets/wireguard-mini-provider-psk:/run/secrets/wireguard-mini-provider-psk" secretOutput.containers.wg-mini-node.extraFlags)
    "hostModule must bind explicit sops presharedKeyFile paths into the generated WG container"
  && require (secretOutput.containers.wg-mini-node.privateNetwork == true)
    "hostModule must isolate generated WG containers in a private network namespace"
  && require (secretOutput.containers.wg-mini-node.additionalCapabilities == [ "CAP_NET_ADMIN" "CAP_NET_RAW" ])
    "hostModule must grant only explicit WG runtime network capabilities"
  && require (secretOutput.containers.wg-mini-node.autoStart == true)
    "hostModule must auto-start the generated WG container at boot"
  && require (systemdServicesOf secretOutput == { })
    "hostModule must not require a host-specific sops unit that may not exist"
  && require (!(nonSecretOutput.containers.wg-mini-node ? extraFlags))
    "hostModule must not invent secret bind flags for non-sops key paths"
  && require (nonSecretOutput.containers.wg-mini-node.autoStart == true)
    "hostModule must auto-start generated WG containers without secret paths too"
  && require (systemdServicesOf nonSecretOutput == { })
    "hostModule must not add sops ordering for non-sops key paths"
' >/dev/null

echo "PASS FS-470-HDS-010-SDS-010-SMS-021 wg secret file binds"
