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
        controlPlane = {
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
      (hostModule rendererInput { config = { }; inherit lib pkgs; }).content.containers.wg-mini-node;
  secretContainer = evalModule {
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
  nonSecretContainer = evalModule {
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
  require = cond: msg: if cond then true else throw msg;
in
  require (secretContainer.bindMounts."/run/secrets/wireguard-mini-provider-private-key".hostPath == "/run/secrets/wireguard-mini-provider-private-key")
    "hostModule must bind the explicit sops privateKeyFile into the generated WG container"
  && require (secretContainer.bindMounts."/run/secrets/wireguard-mini-provider-private-key".isReadOnly == true)
    "hostModule must mount the sops privateKeyFile read-only"
  && require (secretContainer.bindMounts."/run/secrets/wireguard-mini-provider-psk".hostPath == "/run/secrets/wireguard-mini-provider-psk")
    "hostModule must bind explicit sops presharedKeyFile paths into the generated WG container"
  && require (!(nonSecretContainer ? bindMounts))
    "hostModule must not invent bind mounts for non-sops key paths"
' >/dev/null

echo "PASS FS-470-HDS-010-SDS-010-SMS-021 wg secret bind mounts"
