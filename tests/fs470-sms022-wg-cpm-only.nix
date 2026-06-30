{ repoRoot ? toString ./..
, system ? builtins.currentSystem
}:

let
  flake = builtins.getFlake repoRoot;
  pkgs = import flake.inputs.nixpkgs { inherit system; };
  lib = pkgs.lib;
  hostModule = flake.libBySystem.${system}.renderer.hostModule;

  baseWgData = {
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

  evalNetdevs =
    wgData:
    let
      rendererInput = {
        hostName = "s-router-nixos";
        controlPlane.control_plane_model = {
          wgInventory.wg-mini = wgData;
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
      evaluated = import (flake.inputs.nixpkgs + "/nixos/lib/eval-config.nix") {
        inherit system;
        modules = [
          (hostModule rendererInput)
        ];
      };
    in
      evaluated.config.containers.wg-mini-node.config.systemd.network.netdevs;

  forceNetdevs = wgData: builtins.deepSeq (evalNetdevs wgData) "ok";
in
{
  valid = forceNetdevs baseWgData;
  missingInterface = forceNetdevs (builtins.removeAttrs baseWgData [ "interface" ]);
  tooLongInterface = forceNetdevs (baseWgData // { interface = "wg-remote-egress0"; });
  missingPrivateKeyFile = forceNetdevs (builtins.removeAttrs baseWgData [ "privateKeyFile" ]);
  missingListenPort = forceNetdevs (builtins.removeAttrs baseWgData [ "listenPort" ]);
  missingPeers = forceNetdevs (builtins.removeAttrs baseWgData [ "peers" ]);
  missingPeerPublicKey = forceNetdevs (baseWgData // {
    peers = [ (builtins.removeAttrs (builtins.elemAt baseWgData.peers 0) [ "publicKey" ]) ];
  });
  missingPeerEndpoint = forceNetdevs (baseWgData // {
    peers = [ (builtins.removeAttrs (builtins.elemAt baseWgData.peers 0) [ "endpoint" ]) ];
  });
  missingPeerAllowedIPs = forceNetdevs (baseWgData // {
    peers = [ (builtins.removeAttrs (builtins.elemAt baseWgData.peers 0) [ "allowedIPs" ]) ];
  });
}
