{
  lib,
  pkgs,
  config,
  ...
}:

let
  cfg = config.services.network-renderer-wireguard.providerRuntime;

  fileContract =
    if cfg.providerContractFile == null then
      { }
    else
      builtins.fromJSON (builtins.readFile cfg.providerContractFile);

  contract = lib.recursiveUpdate fileContract cfg.providerContract;

  providerContractCm = import ../s88/ControlModule/provider-contract.nix { inherit lib; };
  addressingServicesCm = import ../s88/ControlModule/addressing-services.nix { inherit lib; };
  firewallNatCm = import ../s88/ControlModule/firewall-nat.nix { inherit lib; };
  tunnelRuntimeCm = import ../s88/ControlModule/tunnel-runtime.nix { inherit lib pkgs; };

  providerState = providerContractCm.normalize contract;
  inherit (providerState)
    ownNetworkStack
    enableHealthCheck
    lanAddresses
    lanInterface
    wanInterface
    vpnInterface
    firewallMode
    nat66Enable
    dhcp4Enable
    raEnable
    returnRoutesForLan
    dnsMode
    ;

  dhcp4Config = addressingServicesCm.dhcp4Config providerState;
  radvdConfig = addressingServicesCm.radvdConfig providerState;
  nftFilterRules = firewallNatCm.nftFilterRules providerState;
  nftNatRules = firewallNatCm.nftNatRules providerState;
  wanConnectionText = tunnelRuntimeCm.wanConnectionText providerState;
in
{
  options.services.network-renderer-wireguard.providerRuntime = {
    enable = lib.mkEnableOption "WireGuard provider runtime materialization";

    providerContract = lib.mkOption {
      type = lib.types.attrs;
      default = { };
      description = ''
        Provider contract emitted by the model/CPM/provider pipeline. This
        contract, not host-local options, owns provider class, mode, interface
        names, profile paths, address authority, NAT, firewall, DHCP, RA, DNS,
        public ingress, and routed-prefix behavior.
      '';
    };

    providerContractFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Optional JSON provider contract. Values in providerContract override
        file values for test fixtures and controlled deployment overlays.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = providerContractCm.assertions providerState;

    system.stateVersion = lib.mkDefault "25.11";

    services.resolved.enable = lib.mkIf ownNetworkStack false;
    systemd.services.systemd-networkd-wait-online.enable = lib.mkIf ownNetworkStack (lib.mkForce false);

    systemd.tmpfiles.rules = [
      "d /run/kea 0755 root root -"
      "d /var/lib/kea 0755 root root -"
      "d /etc/kea 0755 root root -"
      "d /etc/radvd 0755 root root -"
    ];

    networking = {
      useNetworkd = true;
      useDHCP = lib.mkIf ownNetworkStack (lib.mkForce false);
      useHostResolvConf = lib.mkIf ownNetworkStack (lib.mkForce false);
      firewall.enable = lib.mkIf (firewallMode == "dedicated-gateway") false;

      networkmanager = {
        enable = true;
        dns = providerState.get [ "networkManager" "dns" ] dnsMode;
        unmanaged = [
          "interface-name:${lanInterface}"
        ];
      };

      nftables = {
        enable = true;
        ruleset = lib.mkAfter ''
          ${nftFilterRules}
          ${nftNatRules}
        '';
      };
    };

    boot.kernelModules = lib.optional nat66Enable "ip6table_nat";
    boot.kernel.sysctl = {
      "net.ipv4.ip_forward" = 1;
      "net.ipv4.tcp_l3mdev_accept" = 1;
      "net.ipv6.conf.all.forwarding" = 1;
    };

    systemd.network.enable = true;
    systemd.network.networks."20-${lanInterface}" = {
      matchConfig.Name = lanInterface;
      networkConfig = {
        Address = lanAddresses;
        ConfigureWithoutCarrier = true;
        IPv6AcceptRA = false;
      };
      routes = returnRoutesForLan;
    };

    environment.etc."NetworkManager/system-connections/${wanInterface}.nmconnection" = {
      mode = "0600";
      text = wanConnectionText;
    };

    systemd.targets.wireguard-provider-ready = {
      description = "WireGuard provider interface is up and ready";
      wantedBy = [ "multi-user.target" ];
    };

    systemd.services.wireguard-provider-dispatcher = tunnelRuntimeCm.dispatcherService providerState;

    systemd.services.wireguard-provider-health =
      lib.mkIf enableHealthCheck (tunnelRuntimeCm.healthService providerState);

    systemd.timers.wireguard-provider-health =
      lib.mkIf enableHealthCheck (tunnelRuntimeCm.healthTimer providerState);

    environment.etc."kea/kea-dhcp4.conf" = lib.mkIf dhcp4Enable {
      text = dhcp4Config;
      mode = "0644";
    };

    systemd.services.kea-dhcp4 = lib.mkIf dhcp4Enable {
      wantedBy = [ "multi-user.target" ];
      requires = [ "wireguard-provider-ready.target" ];
      after = [ "wireguard-provider-ready.target" ];
      serviceConfig = {
        ExecStart = "${pkgs.kea}/bin/kea-dhcp4 -c /etc/kea/kea-dhcp4.conf";
        Restart = "on-failure";
        RestartSec = 10;
        StartLimitBurst = 0;
      };
    };

    environment.etc."radvd.conf" = lib.mkIf raEnable {
      text = radvdConfig;
      mode = "0644";
    };

    systemd.services.radvd = lib.mkIf raEnable {
      wantedBy = [ "multi-user.target" ];
      requires = [ "wireguard-provider-ready.target" ];
      after = [ "wireguard-provider-ready.target" ];
      serviceConfig = {
        ExecStart = "${pkgs.radvd}/bin/radvd -n -C /etc/radvd.conf ${lanInterface}";
        Restart = "on-failure";
        RestartSec = 10;
        StartLimitBurst = 0;
      };
    };

    environment.systemPackages = with pkgs; [
      dhcpcd
      dig
      dnsutils
      gron
      jq
      nftables
      openvpn
      tcpdump
      tmux
      traceroute
      tshark
      wireguard-tools
    ];
  };
}
