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

  pathName = path: lib.concatStringsSep "." path;
  get = path: default: lib.attrByPath path default contract;
  required =
    path:
    let
      value = get path null;
    in
    if value == null then
      throw "network-renderer-wireguard provider contract missing ${pathName path}"
    else
      value;

  contractId = get [ "id" ] "wireguard-provider";
  providerClass = required [ "provider" "class" ];
  providerMode = required [ "provider" "mode" ];
  wanInterface = required [ "interfaces" "wan" ];
  lanInterface = required [ "interfaces" "lan" ];
  vpnInterface = required [ "interfaces" "vpn" ];
  profilePath = required [ "profile" "path" ];
  profileFormat = required [ "profile" "format" ];

  ownNetworkStack = get [ "runtime" "ownNetworkStack" ] true;
  enableHealthCheck = get [ "services" "healthCheck" "enable" ] true;
  healthTarget4 = get [ "services" "healthCheck" "target4" ] "1.1.1.1";
  healthInterval = get [ "services" "healthCheck" "interval" ] "60s";

  lanIPv4 = get [ "lan" "ipv4" "address" ] null;
  lanIPv6 = get [ "lan" "ipv6" "address" ] null;
  lanAddresses = lib.filter (value: value != null) [
    lanIPv4
    lanIPv6
  ];

  wanIPv4Method = get [ "wan" "ipv4" "method" ] "auto";
  wanIPv6Method = get [ "wan" "ipv6" "method" ] "auto";
  wanIPv4RouteMetric = toString (get [ "wan" "ipv4" "routeMetric" ] 300);
  wanIPv6RouteMetric = toString (get [ "wan" "ipv6" "routeMetric" ] 300);

  dhcp4Enable = get [ "services" "dhcp4" "enable" ] false;
  dhcp4Subnet = if dhcp4Enable then required [ "services" "dhcp4" "subnet" ] else null;
  dhcp4Pool = if dhcp4Enable then required [ "services" "dhcp4" "pool" ] else null;
  dhcp4Gateway = if dhcp4Enable then required [ "services" "dhcp4" "gateway" ] else null;
  dhcp4Dns = get [ "services" "dhcp4" "dns" ] [ ];
  dhcp4LeaseFile = get [ "services" "dhcp4" "leaseFile" ] "/var/lib/kea/dhcp4.leases";

  raEnable = get [ "services" "ra" "enable" ] false;
  raPrefix = if raEnable then required [ "services" "ra" "prefix" ] else null;
  raRdnss = get [ "services" "ra" "rdnss" ] [ ];

  firewallMode = get [ "firewall" "mode" ] "dedicated-gateway";
  allowLanToVpn = get [ "firewall" "allowLanToVpn" ] true;
  denyLanToWan = get [ "firewall" "denyLanToWan" ] true;
  denyWanToLan = get [ "firewall" "denyWanToLan" ] true;

  nat44Enable = get [ "nat" "ipv4" "enable" ] false;
  nat44Sources = get [ "nat" "ipv4" "sourceCidrs" ] [ ];
  nat66Enable = get [ "nat" "ipv6" "enable" ] false;
  nat66Sources = get [ "nat" "ipv6" "sourceCidrs" ] [ ];

  routedIPv6Prefixes = get [ "routes" "ipv6" "routedClientPrefixes" ] [ ];
  publicIngress = get [ "publicIngress" ] [ ];

  dhcp4Config =
    builtins.toJSON {
      Dhcp4 = {
        interfaces-config = {
          interfaces = [ lanInterface ];
        };
        valid-lifetime = get [ "services" "dhcp4" "validLifetime" ] 600;
        renew-timer = get [ "services" "dhcp4" "renewTimer" ] 300;
        rebind-timer = get [ "services" "dhcp4" "rebindTimer" ] 540;
        lease-database = {
          type = "memfile";
          persist = true;
          name = dhcp4LeaseFile;
        };
        subnet4 = [
          {
            id = get [ "services" "dhcp4" "subnetId" ] 1;
            subnet = dhcp4Subnet;
            pools = [
              {
                pool = dhcp4Pool;
              }
            ];
            option-data = [
              {
                name = "routers";
                data = dhcp4Gateway;
              }
              {
                name = "domain-name-servers";
                data = lib.concatStringsSep ", " dhcp4Dns;
              }
            ];
          }
        ];
      };
    };

  radvdConfig = ''
    interface ${lanInterface} {
      AdvSendAdvert on;
      MinRtrAdvInterval ${toString (get [ "services" "ra" "minInterval" ] 10)};
      MaxRtrAdvInterval ${toString (get [ "services" "ra" "maxInterval" ] 30)};
      ${lib.optionalString (raRdnss != [ ]) ''
        RDNSS ${lib.concatStringsSep " " raRdnss} {
          AdvRDNSSLifetime ${toString (get [ "services" "ra" "rdnssLifetime" ] 800)};
        };
      ''}
      prefix ${raPrefix} {
        AdvOnLink on;
        AdvAutonomous on;
        AdvRouterAddr on;
      };
    };
  '';

  nftFilterRules = lib.optionalString (firewallMode == "dedicated-gateway") ''
    table inet network_renderer_wireguard_filter {
      chain input {
        type filter hook input priority filter; policy drop;
        iifname "lo" accept
        ct state established,related accept
        iifname "${lanInterface}" accept
        iifname "${wanInterface}" drop
      }

      chain forward {
        type filter hook forward priority filter; policy drop;
        ct state invalid drop
        ct state established,related accept
        ${lib.optionalString allowLanToVpn ''
          iifname "${lanInterface}" oifname "${vpnInterface}" accept comment "wg-provider-lan-to-vpn ${contractId}"
        ''}
        iifname "${vpnInterface}" oifname "${lanInterface}" accept comment "wg-provider-vpn-return ${contractId}"
        ${lib.optionalString denyLanToWan ''
          iifname "${lanInterface}" oifname "${wanInterface}" drop comment "wg-provider-deny-lan-to-wan ${contractId}"
        ''}
        ${lib.optionalString denyWanToLan ''
          iifname "${wanInterface}" oifname "${lanInterface}" drop comment "wg-provider-deny-wan-to-lan ${contractId}"
        ''}
      }

      chain output {
        type filter hook output priority filter; policy accept;
      }
    }
  '';

  nat44Rules = lib.concatMapStringsSep "\n" (
    source:
    ''        ip saddr ${source} oifname "${vpnInterface}" masquerade comment "wg-provider-nat44 ${contractId}"''
  ) nat44Sources;

  nat66Rules = lib.concatMapStringsSep "\n" (
    source:
    ''        ip6 saddr ${source} oifname "${vpnInterface}" masquerade comment "wg-provider-nat66 ${contractId}"''
  ) nat66Sources;

  nftNatRules = lib.optionalString (nat44Enable || nat66Enable) ''
    table inet network_renderer_wireguard_nat {
      chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
${nat44Rules}
${nat66Rules}
      }
    }
  '';
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
    assertions = [
      {
        assertion = builtins.elem providerClass [
          "self-hosted"
          "commercial-imported"
        ];
        message = "network-renderer-wireguard provider.class must be self-hosted or commercial-imported";
      }
      {
        assertion = builtins.elem providerMode [
          "egress-only"
          "public-ingress"
          "routed-prefix"
        ];
        message = "network-renderer-wireguard provider.mode must be egress-only, public-ingress, or routed-prefix";
      }
      {
        assertion = builtins.elem profileFormat [
          "wireguard"
          "openvpn"
        ];
        message = "network-renderer-wireguard profile.format must be wireguard or openvpn";
      }
      {
        assertion = lanAddresses != [ ];
        message = "network-renderer-wireguard contract must provide at least one LAN address";
      }
      {
        assertion = (!dhcp4Enable) || lanIPv4 != null;
        message = "network-renderer-wireguard DHCPv4 requires lan.ipv4.address";
      }
      {
        assertion = (!dhcp4Enable) || dhcp4Dns != [ ];
        message = "network-renderer-wireguard DHCPv4 requires services.dhcp4.dns from the provider contract";
      }
      {
        assertion = (!raEnable) || lanIPv6 != null;
        message = "network-renderer-wireguard RA requires lan.ipv6.address";
      }
      {
        assertion = (!raEnable) || raRdnss != [ ];
        message = "network-renderer-wireguard RA requires services.ra.rdnss from the provider contract";
      }
      {
        assertion = (!nat44Enable) || nat44Sources != [ ];
        message = "network-renderer-wireguard NAT44 requires nat.ipv4.sourceCidrs";
      }
      {
        assertion = (!nat66Enable) || nat66Sources != [ ];
        message = "network-renderer-wireguard NAT66 requires nat.ipv6.sourceCidrs";
      }
      {
        assertion = providerMode != "routed-prefix" || routedIPv6Prefixes != [ ];
        message = "network-renderer-wireguard routed-prefix mode requires routes.ipv6.routedClientPrefixes";
      }
      {
        assertion = providerMode != "public-ingress" || publicIngress != [ ];
        message = "network-renderer-wireguard public-ingress mode requires publicIngress contracts";
      }
      {
        assertion = providerMode != "routed-prefix" || !nat66Enable;
        message = "network-renderer-wireguard routed client GUA mode must not enable NAT66";
      }
    ];

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
        dns = get [ "networkManager" "dns" ] "default";
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
    };

    environment.etc."NetworkManager/system-connections/${wanInterface}.nmconnection" = {
      mode = "0600";
      text = ''
        [connection]
        id=${wanInterface}
        type=ethernet
        interface-name=${wanInterface}
        autoconnect=true
        permissions=

        [ipv4]
        method=${wanIPv4Method}
        route-metric=${wanIPv4RouteMetric}

        [ipv6]
        method=${wanIPv6Method}
        route-metric=${wanIPv6RouteMetric}
      '';
    };

    systemd.targets.wireguard-provider-ready = {
      description = "WireGuard provider interface is up and ready";
      wantedBy = [ "multi-user.target" ];
    };

    systemd.services.wireguard-provider-dispatcher = {
      description = "Bring up provider tunnel ${vpnInterface} from model/provider contract";
      after = [ "NetworkManager-wait-online.service" ];
      requires = [ "NetworkManager-wait-online.service" ];
      wantedBy = [ "multi-user.target" ];

      path = with pkgs; [
        coreutils
        gawk
        gnugrep
        iproute2
        networkmanager
        networkmanager-openvpn
        wireguard-tools
      ];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        Restart = "on-failure";
        RestartSec = 10;

        ExecStart = pkgs.writeShellScript "wireguard-provider-dispatcher-start" ''
          set -euo pipefail
          CONF=${lib.escapeShellArg profilePath}
          IFACE=${lib.escapeShellArg vpnInterface}
          FORMAT=${lib.escapeShellArg profileFormat}
          UUID_FILE=/run/network-renderer-wireguard.uuid

          test -s "$CONF" || {
            echo "[wireguard-provider] missing provider profile: $CONF" >&2
            exit 1
          }

          if nmcli -t -f NAME con show | grep -qx "$IFACE"; then
            nmcli con down "$IFACE" || true
            nmcli con delete "$IFACE" || true
          fi

          BEFORE=$(nmcli -t -f UUID con show | sort || true)

          case "$FORMAT" in
            wireguard)
              nmcli connection import type wireguard file "$CONF"
              ;;
            openvpn)
              nmcli connection import type openvpn file "$CONF"
              ;;
            *)
              echo "[wireguard-provider] unsupported profile format from contract: $FORMAT" >&2
              exit 1
              ;;
          esac

          AFTER=$(nmcli -t -f UUID con show | sort)
          NEW_UUID=$(comm -13 <(printf "%s\n" "$BEFORE") <(printf "%s\n" "$AFTER") | tail -n1)
          if [ -z "''${NEW_UUID:-}" ]; then
            echo "[wireguard-provider] could not determine imported connection UUID" >&2
            exit 1
          fi

          nmcli con modify "$NEW_UUID" connection.id "$IFACE"
          nmcli con modify "$NEW_UUID" connection.interface-name "$IFACE"
          nmcli con modify "$NEW_UUID" connection.autoconnect yes
          nmcli con up "$NEW_UUID"
          echo "$NEW_UUID" > "$UUID_FILE"

          for _ in $(seq 1 20); do
            if ip link show "$IFACE" >/dev/null 2>&1; then
              systemctl start wireguard-provider-ready.target
              exit 0
            fi
            sleep 1
          done

          echo "[wireguard-provider] interface did not appear: $IFACE" >&2
          exit 1
        '';

        ExecStop = pkgs.writeShellScript "wireguard-provider-dispatcher-stop" ''
          set -euo pipefail
          UUID_FILE=/run/network-renderer-wireguard.uuid
          if [ -f "$UUID_FILE" ]; then
            UUID=$(cat "$UUID_FILE")
            nmcli con down "$UUID" || true
            nmcli con delete "$UUID" || true
            rm -f "$UUID_FILE"
          else
            nmcli con down ${lib.escapeShellArg vpnInterface} || true
            nmcli con delete ${lib.escapeShellArg vpnInterface} || true
          fi
        '';
      };
    };

    systemd.services.wireguard-provider-health = lib.mkIf enableHealthCheck {
      description = "Check provider tunnel health from model/provider contract";
      after = [ "wireguard-provider-ready.target" ];
      requires = [ "wireguard-provider-ready.target" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = pkgs.writeShellScript "wireguard-provider-health" ''
          set -euo pipefail
          iface=${lib.escapeShellArg vpnInterface}
          rx_path="/sys/class/net/$iface/statistics/rx_bytes"

          if [ ! -d "/sys/class/net/$iface" ]; then
            echo "[wireguard-provider-health] $iface missing; restarting provider dispatcher" >&2
            systemctl restart wireguard-provider-dispatcher.service
            exit 0
          fi

          if [ ! -r "$rx_path" ]; then
            echo "[wireguard-provider-health] cannot read $rx_path; restarting provider dispatcher" >&2
            systemctl restart wireguard-provider-dispatcher.service
            exit 0
          fi

          rx_before=$(cat "$rx_path")
          sleep 5
          rx_after=$(cat "$rx_path")

          if [ "$rx_before" = "$rx_after" ]; then
            if ! ${pkgs.iputils}/bin/ping -c1 -I "$iface" -W2 ${lib.escapeShellArg healthTarget4} >/dev/null 2>&1; then
              echo "[wireguard-provider-health] no RX delta and ping failed; restarting provider dispatcher" >&2
              systemctl restart wireguard-provider-dispatcher.service
              exit 0
            fi
          fi
        '';
      };
    };

    systemd.timers.wireguard-provider-health = lib.mkIf enableHealthCheck {
      description = "Periodic provider tunnel health check";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "30s";
        OnUnitActiveSec = healthInterval;
        AccuracySec = "5s";
        Unit = "wireguard-provider-health.service";
      };
    };

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
