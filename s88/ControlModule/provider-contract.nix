{ lib }:

let
  pathName = path: lib.concatStringsSep "." path;
in
{
  normalize =
    contract:
    let
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

      dhcp4Enable = get [ "services" "dhcp4" "enable" ] false;
      raEnable = get [ "services" "ra" "enable" ] false;
      lanIPv4 = get [ "lan" "ipv4" "address" ] null;
      lanIPv6 = get [ "lan" "ipv6" "address" ] null;
    in
    rec {
      inherit contract get required dhcp4Enable raEnable lanIPv4 lanIPv6;

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

      lanAddresses = lib.filter (value: value != null) [
        lanIPv4
        lanIPv6
      ];

      wanIPv4Method = get [ "wan" "ipv4" "method" ] "auto";
      wanIPv6Method = get [ "wan" "ipv6" "method" ] "auto";
      wanIPv4RouteMetric = toString (get [ "wan" "ipv4" "routeMetric" ] 300);
      wanIPv6RouteMetric = toString (get [ "wan" "ipv6" "routeMetric" ] 300);

      dhcp4Subnet = if dhcp4Enable then required [ "services" "dhcp4" "subnet" ] else null;
      dhcp4Pool = if dhcp4Enable then required [ "services" "dhcp4" "pool" ] else null;
      dhcp4Gateway = if dhcp4Enable then required [ "services" "dhcp4" "gateway" ] else null;
      dhcp4Dns = get [ "services" "dhcp4" "dns" ] [ ];
      dhcp4LeaseFile = get [ "services" "dhcp4" "leaseFile" ] "/var/lib/kea/dhcp4.leases";

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
    };

  assertions =
    state:
    [
      {
        assertion = builtins.elem state.providerClass [
          "self-hosted"
          "commercial-imported"
        ];
        message = "network-renderer-wireguard provider.class must be self-hosted or commercial-imported";
      }
      {
        assertion = builtins.elem state.providerMode [
          "egress-only"
          "public-ingress"
          "routed-prefix"
        ];
        message = "network-renderer-wireguard provider.mode must be egress-only, public-ingress, or routed-prefix";
      }
      {
        assertion = builtins.elem state.profileFormat [
          "wireguard"
          "openvpn"
        ];
        message = "network-renderer-wireguard profile.format must be wireguard or openvpn";
      }
      {
        assertion = state.lanAddresses != [ ];
        message = "network-renderer-wireguard contract must provide at least one LAN address";
      }
      {
        assertion = (!state.dhcp4Enable) || state.lanIPv4 != null;
        message = "network-renderer-wireguard DHCPv4 requires lan.ipv4.address";
      }
      {
        assertion = (!state.dhcp4Enable) || state.dhcp4Dns != [ ];
        message = "network-renderer-wireguard DHCPv4 requires services.dhcp4.dns from the provider contract";
      }
      {
        assertion = (!state.raEnable) || state.lanIPv6 != null;
        message = "network-renderer-wireguard RA requires lan.ipv6.address";
      }
      {
        assertion = (!state.raEnable) || state.raRdnss != [ ];
        message = "network-renderer-wireguard RA requires services.ra.rdnss from the provider contract";
      }
      {
        assertion = (!state.nat44Enable) || state.nat44Sources != [ ];
        message = "network-renderer-wireguard NAT44 requires nat.ipv4.sourceCidrs";
      }
      {
        assertion = (!state.nat66Enable) || state.nat66Sources != [ ];
        message = "network-renderer-wireguard NAT66 requires nat.ipv6.sourceCidrs";
      }
      {
        assertion = state.providerMode != "routed-prefix" || state.routedIPv6Prefixes != [ ];
        message = "network-renderer-wireguard routed-prefix mode requires routes.ipv6.routedClientPrefixes";
      }
      {
        assertion = state.providerMode != "public-ingress" || state.publicIngress != [ ];
        message = "network-renderer-wireguard public-ingress mode requires publicIngress contracts";
      }
      {
        assertion = state.providerMode != "routed-prefix" || !state.nat66Enable;
        message = "network-renderer-wireguard routed client GUA mode must not enable NAT66";
      }
    ];
}
