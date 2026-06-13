{ lib }:

let
  pathName = path: lib.concatStringsSep "." path;
  isNonEmptyString = value: builtins.isString value && value != "";
  peerField = peer: name: if builtins.hasAttr name peer then peer.${name} else null;
  peerString = peer: name: if isNonEmptyString (peerField peer name) then peerField peer name else null;
  peerList = peer: name: if builtins.isList (peerField peer name) then peerField peer name else [ ];
  endpointAddress = endpoint: endpoint.address or (endpoint.host or (endpoint.name or null));
  routeField = route: name: if builtins.hasAttr name route then route.${name} else null;
  exposureField = exposure: name: if builtins.hasAttr name exposure then exposure.${name} else null;
  isValidProtocol = protocol: builtins.elem protocol [
    "tcp"
    "udp"
  ];
  isGlobalUnicastIPv6 = value:
    builtins.isString value && builtins.match "^[[:space:]]*[23][0-9A-Fa-f].*" value != null;
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

      contractId = get [ "id" ] null;
      providerClass = required [ "provider" "class" ];
      providerMode = required [ "provider" "mode" ];
      publicIngressAuthority = get [ "provider" "publicIngressAuthority" ] false;
      routedClientPrefixAuthority = get [ "provider" "routedClientPrefixAuthority" ] false;
      prefixAuthority = required [ "provider" "prefixAuthority" ];
      dnsMode = required [ "dns" "mode" ];

      wanInterface = required [ "interfaces" "wan" ];
      lanInterface = required [ "interfaces" "lan" ];
      vpnInterface = required [ "interfaces" "vpn" ];

      profileMode = required [ "profile" "mode" ];
      generatedConfigPath =
        get [ "runtime" "generatedConfigPath" ] null;
      uuidFile = required [ "runtime" "uuidFile" ];

      profilePath =
        if profileMode == "generated-peer" then generatedConfigPath else required [ "profile" "path" ];
      profileFormat =
        if profileMode == "generated-peer" then "wireguard" else required [ "profile" "format" ];

      generatedPrivateKeyFile = get [ "profile" "generatedPeer" "privateKeyFile" ] null;
      generatedAddresses = get [ "profile" "generatedPeer" "addresses" ] [ ];
      generatedDns = get [ "profile" "generatedPeer" "dns" ] [ ];
      generatedMtu = get [ "profile" "generatedPeer" "mtu" ] null;
      generatedPeers = get [ "profile" "generatedPeer" "peers" ] [ ];

      ownNetworkStack = get [ "runtime" "ownNetworkStack" ] false;

      enableHealthCheck = get [ "services" "healthCheck" "enable" ] false;
      healthTarget4 = get [ "services" "healthCheck" "target4" ] null;
      healthInterval = get [ "services" "healthCheck" "interval" ] null;

      lanAddresses = lib.filter (value: value != null) [
        lanIPv4
        lanIPv6
      ];

      wanIPv4Method = get [ "wan" "ipv4" "method" ] null;
      wanIPv6Method = get [ "wan" "ipv6" "method" ] null;
      wanIPv4RouteMetric = let m = get [ "wan" "ipv4" "routeMetric" ] null; in if m == null then null else toString m;
      wanIPv6RouteMetric = let m = get [ "wan" "ipv6" "routeMetric" ] null; in if m == null then null else toString m;

      dhcp4Subnet = if dhcp4Enable then required [ "services" "dhcp4" "subnet" ] else null;
      dhcp4Pool = if dhcp4Enable then required [ "services" "dhcp4" "pool" ] else null;
      dhcp4Gateway = if dhcp4Enable then required [ "services" "dhcp4" "gateway" ] else null;
      dhcp4Dns = get [ "services" "dhcp4" "dns" ] [ ];
      dhcp4LeaseFile = get [ "services" "dhcp4" "leaseFile" ] null;

      raPrefix = if raEnable then required [ "services" "ra" "prefix" ] else null;
      raRdnss = get [ "services" "ra" "rdnss" ] [ ];

      firewallMode = get [ "firewall" "mode" ] null;
      allowLanToVpn = get [ "firewall" "allowLanToVpn" ] null;
      denyLanToWan = get [ "firewall" "denyLanToWan" ] null;
      denyWanToLan = get [ "firewall" "denyWanToLan" ] null;

      nat44Enable = required [ "nat" "ipv4" "enable" ];
      nat44Sources = get [ "nat" "ipv4" "sourceCidrs" ] [ ];
      nat44ToAddress = get [ "nat" "ipv4" "toAddress" ] null;
      nat66Enable = required [ "nat" "ipv6" "enable" ];
      nat66Sources = get [ "nat" "ipv6" "sourceCidrs" ] [ ];
      nat66ToAddress = get [ "nat" "ipv6" "toAddress" ] null;

      publicEndpoint = get [ "provider" "publicEndpoint" ] null;
      routedIPv6Prefixes = get [ "routes" "ipv6" "routedClientPrefixes" ] [ ];
      providerOwnedIPv6Prefixes = get [ "routes" "ipv6" "providerOwnedPrefixes" ] [ ];
      returnRoutes = get [ "routes" "returnRoutes" ] [ ];
      publicIngress = required [ "publicIngress" ];
      portForwards = required [ "portForwards" ];

      hasClientPrefixAuthority =
        builtins.elem prefixAuthority [
          "routed-prefix"
          "provider-owned-prefix"
        ]
        || routedIPv6Prefixes != [ ]
        || providerOwnedIPv6Prefixes != [ ];

      normalizedReturnRoutes = map (route: {
        destination = routeField route "destination";
        gateway = routeField route "gateway";
        interface = route.interface or lanInterface;
      }) returnRoutes;

      returnRoutesForLan = map (route: {
        Destination = route.destination;
        Gateway = route.gateway;
      }) (builtins.filter (route: route.interface == lanInterface) normalizedReturnRoutes);

      normalizedPublicIngress = map (ingress: {
        id = ingress.id or contractId;
        protocol = ingress.protocol or null;
        listenPort = exposureField ingress "listenPort";
        targetAddress = ingress.targetAddress or null;
        targetPort = exposureField ingress "targetPort";
        ingressInterface = ingress.ingressInterface or vpnInterface;
        targetInterface = ingress.targetInterface or lanInterface;
      }) publicIngress;

      normalizedPortForwards = map (forward: {
        id = forward.id or contractId;
        protocol = forward.protocol or null;
        listenPort = exposureField forward "listenPort";
        targetAddress = forward.targetAddress or null;
        targetPort = exposureField forward "targetPort";
        ingressInterface = forward.ingressInterface or wanInterface;
        targetInterface = forward.targetInterface or lanInterface;
      }) portForwards;

      generatedPeerForScript = {
        privateKeyFile =
          if generatedPrivateKeyFile == null then
            "/run/network-renderer-wireguard/missing-private-key"
          else
            generatedPrivateKeyFile;
        addresses = generatedAddresses;
        dns = generatedDns;
        mtu = generatedMtu;
        peers = map (peer: {
          publicKey = peerString peer "publicKey";
          endpoint = peerString peer "endpoint";
          allowedIPs = peerList peer "allowedIPs";
          presharedKeyFile = peerField peer "presharedKeyFile";
          persistentKeepalive = peerField peer "persistentKeepalive";
        }) generatedPeers;
      };
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
        assertion = builtins.elem state.prefixAuthority [
          "none"
          "host-only-128"
          "routed-prefix"
          "provider-owned-prefix"
        ];
        message = "network-renderer-wireguard provider.prefixAuthority must be none, host-only-128, routed-prefix, or provider-owned-prefix";
      }
      {
        assertion = builtins.elem state.profileMode [
          "profile-import"
          "generated-peer"
        ];
        message = "network-renderer-wireguard profile.mode must be profile-import or generated-peer";
      }
      {
        assertion = builtins.elem state.profileFormat [
          "wireguard"
          "openvpn"
        ];
        message = "network-renderer-wireguard profile.format must be wireguard or openvpn";
      }
      {
        assertion = state.profileMode != "generated-peer" || state.profileFormat == "wireguard";
        message = "network-renderer-wireguard generated-peer mode requires wireguard profile format";
      }
      {
        assertion = state.profileMode != "generated-peer" || isNonEmptyString state.generatedPrivateKeyFile;
        message = "network-renderer-wireguard generated-peer mode requires profile.generatedPeer.privateKeyFile";
      }
      {
        assertion = state.profileMode != "generated-peer" || state.generatedAddresses != [ ];
        message = "network-renderer-wireguard generated-peer mode requires profile.generatedPeer.addresses";
      }
      {
        assertion = state.profileMode != "generated-peer" || state.generatedPeers != [ ];
        message = "network-renderer-wireguard generated-peer mode requires profile.generatedPeer.peers";
      }
      {
        assertion = state.profileMode != "generated-peer" || builtins.all (peer: isNonEmptyString (peerField peer "publicKey")) state.generatedPeers;
        message = "network-renderer-wireguard generated-peer peers require publicKey";
      }
      {
        assertion = state.profileMode != "generated-peer" || builtins.all (peer: isNonEmptyString (peerField peer "endpoint")) state.generatedPeers;
        message = "network-renderer-wireguard generated-peer peers require endpoint";
      }
      {
        assertion = state.profileMode != "generated-peer" || builtins.all (peer: peerList peer "allowedIPs" != [ ]) state.generatedPeers;
        message = "network-renderer-wireguard generated-peer peers require allowedIPs";
      }
      {
        assertion = state.profileMode != "generated-peer" || isNonEmptyString state.generatedConfigPath;
        message = "network-renderer-wireguard generated-peer mode requires runtime.generatedConfigPath";
      }
      {
        assertion = state.providerClass != "self-hosted" || state.publicEndpoint != null;
        message = "network-renderer-wireguard self-hosted mode requires provider.publicEndpoint";
      }
      {
        assertion =
          state.providerClass != "self-hosted"
          || (state.publicEndpoint != null && isNonEmptyString (endpointAddress state.publicEndpoint));
        message = "network-renderer-wireguard self-hosted public endpoint requires address, host, or name";
      }
      {
        assertion =
          state.providerClass != "self-hosted"
          || (state.publicEndpoint != null && (state.publicEndpoint.port or null) != null);
        message = "network-renderer-wireguard self-hosted public endpoint requires port";
      }
      {
        assertion = isNonEmptyString state.uuidFile;
        message = "network-renderer-wireguard runtime.uuidFile must be explicit";
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
        assertion = (!state.dhcp4Enable) || state.dhcp4LeaseFile != null;
        message = "network-renderer-wireguard DHCPv4 requires services.dhcp4.leaseFile from the provider contract";
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
        assertion = state.nat44ToAddress == null || isNonEmptyString state.nat44ToAddress;
        message = "network-renderer-wireguard NAT44 SNAT target requires nat.ipv4.toAddress";
      }
      {
        assertion = state.nat66ToAddress == null || isNonEmptyString state.nat66ToAddress;
        message = "network-renderer-wireguard NAT66 SNAT target requires nat.ipv6.toAddress";
      }
      {
        assertion =
          state.providerMode != "routed-prefix"
          || state.routedIPv6Prefixes != [ ]
          || state.providerOwnedIPv6Prefixes != [ ];
        message = "network-renderer-wireguard routed-prefix mode requires routes.ipv6.routedClientPrefixes or routes.ipv6.providerOwnedPrefixes";
      }
      {
        assertion =
          state.providerMode != "public-ingress"
          || state.normalizedPublicIngress != [ ]
          || state.normalizedPortForwards != [ ];
        message = "network-renderer-wireguard public-ingress mode requires publicIngress or portForwards contracts";
      }
      {
        assertion =
          state.providerClass != "commercial-imported"
          || state.normalizedPublicIngress == [ ]
          || state.publicIngressAuthority;
        message = "network-renderer-wireguard commercial-imported public ingress requires provider.publicIngressAuthority";
      }
      {
        assertion =
          state.providerClass != "commercial-imported"
          || (state.routedIPv6Prefixes == [ ] && state.providerOwnedIPv6Prefixes == [ ])
          || state.routedClientPrefixAuthority;
        message = "network-renderer-wireguard commercial-imported routed prefixes require provider.routedClientPrefixAuthority";
      }
      {
        assertion = state.providerMode != "routed-prefix" || !state.nat66Enable;
        message = "network-renderer-wireguard routed client GUA mode must not enable NAT66";
      }
      {
        assertion = state.prefixAuthority != "routed-prefix" || state.routedIPv6Prefixes != [ ];
        message = "network-renderer-wireguard routed-prefix authority requires routes.ipv6.routedClientPrefixes";
      }
      {
        assertion = state.prefixAuthority != "provider-owned-prefix" || state.providerOwnedIPv6Prefixes != [ ];
        message = "network-renderer-wireguard provider-owned-prefix authority requires routes.ipv6.providerOwnedPrefixes";
      }
      {
        assertion = (!state.hasClientPrefixAuthority) || state.normalizedReturnRoutes != [ ];
        message = "network-renderer-wireguard routed or provider-owned client prefixes require explicit return routes";
      }
      {
        assertion = (!state.hasClientPrefixAuthority) || !state.nat66Enable;
        message = "network-renderer-wireguard routed or provider-owned client prefixes must not enable NAT66";
      }
      {
        assertion = (!state.hasClientPrefixAuthority) || !(isGlobalUnicastIPv6 state.lanIPv6);
        message = "network-renderer-wireguard routed or provider-owned client prefixes must not assign client GUA to router LAN interfaces";
      }
      {
        assertion =
          state.prefixAuthority != "host-only-128"
          || (state.routedIPv6Prefixes == [ ] && state.providerOwnedIPv6Prefixes == [ ]);
        message = "network-renderer-wireguard host-only-128 prefix authority must not expose routed or provider-owned downstream GUA prefixes";
      }
      {
        assertion = builtins.all isNonEmptyString state.providerOwnedIPv6Prefixes;
        message = "network-renderer-wireguard provider-owned prefixes must be non-empty strings";
      }
      {
        assertion =
          builtins.all (
            route:
            isNonEmptyString route.destination
            && isNonEmptyString route.gateway
            && isNonEmptyString route.interface
          ) state.normalizedReturnRoutes;
        message = "network-renderer-wireguard return routes require destination, gateway, and interface";
      }
      {
        assertion = builtins.all (route: route.interface == state.lanInterface) state.normalizedReturnRoutes;
        message = "network-renderer-wireguard return route projection currently requires interface to match interfaces.lan";
      }
      {
        assertion =
          builtins.all (
            ingress:
            isValidProtocol ingress.protocol
            && ingress.listenPort != null
            && isNonEmptyString ingress.targetAddress
            && ingress.targetPort != null
            && isNonEmptyString ingress.ingressInterface
            && isNonEmptyString ingress.targetInterface
          ) state.normalizedPublicIngress;
        message = "network-renderer-wireguard public ingress entries require protocol, listenPort, targetAddress, targetPort, ingressInterface, and targetInterface";
      }
      {
        assertion =
          builtins.all (
            forward:
            isValidProtocol forward.protocol
            && forward.listenPort != null
            && isNonEmptyString forward.targetAddress
            && forward.targetPort != null
            && isNonEmptyString forward.ingressInterface
            && isNonEmptyString forward.targetInterface
          ) state.normalizedPortForwards;
        message = "network-renderer-wireguard port forwards require protocol, listenPort, targetAddress, targetPort, ingressInterface, and targetInterface";
      }
      {
        assertion = (!state.enableHealthCheck) || state.healthInterval != null;
        message = "network-renderer-wireguard health check requires services.healthCheck.interval when enabled";
      }
    ];
}
