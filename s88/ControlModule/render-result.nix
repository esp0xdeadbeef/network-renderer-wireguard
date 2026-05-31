{ }:

{
  build =
    {
      providerContract,
      nixosModule,
      requiredCapabilities ? [ ],
    }:
    let
      capabilities = [
        "provider-runtime"
        "wireguard-profile-import"
        "wireguard-generated-peer"
        "wireguard-public-endpoint"
        "wireguard-provider-owned-prefix"
        "wireguard-return-routes"
        "wireguard-public-ingress"
        "wireguard-port-forward"
        "wireguard-commercial-egress-only"
        "wireguard-commercial-port-forward"
        "wireguard-commercial-public-ingress-authority"
        "wireguard-commercial-routed-prefix-authority"
        "wireguard-host-only-128"
        "wireguard-host-only-nat44"
        "wireguard-host-only-nat66"
        "wireguard-host-only-snat"
        "wireguard-host-only-no-downstream-gua"
        "wireguard-routed-client-prefix"
        "wireguard-provider-owned-client-prefix"
        "wireguard-client-prefix-return-routes"
        "wireguard-client-prefix-no-nat66"
        "wireguard-client-prefix-no-router-gua"
        "wireguard-request-minimum-schema"
        "wireguard-provider-class-parsing"
        "wireguard-no-provider-name-inference"
        "source-scoped-nat44"
        "source-scoped-nat66"
        "dhcp4"
        "ra-rdnss"
      ];
      missingRequiredCapabilities =
        builtins.filter (capability: !(builtins.elem capability capabilities)) requiredCapabilities;
    in
    if missingRequiredCapabilities != [ ] then
      throw "wireguard-provider required target capabilities not declared: ${builtins.concatStringsSep ", " missingRequiredCapabilities}"
    else
    {
      rendererClass = "provider";
      targetRenderer = "wireguard-provider";
      scope = {
        providerId = providerContract.id or "wireguard-provider";
      };
      capabilities = capabilities;
      artifacts = {
        nixosModules = {
          providerRuntime = nixosModule;
        };
        providerSurfaces = {
          providerClass = providerContract.provider.class or null;
          providerMode = providerContract.provider.mode or null;
          publicEndpoint = providerContract.provider.publicEndpoint or null;
          prefixAuthority = providerContract.provider.prefixAuthority or null;
          dnsMode = providerContract.dns.mode or null;
          publicIngressAuthority = providerContract.provider.publicIngressAuthority or false;
          routedClientPrefixAuthority = providerContract.provider.routedClientPrefixAuthority or false;
          routedIPv6Prefixes = providerContract.routes.ipv6.routedClientPrefixes or [ ];
          providerOwnedIPv6Prefixes = providerContract.routes.ipv6.providerOwnedPrefixes or [ ];
          returnRoutes = providerContract.routes.returnRoutes or [ ];
          publicIngress = providerContract.publicIngress or [ ];
          portForwards = providerContract.portForwards or [ ];
          nat44 = providerContract.nat.ipv4 or { };
          nat66 = providerContract.nat.ipv6 or { };
        };
      };
      diagnostics = [ ];
      unsupportedContracts = [ ];
      validationHints = [
        "SMT-WG-VALIDATE-001"
        "SMT-WG-EGRESS-001"
        "SMT-WG-NAT-001"
        "SMT-WG-NO-INFERENCE-001"
      ];
      trace = {
        sms = [
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-001-SMS-001-001"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-001-SMS-001-002"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-001-SMS-001-003"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-001-SMS-001-004"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-001-SMS-001-005"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-001-SMS-001-006"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-001-SMS-001-007"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-002-SMS-001-001"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-002-SMS-001-002"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-002-SMS-001-003"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-002-SMS-001-004"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-002-SMS-001-005"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-003-SMS-001-001"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-003-SMS-001-002"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-003-SMS-001-003"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-003-SMS-001-004"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-003-SMS-001-005"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-004-SMS-001-001"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-004-SMS-001-002"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-004-SMS-001-003"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-004-SMS-001-004"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-004-SMS-001-005"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-005-SMS-001-001"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-005-SMS-001-002"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-005-SMS-001-003"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-005-SMS-001-004"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-005-SMS-001-005"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-001"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-002"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-003"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-004"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-005"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-006"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-007"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-008"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-009"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-010"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-011"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-012"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-013"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-007-SMS-001-001"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-007-SMS-001-002"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-007-SMS-001-003"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-007-SMS-001-004"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-007-SMS-001-005"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-007-SMS-001-006"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-007-SMS-001-007"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-007-SMS-001-008"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-007-SMS-001-009"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-008-SMS-001-001"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-008-SMS-001-002"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-008-SMS-001-003"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-008-SMS-001-004"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-008-SMS-001-005"
        ];
        cmc = [
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-001-SMS-001-CMC-001-001"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-001-SMS-001-CMC-001-002"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-001-SMS-001-CMC-001-003"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-001-SMS-001-CMC-001-004"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-001-SMS-001-CMC-001-005"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-001-SMS-001-CMC-001-006"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-001-SMS-001-CMC-001-007"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-002-SMS-001-CMC-001-001"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-002-SMS-001-CMC-001-002"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-002-SMS-001-CMC-001-003"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-002-SMS-001-CMC-001-004"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-002-SMS-001-CMC-001-005"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-003-SMS-001-CMC-001-001"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-003-SMS-001-CMC-001-002"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-003-SMS-001-CMC-001-003"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-003-SMS-001-CMC-001-004"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-003-SMS-001-CMC-001-005"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-004-SMS-001-CMC-001-001"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-004-SMS-001-CMC-001-002"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-004-SMS-001-CMC-001-003"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-004-SMS-001-CMC-001-004"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-004-SMS-001-CMC-001-005"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-005-SMS-001-CMC-001-001"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-005-SMS-001-CMC-001-002"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-005-SMS-001-CMC-001-003"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-005-SMS-001-CMC-001-004"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-005-SMS-001-CMC-001-005"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-CMC-001-001"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-CMC-001-002"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-CMC-001-003"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-CMC-001-004"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-CMC-001-005"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-CMC-001-006"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-CMC-001-007"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-CMC-001-008"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-CMC-001-009"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-CMC-001-010"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-CMC-001-011"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-CMC-001-012"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-006-SMS-001-CMC-001-013"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-007-SMS-001-CMC-001-001"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-007-SMS-001-CMC-001-002"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-007-SMS-001-CMC-001-003"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-007-SMS-001-CMC-001-004"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-007-SMS-001-CMC-001-005"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-007-SMS-001-CMC-001-006"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-007-SMS-001-CMC-001-007"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-007-SMS-001-CMC-001-008"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-007-SMS-001-CMC-001-009"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-008-SMS-001-CMC-001-001"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-008-SMS-001-CMC-001-002"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-008-SMS-001-CMC-001-003"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-008-SMS-001-CMC-001-004"
          "USR-MODEL-001-FS-001-HDS-005-SDS-001-008-SMS-001-CMC-001-005"
        ];
      };
    };
}
