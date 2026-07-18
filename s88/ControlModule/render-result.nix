{ }:

{
  build =
    {
      providerContract,
      nixosModule,
      requiredCapabilities ? [ ],
    }:
    let
      provenanceInput =
        if builtins.isAttrs (providerContract.provenance or null) then
          providerContract.provenance
        else
          { };
      provenanceRequested =
        if builtins.isAttrs (provenanceInput.requested or null) then
          provenanceInput.requested
        else
          { };
      provenanceSourceClasses =
        if builtins.isAttrs (provenanceInput.sourceClasses or null) then
          provenanceInput.sourceClasses
        else
          { };
      redactedSourceClasses =
        builtins.mapAttrs
          (name: sourceClass:
            if name == "protectedInventory" && builtins.isAttrs sourceClass && builtins.hasAttr "secretValue" sourceClass then
              sourceClass // {
                secretValue = "<redacted>";
              }
            else
              sourceClass
          )
          provenanceSourceClasses;
      provenanceMissingSourceClasses =
        let
          requiredSourceClasses = [
            "userIntent"
            "publicInventory"
            "protectedInventory"
          ];
          optionalSourceClasses = [
            "runtimeFacts"
            "validationContext"
          ];
          missingRequired =
            builtins.filter
              (name: !(builtins.hasAttr name provenanceSourceClasses))
              requiredSourceClasses;
          missingOptional =
            builtins.filter
              (name: !(builtins.hasAttr name provenanceSourceClasses))
              optionalSourceClasses;
        in
        missingRequired
        ++ (map (name: "${name}:not-declared") missingOptional);
      requestedScope =
        provenanceRequested.scope or null;
      requestedTarget =
        provenanceRequested.target or null;
      requestedDerivedScope =
        if builtins.isAttrs requestedScope then
          requestedScope
        else
          { };
      outputArtifact = "provider-runtime-output.json";
      provenanceRecord =
        {
        renderer = {
          name = "network-renderer-wireguard";
          repository = "network-renderer-wireguard";
          schemaVersion = 1;
        };
        input = {
          kind = "provider-contract";
          path = provenanceInput.path or null;
        };
        output = {
          kind = "provider-runtime-module";
          artifact = outputArtifact;
        };
        sources = {
          sourceClasses = redactedSourceClasses;
          missingSourceClasses = provenanceMissingSourceClasses;
        };
        requested = {
          scope = requestedScope;
          target =
            if builtins.isAttrs requestedTarget then
              requestedTarget
            else
              {
                renderer = "wireguard";
                role = "renderer-output";
              };
          derivedScope = requestedDerivedScope;
        };
        locks = {
          upstream = provenanceInput.locks or { };
          renderer = {
            available = true;
          };
        };
        redaction = {
          protectedValues = "redacted";
        };
      }
      // (
        let
          controlledBaseline = provenanceInput.controlledBaseline or provenanceInput.sourceBaseline or null;
        in
          if controlledBaseline != null then
            { controlledBaseline = controlledBaseline; }
          else
            { }
      );
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
        metadata = {
          provenance = provenanceRecord;
        };
        rendererClass = "provider";
        targetRenderer = "wireguard-provider";
        scope = {
          providerId = providerContract.id or null;
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
          "FS-470-HDS-010-SDS-010-SMS-010"
          "FS-470-HDS-010-SDS-010-SMS-020"
          "FS-470-HDS-010-SDS-010-SMS-021"
          "FS-470-HDS-010-SDS-010-SMS-022"
          "FS-470-HDS-010-SDS-010-SMS-030"
          "FS-470-HDS-010-SDS-010-SMS-040"
          "FS-470-HDS-010-SDS-010-SMS-041"
          "FS-470-HDS-010-SDS-010-SMS-050"
          "FS-470-HDS-010-SDS-010-SMS-060"
          "FS-470-HDS-010-SDS-010-SMS-070"
          "FS-470-HDS-010-SDS-010-SMS-080"
        ];
      };
    };
}
