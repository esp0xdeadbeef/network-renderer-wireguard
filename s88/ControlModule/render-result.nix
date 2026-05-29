{ }:

{
  build =
    {
      providerContract,
      nixosModule,
    }:
    {
      rendererClass = "provider";
      targetRenderer = "wireguard-provider";
      scope = {
        providerId = providerContract.id or "wireguard-provider";
      };
      artifacts = {
        nixosModules = {
          providerRuntime = nixosModule;
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
          "SMS-MOD-014"
          "SMS-MOD-015"
        ];
        cmc = [
          "CMC-MOD-013"
          "CMC-MOD-014"
        ];
      };
    };
}
