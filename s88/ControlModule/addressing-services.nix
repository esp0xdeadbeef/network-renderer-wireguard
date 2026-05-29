{ lib }:

{
  dhcp4Config =
    state:
    builtins.toJSON {
      Dhcp4 = {
        interfaces-config = {
          interfaces = [ state.lanInterface ];
        };
        valid-lifetime = state.get [ "services" "dhcp4" "validLifetime" ] 600;
        renew-timer = state.get [ "services" "dhcp4" "renewTimer" ] 300;
        rebind-timer = state.get [ "services" "dhcp4" "rebindTimer" ] 540;
        lease-database = {
          type = "memfile";
          persist = true;
          name = state.dhcp4LeaseFile;
        };
        subnet4 = [
          {
            id = state.get [ "services" "dhcp4" "subnetId" ] 1;
            subnet = state.dhcp4Subnet;
            pools = [
              {
                pool = state.dhcp4Pool;
              }
            ];
            option-data = [
              {
                name = "routers";
                data = state.dhcp4Gateway;
              }
              {
                name = "domain-name-servers";
                data = lib.concatStringsSep ", " state.dhcp4Dns;
              }
            ];
          }
        ];
      };
    };

  radvdConfig =
    state:
    ''
      interface ${state.lanInterface} {
        AdvSendAdvert on;
        MinRtrAdvInterval ${toString (state.get [ "services" "ra" "minInterval" ] 10)};
        MaxRtrAdvInterval ${toString (state.get [ "services" "ra" "maxInterval" ] 30)};
        ${lib.optionalString (state.raRdnss != [ ]) ''
          RDNSS ${lib.concatStringsSep " " state.raRdnss} {
            AdvRDNSSLifetime ${toString (state.get [ "services" "ra" "rdnssLifetime" ] 800)};
          };
        ''}
        prefix ${state.raPrefix} {
          AdvOnLink on;
          AdvAutonomous on;
          AdvRouterAddr on;
        };
      };
    '';
}
