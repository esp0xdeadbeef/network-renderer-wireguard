{ lib }:

{
  nftFilterRules =
    state:
    lib.optionalString (state.firewallMode == "dedicated-gateway") ''
      table inet network_renderer_wireguard_filter {
        chain input {
          type filter hook input priority filter; policy drop;
          iifname "lo" accept
          ct state established,related accept
          iifname "${state.lanInterface}" accept
          iifname "${state.wanInterface}" drop
        }

        chain forward {
          type filter hook forward priority filter; policy drop;
          ct state invalid drop
          ct state established,related accept
          ${lib.optionalString state.allowLanToVpn ''
            iifname "${state.lanInterface}" oifname "${state.vpnInterface}" accept comment "wg-provider-lan-to-vpn ${state.contractId}"
          ''}
          iifname "${state.vpnInterface}" oifname "${state.lanInterface}" accept comment "wg-provider-vpn-return ${state.contractId}"
          ${lib.optionalString state.denyLanToWan ''
            iifname "${state.lanInterface}" oifname "${state.wanInterface}" drop comment "wg-provider-deny-lan-to-wan ${state.contractId}"
          ''}
          ${lib.optionalString state.denyWanToLan ''
            iifname "${state.wanInterface}" oifname "${state.lanInterface}" drop comment "wg-provider-deny-wan-to-lan ${state.contractId}"
          ''}
        }

        chain output {
          type filter hook output priority filter; policy accept;
        }
      }
    '';

  nftNatRules =
    state:
    let
      nat44Rules = lib.concatMapStringsSep "\n" (
        source:
        ''        ip saddr ${source} oifname "${state.vpnInterface}" masquerade comment "wg-provider-nat44 ${state.contractId}"''
      ) state.nat44Sources;

      nat66Rules = lib.concatMapStringsSep "\n" (
        source:
        ''        ip6 saddr ${source} oifname "${state.vpnInterface}" masquerade comment "wg-provider-nat66 ${state.contractId}"''
      ) state.nat66Sources;
    in
    lib.optionalString (state.nat44Enable || state.nat66Enable) ''
      table inet network_renderer_wireguard_nat {
        chain postrouting {
          type nat hook postrouting priority srcnat; policy accept;
    ${nat44Rules}
    ${nat66Rules}
        }
      }
    '';
}
