{ lib }:

let
  isIPv6 = address: builtins.match ".*:.*" address != null;
  nftDnatTarget =
    forward:
    if isIPv6 forward.targetAddress then
      "ip6 to [${forward.targetAddress}]:${toString forward.targetPort}"
    else
      "ip to ${forward.targetAddress}:${toString forward.targetPort}";
in
{
  nftFilterRules =
    state:
    let
      publicIngressRules = lib.concatMapStringsSep "\n" (
        ingress:
        ''          iifname "${ingress.ingressInterface}" oifname "${ingress.targetInterface}" ${ingress.protocol} dport ${toString ingress.targetPort} accept comment "wg-provider-public-ingress ${state.contractId} ${ingress.id}"''
      ) state.normalizedPublicIngress;
      portForwardRules = lib.concatMapStringsSep "\n" (
        forward:
        ''          iifname "${forward.ingressInterface}" oifname "${forward.targetInterface}" ${forward.protocol} dport ${toString forward.targetPort} accept comment "wg-provider-port-forward ${state.contractId} ${forward.id}"''
      ) state.normalizedPortForwards;
    in
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
${publicIngressRules}
${portForwardRules}
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
        if state.nat44ToAddress == null then
          ''        ip saddr ${source} oifname "${state.vpnInterface}" masquerade comment "wg-provider-nat44 ${state.contractId}"''
        else
          ''        ip saddr ${source} oifname "${state.vpnInterface}" snat ip to ${state.nat44ToAddress} comment "wg-provider-snat44 ${state.contractId}"''
      ) state.nat44Sources;

      nat66Rules = lib.concatMapStringsSep "\n" (
        source:
        if state.nat66ToAddress == null then
          ''        ip6 saddr ${source} oifname "${state.vpnInterface}" masquerade comment "wg-provider-nat66 ${state.contractId}"''
        else
          ''        ip6 saddr ${source} oifname "${state.vpnInterface}" snat ip6 to ${state.nat66ToAddress} comment "wg-provider-snat66 ${state.contractId}"''
      ) state.nat66Sources;
      portForwardRules = lib.concatMapStringsSep "\n" (
        forward:
        ''        iifname "${forward.ingressInterface}" ${forward.protocol} dport ${toString forward.listenPort} dnat ${nftDnatTarget forward} comment "wg-provider-port-forward ${state.contractId} ${forward.id}"''
      ) state.normalizedPortForwards;
    in
    lib.optionalString (state.nat44Enable || state.nat66Enable || state.normalizedPortForwards != [ ]) ''
      table inet network_renderer_wireguard_nat {
        ${lib.optionalString (state.normalizedPortForwards != [ ]) ''
        chain prerouting {
          type nat hook prerouting priority dstnat; policy accept;
${portForwardRules}
        }
        ''}
        chain postrouting {
          type nat hook postrouting priority srcnat; policy accept;
    ${nat44Rules}
    ${nat66Rules}
        }
      }
    '';
}
