#!/usr/bin/env bash
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-010
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-020
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-030
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-040
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

fail() {
  echo "FAIL fs470-wireguard-remote-egress-smt: $*" >&2
  exit 1
}

eval_json() {
  local attr="$1"
  nix eval --json --impure --file tests/fs470-wireguard-remote-egress-smt.nix "${attr}"
}

remote_egress="$(eval_json remoteEgress)"

for phrase in \
  '"dispatcherDescription":"Bring up provider tunnel wg-re-egress0 from model/provider contract"' \
  '"hasProviderRuntimeModule":true' \
  '"profileMode":"generated-peer"' \
  '"generatedConfigPath":"/run/network-renderer-wireguard/fs470-generated.conf"' \
  '"privateKeyFile":"/run/keys/fs470-wg-private"' \
  '"endpoint":"198.51.100.47:51820"' \
  '"allowedIPs":["0.0.0.0/0","::/0"]' \
  '"presharedKeyFile":"/run/keys/fs470-wg-psk"' \
  '"persistentKeepalive":25' \
  'iifname \"edge-lan0\" oifname \"wg-re-egress0\" accept comment \"wg-provider-lan-to-vpn fs470-remote-egress\"' \
  'iifname \"edge-lan0\" oifname \"uplink0\" drop comment \"wg-provider-deny-lan-to-wan fs470-remote-egress\"' \
  'ip saddr 10.147.0.0/24 oifname \"wg-re-egress0\" masquerade comment \"wg-provider-nat44 fs470-remote-egress\"' \
  'ip6 saddr fd47:147::/64 oifname \"wg-re-egress0\" masquerade comment \"wg-provider-nat66 fs470-remote-egress\"'; do
  grep -Fq "${phrase}" <<<"${remote_egress}" || fail "SMS-010 remote egress materialization missing phrase: ${phrase}"
done

for phrase in \
  '"providerClass":"commercial-imported"' \
  '"providerMode":"egress-only"' \
  '"prefixAuthority":"host-only-128"' \
  '"publicIngress":[]' \
  '"portForwards":[]' \
  '"routedIPv6Prefixes":[]' \
  '"providerOwnedIPv6Prefixes":[]' \
  '"wireguard-host-only-128"' \
  '"wireguard-host-only-nat44"' \
  '"wireguard-host-only-nat66"' \
  '"wireguard-no-provider-name-inference"'; do
  grep -Fq "${phrase}" <<<"${remote_egress}" || fail "SMS-010 provider surface boundary missing phrase: ${phrase}"
done

for phrase in \
  '"subnet":"10.147.0.0/24"' \
  '"pool":"10.147.0.100 - 10.147.0.180"' \
  '"data":"10.147.0.1"' \
  'interface edge-lan0' \
  'RDNSS fd47:147::1' \
  'prefix fd47:147::/64'; do
  grep -Fq "${phrase}" <<<"${remote_egress}" || fail "SMS-020 overlay IPAM binding missing phrase: ${phrase}"
done

for forbidden in \
  "2001:db8:470::/64" \
  "wg-provider-public-ingress fs470-remote-egress" \
  "wg-provider-port-forward fs470-remote-egress"; do
  if grep -Fq "${forbidden}" <<<"${remote_egress}"; then
    fail "renderer invented unrelated routing/IPAM/bootstrap authority: ${forbidden}"
  fi
done

dhcp_and_ra="$(nix eval --json --impure --file tests/fs470-wireguard-remote-egress-smt.nix remoteEgress.dhcp4Config && nix eval --raw --impure --file tests/fs470-wireguard-remote-egress-smt.nix remoteEgress.radvdConfig)"
if grep -Fq "10.47.0.1" <<<"${dhcp_and_ra}"; then
  fail "SMS-040 bootstrap peer DNS leaked into customer DHCP/RA payload"
fi

unrelated_pool_denied_errors="$(eval_json unrelatedPoolDeniedErrors)"
grep -Fq "host-only-128 prefix authority must not expose routed or provider-owned downstream GUA prefixes" \
  <<<"${unrelated_pool_denied_errors}" \
  || fail "SMS-030 unrelated routed-pool denial assertion missing"

bootstrap_payload_missing_endpoint_errors="$(eval_json bootstrapPayloadMissingEndpointErrors)"
grep -Fq "generated-peer peers require endpoint" <<<"${bootstrap_payload_missing_endpoint_errors}" \
  || fail "SMS-040 bootstrap payload required-field assertion missing"

echo "PASS fs470-wireguard-remote-egress-smt"
