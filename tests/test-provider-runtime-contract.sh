#!/usr/bin/env bash
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-010
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-020
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-021
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-022
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-030
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-040
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-041
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-050
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-060
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-070
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-080
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

fail() {
  echo "FAIL provider-runtime-contract: $*" >&2
  exit 1
}

eval_json() {
  local attr="$1"
  nix eval --json --impure --file tests/provider-runtime-contract.nix "${attr}"
}

expect_eval_failure() {
  local attr="$1"
  local phrase="$2"
  local stderr_path
  stderr_path="$(mktemp)"
  if nix eval --json --impure --file tests/provider-runtime-contract.nix "${attr}" >/dev/null 2>"${stderr_path}"; then
    rm -f "${stderr_path}"
    fail "${attr} was accepted"
  fi
  grep -Fq "${phrase}" "${stderr_path}" || {
    cat "${stderr_path}" >&2
    rm -f "${stderr_path}"
    fail "${attr} diagnostic did not contain: ${phrase}"
  }
  rm -f "${stderr_path}"
}

valid_json="$(eval_json valid)"

for phrase in \
  "Bring up provider tunnel wg0 from model/provider contract" \
  "wg-provider-lan-to-vpn test-provider" \
  "wg-provider-nat44 test-provider" \
  "wg-provider-nat66 test-provider" \
  "10.66.0.100 - 10.66.0.200" \
  "RDNSS fd42:66::1"; do
  grep -Fq "${phrase}" <<<"${valid_json}" || fail "valid contract missing rendered phrase: ${phrase}"
done

routed_nat66_errors="$(eval_json routedWithNat66Errors)"
grep -Fq "routed client GUA mode must not enable NAT66" <<<"${routed_nat66_errors}" || \
  fail "routed-prefix NAT66 negative assertion missing"

public_ingress_errors="$(eval_json publicIngressMissingErrors)"
grep -Fq "public-ingress mode requires publicIngress or portForwards contracts" <<<"${public_ingress_errors}" || \
  fail "public-ingress missing-contract assertion missing"

expect_eval_failure missingDnsModeResult "provider contract missing dns.mode"
expect_eval_failure missingPrefixAuthorityResult "provider contract missing provider.prefixAuthority"
expect_eval_failure missingRuntimePathResult "provider contract missing runtime.uuidFile"
expect_eval_failure missingPublicIngressListResult "provider contract missing publicIngress"
expect_eval_failure missingPortForwardsListResult "provider contract missing portForwards"
expect_eval_failure missingNat44ModeResult "provider contract missing nat.ipv4.enable"
expect_eval_failure missingProfileModeResult "FS-470-HDS-010-SDS-010-SMS-041: network-renderer-wireguard provider contract missing profile.mode"
expect_eval_failure badProviderClassRenderResult "provider.class must be self-hosted or commercial-imported"
expect_eval_failure badProviderModeRenderResult "provider.mode must be egress-only, public-ingress, or routed-prefix"
expect_eval_failure badPrefixAuthorityRenderResult "provider.prefixAuthority must be none, host-only-128, routed-prefix, or provider-owned-prefix"

self_hosted_missing_endpoint_errors="$(eval_json selfHostedMissingEndpointErrors)"
grep -Fq "self-hosted mode requires provider.publicEndpoint" <<<"${self_hosted_missing_endpoint_errors}" || \
  fail "self-hosted missing public endpoint assertion missing"

self_hosted_bad_return_route_errors="$(eval_json selfHostedBadReturnRouteErrors)"
grep -Fq "return routes require destination, gateway, and interface" <<<"${self_hosted_bad_return_route_errors}" || \
  fail "self-hosted bad return-route assertion missing"

self_hosted_bad_public_ingress_errors="$(eval_json selfHostedBadPublicIngressErrors)"
grep -Fq "public ingress entries require protocol, listenPort, targetAddress, targetPort, ingressInterface, and targetInterface" <<<"${self_hosted_bad_public_ingress_errors}" || \
  fail "self-hosted bad public-ingress assertion missing"

self_hosted_bad_port_forward_errors="$(eval_json selfHostedBadPortForwardErrors)"
grep -Fq "port forwards require protocol, listenPort, targetAddress, targetPort, ingressInterface, and targetInterface" <<<"${self_hosted_bad_port_forward_errors}" || \
  fail "self-hosted bad port-forward assertion missing"

self_hosted_exposure="$(eval_json selfHostedExposure)"
for phrase in \
  '"address":"203.0.113.10"' \
  '"port":51820' \
  '"providerClass":"self-hosted"' \
  '"providerMode":"public-ingress"' \
  '"providerOwnedIPv6Prefixes":["2001:db8:70::/64"]' \
  '"Destination":"2001:db8:70:10::/64"' \
  '"Gateway":"fd42:66::2"' \
  'wg-provider-public-ingress test-provider https-ingress' \
  'wg-provider-port-forward test-provider wg-game' \
  'dnat ip to 10.66.0.20:51820' \
  '"wireguard-public-endpoint"' \
  '"wireguard-provider-owned-prefix"' \
  '"wireguard-return-routes"' \
  '"wireguard-public-ingress"' \
  '"wireguard-port-forward"'; do
  grep -Fq "${phrase}" <<<"${self_hosted_exposure}" || fail "self-hosted exposure contract missing phrase: ${phrase}"
done

commercial_public_ingress_without_authority_errors="$(eval_json commercialPublicIngressWithoutAuthorityErrors)"
grep -Fq "commercial-imported public ingress requires provider.publicIngressAuthority" <<<"${commercial_public_ingress_without_authority_errors}" || \
  fail "commercial public-ingress authority assertion missing"

commercial_routed_without_authority_errors="$(eval_json commercialRoutedWithoutAuthorityErrors)"
grep -Fq "commercial-imported routed prefixes require provider.routedClientPrefixAuthority" <<<"${commercial_routed_without_authority_errors}" || \
  fail "commercial routed-prefix authority assertion missing"

commercial_port_forward="$(eval_json commercialPortForward)"
for phrase in \
  'wg-provider-port-forward test-provider commercial-forward' \
  'dnat ip to 10.66.0.30:443' \
  '"publicIngressAuthority":false' \
  '"routedClientPrefixAuthority":false' \
  '"providerClass":"commercial-imported"' \
  '"providerMode":"public-ingress"' \
  '"wireguard-commercial-port-forward"'; do
  grep -Fq "${phrase}" <<<"${commercial_port_forward}" || fail "commercial port-forward contract missing phrase: ${phrase}"
done

commercial_public_ingress_authority="$(eval_json commercialPublicIngressAuthority)"
for phrase in \
  '"publicIngressAuthority":true' \
  'wg-provider-public-ingress test-provider commercial-public-ingress' \
  '"wireguard-commercial-public-ingress-authority"'; do
  grep -Fq "${phrase}" <<<"${commercial_public_ingress_authority}" || fail "commercial public-ingress authority contract missing phrase: ${phrase}"
done

commercial_routed_authority="$(eval_json commercialRoutedAuthority)"
for phrase in \
  '"routedClientPrefixAuthority":true' \
  '"providerClass":"commercial-imported"' \
  '"providerMode":"routed-prefix"' \
  '"routedIPv6Prefixes":["2001:db8:80::/64"]' \
  '"wireguard-commercial-routed-prefix-authority"' \
  '"hasProviderRuntimeModule":true'; do
  grep -Fq "${phrase}" <<<"${commercial_routed_authority}" || fail "commercial routed-prefix authority contract missing phrase: ${phrase}"
done

host_only_nat44_missing_source_errors="$(eval_json hostOnlyNat44MissingSourceErrors)"
grep -Fq "NAT44 requires nat.ipv4.sourceCidrs" <<<"${host_only_nat44_missing_source_errors}" || \
  fail "host-only NAT44 missing source assertion missing"

host_only_nat66_missing_source_errors="$(eval_json hostOnlyNat66MissingSourceErrors)"
grep -Fq "NAT66 requires nat.ipv6.sourceCidrs" <<<"${host_only_nat66_missing_source_errors}" || \
  fail "host-only NAT66 missing source assertion missing"

host_only_downstream_gua_errors="$(eval_json hostOnlyDownstreamGuaErrors)"
grep -Fq "host-only-128 prefix authority must not expose routed or provider-owned downstream GUA prefixes" <<<"${host_only_downstream_gua_errors}" || \
  fail "host-only downstream GUA refusal assertion missing"

too_long_vpn_interface_errors="$(eval_json tooLongVpnInterfaceErrors)"
grep -Fq "interfaces.vpn must be a non-empty Linux interface name with length <= 15" <<<"${too_long_vpn_interface_errors}" || \
  fail "too-long VPN interface assertion missing"

host_only="$(eval_json hostOnly)"
for phrase in \
  '"prefixAuthority":"host-only-128"' \
  '"providerClass":"commercial-imported"' \
  '"providerMode":"egress-only"' \
  'ip saddr 10.66.0.0/24 oifname \"wg0\" masquerade comment \"wg-provider-nat44 test-provider\"' \
  'ip6 saddr fd42:66::/64 oifname \"wg0\" masquerade comment \"wg-provider-nat66 test-provider\"' \
  '"wireguard-host-only-128"' \
  '"wireguard-host-only-nat44"' \
  '"wireguard-host-only-nat66"' \
  '"wireguard-host-only-no-downstream-gua"'; do
  grep -Fq "${phrase}" <<<"${host_only}" || fail "host-only contract missing phrase: ${phrase}"
done

host_only_snat="$(eval_json hostOnlySnat)"
for phrase in \
  'snat ip to 198.51.100.44' \
  'snat ip6 to 2001:db8:44::1' \
  '"toAddress":"198.51.100.44"' \
  '"toAddress":"2001:db8:44::1"' \
  '"wireguard-host-only-snat"'; do
  grep -Fq "${phrase}" <<<"${host_only_snat}" || fail "host-only SNAT contract missing phrase: ${phrase}"
done

client_prefix_missing_return_route_errors="$(eval_json clientPrefixMissingReturnRouteErrors)"
grep -Fq "routed or provider-owned client prefixes require explicit return routes" <<<"${client_prefix_missing_return_route_errors}" || \
  fail "client prefix missing return-route assertion missing"

client_prefix_nat66_errors="$(eval_json clientPrefixNat66Errors)"
grep -Fq "routed or provider-owned client prefixes must not enable NAT66" <<<"${client_prefix_nat66_errors}" || \
  fail "client prefix NAT66 refusal assertion missing"

client_prefix_router_gua_errors="$(eval_json clientPrefixRouterGuaErrors)"
grep -Fq "routed or provider-owned client prefixes must not assign client GUA to router LAN interfaces" <<<"${client_prefix_router_gua_errors}" || \
  fail "client prefix router-GUA refusal assertion missing"

routed_prefix="$(eval_json routedPrefix)"
for phrase in \
  '"prefixAuthority":"routed-prefix"' \
  '"providerClass":"self-hosted"' \
  '"providerMode":"routed-prefix"' \
  '"routedIPv6Prefixes":["2001:db8:91::/64"]' \
  '"Destination":"2001:db8:91::/64"' \
  '"Gateway":"fd42:66::91"' \
  '"wireguard-routed-client-prefix"' \
  '"wireguard-client-prefix-return-routes"' \
  '"wireguard-client-prefix-no-nat66"' \
  '"wireguard-client-prefix-no-router-gua"'; do
  grep -Fq "${phrase}" <<<"${routed_prefix}" || fail "routed-prefix contract missing phrase: ${phrase}"
done

provider_owned_prefix="$(eval_json providerOwnedPrefix)"
for phrase in \
  '"prefixAuthority":"provider-owned-prefix"' \
  '"providerClass":"self-hosted"' \
  '"providerMode":"routed-prefix"' \
  '"providerOwnedIPv6Prefixes":["2001:db8:92::/64"]' \
  '"Destination":"2001:db8:92::/64"' \
  '"Gateway":"fd42:66::92"' \
  '"wireguard-provider-owned-client-prefix"'; do
  grep -Fq "${phrase}" <<<"${provider_owned_prefix}" || fail "provider-owned-prefix contract missing phrase: ${phrase}"
done

generated_peer="$(eval_json generatedPeer)"
for phrase in \
  '"profileMode":"generated-peer"' \
  '"generatedConfigPath":"/run/network-renderer-wireguard/generated-test-provider.conf"' \
  '"uuidFile":"/run/network-renderer-wireguard/test-provider.uuid"' \
  '"privateKeyFile":"/run/keys/wg-private"' \
  '"endpoint":"198.51.100.10:51820"' \
  '"allowedIPs":["0.0.0.0/0","::/0"]' \
  '"presharedKeyFile":"/run/keys/wg-psk"' \
  '"mtu":1420' \
  '"hasProviderRuntimeModule":true'; do
  grep -Fq "${phrase}" <<<"${generated_peer}" || fail "generated-peer contract missing phrase: ${phrase}"
done

generated_peer_missing_endpoint_errors="$(eval_json generatedPeerMissingEndpointErrors)"
grep -Fq "generated-peer peers require endpoint" <<<"${generated_peer_missing_endpoint_errors}" || \
  fail "generated-peer missing endpoint assertion missing"
grep -Fq "FS-470-HDS-010-SDS-010-SMS-041" <<<"${generated_peer_missing_endpoint_errors}" || \
  fail "generated-peer missing endpoint assertion must carry SMS-041 trace ID"

generated_peer_missing_private_key_errors="$(eval_json generatedPeerMissingPrivateKeyErrors)"
grep -Fq "FS-470-HDS-010-SDS-010-SMS-041: network-renderer-wireguard generated-peer mode requires profile.generatedPeer.privateKeyFile" <<<"${generated_peer_missing_private_key_errors}" || \
  fail "generated-peer missing private key assertion must carry SMS-041 trace ID"

health_check_missing_target_errors="$(eval_json healthCheckMissingTargetErrors)"
grep -Fq "FS-470-HDS-010-SDS-010-SMS-041: health check target required by CPM provider contract" <<<"${health_check_missing_target_errors}" || \
  fail "health-check missing target assertion must carry SMS-041 trace ID"

firewall_missing_action_errors="$(eval_json firewallMissingActionErrors)"
grep -Fq "FS-470-HDS-010-SDS-010-SMS-041: firewall rule action required by CPM provider contract, cannot default to allow or deny" <<<"${firewall_missing_action_errors}" || \
  fail "firewall missing action assertion must carry SMS-041 trace ID"

name_inference="$(eval_json nameInference)"
for phrase in \
  '"publicIngress":[]' \
  '"portForwards":[]' \
  '"routedIPv6Prefixes":[]' \
  '"providerOwnedIPv6Prefixes":[]' \
  '"dnsMode":"none"' \
  '"nat66":{"enable":false,"sourceCidrs":[]}' \
  '"wireguard-no-provider-name-inference"'; do
  grep -Fq "${phrase}" <<<"${name_inference}" || fail "name-inference fixture missing phrase: ${phrase}"
done
for forbidden in \
  "wg-provider-public-ingress public-ingress-routed-gua-dns-nat66-hostile" \
  "wg-provider-port-forward public-ingress-routed-gua-dns-nat66-hostile" \
  "wg-provider-nat66 public-ingress-routed-gua-dns-nat66-hostile"; do
  if grep -Fq "${forbidden}" <<<"${name_inference}"; then
    fail "name-inference fixture inferred forbidden behavior from provider/profile names: ${forbidden}"
  fi
done

render_result_shape="$(eval_json renderResultShape)"
for phrase in \
  '"rendererClass":"provider"' \
  '"targetRenderer":"wireguard-provider"' \
  '"providerId":"test-provider"' \
  '"providerClass":"commercial-imported"' \
  '"providerMode":"egress-only"' \
  '"prefixAuthority":"none"' \
  '"provider-runtime"' \
  '"wireguard-profile-import"' \
  '"wireguard-generated-peer"' \
  '"wireguard-public-endpoint"' \
  '"wireguard-provider-owned-prefix"' \
  '"wireguard-return-routes"' \
  '"wireguard-public-ingress"' \
  '"wireguard-port-forward"' \
  '"wireguard-request-minimum-schema"' \
  '"wireguard-provider-class-parsing"' \
  '"wireguard-no-provider-name-inference"' \
  '"source-scoped-nat44"' \
  '"source-scoped-nat66"' \
  '"diagnostics":[]' \
  '"unsupportedContracts":[]' \
  '"hasProviderRuntimeModule":true' \
  '"SMT-WG-VALIDATE-001"'; do
  grep -Fq "${phrase}" <<<"${render_result_shape}" || fail "render result shape missing phrase: ${phrase}"
done

for gamp_id in \
  "FS-470-HDS-010-SDS-010-SMS-010" \
  "FS-470-HDS-010-SDS-010-SMS-020" \
  "FS-470-HDS-010-SDS-010-SMS-021" \
  "FS-470-HDS-010-SDS-010-SMS-022" \
  "FS-470-HDS-010-SDS-010-SMS-030" \
  "FS-470-HDS-010-SDS-010-SMS-040" \
  "FS-470-HDS-010-SDS-010-SMS-041" \
  "FS-470-HDS-010-SDS-010-SMS-050" \
  "FS-470-HDS-010-SDS-010-SMS-060" \
  "FS-470-HDS-010-SDS-010-SMS-070" \
  "FS-470-HDS-010-SDS-010-SMS-080"; do
  grep -Fq "\"${gamp_id}\"" <<<"${render_result_shape}" || fail "render result shape missing request schema trace: ${gamp_id}"
done

if grep -Fq '"cmc":' <<<"${render_result_shape}"; then
  fail "render result trace contains invalid trace.cmc namespace"
fi

required_capability_shape="$(eval_json renderResultWithRequiredCapabilitiesShape)"
for phrase in \
  '"targetRenderer":"wireguard-provider"' \
  '"provider-runtime"' \
  '"source-scoped-nat44"' \
  '"hasProviderRuntimeModule":true'; do
  grep -Fq "${phrase}" <<<"${required_capability_shape}" || fail "required capability render result missing phrase: ${phrase}"
done

missing_capability_stderr="$(mktemp)"
trap 'rm -f "${missing_capability_stderr}"' EXIT
if nix eval --json --impure --file tests/provider-runtime-contract.nix missingRequiredCapabilityResult >/dev/null 2>"${missing_capability_stderr}"; then
  fail "missing required capability was accepted"
fi
grep -Fq "wireguard-provider required target capabilities not declared: future-public-ingress" "${missing_capability_stderr}" \
  || fail "missing required capability diagnostic did not name future-public-ingress"

stale_sms="SMS"
stale_cmc="CMC"
stale_fs="FS"
stale_fn="FN"
stale_sds="SDS"
stale_sw="SW"
stale_hds="HDS"
stale_inf="INF"
stale_smd="SM""D"
stale_smds="${stale_smd}""S"
stale_pattern="${stale_sms}-MOD|${stale_cmc}-MOD|${stale_fs}-${stale_fn}|${stale_sds}-${stale_sw}|${stale_hds}-${stale_inf}|${stale_smd}|${stale_smds}"

if grep -Eq "${stale_pattern}" <<<"${render_result_shape}"; then
  fail "render result trace contains stale non-direct GAMP identifiers: ${render_result_shape}"
fi

echo "PASS provider-runtime-contract"
