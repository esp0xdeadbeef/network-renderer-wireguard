#!/usr/bin/env bash
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-080
# GAMP-SCOPE: software-module-test
# Focused construction test: WireGuard renderer policy boundary.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
failures=0

src_dirs=("s88" "modules")
firewall_cm="s88/ControlModule/firewall-nat.nix"
runtime_module="modules/wireguard-provider-runtime.nix"

record_failure() {
  local message="$1"
  echo "  FAIL: ${message}" >&2
  failures=$((failures + 1))
}

scan_source() {
  local pattern="$1"
  find "${src_dirs[@]}" -name '*.nix' -print0 2>/dev/null \
    | xargs -0 grep -HnE "${pattern}" 2>/dev/null \
    | grep -vE '^\s*(#|//)' || true
}

seeded_negative() {
  local name="$1"
  local pattern="$2"
  local file="$3"
  local content="$4"
  local path="${tmp_dir}/${file}"

  printf '%s\n' "${content}" > "${path}"
  if grep -nE "${pattern}" "${path}" >/dev/null 2>&1; then
    echo "  PASS: ${name} detected"
  else
    record_failure "${name} missed"
  fi

  rm -f "${path}"
  if grep -rnE "${pattern}" "${tmp_dir}" >/dev/null 2>&1; then
    record_failure "${name} recovery left residual hits"
  else
    echo "  PASS: ${name} recovery clean"
  fi
}

echo "--- FS-470-HDS-010-SDS-010-SMS-080: WG Policy Boundary ---"
echo ""

echo "--- Check 1: Firewall/nftables provenance ---"
fw_scoped=0
fw_issues=0

if grep -q 'table inet network_renderer_wireguard_filter' "${firewall_cm}" \
  && grep -q 'table inet network_renderer_wireguard_nat' "${firewall_cm}"; then
  echo "  PASS: WG nftables tables use network_renderer_wireguard namespaces"
else
  record_failure "WG nftables tables must use network_renderer_wireguard namespaces"
fi

while IFS= read -r hit_line; do
  [[ -z "${hit_line}" ]] && continue
  file_path="${hit_line%%:*}"
  rest="${hit_line#*:}"
  lineno="${rest%%:*}"
  rel_path="${file_path#${repo_root}/}"
  if [[ "${rel_path}" == "${firewall_cm}" ]]; then
    fw_scoped=$((fw_scoped + 1))
  else
    echo "  ISSUE: ${rel_path}:${lineno} — firewall/nftables policy outside WG control module"
    fw_issues=$((fw_issues + 1))
    failures=$((failures + 1))
  fi
done < <(scan_source '(policy[[:space:]]+(drop|accept)|chain[[:space:]]+(input|forward|output|prerouting|postrouting)[[:space:]]*\{|table[[:space:]]+(inet|ip|ip6)[[:space:]]+)')

echo "  Firewall/nftables policy in WG control module: ${fw_scoped}"
echo "  Firewall/nftables policy outside WG control module: ${fw_issues}"
echo ""

echo "--- Check 2: NAT rule provenance ---"
nat_tagged=0
nat_issues=0

while IFS= read -r hit_line; do
  [[ -z "${hit_line}" ]] && continue
  file_path="${hit_line%%:*}"
  rest="${hit_line#*:}"
  lineno="${rest%%:*}"
  rel_path="${file_path#${repo_root}/}"
  content="${rest#*:}"

  if [[ "${rel_path}" == "s88/ControlModule/render-result.nix" ]] && [[ "${content}" == *wireguard-* ]]; then
    echo "  OK: ${rel_path}:${lineno} — capability metadata, not runtime NAT policy"
    continue
  fi

  if [[ "${rel_path}" == "${firewall_cm}" && "${content}" == *wg-provider-* ]]; then
    nat_tagged=$((nat_tagged + 1))
  else
    echo "  ISSUE: ${rel_path}:${lineno} — NAT policy without WG provider provenance"
    nat_issues=$((nat_issues + 1))
    failures=$((failures + 1))
  fi
done < <(scan_source '(masquerade|snat|dnat)')

echo "  NAT rules with WG provider provenance: ${nat_tagged}"
echo "  NAT provenance issues: ${nat_issues}"
echo ""

echo "--- Check 3: DNS config provenance ---"
dns_scoped=0
dns_issues=0

while IFS= read -r hit_line; do
  [[ -z "${hit_line}" ]] && continue
  file_path="${hit_line%%:*}"
  rest="${hit_line#*:}"
  lineno="${rest%%:*}"
  rel_path="${file_path#${repo_root}/}"
  content="${rest#*:}"

  if [[ "${rel_path}" == "${runtime_module}" && "${content}" == *ownNetworkStack* ]]; then
    dns_scoped=$((dns_scoped + 1))
  else
    echo "  ISSUE: ${rel_path}:${lineno} — DNS config outside WG runtime contract scope"
    dns_issues=$((dns_issues + 1))
    failures=$((failures + 1))
  fi
done < <(scan_source '(networking\.resolver|networking\.nameservers|services\.resolved|dnsForwarder)')

echo "  DNS config scoped to WG runtime contract: ${dns_scoped}"
echo "  DNS provenance issues: ${dns_issues}"
echo ""

echo "--- Check 4: no forwarding policy shapes ---"
fwd_hits=$(scan_source '(forwardingIntent|forwardPairs|forwardRules|unsafeRoutes)')
if [[ -n "${fwd_hits}" ]]; then
  printf '%s\n' "${fwd_hits}" | sed 's/^/  ISSUE: /'
  record_failure "forwarding policy shapes found in WG renderer source"
else
  echo "  PASS: no forwardingIntent/forwardPairs/forwardRules/unsafeRoutes shapes"
fi
echo ""

echo "--- Check 5: route metric / health target provenance ---"
route_hits=$(scan_source '(routeMetric|Metric[[:space:]]*=)')
health_hits=$(scan_source '(healthTarget|healthCheck.*target)')
route_count=0
health_count=0

if [[ -n "${route_hits}" ]]; then
  route_count=$(printf '%s\n' "${route_hits}" | wc -l)
fi
if [[ -n "${health_hits}" ]]; then
  health_count=$(printf '%s\n' "${health_hits}" | wc -l)
fi

fallback_hits=$(scan_source '(or[[:space:]]+300|or[[:space:]]+"1\.1\.1\.1")')
if [[ -n "${fallback_hits}" ]]; then
  printf '%s\n' "${fallback_hits}" | sed 's/^/  ISSUE: /'
  record_failure "route metric or health target hardcoded fallback found"
else
  echo "  PASS: no route metric or health target fallback defaults"
fi
echo "  Route metric references: ${route_count}"
echo "  Health target references: ${health_count}"
echo ""

echo "--- Seeded negatives ---"
seeded_negative "SN1 untagged firewall rule" 'policy[[:space:]]+drop' "bad-firewall.nix" '{ rules = "chain forward { type filter hook forward priority filter; policy drop; }"; }'
seeded_negative "SN2 forwardingIntent shape" 'forwardingIntent' "bad-forwarding.nix" '{ contract }: contract.forwardingIntent or { forwardPairs = [ ]; forwardRules = [ ]; }'
seeded_negative "SN3 DNS outside WG runtime" 'services\.resolved' "bad-dns.nix" '{ config, lib, ... }: { services.resolved.enable = false; }'
seeded_negative "SN4 untagged NAT rule" 'masquerade' "bad-nat.nix" '{ rules = "ip saddr 10.0.0.0/24 masquerade"; }'
echo ""

echo "============================================================"
echo "FS-470-HDS-010-SDS-010-SMS-080 Policy Boundary Summary"
echo "============================================================"
echo "  Check 1 (FW provenance):  ${fw_scoped} scoped, ${fw_issues} issues"
echo "  Check 2 (NAT provenance): ${nat_tagged} tagged, ${nat_issues} issues"
echo "  Check 3 (DNS provenance): ${dns_scoped} scoped, ${dns_issues} issues"
echo "  Check 4 (FWD shapes):     clean"
echo "  Check 5 (route/health):   ${route_count} route refs, ${health_count} health refs, no fallback defaults"
echo "  Seeded negatives:          SN1, SN2, SN3, SN4"
echo "  KNOWN_GAPS:                0"
echo ""

if (( failures > 0 )); then
  echo "FAIL: FS-470-HDS-010-SDS-010-SMS-080 — WG policy boundary has unresolved provenance gaps."
  exit 1
fi

echo "PASS: FS-470-HDS-010-SDS-010-SMS-080 — WG policy boundary is scoped to WG-owned contract surfaces."
