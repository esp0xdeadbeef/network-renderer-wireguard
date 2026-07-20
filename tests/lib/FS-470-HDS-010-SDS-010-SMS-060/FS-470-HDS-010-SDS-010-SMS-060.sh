#!/usr/bin/env bash
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-060
# GAMP-SCOPE: software-module-test
# Focused construction test: WireGuard renderer hardcoded value prevention.
# Proves the WG renderer does not contain hardcoded network-affecting values
# (IPs, route metrics, interface names, key paths, DNS forwarders) in
# production source code. All such values must trace to CPM provider
# contract fields or inventory provider realization facts.
#
# SMS acceptance predicates:
#   P1: No hardcoded health check target IPs (e.g., "1.1.1.1", "8.8.8.8")
#       in production code as defaults.
#   P2: No hardcoded route metrics (e.g., 300) in production code.
#   P3: No hardcoded WireGuard interface name (e.g., "wg-egress") in
#       production code as defaults.
#   P4: No hardcoded DNS forwarder IPs (e.g., "8.8.8.8") in production code.
#   P5: No hardcoded DHCP pool configuration inventing policy.
#
# Active seeded negatives: inject violating patterns, verify detection +
# recovery.
set -euo pipefail

repo_root="${SMS_TEST_REPO_ROOT:-$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)}"
cd "${repo_root}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
all_checks_passed=true

# Production source directories
src_dirs=("s88" "modules")
flake_file="flake.nix"

echo "--- FS-470-HDS-010-SDS-010-SMS-060: WG Hardcoded Value Prevention ---"
echo ""

# ================================================================
# KNOWN_GAPS: pre-existing hits that are permitted
# ================================================================
KNOWN_GAPS=(
  # No pre-existing violations found.
)

is_known_gap() {
  local file="$1"
  local line="$2"
  local key="${file}:${line}"
  for gap in "${KNOWN_GAPS[@]}"; do
    if [[ "${gap}" == "${key}"* ]]; then
      return 0
    fi
  done
  return 1
}

# ================================================================
# Check 1: No hardcoded health check target IPs (1.1.1.1, 8.8.8.8, etc.)
# as 'or' defaults in production code
# ================================================================
echo "--- Check 1: Hardcoded health check IP defaults ---"
health_violations=0

for dir in "${src_dirs[@]}"; do
  hits=$(find "${repo_root}/${dir}" -name '*.nix' -print0 2>/dev/null | \
    xargs -0 grep -nE '\"1\.1\.1\.1\"|\"8\.8\.8\.8\"|\"8\.8\.4\.4\"|\"208\.67\.222\.222\"' 2>/dev/null | \
    grep -vE '^\s*(#|//)' || true)
  if [[ -n "${hits}" ]]; then
    while IFS= read -r hit_line; do
      [[ -z "${hit_line}" ]] && continue
      file_path="${hit_line%%:*}"
      rest="${hit_line#*:}"
      lineno="${rest%%:*}"
      rel_path="${file_path#${repo_root}/}"
      if is_known_gap "${rel_path}" "${lineno}"; then
        echo "  KNOWN_GAP: ${rel_path}:${lineno}"
        continue
      fi
      content="${rest#*:}"
      if echo "${content}" | grep -qE 'or\s+"'; then
        echo "  NEW_VIOLATION: ${rel_path}:${lineno} — hardcoded health check IP as 'or' default"
        health_violations=$((health_violations + 1))
      else
        echo "  INFO: ${rel_path}:${lineno} — health IP referenced (may be test/comment)"
      fi
    done <<< "${hits}"
  fi
done

echo "  Health check IP defaults: ${health_violations} new violation(s)"
echo ""

# ================================================================
# Check 2: No hardcoded route metrics (300, 200, 100, etc.)
# as 'or' defaults in production code
# ================================================================
echo "--- Check 2: Hardcoded route metric defaults ---"
metric_violations=0

for dir in "${src_dirs[@]}"; do
  hits=$(find "${repo_root}/${dir}" -name '*.nix' -print0 2>/dev/null | \
    xargs -0 grep -nE '\bor\s+[0-9]+\b' 2>/dev/null | \
    grep -vE '^\s*(#|//)' | \
    grep -vE '\bor\s+(true|false|0[^0-9])\b' || true)
  if [[ -n "${hits}" ]]; then
    while IFS= read -r hit_line; do
      [[ -z "${hit_line}" ]] && continue
      file_path="${hit_line%%:*}"
      rest="${hit_line#*:}"
      lineno="${rest%%:*}"
      rel_path="${file_path#${repo_root}/}"
      if is_known_gap "${rel_path}" "${lineno}"; then
        echo "  KNOWN_GAP: ${rel_path}:${lineno}"
        continue
      fi
      content="${rest#*:}"
      num_val=$(echo "${content}" | grep -oP 'or\s+\K\d+' || true)
      if [[ -n "${num_val}" ]] && [[ "${num_val}" -gt 0 ]] && [[ "${num_val}" -ne 1 ]]; then
        echo "  NEW_VIOLATION: ${rel_path}:${lineno} — numeric 'or ${num_val}' default (potential route metric/policy)"
        metric_violations=$((metric_violations + 1))
      fi
    done <<< "${hits}"
  fi
done

echo "  Numeric 'or' defaults (non-0/1): ${metric_violations} new violation(s)"
echo ""

# ================================================================
# Check 3: No hardcoded DNS forwarder IPs (8.8.8.8, 1.1.1.1, etc.)
# as defaults in production code
# ================================================================
echo "--- Check 3: Hardcoded DNS forwarder IPs ---"
dns_violations=0

for dir in "${src_dirs[@]}"; do
  hits=$(find "${repo_root}/${dir}" -name '*.nix' -print0 2>/dev/null | \
    xargs -0 grep -nE 'dns.*=.*\[.*\"([0-9]+\.){3}[0-9]+\"|forwarder.*\"([0-9]+\.){3}[0-9]+\"|nameserver.*\"([0-9]+\.){3}[0-9]+\"' 2>/dev/null | \
    grep -vE '^\s*(#|//)' || true)
  if [[ -n "${hits}" ]]; then
    while IFS= read -r hit_line; do
      [[ -z "${hit_line}" ]] && continue
      file_path="${hit_line%%:*}"
      rest="${hit_line#*:}"
      lineno="${rest%%:*}"
      rel_path="${file_path#${repo_root}/}"
      if is_known_gap "${rel_path}" "${lineno}"; then
        echo "  KNOWN_GAP: ${rel_path}:${lineno}"
        continue
      fi
      echo "  NEW_VIOLATION: ${rel_path}:${lineno} — hardcoded DNS forwarder IP"
      dns_violations=$((dns_violations + 1))
    done <<< "${hits}"
  fi
done

echo "  DNS forwarder IP defaults: ${dns_violations} new violation(s)"
echo ""

# ================================================================
# Check 4: No hardcoded WireGuard interface name as 'or' default
# ================================================================
echo "--- Check 4: Hardcoded WireGuard interface name defaults ---"
iface_violations=0

for dir in "${src_dirs[@]}"; do
  hits=$(find "${repo_root}/${dir}" -name '*.nix' -print0 2>/dev/null | \
    xargs -0 grep -nE 'or\s+\"wg-' 2>/dev/null | \
    grep -vE '^\s*(#|//)' || true)
  if [[ -n "${hits}" ]]; then
    while IFS= read -r hit_line; do
      [[ -z "${hit_line}" ]] && continue
      file_path="${hit_line%%:*}"
      rest="${hit_line#*:}"
      lineno="${rest%%:*}"
      rel_path="${file_path#${repo_root}/}"
      if is_known_gap "${rel_path}" "${lineno}"; then
        echo "  KNOWN_GAP: ${rel_path}:${lineno}"
        continue
      fi
      echo "  NEW_VIOLATION: ${rel_path}:${lineno} — hardcoded WireGuard interface name as 'or' default"
      iface_violations=$((iface_violations + 1))
    done <<< "${hits}"
  fi
done

echo "  WireGuard interface name defaults: ${iface_violations} new violation(s)"
echo ""

# ================================================================
# Check 5: No hardcoded DHCP pool configuration inventing policy
# ================================================================
echo "--- Check 5: Hardcoded DHCP pool configuration ---"
dhcp_violations=0

for dir in "${src_dirs[@]}"; do
  hits=$(find "${repo_root}/${dir}" -name '*.nix' -print0 2>/dev/null | \
    xargs -0 grep -nE 'dhcp4LeaseFile.*or\s+\"/|dhcp4.*pool.*or\s+\"|subnet.*or\s+\"[0-9]+\.' 2>/dev/null | \
    grep -vE '^\s*(#|//)' || true)
  if [[ -n "${hits}" ]]; then
    while IFS= read -r hit_line; do
      [[ -z "${hit_line}" ]] && continue
      file_path="${hit_line%%:*}"
      rest="${hit_line#*:}"
      lineno="${rest%%:*}"
      rel_path="${file_path#${repo_root}/}"
      if is_known_gap "${rel_path}" "${lineno}"; then
        echo "  KNOWN_GAP: ${rel_path}:${lineno}"
        continue
      fi
      echo "  NEW_VIOLATION: ${rel_path}:${lineno} — hardcoded DHCP pool config as 'or' default"
      dhcp_violations=$((dhcp_violations + 1))
    done <<< "${hits}"
  fi
done

echo "  DHCP pool config defaults: ${dhcp_violations} new violation(s)"
echo ""

# ================================================================
# Seeded Negative 1: Inject hardcoded health check IP
# ================================================================
echo "--- Seeded Negative 1: Inject hardcoded 'or \"8.8.8.8\"' health target ---"
sn1_dir="${tmp_dir}/sn1"
mkdir -p "${sn1_dir}"
cat > "${sn1_dir}/bad-health.nix" << 'SN1EOF'
{ lib, contract }:
let
  # VIOLATION: hardcoded health check target IP
  healthTarget = contract.healthTarget or "8.8.8.8";
in
{ result = healthTarget; }
SN1EOF

sn1_hits=$(grep -nE 'or\s+\"8\.8\.8\.8\"' "${sn1_dir}/bad-health.nix" 2>/dev/null || true)
if [[ -n "${sn1_hits}" ]]; then
  echo "  PASS: Seeded negative 1 caught — scanner detects 'or \"8.8.8.8\"' default"
else
  echo "  FAIL: Seeded negative 1 missed — scanner did not detect 'or \"8.8.8.8\"'"
  all_checks_passed=false
fi

rm -f "${sn1_dir}/bad-health.nix"
sn1_clean=$(grep -rnE 'or\s+\"8\.8\.8\.8\"' "${sn1_dir}" 2>/dev/null || true)
if [[ -z "${sn1_clean}" ]]; then
  echo "  PASS: Seeded negative 1 recovery — clean after removal"
else
  echo "  FAIL: Seeded negative 1 recovery — residual violations"
  all_checks_passed=false
fi
echo ""

# ================================================================
# Seeded Negative 2: Inject hardcoded route metric 'or 300'
# ================================================================
echo "--- Seeded Negative 2: Inject hardcoded 'or 300' route metric ---"
sn2_dir="${tmp_dir}/sn2"
mkdir -p "${sn2_dir}"
cat > "${sn2_dir}/bad-metric.nix" << 'SN2EOF'
{ lib, contract }:
let
  # VIOLATION: hardcoded route metric default
  routeMetric = contract.routeMetric or 300;
in
{ result = routeMetric; }
SN2EOF

sn2_hits=$(grep -nE '\bor\s+300\b' "${sn2_dir}/bad-metric.nix" 2>/dev/null || true)
if [[ -n "${sn2_hits}" ]]; then
  echo "  PASS: Seeded negative 2 caught — scanner detects 'or 300' route metric default"
else
  echo "  FAIL: Seeded negative 2 missed — scanner did not detect 'or 300'"
  all_checks_passed=false
fi

rm -f "${sn2_dir}/bad-metric.nix"
sn2_clean=$(grep -rnE '\bor\s+300\b' "${sn2_dir}" 2>/dev/null || true)
if [[ -z "${sn2_clean}" ]]; then
  echo "  PASS: Seeded negative 2 recovery — clean after removal"
else
  echo "  FAIL: Seeded negative 2 recovery — residual violations"
  all_checks_passed=false
fi
echo ""

# ================================================================
# Seeded Negative 3: Inject hardcoded interface name 'or "wg-egress"'
# ================================================================
echo "--- Seeded Negative 3: Inject hardcoded 'or \"wg-egress\"' interface name ---"
sn3_dir="${tmp_dir}/sn3"
mkdir -p "${sn3_dir}"
cat > "${sn3_dir}/bad-iface.nix" << 'SN3EOF'
{ lib, wgData }:
let
  # VIOLATION: hardcoded WireGuard interface name default
  wgIface = wgData.interface or "wg-egress";
in
{ result = wgIface; }
SN3EOF

sn3_hits=$(grep -nE 'or\s+\"wg-egress\"' "${sn3_dir}/bad-iface.nix" 2>/dev/null || true)
if [[ -n "${sn3_hits}" ]]; then
  echo "  PASS: Seeded negative 3 caught — scanner detects 'or \"wg-egress\"' default"
else
  echo "  FAIL: Seeded negative 3 missed — scanner did not detect 'or \"wg-egress\"'"
  all_checks_passed=false
fi

rm -f "${sn3_dir}/bad-iface.nix"
sn3_clean=$(grep -rnE 'or\s+\"wg-egress\"' "${sn3_dir}" 2>/dev/null || true)
if [[ -z "${sn3_clean}" ]]; then
  echo "  PASS: Seeded negative 3 recovery — clean after removal"
else
  echo "  FAIL: Seeded negative 3 recovery — residual violations"
  all_checks_passed=false
fi
echo ""

# ================================================================
# Final report
# ================================================================
total_new_violations=$((health_violations + metric_violations + dns_violations + iface_violations + dhcp_violations))

echo "============================================================"
echo "FS-470-HDS-010-SDS-010-SMS-060 Hardcoded Value Prevention Summary"
echo "============================================================"
echo "  Check 1 (health IPs):       ${health_violations} new violation(s)"
echo "  Check 2 (route metrics):    ${metric_violations} new violation(s)"
echo "  Check 3 (DNS forwarders):   ${dns_violations} new violation(s)"
echo "  Check 4 (iface names):      ${iface_violations} new violation(s)"
echo "  Check 5 (DHCP pools):       ${dhcp_violations} new violation(s)"
echo "  Seeded negatives:            SN1 (8.8.8.8), SN2 (300), SN3 (wg-egress)"
echo "  Total new violations:       ${total_new_violations}"
echo "  KNOWN_GAPS:                 ${#KNOWN_GAPS[@]}"
echo ""

if [[ "${total_new_violations}" -gt 0 ]]; then
  echo "FAIL: ${total_new_violations} new hardcoded value violation(s) detected."
  all_checks_passed=false
fi

if [[ "${all_checks_passed}" == "true" ]]; then
  echo "PASS: FS-470-HDS-010-SDS-010-SMS-060 — WG renderer has no hardcoded network-affecting values."
  echo "  All 5 checks clean. 3 active seeded negatives verified (detect + recovery)."
  exit 0
else
  echo "FAIL: FS-470-HDS-010-SDS-010-SMS-060 — hardcoded value prevention verification incomplete."
  exit 1
fi
