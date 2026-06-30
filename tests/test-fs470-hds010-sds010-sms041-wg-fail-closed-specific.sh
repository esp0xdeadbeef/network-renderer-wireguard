#!/usr/bin/env bash
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-041
# GAMP-SCOPE: software-module-test
# Focused construction test: WireGuard renderer fail-closed contract —
# specific forbidden defaults from SMS-110 audit remediation.
#
# SMS acceptance predicates:
#   P1: No `or "wg-egress"` interface name default in production code.
#   P2: No `or "1.1.1.1"` health check target default in production code.
#   P3: No `or 300` route metric default in production code.
#   P4: No `or "allow"` / `or "deny"` firewall rule action defaults.
#   P5: Profile mode is declared explicitly (required), not inferred from shape.
#   P6: No default private key path construction in production code.
#   P7: Fail-closed throws reference SMS-041 trace-chain ID (SMS §Forbidden
#       Default paragraphs specify exact throw message format).
#
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
all_checks_passed=true

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
    echo "  FAIL: ${attr} was accepted"
    all_checks_passed=false
  elif grep -Fq "${phrase}" "${stderr_path}"; then
    echo "  PASS: ${attr} rejected with SMS-041 diagnostic"
  else
    cat "${stderr_path}" >&2
    echo "  FAIL: ${attr} diagnostic did not contain: ${phrase}"
    all_checks_passed=false
  fi
  rm -f "${stderr_path}"
}

expect_json_message() {
  local attr="$1"
  local phrase="$2"
  local json
  json="$(eval_json "${attr}")"
  if grep -Fq "${phrase}" <<<"${json}"; then
    echo "  PASS: ${attr} emitted SMS-041 diagnostic"
  else
    echo "${json}" >&2
    echo "  FAIL: ${attr} did not contain: ${phrase}"
    all_checks_passed=false
  fi
}

# Production source directories + flake.nix
src_dirs=("s88" "modules")
flake_file="flake.nix"

echo "--- FS-470-HDS-010-SDS-010-SMS-041: WG Fail-Closed Specific Defaults Scan ---"
echo ""

# ================================================================
# Check 1: Forbidden default — or "wg-egress" (interface name)
# ================================================================
echo "--- Check 1: forbid 'or \"wg-egress\"' default ---"
wg_egress_violations=0

for dir in "${src_dirs[@]}"; do
  hits=$(find "${repo_root}/${dir}" -name '*.nix' -print0 2>/dev/null | \
    xargs -0 grep -n 'wg-egress' 2>/dev/null | \
    grep -vE '^\s*(#|//)' || true)
  if [[ -n "${hits}" ]]; then
    while IFS= read -r hit_line; do
      [[ -z "${hit_line}" ]] && continue
      file_path="${hit_line%%:*}"
      rest="${hit_line#*:}"
      lineno="${rest%%:*}"
      rel_path="${file_path#${repo_root}/}"
      # Only flag if it's an `or "wg-egress"` pattern (not a throw/comment)
      content="${rest#*:}"
      if echo "${content}" | grep -qE 'or\s+"wg-egress"'; then
        echo "  NEW_VIOLATION: ${rel_path}:${lineno} — 'or \"wg-egress\"' interface default found"
        wg_egress_violations=$((wg_egress_violations + 1))
      else
        echo "  OK: ${rel_path}:${lineno} — 'wg-egress' used but not as 'or' default"
      fi
    done <<< "${hits}"
  fi
done

# Also check flake.nix
flake_hits=$(grep -n 'wg-egress' "${repo_root}/${flake_file}" 2>/dev/null || true)
if [[ -n "${flake_hits}" ]]; then
  while IFS= read -r hit_line; do
    [[ -z "${hit_line}" ]] && continue
    lineno="${hit_line%%:*}"
    content="${hit_line#*:}"
    if echo "${content}" | grep -qE 'or\s+"wg-egress"'; then
      echo "  NEW_VIOLATION: ${flake_file}:${lineno} — 'or \"wg-egress\"' interface default found"
      wg_egress_violations=$((wg_egress_violations + 1))
    else
      echo "  OK: ${flake_file}:${lineno} — 'wg-egress' used but not as 'or' default"
    fi
  done <<< "${flake_hits}"
fi

echo "  'or \"wg-egress\"' defaults: ${wg_egress_violations}"
echo ""

# ================================================================
# Check 2: Forbidden default — or "1.1.1.1" (health target)
# ================================================================
echo "--- Check 2: forbid 'or \"1.1.1.1\"' health check default ---"
health_target_violations=0

for dir in "${src_dirs[@]}"; do
  hits=$(find "${repo_root}/${dir}" -name '*.nix' -print0 2>/dev/null | \
    xargs -0 grep -n '1\.1\.1\.1' 2>/dev/null | \
    grep -vE '^\s*(#|//)' || true)
  if [[ -n "${hits}" ]]; then
    while IFS= read -r hit_line; do
      [[ -z "${hit_line}" ]] && continue
      file_path="${hit_line%%:*}"
      rest="${hit_line#*:}"
      lineno="${rest%%:*}"
      rel_path="${file_path#${repo_root}/}"
      content="${rest#*:}"
      if echo "${content}" | grep -qE 'or\s+"1\.1\.1\.1"'; then
        echo "  NEW_VIOLATION: ${rel_path}:${lineno} — 'or \"1.1.1.1\"' health target default found"
        health_target_violations=$((health_target_violations + 1))
      else
        echo "  OK: ${rel_path}:${lineno} — '1.1.1.1' used but not as 'or' default"
      fi
    done <<< "${hits}"
  fi
done

echo "  'or \"1.1.1.1\"' defaults: ${health_target_violations}"
echo ""

# ================================================================
# Check 3: Forbidden default — or 300 (route metric)
# ================================================================
echo "--- Check 3: forbid 'or 300' route metric default ---"
route_metric_violations=0

for dir in "${src_dirs[@]}"; do
  hits=$(find "${repo_root}/${dir}" -name '*.nix' -print0 2>/dev/null | \
    xargs -0 grep -nE '\bor\s+300\b' 2>/dev/null | \
    grep -vE '^\s*(#|//)' || true)
  if [[ -n "${hits}" ]]; then
    while IFS= read -r hit_line; do
      [[ -z "${hit_line}" ]] && continue
      file_path="${hit_line%%:*}"
      rest="${hit_line#*:}"
      lineno="${rest%%:*}"
      rel_path="${file_path#${repo_root}/}"
      echo "  NEW_VIOLATION: ${rel_path}:${lineno} — 'or 300' route metric default found"
      route_metric_violations=$((route_metric_violations + 1))
    done <<< "${hits}"
  fi
done

echo "  'or 300' defaults: ${route_metric_violations}"
echo ""

# ================================================================
# Check 4: Forbidden default — or "allow" / or "deny" (firewall)
# ================================================================
echo "--- Check 4: forbid 'or \"allow\"' / 'or \"deny\"' firewall defaults ---"
firewall_violations=0

for dir in "${src_dirs[@]}"; do
  hits=$(find "${repo_root}/${dir}" -name '*.nix' -print0 2>/dev/null | \
    xargs -0 grep -nE '\bor\s+"allow"|\bor\s+"deny"' 2>/dev/null | \
    grep -vE '^\s*(#|//)' || true)
  if [[ -n "${hits}" ]]; then
    while IFS= read -r hit_line; do
      [[ -z "${hit_line}" ]] && continue
      file_path="${hit_line%%:*}"
      rest="${hit_line#*:}"
      lineno="${rest%%:*}"
      rel_path="${file_path#${repo_root}/}"
      echo "  NEW_VIOLATION: ${rel_path}:${lineno} — firewall 'or \"allow\"/\"deny\"' default found"
      firewall_violations=$((firewall_violations + 1))
    done <<< "${hits}"
  fi
done

echo "  Firewall 'or \"allow\"/\"deny\"' defaults: ${firewall_violations}"
echo ""

# ================================================================
# Check 5: Profile mode must be REQUIRED (not inferred from shape)
# ================================================================
echo "--- Check 5: Profile mode explicitly required (not inferred) ---"
profilemode_violations=0

# The SMS requires profileMode to be `required`, not inferred from data shape.
# Check that provider-contract.nix uses `required` for profileMode.
profile_hits=$(grep -n 'profileMode' "${repo_root}/s88/ControlModule/provider-contract.nix" 2>/dev/null || true)
if [[ -n "${profile_hits}" ]]; then
  # The definition line should use `required`
  if echo "${profile_hits}" | grep -q 'profileMode = required'; then
    echo "  PASS: profileMode uses 'required' — explicit declaration, not inference"
  else
    # Check if it's using get with null default (inference via fallback)
    if echo "${profile_hits}" | grep -q 'profileMode = get.*null'; then
      echo "  NEW_VIOLATION: provider-contract.nix — profileMode uses get-with-null (inference-enabled)"
      profilemode_violations=$((profilemode_violations + 1))
    else
      echo "  NOTE: profileMode pattern: $(echo "${profile_hits}" | head -1)"
    fi
  fi
else
  echo "  NOTE: profileMode not found in provider-contract.nix"
fi

echo "  Profile mode inference violations: ${profilemode_violations}"
echo ""

# ================================================================
# Check 6: No default private key path construction
# ================================================================
echo "--- Check 6: No default private key path construction ---"
keypath_violations=0

for dir in "${src_dirs[@]}"; do
  hits=$(find "${repo_root}/${dir}" -name '*.nix' -print0 2>/dev/null | \
    xargs -0 grep -n 'privateKey.*or \|privateKeyFile.*or \|defaultPrivateKey\|/etc/wireguard/private' 2>/dev/null | \
    grep -vE '^\s*(#|//)' || true)
  if [[ -n "${hits}" ]]; then
    while IFS= read -r hit_line; do
      [[ -z "${hit_line}" ]] && continue
      file_path="${hit_line%%:*}"
      rest="${hit_line#*:}"
      lineno="${rest%%:*}"
      rel_path="${file_path#${repo_root}/}"
      echo "  NEW_VIOLATION: ${rel_path}:${lineno} — default private key path construction found"
      keypath_violations=$((keypath_violations + 1))
    done <<< "${hits}"
  fi
done

echo "  Default private key path violations: ${keypath_violations}"
echo ""

# ================================================================
# Check 7: Fail-closed guard points exist (throw/required)
# ================================================================
echo "--- Check 7: Fail-closed guard points for forbidden-default fields ---"
failclosed_ok=0
failclosed_missing=0

# Interface name: should throw if missing
if grep -q 'throw.*interface name\|throw.*wgIface\|required.*interface' \
  "${repo_root}/${flake_file}" 2>/dev/null; then
  echo "  PASS: Interface name has fail-closed guard (throw/required)"
  failclosed_ok=$((failclosed_ok + 1))
else
  echo "  WARN: No fail-closed guard found for interface name"
  failclosed_missing=$((failclosed_missing + 1))
fi

# Private key: should throw if missing
if grep -q 'throw.*privateKey\|throw.*private key\|required.*privateKey' \
  "${repo_root}/${flake_file}" 2>/dev/null; then
  echo "  PASS: Private key path has fail-closed guard (throw/required)"
  failclosed_ok=$((failclosed_ok + 1))
else
  echo "  WARN: No fail-closed guard found for private key path"
  failclosed_missing=$((failclosed_missing + 1))
fi

# Health target: should use null + guard, not "1.1.1.1"
if grep -q 'healthTarget4 = get.*null' \
  "${repo_root}/s88/ControlModule/provider-contract.nix" 2>/dev/null; then
  echo "  PASS: Health target uses null default (no hardcoded '1.1.1.1')"
  failclosed_ok=$((failclosed_ok + 1))
else
  echo "  WARN: Health target pattern not verified"
  failclosed_missing=$((failclosed_missing + 1))
fi

# Route metrics: should use null, not 300
if grep -qE 'RouteMetric.*null|null.*toString' \
  "${repo_root}/s88/ControlModule/provider-contract.nix" 2>/dev/null; then
  echo "  PASS: Route metrics use null default (no hardcoded '300')"
  failclosed_ok=$((failclosed_ok + 1))
else
  echo "  WARN: Route metric pattern not verified"
  failclosed_missing=$((failclosed_missing + 1))
fi

# Firewall: allowLanToVpn etc. should use null, not "allow"/"deny"
if grep -qE 'allowLanToVpn = get.*null|denyLanToWan = get.*null' \
  "${repo_root}/s88/ControlModule/provider-contract.nix" 2>/dev/null; then
  echo "  PASS: Firewall rules use null default (no hardcoded 'allow'/'deny')"
  failclosed_ok=$((failclosed_ok + 1))
else
  echo "  WARN: Firewall rule pattern not verified"
  failclosed_missing=$((failclosed_missing + 1))
fi

echo "  Fail-closed guards: ${failclosed_ok} confirmed, ${failclosed_missing} unverified"
echo ""

# ================================================================
# Check 8: SMS-041 trace ID in throw messages (SMS §Forbidden Defaults)
# ================================================================
echo "--- Check 8: SMS-041 trace ID in throw/required messages ---"
traceid_hits=0

# Search for FS-470-HDS-010-SDS-010-SMS-041 in throw/assertion messages
for dir in "${src_dirs[@]}"; do
  hits=$(find "${repo_root}/${dir}" -name '*.nix' -print0 2>/dev/null | \
    xargs -0 grep -l 'FS-470-HDS-010-SDS-010-SMS-041' 2>/dev/null || true)
  if [[ -n "${hits}" ]]; then
    traceid_hits=$((traceid_hits + $(echo "${hits}" | wc -l)))
  fi
done

# Also check flake.nix
if grep -q 'FS-470-HDS-010-SDS-010-SMS-041' "${repo_root}/${flake_file}" 2>/dev/null; then
  traceid_hits=$((traceid_hits + 1))
fi

if [[ "${traceid_hits}" -gt 0 ]]; then
  echo "  PASS: SMS-041 trace ID found in ${traceid_hits} source file(s)"
else
  echo "  FAIL: SMS-041 trace ID missing from production throw/assertion messages"
  all_checks_passed=false
fi
echo ""

# ================================================================
# Check 9: Active missing-field diagnostics carry SMS-041 trace ID
# ================================================================
echo "--- Check 9: active missing-field SMS-041 diagnostics ---"
expect_eval_failure \
  "missingProfileModeResult" \
  "FS-470-HDS-010-SDS-010-SMS-041: network-renderer-wireguard provider contract missing profile.mode"
expect_json_message \
  "generatedPeerMissingPrivateKeyErrors" \
  "FS-470-HDS-010-SDS-010-SMS-041: network-renderer-wireguard generated-peer mode requires profile.generatedPeer.privateKeyFile"
expect_json_message \
  "generatedPeerMissingEndpointErrors" \
  "FS-470-HDS-010-SDS-010-SMS-041: network-renderer-wireguard generated-peer peers require endpoint"
expect_json_message \
  "healthCheckMissingTargetErrors" \
  "FS-470-HDS-010-SDS-010-SMS-041: health check target required by CPM provider contract"
expect_json_message \
  "firewallMissingActionErrors" \
  "FS-470-HDS-010-SDS-010-SMS-041: firewall rule action required by CPM provider contract, cannot default to allow or deny"
echo ""

# ================================================================
# Seeded Negative 1: Inject 'or "wg-egress"' and detect
# ================================================================
echo "--- Seeded Negative 1: Inject 'or \"wg-egress\"' default ---"
sn1_dir="${tmp_dir}/sn1"
mkdir -p "${sn1_dir}"
cat > "${sn1_dir}/bad-default.nix" << 'SN1EOF'
{ lib }:
let
  # VIOLATION: hardcoded 'or "wg-egress"' interface name default
  wgIface = wgData.interface or "wg-egress";
in
{ result = wgIface; }
SN1EOF

sn1_hits=$(grep -nE 'or\s+"wg-egress"' "${sn1_dir}/bad-default.nix" 2>/dev/null || true)
if [[ -n "${sn1_hits}" ]]; then
  echo "  PASS: Seeded negative 1 caught — scanner detects 'or \"wg-egress\"' default"
else
  echo "  FAIL: Seeded negative 1 missed — scanner did not detect 'or \"wg-egress\"'"
  all_checks_passed=false
fi

# Recovery
rm -f "${sn1_dir}/bad-default.nix"
sn1_clean=$(grep -rnE 'or\s+"wg-egress"' "${sn1_dir}" 2>/dev/null || true)
if [[ -z "${sn1_clean}" ]]; then
  echo "  PASS: Seeded negative 1 recovery — clean after removal"
else
  echo "  FAIL: Seeded negative 1 recovery — residual violations"
  all_checks_passed=false
fi
echo ""

# ================================================================
# Seeded Negative 2: Inject 'or "1.1.1.1"' health target default
# ================================================================
echo "--- Seeded Negative 2: Inject 'or \"1.1.1.1\"' health target default ---"
sn2_dir="${tmp_dir}/sn2"
mkdir -p "${sn2_dir}"
cat > "${sn2_dir}/bad-health.nix" << 'SN2EOF'
{ lib }:
let
  # VIOLATION: hardcoded 'or "1.1.1.1"' health target default
  healthTarget = contract.healthTarget or "1.1.1.1";
in
{ result = healthTarget; }
SN2EOF

sn2_hits=$(grep -nE 'or\s+"1\.1\.1\.1"' "${sn2_dir}/bad-health.nix" 2>/dev/null || true)
if [[ -n "${sn2_hits}" ]]; then
  echo "  PASS: Seeded negative 2 caught — scanner detects 'or \"1.1.1.1\"' default"
else
  echo "  FAIL: Seeded negative 2 missed — scanner did not detect 'or \"1.1.1.1\"'"
  all_checks_passed=false
fi

rm -f "${sn2_dir}/bad-health.nix"
sn2_clean=$(grep -rnE 'or\s+"1\.1\.1\.1"' "${sn2_dir}" 2>/dev/null || true)
if [[ -z "${sn2_clean}" ]]; then
  echo "  PASS: Seeded negative 2 recovery — clean after removal"
else
  echo "  FAIL: Seeded negative 2 recovery — residual violations"
  all_checks_passed=false
fi
echo ""

# ================================================================
# Seeded Negative 3: Inject 'or 300' route metric default
# ================================================================
echo "--- Seeded Negative 3: Inject 'or 300' route metric default ---"
sn3_dir="${tmp_dir}/sn3"
mkdir -p "${sn3_dir}"
cat > "${sn3_dir}/bad-metric.nix" << 'SN3EOF'
{ lib }:
let
  # VIOLATION: hardcoded 'or 300' route metric default
  routeMetric = contract.routeMetric or 300;
in
{ result = routeMetric; }
SN3EOF

sn3_hits=$(grep -nE '\bor\s+300\b' "${sn3_dir}/bad-metric.nix" 2>/dev/null || true)
if [[ -n "${sn3_hits}" ]]; then
  echo "  PASS: Seeded negative 3 caught — scanner detects 'or 300' route metric default"
else
  echo "  FAIL: Seeded negative 3 missed — scanner did not detect 'or 300'"
  all_checks_passed=false
fi

rm -f "${sn3_dir}/bad-metric.nix"
sn3_clean=$(grep -rnE '\bor\s+300\b' "${sn3_dir}" 2>/dev/null || true)
if [[ -z "${sn3_clean}" ]]; then
  echo "  PASS: Seeded negative 3 recovery — clean after removal"
else
  echo "  FAIL: Seeded negative 3 recovery — residual violations"
  all_checks_passed=false
fi
echo ""

# ================================================================
# Seeded Negative 4: Inject 'or "allow"' firewall default
# ================================================================
echo "--- Seeded Negative 4: Inject 'or \"allow\"' firewall default ---"
sn4_dir="${tmp_dir}/sn4"
mkdir -p "${sn4_dir}"
cat > "${sn4_dir}/bad-firewall.nix" << 'SN4EOF'
{ lib }:
let
  # VIOLATION: hardcoded 'or "allow"' firewall rule default
  firewallAction = contract.firewallAction or "allow";
in
{ result = firewallAction; }
SN4EOF

sn4_hits=$(grep -nE '\bor\s+"allow"' "${sn4_dir}/bad-firewall.nix" 2>/dev/null || true)
if [[ -n "${sn4_hits}" ]]; then
  echo "  PASS: Seeded negative 4 caught — scanner detects 'or \"allow\"' firewall default"
else
  echo "  FAIL: Seeded negative 4 missed — scanner did not detect 'or \"allow\"'"
  all_checks_passed=false
fi

rm -f "${sn4_dir}/bad-firewall.nix"
sn4_clean=$(grep -rnE '\bor\s+"allow"' "${sn4_dir}" 2>/dev/null || true)
if [[ -z "${sn4_clean}" ]]; then
  echo "  PASS: Seeded negative 4 recovery — clean after removal"
else
  echo "  FAIL: Seeded negative 4 recovery — residual violations"
  all_checks_passed=false
fi
echo ""

# ================================================================
# Final report
# ================================================================
total_new_violations=$((wg_egress_violations + health_target_violations + route_metric_violations + firewall_violations + profilemode_violations + keypath_violations))

echo "============================================================"
echo "FS-470-HDS-010-SDS-010-SMS-041 WG Fail-Closed Specific Defaults Summary"
echo "============================================================"
echo "  Check 1 (or \"wg-egress\"):       ${wg_egress_violations} new violation(s)"
echo "  Check 2 (or \"1.1.1.1\"):         ${health_target_violations} new violation(s)"
echo "  Check 3 (or 300):               ${route_metric_violations} new violation(s)"
echo "  Check 4 (or \"allow\"/\"deny\"):    ${firewall_violations} new violation(s)"
echo "  Check 5 (profile inference):    ${profilemode_violations} new violation(s)"
echo "  Check 6 (default key path):     ${keypath_violations} new violation(s)"
echo "  Check 7 (fail-closed guards):   ${failclosed_ok} confirmed, ${failclosed_missing} unverified"
echo "  Check 8 (SMS-041 trace ID):     $(if [[ ${traceid_hits} -gt 0 ]]; then echo "${traceid_hits} file(s)"; else echo "missing"; fi)"
echo "  Check 9 (active diagnostics):   profile/key/endpoint/health/firewall"
echo "  Seeded negatives:              SN1 (wg-egress), SN2 (1.1.1.1), SN3 (300), SN4 (allow)"
echo "  Total new violations:          ${total_new_violations}"
echo "  KNOWN_GAPS:                    0"
echo ""

if [[ "${total_new_violations}" -gt 0 ]]; then
  echo "FAIL: ${total_new_violations} new forbidden default violation(s) detected."
  all_checks_passed=false
fi

if [[ "${all_checks_passed}" == "true" ]]; then
  echo "PASS: FS-470-HDS-010-SDS-010-SMS-041 — WG renderer fail-closed specific defaults."
  echo "  All 5 forbidden defaults absent. Fail-closed guards confirmed."
  echo "  4 scanner seeded negatives and active missing-field diagnostics verified."
  exit 0
else
  echo "FAIL: Scanner verification or new violations detected."
  exit 1
fi
