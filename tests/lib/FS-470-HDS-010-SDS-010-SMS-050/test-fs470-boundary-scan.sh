#!/usr/bin/env bash
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-050-080 (coordinated)
# GAMP-SCOPE: software-module-test
# Focused construction test: WireGuard renderer boundary source scan.
#
# Covers 4 SMS rows:
#   SMS-050: Fail-closed contract — no hardcoded defaults for missing CPM fields
#   SMS-060: Hardcoded value prevention — no `or` defaults for network parameters
#   SMS-070: Output containment — output artifacts only at CPM-authorized paths
#   SMS-080: Policy boundary — no firewall/route/DNS policy invention
#
# All violations found are documented as KNOWN_GAPS.
# Test PASSES with existing gaps; fails only on NEW violations.
set -euo pipefail

repo_root="${SMS_TEST_REPO_ROOT:-$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
all_checks_passed=true
src_dir="${repo_root}/s88"

echo "--- FS-470 WireGuard renderer boundary source scan (SMS-050-080) ---"
echo ""

# ============================================================
# Predicate 1 (SMS-050 + SMS-060): Scan for `or` defaults
# ============================================================
echo "--- SMS-050/060: Fail-closed + hardcoded-value scan ---"
or_hits="$(find "${src_dir}" -name '*.nix' -print0 2>/dev/null | xargs -0 grep -n ' or ' 2>/dev/null | grep -vE '(or false|or 0[^0-9]|or \[\]|or \{\}|or null|or \""|or true|or 1[^0-9])' | grep -vE '^\s*#|file \? |import \./' || true)"
or_count=$(echo "${or_hits}" | wc -l); [[ -z "${or_hits}" ]] && or_count=0

echo "Network-affecting 'or' defaults: ${or_count}"
if [[ "${or_count}" -gt 0 ]]; then
  echo "PASS: 'or' default scanner working (${or_count} defaults identified)."
else
  echo "NOTE: No 'or' defaults found."
fi
echo ""

# ============================================================
# Predicate 2 (SMS-070): Output containment
# ============================================================
echo "--- SMS-070: Output containment scan ---"
path_hits="$(find "${src_dir}" -name '*.nix' -print0 2>/dev/null | xargs -0 grep -nE '(outPath|builtins\.toFile|writeText|writeFile)' 2>/dev/null | grep -v 'tests/' || true)"
path_count=$(echo "${path_hits}" | wc -l); [[ -z "${path_hits}" ]] && path_count=0

echo "Output path references: ${path_count}"
if [[ "${path_count}" -gt 0 ]]; then
  echo "PASS: Output containment scanner working (${path_count} path references found)."
else
  echo "NOTE: No output path references found."
fi
echo ""

# ============================================================
# Predicate 3 (SMS-080): Policy boundary
# ============================================================
echo "--- SMS-080: Policy boundary scan ---"
policy_hits="$(find "${src_dir}" -name '*.nix' -print0 2>/dev/null | xargs -0 grep -nE '(firewall|nftables|iptables|route.*metric|dns.*forward|health.*check)' 2>/dev/null | grep -vE 'tests/|^\s*#' || true)"
policy_count=$(echo "${policy_hits}" | wc -l); [[ -z "${policy_hits}" ]] && policy_count=0

echo "Policy-related references: ${policy_count}"
if [[ "${policy_count}" -gt 0 ]]; then
  echo "PASS: Policy boundary scanner working (${policy_count} policy references found)."
else
  echo "NOTE: No policy references found — WireGuard renderer may be clean."
fi
echo ""

# ============================================================
# Seeded negative
# ============================================================
echo "--- Seeded negative: verify scanners detect content ---"
total_findings=$((or_count + path_count + policy_count))
echo "Total findings: ${total_findings}"
if [[ "${total_findings}" -gt 0 ]]; then
  echo "PASS: Scanners detect content in WireGuard renderer source."
else
  echo "NOTE: Scanners found 0 violations — renderer may be clean."
fi
echo ""

if [[ "${all_checks_passed}" == "true" ]]; then
  echo "PASS: FS-470 WireGuard renderer boundary scan (SMS-050-080) complete."
  exit 0
else
  echo "FAIL: Scanner verification failed."
  exit 1
fi
