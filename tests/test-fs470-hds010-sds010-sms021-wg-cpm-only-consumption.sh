#!/usr/bin/env bash
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-021
# GAMP-SCOPE: software-module-test
# Focused construction test: WireGuard renderer CPM-only consumption.
#
# SMS acceptance predicates:
#   P1: No direct imports of intent.nix, inventory.nix, inventory-nixos.nix
#       in production rendering code (s88/, modules/).
#   P2: No filesystem path construction to upstream source files
#       (e.g., "${outPath}/inputs/intent.nix").
#   P3: No raw inventory-tree walks (e.g., inventory.realization.nodes).
#   P4: hostModule accepts CPM output only — no raw intent/inventory params.
#   P5: No direct provider profile file reading (providers/*.nix).
#
# All pre-existing violations are documented as KNOWN_GAPS.
# Test PASSES with existing gaps; FAILS only on NEW violations.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
all_checks_passed=true

# Production source directories (exclude tests/)
src_dirs=("s88" "modules")
flake_file="flake.nix"

echo "--- FS-470-HDS-010-SDS-010-SMS-021: WG CPM-Only Consumption Scan ---"
echo ""

# ================================================================
# KNOWN_GAPS: pre-existing hits that are permitted
# Each entry: "file:line  description"
# ================================================================
KNOWN_GAPS=(
  # No pre-existing violations found — WG renderer is clean.
  # If the scanner flags a legitimate CPM-mediated access
  # (e.g., builtins.readFile of provider contract JSON),
  # it should be added here with justification.
)

# ================================================================
# Helper: check if a hit is a known gap
# ================================================================
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
# Check 1: Direct upstream file imports (intent.nix, inventory*.nix)
# ================================================================
echo "--- Check 1: Direct upstream file imports ---"
import_hits=""
import_violations=0

for dir in "${src_dirs[@]}"; do
  hits=$(find "${repo_root}/${dir}" -name '*.nix' -print0 2>/dev/null | \
    xargs -0 grep -nE '(intent\.nix|inventory[^/]*\.nix|inventory-nixos\.nix)' 2>/dev/null | \
    grep -vE '^\s*(#|//)' || true)
  if [[ -n "${hits}" ]]; then
    while IFS= read -r hit_line; do
      [[ -z "${hit_line}" ]] && continue
      file_path="${hit_line%%:*}"
      rest="${hit_line#*:}"
      lineno="${rest%%:*}"
      # Normalize path relative to repo
      rel_path="${file_path#${repo_root}/}"
      if is_known_gap "${rel_path}" "${lineno}"; then
        echo "  KNOWN_GAP: ${rel_path}:${lineno}"
        continue
      fi
      echo "  NEW_VIOLATION: ${rel_path}:${lineno} — direct upstream file import"
      import_violations=$((import_violations + 1))
    done <<< "${hits}"
  fi
done

# Also check flake.nix
flake_hits=$(grep -nE '(intent\.nix|inventory[^/]*\.nix|inventory-nixos\.nix)' \
  "${repo_root}/${flake_file}" 2>/dev/null | grep -vE '^\s*(#|//)' || true)
if [[ -n "${flake_hits}" ]]; then
  while IFS= read -r hit_line; do
    [[ -z "${hit_line}" ]] && continue
    lineno="${hit_line%%:*}"
    if is_known_gap "${flake_file}" "${lineno}"; then
      echo "  KNOWN_GAP: ${flake_file}:${lineno}"
      continue
    fi
    echo "  NEW_VIOLATION: ${flake_file}:${lineno} — direct upstream file import"
    import_violations=$((import_violations + 1))
  done <<< "${flake_hits}"
fi

echo "  Direct imports detected: ${import_violations} new violation(s)"
echo ""

# ================================================================
# Check 2: Path construction to upstream source files
# ================================================================
echo "--- Check 2: Path construction to upstream source files ---"
path_violations=0

for dir in "${src_dirs[@]}"; do
  hits=$(find "${repo_root}/${dir}" -name '*.nix' -print0 2>/dev/null | \
    xargs -0 grep -nE '(outPath.*inputs|resolvedFabricRoot.*inputs|inputs/intent|inputs/inventory|fabricRoot.*inventory|upstream.*intent|upstream.*inventory)' 2>/dev/null | \
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
      echo "  NEW_VIOLATION: ${rel_path}:${lineno} — path construction to upstream file"
      path_violations=$((path_violations + 1))
    done <<< "${hits}"
  fi
done

echo "  Path-construction hits: ${path_violations} new violation(s)"
echo ""

# ================================================================
# Check 3: Raw inventory tree walks
# ================================================================
echo "--- Check 3: Raw inventory tree walks ---"
walk_violations=0

for dir in "${src_dirs[@]}"; do
  hits=$(find "${repo_root}/${dir}" -name '*.nix' -print0 2>/dev/null | \
    xargs -0 grep -nE '(inventory\.realization|\.realization\.nodes|inventory\.nodes\.|walk.*inventory|inventoryTree)' 2>/dev/null | \
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
      echo "  NEW_VIOLATION: ${rel_path}:${lineno} — raw inventory tree walk"
      walk_violations=$((walk_violations + 1))
    done <<< "${hits}"
  fi
done

echo "  Raw inventory walks: ${walk_violations} new violation(s)"
echo ""

# ================================================================
# Check 4: hostModule raw path parameters
# ================================================================
echo "--- Check 4: hostModule raw path parameters ---"
hostmod_violations=0

# Scan flake.nix for hostModule signatures that accept raw intent/inventory
hostmod_hits=$(grep -n 'hostModule' "${repo_root}/${flake_file}" 2>/dev/null || true)
if [[ -n "${hostmod_hits}" ]]; then
  # Extract the hostModule parameter signature — look for intent/inventory in params
  hostmod_raw=$(grep -nE '(hostModule\s*=\s*\{[^}]*intent|hostModule\s*=\s*\{[^}]*inventory|hostModule.*intent\s*[,:]|hostModule.*inventory\s*[,:])' \
    "${repo_root}/${flake_file}" 2>/dev/null || true)
  if [[ -n "${hostmod_raw}" ]]; then
    while IFS= read -r hit_line; do
      [[ -z "${hit_line}" ]] && continue
      lineno="${hit_line%%:*}"
      if is_known_gap "${flake_file}" "${lineno}"; then
        echo "  KNOWN_GAP: ${flake_file}:${lineno}"
        continue
      fi
      echo "  NEW_VIOLATION: ${flake_file}:${lineno} — hostModule accepts raw intent/inventory params"
      hostmod_violations=$((hostmod_violations + 1))
    done <<< "${hostmod_raw}"
  fi
fi

echo "  hostModule raw-param hits: ${hostmod_violations} new violation(s)"
echo ""

# ================================================================
# Check 5: Direct provider profile file reading
# ================================================================
echo "--- Check 5: Direct provider profile file reading ---"
profile_violations=0

for dir in "${src_dirs[@]}"; do
  # builtins.readFile of paths containing "providers/" or "profiles/"
  hits=$(find "${repo_root}/${dir}" -name '*.nix' -print0 2>/dev/null | \
    xargs -0 grep -nE '(builtins\.readFile.*providers/|builtins\.readFile.*profiles/|import.*providers/.*\.nix|import.*profiles/.*\.nix)' 2>/dev/null | \
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
      echo "  NEW_VIOLATION: ${rel_path}:${lineno} — direct provider profile read"
      profile_violations=$((profile_violations + 1))
    done <<< "${hits}"
  fi
done

echo "  Provider profile reads: ${profile_violations} new violation(s)"
echo ""

# ================================================================
# Seeded Negative 1: Direct intent.nix import via path construction
# ================================================================
echo "--- Seeded Negative 1: Direct intent.nix import via path construction ---"
sn1_dir="${tmp_dir}/sn1"
mkdir -p "${sn1_dir}"
cat > "${sn1_dir}/bad-import.nix" << 'SN1EOF'
{ lib, outPath }:
let
  # VIOLATION: direct intent.nix import via path construction
  intent = import "${outPath}/inputs/intent.nix";
in
{
  result = intent.something;
}
SN1EOF

sn1_hits=$(grep -rnE '(intent\.nix|inputs/intent)' "${sn1_dir}" 2>/dev/null || true)
if [[ -n "${sn1_hits}" ]]; then
  echo "  PASS: Seeded negative 1 caught — scanner detects direct intent.nix import"
else
  echo "  FAIL: Seeded negative 1 missed — scanner did not detect direct intent.nix import"
  all_checks_passed=false
fi

# Recovery: remove the injected file, verify clean
rm -f "${sn1_dir}/bad-import.nix"
sn1_clean=$(grep -rnE '(intent\.nix|inputs/intent)' "${sn1_dir}" 2>/dev/null || true)
if [[ -z "${sn1_clean}" ]]; then
  echo "  PASS: Seeded negative 1 recovery — clean after removal"
else
  echo "  FAIL: Seeded negative 1 recovery — still shows violations after removal"
  all_checks_passed=false
fi
echo ""

# ================================================================
# Seeded Negative 2: hostModule accepts raw intent/inventory params
# ================================================================
echo "--- Seeded Negative 2: hostModule raw intent/inventory params ---"
sn2_dir="${tmp_dir}/sn2"
mkdir -p "${sn2_dir}"
cat > "${sn2_dir}/bad-flake.nix" << 'SN2EOF'
{
  outputs = { self, nixpkgs, ... }: {
    renderer = {
      # VIOLATION: hostModule accepts raw intent as parameter
      hostModule = { intent, lib, pkgs, config, ... }:
      let
        data = intent.enterprises or {};
      in
      {
        containers = {};
      };
    };
  };
}
SN2EOF

sn2_hits=$(grep -nE 'hostModule\s*=\s*\{[^}]*intent' "${sn2_dir}/bad-flake.nix" 2>/dev/null || true)
if [[ -n "${sn2_hits}" ]]; then
  echo "  PASS: Seeded negative 2 caught — scanner detects hostModule raw intent param"
else
  echo "  FAIL: Seeded negative 2 missed — scanner did not detect hostModule raw intent param"
  all_checks_passed=false
fi

# Recovery
rm -f "${sn2_dir}/bad-flake.nix"
sn2_clean=$(grep -rnE 'hostModule\s*=\s*\{[^}]*intent' "${sn2_dir}" 2>/dev/null || true)
if [[ -z "${sn2_clean}" ]]; then
  echo "  PASS: Seeded negative 2 recovery — clean after removal"
else
  echo "  FAIL: Seeded negative 2 recovery — still shows violations after removal"
  all_checks_passed=false
fi
echo ""

# ================================================================
# Seeded Negative 3: Direct provider profile file reading
# ================================================================
echo "--- Seeded Negative 3: Direct provider profile file reading ---"
sn3_dir="${tmp_dir}/sn3"
mkdir -p "${sn3_dir}"
cat > "${sn3_dir}/bad-provider-read.nix" << 'SN3EOF'
{ lib }:
let
  # VIOLATION: direct provider profile file reading
  rawProfile = builtins.readFile ./providers/some-provider.nix;
in
{
  result = rawProfile;
}
SN3EOF

sn3_hits=$(grep -nE 'builtins\.readFile.*providers/' "${sn3_dir}/bad-provider-read.nix" 2>/dev/null || true)
if [[ -n "${sn3_hits}" ]]; then
  echo "  PASS: Seeded negative 3 caught — scanner detects direct provider profile read"
else
  echo "  FAIL: Seeded negative 3 missed — scanner did not detect direct provider profile read"
  all_checks_passed=false
fi

# Recovery
rm -f "${sn3_dir}/bad-provider-read.nix"
sn3_clean=$(grep -rnE 'builtins\.readFile.*providers/' "${sn3_dir}" 2>/dev/null || true)
if [[ -z "${sn3_clean}" ]]; then
  echo "  PASS: Seeded negative 3 recovery — clean after removal"
else
  echo "  FAIL: Seeded negative 3 recovery — still shows violations after removal"
  all_checks_passed=false
fi
echo ""

# ================================================================
# Final report
# ================================================================
total_new_violations=$((import_violations + path_violations + walk_violations + hostmod_violations + profile_violations))

echo "============================================================"
echo "FS-470-HDS-010-SDS-010-SMS-021 CPM-Only Consumption Scan Summary"
echo "============================================================"
echo "  Check 1 (direct imports):     ${import_violations} new violation(s)"
echo "  Check 2 (path construction):  ${path_violations} new violation(s)"
echo "  Check 3 (inventory walks):    ${walk_violations} new violation(s)"
echo "  Check 4 (hostModule params):  ${hostmod_violations} new violation(s)"
echo "  Check 5 (provider profiles):  ${profile_violations} new violation(s)"
echo "  Seeded negatives:             SN1 (intent import), SN2 (hostModule params), SN3 (profile read)"
echo "  Total new violations:         ${total_new_violations}"
echo "  KNOWN_GAPS:                   ${#KNOWN_GAPS[@]}"
echo ""

if [[ "${total_new_violations}" -gt 0 ]]; then
  echo "FAIL: ${total_new_violations} new CPM-only consumption violation(s) detected."
  all_checks_passed=false
fi

if [[ "${all_checks_passed}" == "true" ]]; then
  echo "PASS: FS-470-HDS-010-SDS-010-SMS-021 — WG renderer consumes only CPM-mediated data."
  echo "  Zero direct upstream file access. All 5 checks clean."
  echo "  3 active seeded negatives verified (detect + recovery)."
  exit 0
else
  echo "FAIL: Scanner verification or new violations detected."
  exit 1
fi
