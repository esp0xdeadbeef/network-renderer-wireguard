#!/usr/bin/env bash
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-050
# GAMP-SCOPE: software-module-test
# Focused construction test: WireGuard renderer fail-closed contract.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
failures=0

src_dirs=("s88" "modules")

record_failure() {
  local message="$1"
  echo "  FAIL: ${message}" >&2
  failures=$((failures + 1))
}

scan_forbidden() {
  local name="$1"
  local pattern="$2"
  local hits

  hits=$(find "${src_dirs[@]}" -name '*.nix' -print0 2>/dev/null | xargs -0 grep -nE "${pattern}" 2>/dev/null || true)
  if [[ -n "${hits}" ]]; then
    printf '%s\n' "${hits}" | sed 's/^/  HIT: /'
    record_failure "${name}"
  else
    echo "  PASS: ${name}"
  fi
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

echo "--- FS-470-HDS-010-SDS-010-SMS-050: WG Fail-Closed Contract Scan ---"
echo ""

echo "--- Check 1: no hardcoded firewall-mode fallback ---"
scan_forbidden "no 'or \"dedicated-gateway\"' fallback" '\bor[[:space:]]+"dedicated-gateway"'
scan_forbidden "no get default to dedicated-gateway" 'get[[:space:]]+\[[^]]*"firewall"[^]]*"mode"[^]]*\][[:space:]]+"dedicated-gateway"'
echo ""

echo "--- Check 2: no hardcoded WAN addressing fallback ---"
scan_forbidden "no 'or \"auto\"' WAN fallback" '\bor[[:space:]]+"auto"'
scan_forbidden "no get default to auto for WAN IPv4" 'get[[:space:]]+\[[^]]*"wan"[^]]*"ipv4"[^]]*"method"[^]]*\][[:space:]]+"auto"'
scan_forbidden "no get default to auto for WAN IPv6" 'get[[:space:]]+\[[^]]*"wan"[^]]*"ipv6"[^]]*"method"[^]]*\][[:space:]]+"auto"'
echo ""

echo "--- Check 3: no NAT/firewall action boolean fallback ---"
scan_forbidden "no NAT enable bool default" 'get[[:space:]]+\[[^]]*"nat"[^]]*"ipv[46]"[^]]*"enable"[^]]*\][[:space:]]+(true|false)'
scan_forbidden "no firewall allowLanToVpn bool default" 'get[[:space:]]+\[[^]]*"firewall"[^]]*"allowLanToVpn"[^]]*\][[:space:]]+(true|false)'
scan_forbidden "no firewall denyLanToWan bool default" 'get[[:space:]]+\[[^]]*"firewall"[^]]*"denyLanToWan"[^]]*\][[:space:]]+(true|false)'
scan_forbidden "no firewall denyWanToLan bool default" 'get[[:space:]]+\[[^]]*"firewall"[^]]*"denyWanToLan"[^]]*\][[:space:]]+(true|false)'
scan_forbidden "no firewall action string fallback" '\bor[[:space:]]+"(allow|deny)"'
echo ""

echo "--- Check 4: active Nix normalization keeps silent fields null ---"
if nix eval --raw --impure --expr '
let
  repoRoot = builtins.getEnv "PWD";
  flake = builtins.getFlake repoRoot;
  pkgs = import flake.inputs.nixpkgs { system = builtins.currentSystem; };
  cm = import (repoRoot + "/s88/ControlModule/provider-contract.nix") { lib = pkgs.lib; };
  contract = {
    id = "sms050-null-default-check";
    provider = {
      class = "commercial-imported";
      mode = "egress-only";
      prefixAuthority = "none";
    };
    interfaces = {
      wan = "eth0";
      lan = "lan0";
      vpn = "wg0";
    };
    profile = {
      mode = "profile-import";
      path = "/run/test/wg.conf";
      format = "wireguard";
    };
    dns.mode = "default";
    runtime.uuidFile = "/run/network-renderer-wireguard/test.uuid";
    publicIngress = [ ];
    portForwards = [ ];
    lan.ipv4.address = "10.66.0.1/24";
    nat = {
      ipv4 = {
        enable = true;
        sourceCidrs = [ "10.66.0.0/24" ];
      };
      ipv6 = {
        enable = false;
        sourceCidrs = [ ];
      };
    };
    wan = {
      ipv4 = { };
      ipv6 = { };
    };
    firewall = { };
  };
  state = cm.normalize contract;
in
  if state.firewallMode == null
     && state.allowLanToVpn == null
     && state.denyLanToWan == null
     && state.denyWanToLan == null
     && state.wanIPv4Method == null
     && state.wanIPv6Method == null
  then "ok"
  else throw "FS-470-HDS-010-SDS-010-SMS-050: silent firewall/WAN fields must remain null"
' >/dev/null; then
  echo "  PASS: silent firewall/WAN fields normalize to null"
else
  record_failure "silent firewall/WAN fields did not normalize to null"
fi
echo ""

echo "--- Seeded negatives ---"
seeded_negative "SN1 dedicated-gateway fallback" '\bor[[:space:]]+"dedicated-gateway"' "bad-firewall.nix" '{ contract }: contract.firewall.mode or "dedicated-gateway"'
seeded_negative "SN2 WAN auto fallback" '\bor[[:space:]]+"auto"' "bad-wan.nix" '{ contract }: contract.wan.ipv4.method or "auto"'
seeded_negative "SN3 firewall allow fallback" '\bor[[:space:]]+"allow"' "bad-action.nix" '{ contract }: contract.firewall.allowLanToVpn or "allow"'
seeded_negative "SN4 NAT enable bool default" 'get[[:space:]]+\[[^]]*"nat"[^]]*"ipv4"[^]]*"enable"[^]]*\][[:space:]]+false' "bad-nat.nix" 'nat44Enable = get [ "nat" "ipv4" "enable" ] false;'
echo ""

echo "============================================================"
echo "FS-470-HDS-010-SDS-010-SMS-050 Fail-Closed Contract Summary"
echo "============================================================"

if (( failures > 0 )); then
  echo "  Total violations: ${failures}"
  echo "  KNOWN_GAPS:       ${failures}"
  echo ""
  echo "FAIL: FS-470-HDS-010-SDS-010-SMS-050 — WG fail-closed contract has unresolved fallback gaps."
  exit 1
fi

echo "  Total violations: 0"
echo "  KNOWN_GAPS:       0"
echo ""
echo "PASS: FS-470-HDS-010-SDS-010-SMS-050 — WG fail-closed contract has no firewall/WAN/NAT action fallback gaps."
