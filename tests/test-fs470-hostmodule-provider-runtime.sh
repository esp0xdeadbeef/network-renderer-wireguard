#!/usr/bin/env bash
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-010
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-020
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-040
# GAMP-SCOPE: software-module-test
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

fail() {
  echo "FAIL fs470-hostmodule-provider-runtime: $*" >&2
  exit 1
}

eval_json() {
  local attr="$1"
  nix eval --json --impure --file tests/fs470-hostmodule-provider-runtime.nix "${attr}"
}

runtime="$(eval_json providerRuntime)"

for phrase in \
  '"providerRuntimeEnabled":true' \
  '"providerContractId":"fs470-remote-egress"' \
  '"dispatcherDescription":"Bring up provider tunnel wg-re-egress0 from model/provider contract"' \
  '"--bind-ro=/run/secrets/wireguard-mini-provider-private-key:/run/secrets/wireguard-mini-provider-private-key"' \
  '"hasNetdevService":false' \
  'iifname \"edge-lan0\" oifname \"wg-re-egress0\" accept comment \"wg-provider-lan-to-vpn fs470-remote-egress\"' \
  'iifname \"edge-lan0\" oifname \"uplink0\" drop comment \"wg-provider-deny-lan-to-wan fs470-remote-egress\"' \
  'ip saddr 10.147.0.0/24 oifname \"wg-re-egress0\" masquerade comment \"wg-provider-nat44 fs470-remote-egress\"' \
  'ip6 saddr fd47:147::/64 oifname \"wg-re-egress0\" masquerade comment \"wg-provider-nat66 fs470-remote-egress\"' \
  '"subnet":"10.147.0.0/24"' \
  '"pool":"10.147.0.100 - 10.147.0.180"' \
  '"data":"10.147.0.1"' \
  'interface edge-lan0' \
  'prefix fd47:147::/64' \
  'RDNSS fd47:147::1'; do
  grep -Fq "${phrase}" <<<"${runtime}" || fail "provider runtime hostModule output missing phrase: ${phrase}"
done

without_runtime="$(eval_json withoutProviderRuntime)"
for phrase in \
  '"hasDispatcher":false' \
  '"hasProviderRuntimeOption":false' \
  '"hasNetdevService":true'; do
  grep -Fq "${phrase}" <<<"${without_runtime}" || fail "wgInventory-only path changed unexpectedly: ${phrase}"
done

echo "PASS fs470-hostmodule-provider-runtime"
