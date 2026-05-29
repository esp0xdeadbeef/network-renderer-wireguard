#!/usr/bin/env bash
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
grep -Fq "public-ingress mode requires publicIngress contracts" <<<"${public_ingress_errors}" || \
  fail "public-ingress missing-contract assertion missing"

render_result_shape="$(eval_json renderResultShape)"
for phrase in \
  '"rendererClass":"provider"' \
  '"targetRenderer":"wireguard-provider"' \
  '"providerId":"test-provider"' \
  '"hasProviderRuntimeModule":true' \
  '"SMT-WG-VALIDATE-001"' \
  '"SMS-MOD-014"' \
  '"CMC-MOD-013"'; do
  grep -Fq "${phrase}" <<<"${render_result_shape}" || fail "render result shape missing phrase: ${phrase}"
done

echo "PASS provider-runtime-contract"
