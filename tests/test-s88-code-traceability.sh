#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
  echo "FAIL s88-code-traceability: $*" >&2
  exit 1
}

required_cm_files=(
  addressing-services.nix
  firewall-nat.nix
  provider-contract.nix
  render-result.nix
  tunnel-runtime.nix
)

for file_name in "${required_cm_files[@]}"; do
  file_path="${repo_root}/s88/ControlModule/${file_name}"
  [[ -f "${file_path}" ]] || fail "missing s88/ControlModule/${file_name}"
  rg -Fq "s88/ControlModule/${file_name}" "${repo_root}/README.md" \
    || fail "README does not describe s88/ControlModule/${file_name}"
done

for file_name in addressing-services.nix firewall-nat.nix provider-contract.nix tunnel-runtime.nix; do
  rg -Fq "../s88/ControlModule/${file_name}" "${repo_root}/modules/wireguard-provider-runtime.nix" \
    || fail "runtime module does not invoke s88/ControlModule/${file_name}"
done

rg -Fq "./s88/ControlModule/render-result.nix" "${repo_root}/flake.nix" \
  || fail "flake renderer API does not invoke s88/ControlModule/render-result.nix"

if rg -n "required \\[|nft add|masquerade|wireguard-provider-dispatcher-start" \
  "${repo_root}/modules/wireguard-provider-runtime.nix" >&2
then
  fail "runtime module regained inline ControlModule projection logic"
fi

echo "PASS s88-code-traceability"
