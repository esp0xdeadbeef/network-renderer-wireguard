#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

fail() {
  echo "FAIL fs100-renderer-output-provenance: $*" >&2
  exit 1
}

eval_json() {
  nix eval --json --impure --file tests/provider-runtime-contract.nix fs100RendererOutputProvenance
}

provenance_json="$(eval_json)"

if grep -Fq "PLAINTEXT-PROTECTED-VALUE" <<<"${provenance_json}"; then
  fail "protected plaintext leaked into renderer provenance"
fi

jq -e '
  .renderer.name == "network-renderer-wireguard" and
  .renderer.schemaVersion == 1 and
  .input.kind == "provider-contract" and
  .input.path == "provider-contracts/fs100-wireguard-provider.json" and
  .output.kind == "provider-runtime-module" and
  .output.artifact == "provider-runtime-output.json" and
  .sources.sourceClasses.userIntent.path == "examples/fs100/intent.nix" and
  .sources.sourceClasses.publicInventory.path == "examples/fs100/inventory-nixos.nix" and
  .sources.sourceClasses.protectedInventory.secretValue == "<redacted>" and
  .sources.sourceClasses.runtimeFacts.ref == "runtime://provider/public-addresses" and
  .sources.sourceClasses.validationContext.profile == "renderer-construction" and
  (.sources.missingSourceClasses | length) == 0 and
  .requested.scope.site == "nixos" and
  .requested.target.renderer == "wireguard" and
  .requested.target.role == "renderer-output" and
  .requested.derivedScope.site == "nixos" and
  .requested.derivedScope.host == "s-router-nixos" and
  .locks.upstream["network-control-plane-model"].rev == "1111222233334444555566667777888899990000" and
  .locks.renderer.available == true and
  .controlledBaseline == "fs100-renderer-output-provenance" and
  .redaction.protectedValues == "redacted"
' <<<"${provenance_json}" >/dev/null || fail "renderer provenance fields did not match expected contract"

echo "PASS fs100-renderer-output-provenance"
