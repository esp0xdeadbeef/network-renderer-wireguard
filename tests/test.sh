#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

if [[ "${NETWORK_REPO_SWEEP:-0}" != "1" && "${NETWORK_REPO_DIRECT_TEST_OK:-0}" != "1" ]]; then
  echo "WARN: direct repo tests are partial; set NETWORK_REPO_DIRECT_TEST_OK=1 for intentional focused runs, or run network-codex-agent/scripts/s-router-full-lab-rebuild-loop.sh for the locked full network-* sweep plus live validation." >&2
fi

bash tests/test-provider-runtime-contract.sh
bash tests/test-fs100-renderer-output-provenance.sh
bash tests/test-fs470-wireguard-remote-egress-smt.sh
bash tests/test-s88-code-traceability.sh
bash tests/test-fs470-boundary-scan.sh
nix flake check --no-write-lock-file
