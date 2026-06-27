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
bash tests/test-fs470-hds010-sds010-sms021-wg-cpm-only-consumption.sh
bash tests/test-fs470-hds010-sds010-sms041-wg-fail-closed-specific.sh
bash tests/FS-470-HDS-010-SDS-010-SMS-050.sh
bash tests/FS-470-HDS-010-SDS-010-SMS-060.sh
bash tests/FS-470-HDS-010-SDS-010-SMS-070.sh
bash tests/FS-470-HDS-010-SDS-010-SMS-080.sh
bash tests/FS-470-HDS-010-SDS-010-SMS-010.sh
bash tests/FS-470-HDS-010-SDS-010-SMS-020.sh
bash tests/FS-470-HDS-010-SDS-010-SMS-040.sh
bash tests/run-fs982-sms110.sh
nix flake check --no-write-lock-file
