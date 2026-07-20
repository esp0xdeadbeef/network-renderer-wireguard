#!/usr/bin/env bash
set -euo pipefail

repo_root="${SMS_TEST_REPO_ROOT:-$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)}"
cd "${repo_root}"

if [[ "${NETWORK_REPO_SWEEP:-0}" != "1" && "${NETWORK_REPO_DIRECT_TEST_OK:-0}" != "1" ]]; then
  echo "WARN: direct repo tests are partial; set NETWORK_REPO_DIRECT_TEST_OK=1 for intentional focused runs, or run network-codex-agent/scripts/s-router-full-lab-rebuild-loop.sh for the locked full network-* sweep plus live validation." >&2
fi

mapfile -t tests < <(
  find tests -maxdepth 1 -regextype posix-extended \( -type f -o -type l \) \
    \( -name 'test-*.sh' -o -regex '.*/FS-[0-9]+-HDS-[0-9]+-SDS-[0-9]+-SMS-[0-9]+\.sh' \) \
    ! -name 'test.sh' -printf '%p\n' | LC_ALL=C sort
)

for test_path in "${tests[@]}"; do
  bash "${test_path}"
done

nix flake check --no-write-lock-file
