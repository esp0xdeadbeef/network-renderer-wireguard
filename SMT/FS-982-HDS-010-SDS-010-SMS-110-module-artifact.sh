#!/usr/bin/env bash
# GAMP-ID: FS-982-HDS-010-SDS-010-SMS-110
# GAMP-SCOPE: software-module-test
# FS-982-SMS-110-RUNTIME: scoped-artifact
# FS-982-SMS-110-ARTIFACT: WireGuard renderer remote-egress provider artifact
# FS-982-SMS-110-EVIDENCE: tests/test-fs470-wireguard-remote-egress-smt.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
  echo "FAIL fs982-sms110-wireguard-smt: $*" >&2
  exit 1
}

evidence="tests/test-fs470-wireguard-remote-egress-smt.sh"
output="$(NETWORK_REPO_DIRECT_TEST_OK=1 bash "${repo_root}/${evidence}" 2>&1)" || {
  printf '%s\n' "${output}" >&2
  fail "${evidence} failed"
}

grep -Fq "PASS fs470-wireguard-remote-egress-smt" <<<"${output}" \
  || fail "${evidence} did not prove WireGuard remote-egress artifact checks"
grep -Fq "renderer invented unrelated routing/IPAM/bootstrap authority" "${repo_root}/${evidence}" \
  || fail "${evidence} does not assert cross-authority rejection"

echo "PASS fs982-sms110-wireguard-smt"
