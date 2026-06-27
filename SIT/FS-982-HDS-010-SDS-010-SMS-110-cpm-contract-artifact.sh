#!/usr/bin/env bash
# GAMP-ID: FS-982-HDS-010-SDS-010-SMS-110
# GAMP-SCOPE: software-integration-test
# FS-982-SMS-110-RUNTIME: scoped-artifact
# FS-982-SMS-110-ARTIFACT: WireGuard renderer explicit provider-contract artifact
# FS-982-SMS-110-EVIDENCE: tests/FS-470-HDS-010-SDS-010-SMS-010.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
  echo "FAIL fs982-sms110-wireguard-sit: $*" >&2
  exit 1
}

evidence="tests/FS-470-HDS-010-SDS-010-SMS-010.sh"
output="$(NETWORK_REPO_DIRECT_TEST_OK=1 bash "${repo_root}/${evidence}" 2>&1)" || {
  printf '%s\n' "${output}" >&2
  fail "${evidence} failed"
}

grep -Fq "PASS: FS-470-HDS-010-SDS-010-SMS-010" <<<"${output}" \
  || fail "${evidence} did not prove explicit provider-contract plan checks"
grep -Fq "Seeded negative 3 (missing peer endpoint):  rejected" <<<"${output}" \
  || fail "${evidence} did not prove missing peer endpoint rejection"

echo "PASS fs982-sms110-wireguard-sit"
