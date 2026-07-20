#!/usr/bin/env bash
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-022
# GAMP-SCOPE: software-module-test
# Focused construction test: WireGuard renderer CPM-only consumption and WG-specific missing-field diagnostics.
set -euo pipefail

repo_root="${SMS_TEST_REPO_ROOT:-$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)}"
cd "${repo_root}"

trace_id="FS-470-HDS-010-SDS-010-SMS-022"
failures=0

record_failure() {
  local message="$1"
  echo "FAIL ${trace_id}: ${message}" >&2
  failures=$((failures + 1))
}

scan_source() {
  local pattern="$1"
  find s88 modules -name '*.nix' -print0 2>/dev/null \
    | xargs -0 grep -HnE "${pattern}" 2>/dev/null \
    | grep -vE '^\s*(#|//)' || true
}

expect_no_hits() {
  local name="$1"
  local pattern="$2"
  local hits

  hits="$(scan_source "${pattern}")"
  if [[ -n "${hits}" ]]; then
    printf '%s\n' "${hits}" | sed 's/^/  HIT: /'
    record_failure "${name}"
  else
    echo "PASS ${name}"
  fi
}

expect_eval_failure() {
  local attr="$1"
  local expected="$2"
  local output
  local rc

  set +e
  output="$(nix eval --raw --impure --file tests/fs470-sms022-wg-cpm-only.nix "${attr}" 2>&1)"
  rc=$?
  set -e

  if (( rc == 0 )); then
    record_failure "${attr} unexpectedly evaluated successfully"
    return
  fi
  if grep -Fq "${expected}" <<<"${output}"; then
    echo "PASS ${attr} rejected with SMS-022 diagnostic"
  else
    printf '%s\n' "${output}" >&2
    record_failure "${attr} missing expected diagnostic: ${expected}"
  fi
}

echo "--- ${trace_id}: WG CPM-only consumption and diagnostics ---"

nix eval --raw --impure --file tests/fs470-sms022-wg-cpm-only.nix valid >/dev/null
echo "PASS valid CPM-preserved wgInventory hostModule input"

expect_no_hits "no direct upstream source imports" '(intent\.nix|inventory[^/]*\.nix|inventory-nixos\.nix)'
expect_no_hits "no internal CPM compilation" '(compileAndBuildFromPaths|compile-and-build-control-plane-model)'
expect_no_hits "no raw inventory tree walks" '(inventory\.controlPlane|inventory\.realization|\.realization\.nodes|inventoryTree)'
expect_no_hits "no raw overlay WireGuard reads" '(inventory\..*overlays.*wireguard|controlPlane\.sites.*overlays.*wireguard)'
expect_no_hits "no hostModule raw intent/inventory parameters" '(hostModule[^{]*\{[^}]*intent|hostModule[^{]*\{[^}]*inventory)'

expect_eval_failure missingInterface "${trace_id}: WireGuard interface name required by CPM-preserved wgInventory"
expect_eval_failure tooLongInterface "${trace_id}: WireGuard interface name from CPM-preserved wgInventory must be <= 15 characters for Linux"
expect_eval_failure missingPrivateKeyFile "${trace_id}: WireGuard private key path required by CPM-preserved wgInventory"
expect_eval_failure missingListenPort "${trace_id}: WireGuard listenPort required by CPM-preserved wgInventory"
expect_eval_failure missingPeers "${trace_id}: WireGuard peers required by CPM-preserved wgInventory"
expect_eval_failure missingPeerPublicKey "${trace_id}: WireGuard peer requires publicKey from CPM-preserved wgInventory"
expect_eval_failure missingPeerEndpoint "${trace_id}: WireGuard peer requires endpoint from CPM-preserved wgInventory"
expect_eval_failure missingPeerAllowedIPs "${trace_id}: WireGuard peer requires allowedIPs from CPM-preserved wgInventory"

if (( failures > 0 )); then
  echo "FAIL ${trace_id}: ${failures} check(s) failed" >&2
  exit 1
fi

echo "PASS ${trace_id}: WG renderer consumes CPM-preserved WG data only and fails closed with SMS-022 diagnostics"
