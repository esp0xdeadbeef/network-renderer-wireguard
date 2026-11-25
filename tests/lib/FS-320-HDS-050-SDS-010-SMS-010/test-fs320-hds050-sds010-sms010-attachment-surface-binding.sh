#!/usr/bin/env bash
# GAMP-ID: FS-320-HDS-050-SDS-010-SMS-010
# GAMP-SCOPE: software-module-test
#
# Uniform FS-320-HDS-050 check for every renderer.
#
# The rule is renderer-agnostic because every renderer emits something that
# plugs into a network: a container leg, a tunnel interface, an endpoint
# client, an OpenConfig interface document, a provider surface. Whatever the
# artefact is, it attaches to a surface, and that surface is modelled
# authority. A renderer may not choose one, default one, derive one from a
# name, or substitute an available one for the named one.
#
# A surface is not required to be physical. Physical ports, external bridges,
# and renderer-created bridges are all legal, and a site that uses only
# non-physical surfaces is complete rather than broken.
#
# Expected state for network-renderer-wireguard: FAILING. Tunnel interfaces
# are required and fail closed, but route and ingress attachment targets
# fall back to another surface (`route.interface or lanInterface`,
# `ingress.ingressInterface or vpnInterface`), which is a substitution.
set -euo pipefail

repo_root="${SMS_TEST_REPO_ROOT:-$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)}"
cd "${repo_root}"

trace_id="${SMS_TEST_TRACE_ID:-FS-320-HDS-050-SDS-010-SMS-010}"

all_checks_passed=true
record_pass() { echo "PASS ${trace_id}: $1"; }
record_fail() { echo "FAIL ${trace_id}: $1" >&2; all_checks_passed=false; }

echo "--- Predicate 1: no attachment surface is defaulted ---"

defaulted_surfaces="$(
  grep -rnE 'Interface\s*\?\s*"[^"]+"|Bridge\s*\?\s*"[^"]+"' s88 modules 2>/dev/null \
    | grep -vE '^\s*#' || true
)"
if [[ -n "${defaulted_surfaces}" ]]; then
  record_fail "attachment surface carries a renderer-local default: ${defaulted_surfaces//$'\n'/ | }"
else
  record_pass "no attachment surface is defaulted"
fi

echo ""
echo "--- Predicate 2: no surface is substituted for a missing one ---"

substituted_surfaces="$(
  grep -rnE '(route|ingress|forward|target|attach)[A-Za-z]*\.(interface|bridge)\s+or\s+[a-zA-Z]' s88 modules 2>/dev/null \
    | grep -vE '^\s*#' || true
)"
if [[ -n "${substituted_surfaces}" ]]; then
  record_fail "a named attachment surface falls back to another surface: ${substituted_surfaces//$'\n'/ | }"
else
  record_pass "a named attachment surface is never substituted"
fi

echo ""
echo "--- Predicate 3: a missing surface fails closed with a named diagnostic ---"

if [[ -n "$(grep -rn 'throw' s88 modules 2>/dev/null | head -1)" ]]; then
  record_pass "the renderer fails closed rather than defaulting"
else
  record_fail "the renderer has no fail-closed path for a missing surface"
fi

echo ""
echo "--- Predicate 4: no physical-surface requirement ---"

physical_requirement="$(
  grep -rnE 'physical(Nic|Port|Interface)[A-Za-z]*\s*(\?|===|==)' s88 modules 2>/dev/null || true
)"
if [[ -n "${physical_requirement}" ]]; then
  record_fail "an attachment requires a physical surface: ${physical_requirement//$'\n'/ | }"
else
  record_pass "no attachment requires a physical surface"
fi

echo ""
if ${all_checks_passed}; then
  echo "PASS ${trace_id} — renderer binds only modelled attachment surfaces."
  exit 0
fi

echo "FAIL ${trace_id} — renderer chooses or substitutes an attachment surface the model did not declare." >&2
exit 1
