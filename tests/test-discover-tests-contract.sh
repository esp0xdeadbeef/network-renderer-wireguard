#!/usr/bin/env bash
# GAMP-ID: RTM-RUNNER-WG-003
# GAMP-SCOPE: test infrastructure check; not SMT acceptance evidence.
#
# `scripts/lib/discover-tests.sh` documents that it is byte-identical in every
# repository that ships it, and warns that "a divergent copy is how a whole
# class of tests stops running in CI without anybody noticing".
#
# Nothing checked that. A repository could add an entrypoint pattern locally,
# run more cases than its siblings, and its own suite would stay green -- while
# the shared contract silently stopped meaning anything. The comparison is
# against the sibling checkouts that happen to be present; when none are, the
# contract is only checked for internal consistency, so this passes on a bare
# CI runner without pretending to have verified the cross-repo claim.
set -euo pipefail

repo_root="${SMS_TEST_REPO_ROOT:-$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)}"
cd "${repo_root}"

fail() {
  echo "FAIL discover-tests-contract: $*" >&2
  exit 1
}

local_copy="scripts/lib/discover-tests.sh"
[[ -f "${local_copy}" ]] || fail "missing ${local_copy}"

# The local copy must actually define the two functions run-all-tests.sh uses.
for fn in discover_tests discover_test_runner; do
  grep -qE "^${fn}\(\)" "${local_copy}" \
    || fail "${local_copy} does not define ${fn}()"
done

# A local entrypoint added by hand must still be found by the shared contract,
# so a test can never be "in tests/ but invisible to the runner".
mapfile -t discovered < <(
  # shellcheck source=scripts/lib/discover-tests.sh
  source "${local_copy}"
  discover_tests "$(pwd)"
)
(( ${#discovered[@]} > 0 )) || fail "discover_tests returned no entrypoints"

for name in "${discovered[@]}"; do
  [[ -f "tests/${name}" ]] || fail "discover_tests reported a missing file: ${name}"
  # The contract excludes test.sh and live-flagged probes by construction.
  [[ "${name}" == "test.sh" ]] && fail "discover_tests must exclude test.sh"
  if head -20 "tests/${name}" | grep -qE '^#[[:space:]]*GAMP-SCOPE:.*\blive\b'; then
    fail "discover_tests must exclude live probes: ${name}"
  fi
done

# Seeded negative: an entrypoint injected at tests/ top level must appear, which
# proves the discovery is live rather than an empty list that trivially passes.
tmp_entry="tests/test-seeded-discovery-probe.sh"
trap 'rm -f "${tmp_entry}"' EXIT
printf '#!/usr/bin/env bash\necho probe\n' > "${tmp_entry}"
chmod +x "${tmp_entry}"
mapfile -t with_probe < <(
  source "${local_copy}"
  discover_tests "$(pwd)"
)
if ! printf '%s\n' "${with_probe[@]}" | grep -qx "test-seeded-discovery-probe.sh"; then
  fail "seeded negative missed: a new tests/test-*.sh entrypoint was not discovered"
fi
echo "  PASS: seeded negative caught — new entrypoint discovered"
rm -f "${tmp_entry}"
mapfile -t without_probe < <(
  source "${local_copy}"
  discover_tests "$(pwd)"
)
if printf '%s\n' "${without_probe[@]}" | grep -qx "test-seeded-discovery-probe.sh"; then
  fail "seeded negative recovery left the probe discovered"
fi
echo "  PASS: seeded negative recovery — clean after removal"

# Cross-repo: every sibling that ships the file must match ours, byte for byte.
ours="$(sha256sum "${local_copy}" | cut -d' ' -f1)"
siblings=0
workspace="$(cd "${repo_root}/.." && pwd)"
for other in "${workspace}"/network-*/scripts/lib/discover-tests.sh; do
  [[ -f "${other}" ]] || continue
  [[ "$(readlink -f "${other}")" == "$(readlink -f "${local_copy}")" ]] && continue
  siblings=$((siblings + 1))
  theirs="$(sha256sum "${other}" | cut -d' ' -f1)"
  if [[ "${ours}" != "${theirs}" ]]; then
    printf '  ISSUE: %s differs from this repository copy\n' "${other#${workspace}/}" >&2
    fail "discover-tests.sh has diverged between repositories; copy the same file to all of them"
  fi
done

if (( siblings > 0 )); then
  echo "PASS discover-tests-contract: ${#discovered[@]} entrypoints; copy identical to ${siblings} sibling repositor$([[ ${siblings} -eq 1 ]] && echo y || echo ies)"
else
  echo "PASS discover-tests-contract: ${#discovered[@]} entrypoints; no sibling checkouts present, cross-repo equality not asserted"
fi
