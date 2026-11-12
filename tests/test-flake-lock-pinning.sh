#!/usr/bin/env bash
# GAMP-ID: RTM-RUNNER-WG-002
# GAMP-SCOPE: test infrastructure check; not SMT acceptance evidence.
#
# Every github input in flake.lock must be pinned to a commit rev.
#
# The requirement is that a `network-*` repository pins the repositories it
# consumes and that `nix flake update` is the only thing that moves them. A
# `github:owner/repo` input without a ref is legitimate in flake.nix -- the lock
# is what pins it -- but if the lock itself ever carries an input with no
# `locked.rev`, then the build follows a moving branch and two runs of the same
# commit can produce different network semantics. That is the failure this
# guards: it is silent, because everything still evaluates.
#
# This runs in the repository suite, so it is picked up automatically by
# run-all-tests.sh (test-*.sh at tests/ top level).
set -euo pipefail

repo_root="${SMS_TEST_REPO_ROOT:-$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)}"
cd "${repo_root}"

fail() {
  echo "FAIL flake-lock-pinning: $*" >&2
  exit 1
}

lock="flake.lock"
[[ -f "${lock}" ]] || fail "missing ${lock}"

[[ -f flake.nix ]] || fail "missing flake.nix"

# Emit one line per input that is a github input and does not carry a locked rev.
unpinned() {
  local path="$1"
  python3 - "${path}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    lock = json.load(fh)

nodes = lock.get("nodes", {})
bad = []
for name, node in nodes.items():
    original = node.get("original", {})
    if original.get("type") != "github":
        continue
    locked = node.get("locked", {})
    rev = locked.get("rev")
    if not rev:
        bad.append(name)
    elif len(rev) != 40 or any(c not in "0123456789abcdef" for c in rev.lower()):
        bad.append(f"{name} (malformed rev {rev!r})")
for name in sorted(bad):
    print(name)
PY
}

hits="$(unpinned "${lock}")"
if [[ -n "${hits}" ]]; then
  printf '%s\n' "${hits}" | sed 's/^/  ISSUE: unpinned github input: /' >&2
  fail "flake.lock has github inputs without a pinned commit rev; run 'nix flake update' and commit the result"
fi

# A sanity floor: the two repositories this renderer consumes must be present, so
# a lock that lost them cannot pass by having nothing to check.
for required in network-control-plane-model network-realization-model; do
  python3 - "${lock}" "${required}" <<'PY' || fail "flake.lock does not pin ${required}"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    lock = json.load(fh)
sys.exit(0 if sys.argv[2] in lock.get("nodes", {}) else 1)
PY
done

# Seeded negative: an unpinned github node must be caught, and removing it must
# recover. Without this the check could pass because it finds nothing at all.
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

python3 - flake.lock "${tmp_dir}/bad.lock" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    lock = json.load(fh)
lock["nodes"]["seeded-unpinned"] = {"original": {"type": "github", "owner": "example", "repo": "seeded"}}
with open(sys.argv[2], "w", encoding="utf-8") as fh:
    json.dump(lock, fh)
PY

seeded_hits="$(unpinned "${tmp_dir}/bad.lock")"
grep -qx "seeded-unpinned" <<<"${seeded_hits}" \
  || fail "seeded negative missed: an unpinned github input was not detected"
echo "  PASS: seeded negative caught — unpinned github input detected"

rm -f "${tmp_dir}/bad.lock"
if [[ -n "$(unpinned "${tmp_dir}/bad.lock" 2>/dev/null || true)" ]]; then
  fail "seeded negative recovery left residual hits"
fi
echo "  PASS: seeded negative recovery — clean after removal"

echo "PASS flake-lock-pinning: every github flake input is pinned to a commit rev"
