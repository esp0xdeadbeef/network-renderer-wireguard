#!/usr/bin/env bash
# GAMP-ID: RTM-RUNNER-WG-001
# GAMP-SCOPE: test runner — auto-discovers all tests, no hardcoded list
set -euo pipefail
exec > >(tee "/tmp/network-renderer-wireguard-tests.out")

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="${REPO_ROOT}/tests"

if [[ ! -d "$TEST_DIR" ]]; then
  echo "ERROR: tests directory not found: ${TEST_DIR}" >&2
  exit 1
fi

MAX_JOBS="${TEST_JOBS:-$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN)}"
if ! [[ "${MAX_JOBS}" =~ ^[0-9]+$ ]] || [[ "${MAX_JOBS}" -lt 1 ]]; then
  MAX_JOBS=1
fi

# ── Auto-discover all test files (excluding test.sh itself) ──
TESTS=()
for f in "${TEST_DIR}"/test-*.sh; do
  [[ "$(basename "$f")" == "test.sh" ]] && continue
  if [[ -f "$f" && -x "$f" ]]; then
    TESTS+=("$(basename "$f")")
  fi
done

if [[ ${#TESTS[@]} -eq 0 ]]; then
  echo "No executable test-*.sh files found in ${TEST_DIR}" >&2
  exit 1
fi

# ── Also run nix flake check as last step ──
TESTS+=("::flake-check")

# ── Per-test timeout (seconds) ──
TEST_TIMEOUT="${TEST_TIMEOUT:-600}"

printf 'Running %s tests with TEST_JOBS=%s (timeout=%ss per test)\n' "${#TESTS[@]}" "${MAX_JOBS}" "${TEST_TIMEOUT}"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT INT TERM

PIDS=()
NAMES=()
LOGS=()
ELAPSED_FILES=()

running_jobs() {
  local count=0 pid
  for pid in "${PIDS[@]:-}"; do
    if kill -0 "${pid}" 2>/dev/null; then count=$((count + 1)); fi
  done
  printf '%s\n' "${count}"
}

wait_for_slot() {
  while [[ "$(running_jobs)" -ge "${MAX_JOBS}" ]]; do sleep 0.2; done
}

SUITE_START_MS="$(date +%s%3N)"

for test_name in "${TESTS[@]}"; do
  wait_for_slot

  LOG="${TMPDIR}/${test_name}.log"
  ELAPSED="${TMPDIR}/${test_name}.elapsed"
  (
    CHILD_START_MS="$(date +%s%3N)"
    cd "${REPO_ROOT}"

    if [[ "$test_name" == "::flake-check" ]]; then
      nix flake check --no-write-lock-file >/dev/null 2>&1
      STATUS=$?
    else
      STATUS=0
      timeout "${TEST_TIMEOUT}" "tests/${test_name}" || STATUS=$?
    fi

    CHILD_END_MS="$(date +%s%3N)"
    printf '%s\n' "$((CHILD_END_MS - CHILD_START_MS))" > "${ELAPSED}"
    exit "${STATUS}"
  ) > "${LOG}" 2>&1 &

  PIDS+=("$!")
  NAMES+=("${test_name}")
  LOGS+=("${LOG}")
  ELAPSED_FILES+=("${ELAPSED}")
done

FAILED=0

for idx in "${!PIDS[@]}"; do
  PID="${PIDS[$idx]}"
  NAME="${NAMES[$idx]}"
  LOG="${LOGS[$idx]}"
  ELAPSED_FILE="${ELAPSED_FILES[$idx]}"

  if wait "${PID}"; then
    ELAPSED_MS="$(cat "${ELAPSED_FILE}")"
    printf 'PASS %sms %s\n' "${ELAPSED_MS}" "${NAME}"
  else
    STATUS=$?
    if [[ -f "${ELAPSED_FILE}" ]]; then
      ELAPSED_MS="$(cat "${ELAPSED_FILE}")"
    else
      ELAPSED_MS="unknown"
    fi
    FAILED=$((FAILED + 1))
    printf 'FAIL %sms %s (exit %s)\n' "${ELAPSED_MS}" "${NAME}" "${STATUS}" >&2
    if [[ -f "${LOG}" ]]; then
      sed "s/^/[${NAME}] /" "${LOG}"
    else
      printf '[%s] log unavailable\n' "${NAME}" >&2
    fi
  fi
done

SUITE_END_MS="$(date +%s%3N)"
printf 'PASS %sms tests (%s total, %s failed)\n' \
  "$((SUITE_END_MS - SUITE_START_MS))" "${#TESTS[@]}" "${FAILED}"
printf 'PASS: %s, FAIL: %s, TOTAL: %s\n' "$(( ${#TESTS[@]} - FAILED ))" "${FAILED}" "${#TESTS[@]}" >&2

if [[ "${FAILED}" -ne 0 ]]; then
  exit 1
fi
