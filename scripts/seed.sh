#!/usr/bin/env bash
# GAMP-ID: TOOL-WG-SEED-001
# GAMP-SCOPE: test infrastructure tool; idempotent fixture seeder
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: scripts/seed.sh --cpm <path> [--output <dir>] [--force] [--help]

  --cpm <path>       Path to CPM output JSON or Nix expression (required)
  --output <dir>     Fixture output directory (default: tests/fixtures/seeded)
  --force            Recompile even if fixture exists
  --help             Show this help

The script caches CPM provider contracts as reusable test fixtures for the
WireGuard renderer. Tests consume these fixtures instead of depending on a
live CPM build.

Output files:
  tests/fixtures/seeded/<name>/cpm-provider-contract.json   CPM output
  tests/fixtures/seeded/<name>/manifest.txt                  Source path + timestamp

Exit codes:
  0  Fixture ready (fresh or cached)
  1  Build failed
  2  Invalid arguments
EOF
}

FORCE=false
CPM_PATH=""
OUTPUT_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cpm)    CPM_PATH="$2"; shift 2 ;;
    --output) OUTPUT_DIR="$2"; shift 2 ;;
    --force)  FORCE=true; shift ;;
    --help)   usage; exit 0 ;;
    *)        echo "Unknown flag: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$CPM_PATH" ]]; then
  echo "ERROR: --cpm is required" >&2; usage; exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CPM_NAME="$(basename "${CPM_PATH%.nix}" | sed 's/\.[^.]*$//')"
OUTPUT_DIR="${OUTPUT_DIR:-${REPO_ROOT}/tests/fixtures/seeded/${CPM_NAME}}"

MANIFEST="${OUTPUT_DIR}/manifest.txt"

# ── Idempotency check ──
if [[ "$FORCE" != "true" && -f "${OUTPUT_DIR}/cpm-provider-contract.json" ]]; then
  echo "seed: fixture exists at ${OUTPUT_DIR} (use --force to re-seed)"
  exit 0
fi

mkdir -p "${OUTPUT_DIR}"
echo "seed: cpm=${CPM_PATH}" > "${MANIFEST}"
echo "seed: started=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${MANIFEST}"

# ── Build CPM provider contract JSON ──
if nix eval --json --impure \
     --expr "import ${REPO_ROOT}/tests/fs470-wireguard-remote-egress-smt.nix" \
     > "${OUTPUT_DIR}/cpm-provider-contract.json" 2>/dev/null; then
  echo "seed: cpm-provider-contract.json built"
else
  # Fallback: try resolving via flake input
  ARCHIVE_JSON="$(mktemp)"
  trap 'rm -f "${ARCHIVE_JSON}"' RETURN
  if nix flake archive --json "path:${REPO_ROOT}" > "${ARCHIVE_JSON}" 2>/dev/null; then
    CPM_REPO="$(jq -er '.inputs["network-control-plane-model"].path // empty' "${ARCHIVE_JSON}")"
    if [[ -n "$CPM_REPO" ]]; then
      echo "seed: CPM repo at ${CPM_REPO}"
      echo "seed: cpm_repo=${CPM_REPO}" >> "${MANIFEST}"
    fi
  fi
  echo "seed: WARNING — could not pre-build cpm-provider-contract.json; test fixtures may need live CPM" >&2
  echo "seed: status=partial" >> "${MANIFEST}"
  exit 1
fi

echo "seed: completed=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${MANIFEST}"
echo "seed: status=ok" >> "${MANIFEST}"
echo "seed: done — fixtures at ${OUTPUT_DIR}"
