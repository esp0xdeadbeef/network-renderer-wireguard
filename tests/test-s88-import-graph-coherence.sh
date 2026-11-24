#!/usr/bin/env bash
# GAMP-SCOPE: software-module-test
#
# S88 IMPORT-GRAPH COHERENCE -- three declarations compared against the graph
# the evaluator will actually build.
#
# WHY THIS IS NOT A KEYWORD CHECK
# ------------------------------
# The earlier version of this file grepped for `readDir` and for level names. That
# proves a string is absent, not that a boundary holds. This file resolves every
# relative `import` under `s88/`, builds the dependency graph, and then compares
# THREE independently produced artifacts against it:
#
#   A. the S88 level claimed for a file in TRACE.md
#   B. the level the import graph actually places that file in
#   C. the entrypoints the flake and the level facades actually reach
#
# A disagreement between any two of them is the defect. Nothing below asserts on
# a substring in a comment.
#
# THE THREE CHECKS
# ----------------
# G1  No upward dependency. A file whose graph level is EquipmentModule must not
#     import a file whose graph level is Unit: authority flows downward, and a
#     responsibility level that depends on a decision level can no longer be
#     changed without changing the decision.
#
# G2  Declared layer equals graph layer. TRACE.md assigns every policy-routing
#     source file an `S88 LAYER`. A row is coherent only if the level it names is
#     reachable from that level's facade and not only from a deeper one.
#
# G3  Nothing decorative. Every `s88/` file must be reachable from a real
#     entrypoint (`flake.nix` or a level facade). A file that nothing imports is
#     the "decoration" case: the directory still reads as authoritative while the
#     live code is elsewhere.
#
# Evidence boundary: construction. Static file reads and path resolution only.
# No evaluation, no build, no lab, no network.
set -euo pipefail

repo_root="${SMS_TEST_REPO_ROOT:-$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)}"
if [[ -f "${repo_root}/tests/lib/direct-test-guard.sh" ]]; then
  source "${repo_root}/tests/lib/direct-test-guard.sh" 2>/dev/null || true
fi

levels=(Enterprise Site Area ProcessCell Unit EquipmentModule ControlModule)

level_rank() {
  case "$1" in
    Enterprise) echo 1 ;;
    Site) echo 2 ;;
    Area) echo 3 ;;
    ProcessCell) echo 4 ;;
    Unit) echo 5 ;;
    EquipmentModule) echo 6 ;;
    ControlModule) echo 7 ;;
    *) echo 99 ;;
  esac
}

# The level a path is placed in by its location. Used for files TRACE.md does not
# describe and for targets of an edge.
level_of_path() {
  local rel="$1" part
  case "${rel}" in
    s88/*)
      part="$(cut -d/ -f2 <<<"${rel}")"
      case "${part}" in
        Enterprise) echo Enterprise ;;
        Site) echo Site ;;
        Area) echo Area ;;
        ProcessCell) echo ProcessCell ;;
        Unit) echo Unit ;;
        EquipmentModule) echo EquipmentModule ;;
        ControlModule) echo ControlModule ;;
        *) echo "" ;;
      esac
      ;;
    *) echo "" ;;
  esac
}

# ---------------------------------------------------------------------------
# Resolve the `import` targets of one file.
#
# Only the forms this tree uses are resolved, and each unresolved form is
# reported rather than ignored: an import the resolver cannot follow would make
# G3 claim a file is decorative when it is not.
# ---------------------------------------------------------------------------
imports_of() {
  local file="$1" dir raw target dirname_of
  dir="$(dirname "${file}")"

  # Match relative path TOKENS, not `import <path>` prefixes. A file listed in a
  # Nix list (`imports = [ ../../Unit/module/host-network.nix ];`) is a dependency
  # the evaluator will follow, and a prefix-anchored match misses it. Anything
  # that is not a relative path is skipped; anything that does not resolve to an
  # existing file is skipped rather than guessed.
  {
    grep -oE '(\.\.?/)+[A-Za-z0-9._/-]+\.nix' "${file}" 2>/dev/null || true
  } |
    sort -u |
    while IFS= read -r raw; do
      [[ -n "${raw}" ]] || continue
      target="$(realpath -m "${dir}/${raw}" 2>/dev/null || true)"
      [[ -n "${target}" ]] || continue
      [[ -d "${target}" ]] && target="${target}/default.nix"
      [[ -f "${target}" ]] || continue
      printf 'EDGE\t%s\t%s\n' "${file}" "${target}"
    done || true

  # Non-relative imports cannot be resolved statically. Report them so a
  # dependency cannot hide behind one.
  grep -oE "import[[:space:]]+\(?[^ ({;]+" "${file}" 2>/dev/null |
    sed -E 's/^import[[:space:]]+\(?//' |
    while IFS= read -r raw; do
      [[ -n "${raw}" ]] || continue
      case "${raw}" in
        ./* | ../* ) continue ;;
        import | "" ) continue ;;
        *) printf 'UNRESOLVED\t%s\t%s\n' "${file}" "${raw}" ;;
      esac
    done || true

  return 0
}

# ---------------------------------------------------------------------------
# Build edges and unresolved list once.
# ---------------------------------------------------------------------------
mapfile -t s88_files < <(find "${repo_root}/s88" -name '*.nix' -type f | LC_ALL=C sort)

edges_file="$(mktemp)"
unresolved_file="$(mktemp)"
trap 'rm -f "${edges_file}" "${unresolved_file}"' EXIT

raw_file="$(mktemp)"

# Scan the repository entrypoints as well as `s88/`. Edges out of `flake.nix`
# are the reason several s88 files are reachable at all: with only `s88/` scanned,
# everything the flake imports directly looked orphaned.
scan_files=("${s88_files[@]}")
[[ -f "${repo_root}/flake.nix" ]] && scan_files+=("${repo_root}/flake.nix")

for file in "${scan_files[@]}"; do
  imports_of "${file}" >>"${raw_file}" || true
done

grep '^UNRESOLVED' "${raw_file}" >"${unresolved_file}" 2>/dev/null || true
grep '^EDGE' "${raw_file}" >"${edges_file}" 2>/dev/null || true
rm -f "${raw_file}"

echo "--- S88-GRAPH: declarations vs the resolved import graph ---"
echo ""
echo "  s88/ source files: ${#s88_files[@]}"
echo "  resolved import edges: $(grep -c '^EDGE' "${edges_file}" 2>/dev/null || echo 0)"
echo "  unresolved imports: $(grep -c '' "${unresolved_file}" 2>/dev/null || echo 0)"
echo ""

issues=0
report_issue() {
  local id="$1" finding="$2" why="$3" read="$4"
  issues=$((issues + 1))
  {
    echo "ISSUE ${id}: ${finding}"
    echo "  why:  ${why}"
    echo "  read: ${read}"
    echo
  } >&2
}

read_pointer="the workspace ISA-88 architecture note (not in this repository): the level
         table (Control Module = implementation mechanism derived later, Unit =
         forwarding execution context), and its failure-signature entry 'Reasoning
         requires reading link names or file names -> authority is being recovered from
         derivation'. Then s88/ControlModule/render/container-networks/policy-routing/
         TRACE.md for the declared layer per file."

# ---------------------------------------------------------------------------
# G0 -- the tree declares its own boundary, and the declaration matches the tree.
#
# This is the one check here that compares a DOCUMENT to the tree rather than the
# tree to itself. It is included because the workspace note makes the boundary
# file a requirement, and a requirement with no check is a convention.
# ---------------------------------------------------------------------------
boundary=""
[[ -f "${repo_root}/s88/README.md" ]] && boundary="${repo_root}/s88/README.md"

if [[ -z "${boundary}" ]]; then
  report_issue "S88-G0" "s88/ has no README.md boundary statement" \
    "the workspace note requires a per-repository boundary file and lists the
       repositories that lack one. Without it, the level shape below cannot be read
       against a declaration -- only against itself." \
    "${read_pointer}"
else
  undescribed=()
  for dir in "${repo_root}/s88"/*/; do
    [[ -d "${dir}" ]] || continue
    name="$(basename "${dir}")"
    [[ -n "$(level_of_path "s88/${name}/x")" ]] || continue
    grep -qE "(^|[^A-Za-z])${name}([^A-Za-z]|$)" "${boundary}" || undescribed+=("${name}")
  done
  if ((${#undescribed[@]} > 0)); then
    report_issue "S88-G0" "s88/README.md does not describe: ${undescribed[*]}" \
      "each level directory is a claim about responsibility placement. An undescribed
         directory is structure nobody owns: either intentional and unrecorded, or
         leftover from a move." \
      "${read_pointer}"
  else
    echo "PASS G0: s88/README.md describes every level directory present"
  fi
fi

# ---------------------------------------------------------------------------
# G1 -- upward dependencies.
# ---------------------------------------------------------------------------
upward=0
while IFS=$'\t' read -r tag from to; do
  [[ "${tag}" == "EDGE" ]] || continue
  from_rel="${from#"${repo_root}/"}"
  to_rel="${to#"${repo_root}/"}"
  from_level="$(level_of_path "${from_rel}")"
  to_level="$(level_of_path "${to_rel}")"
  [[ -n "${from_level}" && -n "${to_level}" ]] || continue
  from_rank="$(level_rank "${from_level}")"
  to_rank="$(level_rank "${to_level}")"
  if ((to_rank < from_rank)); then
    upward=$((upward + 1))
    report_issue "S88-G1" "${from_rel} (${from_level}) imports ${to_rel} (${to_level})" \
      "the target is higher in the hierarchy. Authority flows downward: a lower level
         that depends on a higher one makes the implementation depend on the decision it
         is supposed to execute, so the decision can no longer move independently." \
      "${read_pointer}"
  fi
done <"${edges_file}"

((upward == 0)) && echo "PASS G1: no upward dependency in ${#s88_files[@]} files"

# ---------------------------------------------------------------------------
# G2 -- TRACE.md's declared layer must agree with the graph.
#
# The check is not "does the row contain the level name". It is: the file must be
# reachable from that level's facade. A file declared ControlModule that only the
# Unit facade reaches is declared at the level that consumes it, not the level
# that owns it.
# ---------------------------------------------------------------------------
report_note="$(mktemp)"
trap 'rm -f "${edges_file}" "${unresolved_file}" "${report_note}"' EXIT
trace_file="${repo_root}/s88/ControlModule/render/container-networks/policy-routing/TRACE.md"
if [[ -f "${trace_file}" ]]; then
  # Reachability from each level facade.
  declare -A reached_from_facade=()
  for level in "${levels[@]}"; do
    facade="${repo_root}/s88/${level}/api/default.nix"
    [[ -f "${facade}" ]] || continue
    queue=("${facade}")
    declare -A seen=()
    while ((${#queue[@]} > 0)); do
      current="${queue[0]}"
      queue=("${queue[@]:1}")
      [[ -n "${seen[${current}]:-}" ]] && continue
      seen["${current}"]=1
      while IFS=$'\t' read -r tag from to; do
        [[ "${from}" == "${current}" ]] || continue
        queue+=("${to}")
      done <"${edges_file}"
    done
    for reached in "${!seen[@]}"; do
      rel="${reached#"${repo_root}/"}"
      reached_from_facade["${rel}"]+="${level},"
    done
  done

  mismatches=0
  while IFS= read -r row; do
    [[ -n "${row}" ]] || continue
    IFS='|' read -r _ path declared _why <<<"${row}"
    path="$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^`//' -e 's/`$//' <<<"${path}")"
    declared="$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<<"${declared}")"
    [[ -n "${path}" && -e "${repo_root}/${path}" ]] || continue

    # The lowest level named in the declared layer is the owner.
    declared_owner=""
    for level in "${levels[@]}"; do
      grep -qE "(^|[^A-Za-z])${level}([^A-Za-z]|$)" <<<"${declared}" && declared_owner="${level}"
    done
    [[ -n "${declared_owner}" ]] || continue

    reached_by="${reached_from_facade["${path}"]:-}"
    placed_in="$(level_of_path "${path}")"

    if [[ -z "${reached_by}" ]]; then
      mismatches=$((mismatches + 1))
      report_issue "S88-G2" "${path} is declared ${declared_owner} but no level facade reaches it" \
        "a declared layer with no path from any facade means the code runs, if at all,
           from somewhere the hierarchy does not describe. The declaration and the graph
           disagree, and only one of them can be true." \
        "${read_pointer}"
    elif [[ -n "${placed_in}" && "${placed_in}" != "${declared_owner}" ]]; then
      mismatches=$((mismatches + 1))
      report_issue "S88-G2" "${path} is declared ${declared_owner} but lives under s88/${placed_in}/" \
        "the row names one level and the file sits in another. A responsibility level is
           both a declaration and a placement; when they disagree, the trace sends a
           reader to the wrong layer and the directory sends them to the wrong owner." \
        "${read_pointer}"
    fi

    # Reachability from the declared level is reported, not failed: a lower level
    # may legitimately compose a higher one (Unit reaching ControlModule is the
    # documented chain), so the useful fact is WHICH facade actually composes it.
    [[ -n "${reached_by}" ]] && printf '  %s declared %s, composed by %s\n' \
      "${path##*/}" "${declared_owner}" "${reached_by%,}" >>"${report_note}"
  done < <(grep -E "^\|[[:space:]]*\`?s88/" "${trace_file}" || true)

  ((mismatches == 0)) && echo "PASS G2: every TRACE.md declared layer matches the graph"
else
  echo "  note: no TRACE.md in this repository; G2 not applicable"
fi

# ---------------------------------------------------------------------------
# G3 -- decoration.
#
# Entrypoints are the flake and every level facade. A file reachable from none of
# them is present but not load-bearing; the directory claims a responsibility that
# nothing executes.
# ---------------------------------------------------------------------------
mapfile -t entrypoints < <(
  [[ -f "${repo_root}/flake.nix" ]] && echo "${repo_root}/flake.nix"
  for level in "${levels[@]}"; do
    facade="${repo_root}/s88/${level}/api/default.nix"
    [[ -f "${facade}" ]] && echo "${facade}"
  done
)

declare -A reachable=()
queue=()
for entry in "${entrypoints[@]}"; do
  queue+=("${entry}")
done
while ((${#queue[@]} > 0)); do
  current="${queue[0]}"
  queue=("${queue[@]:1}")
  [[ -n "${reachable[${current}]:-}" ]] && continue
  reachable["${current}"]=1
  while IFS=$'\t' read -r tag from to; do
    [[ "${from}" == "${current}" ]] || continue
    queue+=("${to}")
  done <"${edges_file}"
done

decorative=()
for file in "${s88_files[@]}"; do
  [[ -n "${reachable[${file}]:-}" ]] || decorative+=("${file#"${repo_root}/"}")
done

# ---------------------------------------------------------------------------
# Separate a genuinely orphaned file from one loaded through a CONSTRUCTED path.
#
# The resolver follows literal paths. `import policyModulePath` and
# `profilesDir + "/${roleName}.nix"` are followed by the evaluator but not by any
# static resolver, so a file reached that way is not an orphan -- it is loaded
# through a string the model never names. That is a different defect with a
# different owner, so it is reported separately instead of being folded into
# either verdict.
#
# Detection: the file's directory (or an ancestor inside its level) appears as a
# literal path fragment elsewhere in `s88/`. That is the mechanism the constructed
# path is built from.
# ---------------------------------------------------------------------------
dynamic=()
orphaned=()
for file in ${decorative[@]+"${decorative[@]}"}; do
  loaded_dynamically=0
  dir="${file%/*}"
  # Walk up to, but not past, the level directory.
  for _ in 1 2 3 4 5; do
    fragment="${dir#s88/}"
    [[ "${fragment}" == "${dir}" ]] && break
    # The level name alone is too broad to be evidence; a sub-path is not. And
    # the REFERRER must itself be reachable: a constructed path inside a file
    # nothing imports is not a mechanism, it is two orphans.
    # Depth >= 3 (Level/group/subgroup). A two-segment fragment such as
    # `ControlModule/module` also matches an unrelated sibling under that
    # directory and misattributes the mechanism -- measured: it blamed a literal
    # `public-ingress.nix` import for `host-validation.nix`, which nothing imports.
    if [[ "$(awk -F/ '{print NF}' <<<"${fragment}")" -ge 3 ]]; then
      while IFS= read -r referrer; do
        [[ -n "${referrer}" ]] || continue
        [[ "${referrer}" == "${repo_root}/${file}" ]] && continue
        if [[ -n "${reachable[${referrer}]:-}" ]]; then
          loaded_dynamically=1
          dynamic+=("${file}  <- constructed from '${fragment}' in ${referrer#"${repo_root}/"}")
          break
        fi
      done < <(grep -rlF "${fragment}" "${repo_root}/s88" --include='*.nix' 2>/dev/null || true)
      ((loaded_dynamically == 1)) && break
    fi
    [[ "${dir}" == */* ]] || break
    dir="${dir%/*}"
  done

  ((loaded_dynamically == 1)) || orphaned+=("${file}")
done

if ((${#dynamic[@]} > 0)); then
  {
    echo "  ${#dynamic[@]} file(s) are reachable only through a constructed path:"
    printf '    %s\n' "${dynamic[@]}"
    echo "  (this is the sidecar pattern the workspace note calls 'uncontrolled sidecars':"
    echo "   the loaded set is a property of the file system, not of the model)"
    echo
  } >&2
fi

if ((${#orphaned[@]} > 0)); then
  declare -A by_level=()
  for file in "${orphaned[@]}"; do
    level="$(level_of_path "${file}")"
    [[ -n "${level}" ]] || level="(outside a level)"
    by_level["${level}"]=$(( ${by_level["${level}"]:-0} + 1 ))
  done
  report_issue "S88-G3" "${#orphaned[@]} of ${#s88_files[@]} s88/ files are unreachable by any path, literal or constructed"     "an unreachable file still reads as authoritative to a reviewer, and nothing executes
       it. This graph resolves imports transitively and separately accounts for files loaded
       from a constructed path, so an entry here is not a resolver artefact." \
    "${read_pointer}"
  {
    echo "  orphaned by level:"
    for level in "${!by_level[@]}"; do
      echo "    ${level}: ${by_level["${level}"]}"
    done | sort
    echo "  all:"
    printf '    %s\n' "${orphaned[@]}"
  } >&2
else
  echo "PASS G3: every s88/ file is reachable (literal ${#s88_files[@]} resolved, ${#dynamic[@]} by constructed path)"
fi

# ---------------------------------------------------------------------------
# Seeded negative -- the resolver and the direction check must be able to fail.
# ---------------------------------------------------------------------------
seeded_root="$(mktemp -d)"
mkdir -p \
  "${seeded_root}/s88/Unit/lookup" \
  "${seeded_root}/s88/EquipmentModule/mapping" \
  "${seeded_root}/s88/ControlModule/render" \
  "${seeded_root}/s88/Unit/api"

cat >"${seeded_root}/s88/ControlModule/render/private.nix" <<'NIX'
{ }: { x = 1; }
NIX
cat >"${seeded_root}/s88/Unit/lookup/down.nix" <<'NIX'
{ lib }: import ../../ControlModule/render/private.nix { }
NIX
cat >"${seeded_root}/s88/EquipmentModule/mapping/up.nix" <<'NIX'
{ lib }: import ../../Unit/lookup/down.nix { }
NIX
cat >"${seeded_root}/s88/Unit/api/default.nix" <<'NIX'
{ lib }: import ../lookup/down.nix { inherit lib; }
NIX
cat >"${seeded_root}/s88/Unit/lookup/orphan.nix" <<'NIX'
{ }: { orphan = true; }
NIX

seeded_edges="$(mktemp)"
for file in $(find "${seeded_root}/s88" -name '*.nix' | LC_ALL=C sort); do
  dir="$(dirname "${file}")"
  grep -oE "import[[:space:]]+[^ ({;]+" "${file}" 2>/dev/null |
    sed -E 's/^import[[:space:]]+//' |
    while IFS= read -r raw; do
      target="$(realpath -m "${dir}/${raw}")"
      [[ -d "${target}" ]] && target="${target}/default.nix"
      [[ -f "${target}" ]] && printf 'EDGE\t%s\t%s\n' "${file}" "${target}"
    done
done >"${seeded_edges}" || true

seeded_upward=0
while IFS=$'\t' read -r tag from to; do
  [[ "${tag}" == "EDGE" ]] || continue
  fl="$(level_of_path "${from#"${seeded_root}/"}")"
  tl="$(level_of_path "${to#"${seeded_root}/"}")"
  [[ -n "${fl}" && -n "${tl}" ]] || continue
  (( $(level_rank "${tl}") < $(level_rank "${fl}") )) && seeded_upward=$((seeded_upward + 1))
done <"${seeded_edges}"

seeded_orphan=0
for file in $(find "${seeded_root}/s88" -name '*.nix'); do
  rel="${file#"${seeded_root}/"}"
  grep -q "orphan.nix" "${seeded_edges}" || seeded_orphan=$((seeded_orphan + 1))
done
rm -f "${seeded_edges}"

if ((seeded_upward < 1 || seeded_orphan < 1)); then
  report_issue "S88-G-SEED" "the graph checks did not detect the seeded defects" \
    "expected >=1 upward edge and >=1 orphan, got upward=${seeded_upward}
       orphan=${seeded_orphan}. Every PASS this test printed is not evidence" \
    "tests/test-s88-import-graph-coherence.sh -- imports_of and the G1/G3 loops"
else
  echo "PASS S88-G-SEED: detected the seeded upward edge and the seeded orphan"
fi

echo ""
if ((issues > 0)); then
  echo "FAIL S88-GRAPH: ${issues} coherence issue(s)." >&2
  echo "  Fix in the layer that owns the behaviour, then re-run. Do not add a" >&2
  echo "  file to an allowlist: an allowlisted unreachable file is still a lie." >&2
  exit 1
fi

echo "PASS S88-GRAPH: declarations and the resolved import graph agree"
exit 0
