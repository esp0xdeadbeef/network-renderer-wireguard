#!/usr/bin/env bash
# GAMP-SCOPE: repository readability guard; not SMT acceptance evidence
#
# NO SINGLE-LETTER LET BINDINGS.
#
# A `let` binding names a value so the expression that follows can be read
# without holding a shape in your head. A one-letter name does not do that: it
# replaces a description with a symbol, so the reader has to scroll back to the
# binding to learn what `n` is on every use.
#
# This is not a style preference. The suffix-match this check was written after
# looked like this:
#
#     suffix = "-" + logicalName;
#     n = builtins.stringLength target;
#     m = builtins.stringLength suffix;
#   in
#   n > m && builtins.substring (n - m) m target == suffix
#
# Every name is one letter, so an off-by-one in `n > m` reads as arithmetic
# rather than as "the target must be longer than the suffix". It took a
# cross-repository route comparison to notice the selection had been silently
# matching the wrong records for months. `targetLength`, `suffixLength`, and
# `targetLength > suffixLength` would have made the same bug visible in review.
#
# WHAT IS CHECKED
# ---------------
# A `let` binding whose name is a single letter. Nothing else:
#
#   - lambda parameters are NOT flagged. `map (x: f x)` is an idiom, not a name.
#   - a BRACE PATTERN whose fields are single letters IS flagged (`{ a, b }:`,
#     `{ a, b, ... }:`). Those fields are parameters of a record, so they name
#     things the same way a binding does; `adjacenciesForPair { a, b }` became
#     `{ firstUnit, secondUnit }` under this rule.
#   - attribute names are NOT flagged. `{ a = 1; }` is data, and a field called
#     `a` is the data's business.
#   - `inherit` is NOT flagged.
#
# The distinction is the point: a binding is a *description* the author owes the
# reader; a parameter or a field is not.
#
# Evidence boundary: construction. Static file reads only.
set -euo pipefail

if [[ -n "${SMS_TEST_REPO_ROOT:-}" ]]; then
  repo_root="${SMS_TEST_REPO_ROOT}"
else
  repo_root="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null || true)"
  if [[ -z "${repo_root}" ]]; then
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  fi
fi

echo "--- NO-SINGLE-LETTER: let bindings name what they bind ---"
echo ""

# ---------------------------------------------------------------------------
# The scanner. It tracks two things per file, which is what makes the result
# precise enough to gate on:
#
#   in_let  increments on a `let` that ends a line, decrements on a line that
#           starts with `in`. Only the region between them is binding position.
#   depth   `{` minus `}`. A single-letter *field* inside an attribute set that
#           happens to sit inside a let block is not a binding, and without the
#           depth counter it would be flagged.
#
# Both counters are why this is a scanner and not a grep: `^\s+\w =` alone
# reports every `{ a = ...; }` in the tree.
# ---------------------------------------------------------------------------
scan_bindings() {
  local root="$1"
  # Only existing trees: `find` exits non-zero for a missing path, and under
  # `set -o pipefail` that aborted the caller before it could report anything.
  # A repository without a lib/ is normal (wireguard measured).
  local trees=()
  for tree in s88 lib; do
    [[ -d "${root}/${tree}" ]] && trees+=("${root}/${tree}")
  done
  ((${#trees[@]} > 0)) || return 0
  find "${trees[@]}" -name '*.nix' -type f 2>/dev/null |
    LC_ALL=C sort |
    while IFS= read -r file; do
      awk -v file="${file#"${root}"/}" '
        BEGIN { in_let = 0; depth = 0 }
        {
          code = $0
          sub(/#.*/, "", code)

          if (in_let > 0 && code ~ /^[[:space:]]*in([[:space:]]|$)/) in_let--

          if (in_let > 0 && depth == 0 && code ~ /^[[:space:]]+[a-zA-Z][[:space:]]*=/) {
            printf "%s:%d:%s\n", file, FNR, $0
          }

          # A brace list immediately followed by `:` is a function argument
          # pattern (`{ a, b }:`), so its fields name things the way a binding
          # does. The trailing colon is what makes this precise: `${b}` is an
          # interpolation and `{ a = 1; }` is data, and neither is followed by a
          # colon. Measured: without it, every `"${x}"` in the tree was flagged.
          if (match(code, /\{[^{}]*\}[[:space:]]*:/)) {
            pattern = substr(code, RSTART, RLENGTH)
            sub(/[[:space:]]*:$/, "", pattern)
            gsub(/[{}]/, "", pattern)
            fieldCount = split(pattern, fields, ",")
            for (i = 1; i <= fieldCount; i++) {
              field = fields[i]
              gsub(/^[[:space:]]+/, "", field)
              gsub(/[[:space:]]+$/, "", field)
              if (field ~ /^[a-zA-Z]$/) {
                printf "%s:%d:%s\n", file, FNR, $0
                break
              }
            }
          }

          opens = gsub(/\{/, "{", code)
          closes = gsub(/\}/, "}", code)
          depth += opens - closes
          if (depth < 0) depth = 0

          if (code ~ /(^|[[:space:]])let[[:space:]]*$/) in_let++
        }
      ' "${file}"
    done
}

mapfile -t hits < <(scan_bindings "${repo_root}")

issues=0
if ((${#hits[@]} > 0)); then
  issues=$((issues + 1))
  declare -A per_file=()
  for hit in "${hits[@]}"; do
    path="${hit%%:*}"
    per_file["${path}"]=$(( ${per_file["${path}"]:-0} + 1 ))
  done
  {
    echo "ISSUE: ${#hits[@]} single-letter name(s) in ${#per_file[@]} file(s) (let bindings or brace-pattern fields)"
    for path in "${!per_file[@]}"; do
      echo "    ${path} (${per_file["${path}"]})"
    done | sort
    echo
    echo "  why:  a binding exists to name a value. One letter moves the meaning back"
    echo "        into the reader's head and hides arithmetic that is easier to get"
    echo "        wrong than to read. See this file's header for the bug that cost."
    echo "  fix:  rename to what the value is -- \`n = builtins.length list\` becomes"
    echo "        \`count = builtins.length list\`; \`a\`/\`b\` from \`elemAt\` become"
    echo "        \`first\`/\`second\` (or destructure the list once)."
    echo
    echo "  every hit:"
    printf '    %s\n' "${hits[@]}"
  } >&2
else
  echo "PASS: no single-letter let binding in s88/ or lib/"
fi

# ---------------------------------------------------------------------------
# Seeded negatives. A guard that cannot tell a binding from a field would either
# fail every attribute set or pass every binding, and both are worse than no
# guard, so both directions are asserted.
# ---------------------------------------------------------------------------
seeded_root="$(mktemp -d)"
trap 'rm -rf "${seeded_root}"' EXIT
mkdir -p "${seeded_root}/s88"

cat >"${seeded_root}/s88/seeded-bad.nix" <<'NIX'
{ lib }:
let
  n = builtins.length [ 1 ];
  m = n + 1;
in
m
NIX

cat >"${seeded_root}/s88/seeded-pattern.nix" <<'NIX'
{ lib }:
let
  pair =
    { a, b }:
    [ a b ];
in
pair { a = 1; b = 2; }
NIX

cat >"${seeded_root}/s88/seeded-ok.nix" <<'NIX'
{ lib }:
let
  records = {
    a = 1;
    b = 2;
  };
  rendered = map (x: x) [ 1 ];
in
records // { inherit rendered; }
NIX

seeded_hits="$(scan_bindings "${seeded_root}" | wc -l)"

if ((seeded_hits != 3)); then
  issues=$((issues + 1))
  {
    echo "ISSUE NO-SINGLE-LETTER-SEED: the scanner reported ${seeded_hits} hit(s) on the fixture, expected 3"
    echo "  the fixture binds \`n\` and \`m\` in a let and declares \`{ a, b }\` as a"
    echo "  attribute set with single-letter fields and a single-letter lambda"
    echo "  parameter (must not be). A number other than 2 means this guard is"
    echo "  either missing bindings or accusing data fields, and every verdict above"
    echo "  is therefore not evidence."
  } >&2
else
  echo "PASS NO-SINGLE-LETTER-SEED: found the 2 bindings and the brace pattern, ignored the data fields and the lambda parameter"
fi

echo ""
if ((issues > 0)); then
  echo "FAIL NO-SINGLE-LETTER: ${issues} issue(s)." >&2
  echo "  Rename the binding, do not add it to an allowlist: an allowlisted"
  echo "  one-letter binding is still unreadable." >&2
  exit 1
fi

echo "PASS NO-SINGLE-LETTER: every let binding names what it binds"
exit 0
