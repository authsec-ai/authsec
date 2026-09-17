#!/usr/bin/env bash
# Refuse an ad-hoc join from IGA code into a legacy table.
#
# IGA lives in the same binary, the same database and the same `public` schema
# as everything else, so nothing in PostgreSQL stops an IGA query naming
# `workspaces` or `users` directly. A database privilege would, but it cannot be
# used here: `discovered_agent_iga_links` deliberately foreign-keys the IGA
# estate to the legacy runtime channel, and a role without a grant on `public`
# would forbid that designed join along with every careless one.
#
# So the boundary is a convention, and this is what enforces it. The rule:
#
#   Legacy coupling goes through a NAMED BRIDGE TABLE carrying its own state,
#   evidence and decision record -- the discovered_agent_iga_links pattern --
#   never through a table name typed into an IGA query.
#
# Why it matters beyond tidiness: every such join is a dependency nobody
# declared, and the eventual move of IGA to its own database costs exactly as
# much as the number of them. Keeping the count at zero keeps that move a
# pg_dump instead of a rewrite.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Files that are IGA's own. Anything here may name iga_* freely and nothing else.
# No mapfile: macOS ships bash 3.2, and this has to run on a developer's laptop
# as readily as in CI.
IGA_FILES=""
while IFS= read -r f; do
  IGA_FILES="${IGA_FILES}${f}
"
done < <(
  find repository services controllers models -type f -name '*.go' 2>/dev/null \
    | grep -E '/(iga_[a-z_]*|[a-z_]*_iga)[a-z_]*\.go$' \
    | grep -v '_test\.go$' \
    | sort
)
FILE_COUNT=$(printf '%s' "$IGA_FILES" | grep -c . || true)

# Tables an IGA file may name even though they are not iga_*.
#
# Keep this SHORT and justify every entry. An allowlist that grows without
# argument is the convention failing quietly, which is the thing the check
# exists to prevent.
ALLOWED_NON_IGA=(
  # The bridge itself. It is the sanctioned seam between the runtime channel
  # and the correlated estate, with its own state machine and decision record.
  "discovered_agent_iga_links"
)

echo "== IGA isolation =="
echo "scanning ${FILE_COUNT} IGA source files"

fail=0
found=0
VIOLATIONS="$(mktemp)"

printf '%s' "$IGA_FILES" | while IFS= read -r f; do
  [ -n "$f" ] || continue
  # Table names in SQL positions only: FROM/JOIN/INTO/UPDATE followed by an
  # identifier. Deliberately not every string that looks like a table -- a
  # comment mentioning `workspaces` is not a query.
  while IFS= read -r ref; do
    table="${ref##* }"
    table="${table#public.}"

    # IGA's own tables are the point of the file.
    [[ "$table" == iga_* ]] && continue
    # Not a table: SQL keywords and CTE noise that follow the same words.
    [[ "$table" =~ ^(SELECT|select|VALUES|values|LATERAL|lateral|\(.*)$ ]] && continue

    allowed=0
    for a in "${ALLOWED_NON_IGA[@]}"; do
      [[ "$table" == "$a" ]] && allowed=1 && break
    done
    [ "$allowed" -eq 1 ] && continue

    echo "FAIL: $f names non-IGA table '$table'"
    grep -nE "(FROM|JOIN|INTO|UPDATE)[[:space:]]+(public\.)?${table}\b" "$f" \
      | head -3 | sed 's/^/    line /'
  done < <(
    # Strip line comments first. Prose about the rule is not a breach of it:
    # this check own justification mentions joining the users table, and
    # scanning comments made the file that explains the boundary fail it.
    sed -e 's://.*::' "$f" \
      | grep -ohE '(FROM|JOIN|INTO|UPDATE)[[:space:]]+(public\.)?[a-z_][a-z0-9_]*' \
      | tr -s ' ' | sort -u
  )
done > "$VIOLATIONS"

# The loop above runs in a subshell (it is the right-hand side of a pipe), so
# its `fail` never reaches here. The file is the channel that does.
if [ -s "$VIOLATIONS" ]; then
  fail=1; found=1
  cat "$VIOLATIONS"
fi
rm -f "$VIOLATIONS"

if [ "$found" -eq 0 ]; then
  echo "ok: no IGA file names a legacy table outside the allowlist"
  echo "    (allowlist: ${ALLOWED_NON_IGA[*]})"
fi

echo
if [ "$fail" -ne 0 ]; then
  cat <<'MSG'
IGA isolation FAILED.

A legacy table named directly from IGA code is coupling nobody declared. If the
join is genuinely required, route it through a bridge table that records its own
state and evidence, as discovered_agent_iga_links does -- then add that bridge
to ALLOWED_NON_IGA with a sentence saying why.
MSG
  exit 1
fi
echo "IGA isolation passed."
