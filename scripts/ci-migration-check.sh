#!/usr/bin/env bash
# Refuse the two migration mistakes this repo has actually made.
#
# Both were found by hand in September 2026, both on a branch that looked ready
# to merge, and both would have failed at RUNTIME on a real database rather than
# in review:
#
#   1. Two files sharing a numeric prefix. The runner dedupes on (version, name)
#      and orders with an unstable sort, so both run in undefined order. One
#      branch added its own 006 while 006_discovery_owns_github.sql was already
#      merged.
#
#   2. A file wrapping itself in BEGIN/COMMIT. The runner already opens a
#      transaction per file, so an inner BEGIN ends the runner's own early and
#      its commit then fails with "unexpected transaction status idle".
#      006_discovery_owns_github.sql documents this in its own header, and a
#      later branch did it anyway.
#
# Neither is a matter of taste, and both are one grep. Checked here so nobody
# has to remember.
set -euo pipefail

DIR="migrations/master"
fail=0

echo "== duplicate version prefixes =="
dupes="$(find "$DIR" -name '*.sql' -type f -exec basename {} \; \
  | sed -E 's/^([0-9]+)_.*/\1/' | sort | uniq -d)"
if [ -n "$dupes" ]; then
  fail=1
  for v in $dupes; do
    echo "FAIL: version $v is used by more than one migration:"
    find "$DIR" -name "${v}_*.sql" -exec basename {} \; | sed 's/^/    /'
  done
  echo "    The runner dedupes on (version, name) and sorts unstably, so both"
  echo "    would run in undefined order. Renumber to the next free version."
else
  echo "ok: every version prefix is unique"
fi

echo
echo "== self-transacting migrations =="
found=0
while IFS= read -r f; do
  # Only a statement-position BEGIN/COMMIT matters. A PL/pgSQL DO block's own
  # BEGIN is indented inside $$ ... $$ and is legitimate, so anchor to column 0.
  if grep -qiE '^[[:space:]]*(BEGIN|COMMIT)[[:space:]]*;' "$f"; then
    fail=1; found=1
    echo "FAIL: $(basename "$f") opens or closes its own transaction:"
    grep -niE '^[[:space:]]*(BEGIN|COMMIT)[[:space:]]*;' "$f" | sed 's/^/    line /'
  fi
done < <(find "$DIR" -name '*.sql' -type f | sort)
[ "$found" -eq 0 ] && echo "ok: no migration manages its own transaction"

echo
if [ "$fail" -ne 0 ]; then
  echo "Migration hygiene FAILED."
  exit 1
fi
echo "Migration hygiene passed."
