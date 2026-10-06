#!/usr/bin/env bash
# Tenant-isolation ratchet (ADR-0001 §4.3).
#
# Counts raw SQL statements in non-test Go code outside internal/tenancy that
# are neither written through the scoped layer nor marked
# "// TENANT-EXEMPT: <reason>" on the same or one of the three preceding
# lines. The count may only go down: CI fails if it exceeds the recorded
# baseline. After migrating callers, lower the baseline with --update.
set -euo pipefail
cd "$(dirname "$0")/.."
baseline_file=scripts/tenant-exempt-baseline.txt

count=$(git ls-files '*.go' \
  | grep -v '_test\.go$' \
  | grep -v '^internal/tenancy/' \
  | grep -v '^tests/' \
  | xargs awk '
      FNR == 1 { h1 = h2 = h3 = "" }
      {
        line = $0
        if (line ~ /(SELECT[[:space:]][^"`]*FROM|UPDATE[[:space:]]+[a-z_."]+[[:space:]]+SET|DELETE[[:space:]]+FROM|INSERT[[:space:]]+INTO)/ \
            && line !~ /TENANT-EXEMPT/ && h1 !~ /TENANT-EXEMPT/ && h2 !~ /TENANT-EXEMPT/ && h3 !~ /TENANT-EXEMPT/ \
            && line !~ /^[[:space:]]*\/\//) n++
        h3 = h2; h2 = h1; h1 = line
      }
      END { print n + 0 }')

if [[ "${1:-}" == "--update" ]]; then
  echo "$count" > "$baseline_file"
  echo "tenant-exempt baseline set to $count"
  exit 0
fi

baseline=$(cat "$baseline_file")
echo "unscoped raw SQL statements: $count (baseline $baseline)"
if (( count > baseline )); then
  echo "New raw SQL outside internal/tenancy without a TENANT-EXEMPT reason." >&2
  echo "Use the tenancy package, or add '// TENANT-EXEMPT: <reason>'." >&2
  exit 1
fi
