#!/usr/bin/env bash
# Tenant-isolation ratchet (ADR-0001 §4.3).
#
# Counts raw SQL statements in non-test Go code outside internal/tenancy that
# are neither handed to the scoped layer (tenancy.Exec/Query/QueryRow[Context],
# tenancy.InsertContext, tenancy.GormExec/GormRaw,
# database.queryScoped/insertScoped) nor marked
# "// TENANT-EXEMPT: <reason>" on the same or one of the three preceding
# lines. The count may only go down: CI fails if it exceeds the recorded
# baseline. After migrating callers, lower the baseline with --update.
set -euo pipefail
cd "$(dirname "$0")/.."
baseline_file=scripts/tenant-exempt-baseline.txt

# Packages whose every query runs on the transaction tenancy.RLSTransaction
# opens (app.workspace_id set, role authsec_tenant), so row-level security
# scopes them whatever the SQL text says. Their raw SQL is not counted, but
# the package may reach the database through RLSTransaction only: any other
# use of a DB handle fails the check.
rls_only=(internal/igaread internal/k8sread)
for pkg in "${rls_only[@]}"; do
  other=$(git ls-files "$pkg/*.go" | grep -v '_test\.go$' \
    | xargs grep -nE '(\br\.db\b|\bconfig\.(DB|GetDatabase)\b|\b(gorm|sql)\.Open\(|tenancy\.(Transaction|DB|DBContext|Exec|Query|QueryRow)(Context)?\()' \
    | grep -v 'tenancy\.RLSTransaction(' || true)
  if [[ -n "$other" ]]; then
    echo "$pkg is RLS-only but reaches the database another way:" >&2
    echo "$other" >&2
    exit 1
  fi
done
rls_only_re="^($(IFS='|'; echo "${rls_only[*]}"))/"

count=$(git ls-files '*.go' \
  | grep -v '_test\.go$' \
  | grep -v '^internal/tenancy/' \
  | grep -v '^tests/' \
  | grep -vE "$rls_only_re" \
  | xargs awk '
      BEGIN {
        # A statement handed straight to the scoped layer binds workspace_id
        # to $1 from the tenant context, checked at run time, and is not
        # counted: the statement on the call line or continuing its argument
        # list, including a multi-line SQL string up to its closing backtick.
        scoped = "(tenancy\\.(Exec|Query|QueryRow|Insert|GormExec|GormRaw)(Context)?|queryScoped|insertScoped)\\("
      }
      FNR == 1 { h1 = h2 = h3 = ""; instr = 0; cover = 0 }
      {
        line = $0
        tmp = line
        ticks = gsub(/`/, "", tmp)
        # The call is this line, or an earlier line whose argument list
        # visibly continues onto this one (it ends in "(" or ",").
        call = line ~ scoped || (h1 ~ scoped && h1 ~ /[(,][[:space:]]*$/) \
            || (h2 ~ scoped && h2 ~ /[(,][[:space:]]*$/ && h1 ~ /,[[:space:]]*$/)
        # A statement marked TENANT-EXEMPT (on its line or the three above)
        # covers its multi-line SQL string the same way.
        exempt = line ~ /TENANT-EXEMPT/ || h1 ~ /TENANT-EXEMPT/ || h2 ~ /TENANT-EXEMPT/ || h3 ~ /TENANT-EXEMPT/
        # Every raw string is tracked, so a closing backtick is never taken
        # for an opening one; coverage is decided when a string opens.
        closing = 0
        if (ticks % 2 == 1) {
          if (!instr) { instr = 1; cover = (call || exempt) } else closing = 1
        }
        skip = call || (instr && cover)
        if (closing) { instr = 0; cover = 0 }
        if (!skip && line ~ /(SELECT[[:space:]][^"`]*FROM|UPDATE[[:space:]]+[a-z_."]+[[:space:]]+SET|DELETE[[:space:]]+FROM|INSERT[[:space:]]+INTO)/ \
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
