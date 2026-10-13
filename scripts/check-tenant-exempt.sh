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

# Quarantine (AS-108): files merged from authsec-staging (IGA governance,
# Slack, cloud evidence) before they were moved onto the scoped layer. Their
# statements are counted apart, against their own baseline, which may only go
# down; no file may be added to the list. Every other file is held to the
# main baseline (0).
quarantine_file=scripts/tenant-exempt-quarantine.txt
quarantine_baseline_file=scripts/tenant-exempt-quarantine-baseline.txt

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

hits=$(git ls-files '*.go' \
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
      FNR == 1 { for (v in pend) { print prevfile; delete pend[v] }; h1 = h2 = h3 = ""; instr = 0; cover = 0; svar = ""; prevfile = FILENAME }
      END { for (v in pend) print prevfile }
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
          if (!instr) {
            instr = 1; cover = (call || exempt); acc = ""; hit = 0; svar = ""
            if (match(line, /[A-Za-z_][A-Za-z0-9_]*[[:space:]]*:?=[[:space:]]*`/)) {
              svar = substr(line, RSTART, RLENGTH); sub(/[[:space:]]*:?=.*/, "", svar)
            }
          } else closing = 1
        }
        skip = call || (instr && cover)
        if (instr) acc = acc " " line
        if (!skip && line ~ /(SELECT[[:space:]][^"`]*FROM|UPDATE[[:space:]]+[a-z_."]+[[:space:]]+SET|DELETE[[:space:]]+FROM|INSERT[[:space:]]+INTO)/ \
            && line !~ /TENANT-EXEMPT/ && h1 !~ /TENANT-EXEMPT/ && h2 !~ /TENANT-EXEMPT/ && h3 !~ /TENANT-EXEMPT/ \
            && line !~ /^[[:space:]]*\/\//) { print FILENAME; if (instr) hit = 1 }
        # A statement whose keywords sit on different lines of one raw string
        # (UPDATE t / SET ..., SELECT ... / FROM ...) is judged on the whole
        # string when it closes.
        # A string assigned to a variable (q := `...`) and handed to a scoped
        # call within the next 25 lines is covered by that call.
        if (closing) {
          if (!cover && !hit && acc !~ /TENANT-EXEMPT/ \
              && acc ~ /(SELECT[[:space:]].*[[:space:]]FROM[[:space:]]|UPDATE[[:space:]]+[a-z_."]+[[:space:]]+SET[[:space:]]|DELETE[[:space:]]+FROM[[:space:]]|INSERT[[:space:]]+INTO[[:space:]])/) {
            if (svar != "") { pend[svar] = FNR } else print FILENAME
          }
          instr = 0; cover = 0
        }
        for (v in pend) {
          if (line ~ scoped && index(line, v) > 0) delete pend[v]
          else if (FNR - pend[v] > 25) { print FILENAME; delete pend[v] }
        }
        h3 = h2; h2 = h1; h1 = line
      }')

quarantined=$(grep -vE '^[[:space:]]*(#|$)' "$quarantine_file" || true)
if [[ -n "$quarantined" ]]; then
  qcount=$(grep -cxF -f <(echo "$quarantined") <<<"$hits" || true)
  count=$(grep -cvxF -f <(echo "$quarantined") <<<"$hits" || true)
else
  qcount=0
  count=$(grep -c . <<<"$hits" || true)
fi

if [[ "${1:-}" == "--update" ]]; then
  echo "$count" > "$baseline_file"
  echo "$qcount" > "$quarantine_baseline_file"
  echo "tenant-exempt baseline set to $count (quarantine $qcount)"
  exit 0
fi

qbaseline=$(cat "$quarantine_baseline_file")
echo "quarantined unscoped raw SQL statements: $qcount (baseline $qbaseline)"
if (( qcount > qbaseline )); then
  echo "New raw SQL in a quarantined file (see $quarantine_file)." >&2
  echo "Use the tenancy package, or add '// TENANT-EXEMPT: <reason>'." >&2
  exit 1
fi

baseline=$(cat "$baseline_file")
echo "unscoped raw SQL statements: $count (baseline $baseline)"
if (( count > baseline )); then
  echo "New raw SQL outside internal/tenancy without a TENANT-EXEMPT reason." >&2
  echo "Use the tenancy package, or add '// TENANT-EXEMPT: <reason>'." >&2
  exit 1
fi
