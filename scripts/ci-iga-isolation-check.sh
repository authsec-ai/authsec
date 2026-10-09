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
# IGA_ISOLATION_ROOT runs the check over another tree (the check's own test
# plants violations in a scratch tree; CI never sets it).
ROOT="${IGA_ISOLATION_ROOT:-$ROOT}"
cd "$ROOT"

# ---------------------------------------------------------------------------
# SCOPE IS DECIDED BY CONTENT AND PACKAGE, NOT BY FILE NAME.
#
# A file is IGA code, and is checked, when ANY of these holds:
#   1. it is in an IGA package (IGA_PACKAGES below) -- whatever it is called;
#   2. its code (comments stripped) names an iga_* table in a SQL position
#      (FROM / JOIN / INTO / UPDATE, or gorm .Table("iga_...")), wherever it
#      lives: a reader of shared tables that also reads the graph is IGA code
#      for this purpose, whatever its file is called;
#   3. its name is iga_*.go / *_iga.go under repository, services, controllers
#      or models (the original rule, kept so a new empty-of-SQL IGA file is
#      still in scope).
# Test files are not scanned.
IGA_PACKAGES="internal/igagov internal/igagraph internal/igaread"

# Every non-iga table a checked file may name, with its access mode -- r
# (read-only) or rw -- and the reason it is a designed seam rather than an
# undeclared dependency. Keep this SHORT and justify every entry. An allowlist
# that grows without argument is the convention failing quietly, which is the
# thing the check exists to prevent. Any table not listed here, named by a
# checked file, fails the check; a write (INSERT INTO / UPDATE / DELETE FROM)
# to an r table fails unless the (file, table) pair is in WRITE_ALLOWED.
ALLOWED_SHARED=(
  # The bridge between the runtime channel and the correlated estate, with its
  # own state machine and decision record (the sanctioned seam).
  "discovered_agent_iga_links:rw"

  # The scan lifecycle the pipeline barrier coordinates. §2.10A's abandon
  # transition terminalizes the scan run AND its projection job in ONE
  # transaction; splitting the run update out would break that guarantee.
  "cloud_scan_run:rw"

  # The evidence store. iga_access_edge_evidence / iga_relationship_evidence
  # FK observation_id straight to cloud_observation (031); the read path joins
  # it for provenance and Phase 3 reads it for deployment drift and verify
  # evidence. Read-only (the one-way rule below also forbids writes from the
  # projection).
  "cloud_observation:r"

  # The rest of the AWS collected model the projection and policy READ (§2.5,
  # §3.9): the connector (scope, status, selected regions), IAM role inventory
  # (CreateDate, RoleId incarnation), Access Advisor rows, cross-account trust
  # edges, workloads, and the immutable resource-policy evidence. cloud_* is
  # authoritative and iga_* is derived from it; reading it is the design.
  # Writes are the collectors' own (WRITE_ALLOWED).
  "cloud_connector:r"
  "cloud_identity:r"
  "cloud_usage:r"
  "cloud_assume_edge:r"
  "cloud_workload:r"
  "cloud_policy_document:r"
  "cloud_resource_policy_coverage:r"
  "cloud_resource_policy_observation:r"

  # Phase 3's own tables whose names the spec fixed without the iga_ prefix
  # (053 cloud_enforcement_binding, 054 slack_user_link and
  # workspace_slack_integration). Written only by their owning services
  # (WRITE_ALLOWED).
  "cloud_enforcement_binding:r"
  "slack_user_link:r"
  "workspace_slack_integration:r"

  # The GitHub / Kubernetes collected model: discovery sources and their scan
  # runs (the IaC source FK, the connections view) and the repository / k8s
  # sightings the GitHub and Kubernetes projections read, as the AWS
  # projection reads cloud_*. Read-only, except the k8s sweep's own source
  # bookkeeping (WRITE_ALLOWED).
  "discovery_sources:r"
  "discovery_scan_runs:r"
  "discovered_agents:r"

  # The authorization check for a human decision (§2.14.3, §2.10) and the
  # member's display name / email for owners, approvers and notifications.
  # Membership and identity live here; a bridge would be a cached copy of an
  # authorization answer, the thing least safe to cache. Read-only.
  "workspace_memberships:r"
  "users:r"
)

# The only writes a checked file may make to an r table: (file, table), each
# by the component that owns that table.
WRITE_ALLOWED=(
  # The resource-policy collector's repository (T3.03b) writes its own
  # evidence; it names iga_* only to keep evidence a plan still references.
  "repository/cloud_resource_policy_repository.go:cloud_policy_document"
  "repository/cloud_resource_policy_repository.go:cloud_resource_policy_coverage"
  "repository/cloud_resource_policy_repository.go:cloud_resource_policy_observation"
  # The workload collector's repository writes its workloads; it reads
  # iga_gov_control only to prioritise activity collection for controlled roles.
  "repository/cloud_workload_repository.go:cloud_workload"
  # The enforcement binding service owns 053's binding table.
  "services/cloud_enforcement_binding_service.go:cloud_enforcement_binding"
  # The Slack integration owns 054's tables.
  "services/slack_integration_service.go:slack_user_link"
  "services/slack_integration_service.go:workspace_slack_integration"
  "services/slack_integration_channel.go:slack_user_link"
  "services/slack_integration_channel.go:workspace_slack_integration"
  # The Kubernetes sweep records its progress on its own discovery source.
  "services/k8s_rbac_service.go:discovery_sources"
)

# Files that name an iga_* table but are NOT IGA code, so rule 2 (scope by
# content) must not pull them in. Keep this to purges of a whole workspace.
NOT_IGA=(
  # The workspace purge (DeleteTenant): it deletes EVERY table of a
  # workspace -- auth, RBAC and IGA alike -- in one transaction, by design.
  # It names iga_lifecycle_event only to delete it before workspaces, around
  # 036's RESTRICT FK (D-94). Review fix P0-1.
  "database/workspace_repository.go"
)

echo "== IGA isolation =="

fail=0
# The SQL reading is one perl pass (perl ships with git, macOS and every CI
# image; a per-file pipeline of greps took minutes on Windows). Line comments
# are stripped first: prose about a table is not a query. It reads a file
# list on stdin and, per file:
#   names <file>        -- scope mode: the file names an iga_* table
#   T <file> <table>    -- a table named in a SQL position: FROM / JOIN /
#                          INTO / UPDATE followed by an identifier that is not
#                          a function call, not alias.column and not one of
#                          the file's own CTEs (`name AS (`, `name(cols) AS (`,
#                          the igaread builder's addWith("name", ...)); or
#                          gorm's .Table("name")
#   W <file> <table>    -- a write: INSERT INTO / UPDATE / DELETE FROM <table>
SQLSCAN='
my $mode = shift @ARGV;
while (my $f = <STDIN>) {
  chomp $f; $f =~ s/\r$//;
  next unless length $f;
  open(my $h, "<", $f) or next;
  local $/; my $s = <$h>; close $h;
  $s =~ s{//[^\n]*}{}g;
  if ($mode eq "names") {
    print "$f\n" if $s =~ /(?:FROM|JOIN|INTO|UPDATE)\s+(?:public\.)?iga_[a-z0-9_]+|\.Table\("iga_[a-z0-9_]+/;
    next;
  }
  my %cte;
  $cte{$1} = 1 while $s =~ /\b([a-z_][a-z0-9_]*)\s*(?:\([a-z0-9_, ]*\))?\s+AS\s+(?:NOT\s+)?(?:MATERIALIZED\s+)?\(/g;
  $cte{$1} = 1 while $s =~ /addWith\([`"]([a-z_][a-z0-9_]*)/g;
  my (%t, %w);
  $t{$1} = 1 while $s =~ /(?:FROM|JOIN|INTO|UPDATE)\s+(?:public\.)?([a-z_][a-z0-9_]*)(?![a-z0-9_]|\s*[(.])/g;
  $t{$1} = 1 while $s =~ /\.Table\("([a-z_][a-z0-9_]*)"/g;
  $w{$1} = 1 while $s =~ /(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(?:public\.)?([a-z_][a-z0-9_]*)(?![a-z0-9_]|\s*[(.])/g;
  for my $x (sort keys %t) { print "T $f $x\n" unless $x =~ /^iga_/ || $cte{$x}; }
  for my $x (sort keys %w) { print "W $f $x\n" unless $x =~ /^iga_/ || $cte{$x}; }
}
'

IGA_FILES="$(
  {
    for p in $IGA_PACKAGES; do
      [ -d "$p" ] && find "$p" -type f -name '*.go'
    done
    find repository services controllers models -type f -name '*.go' 2>/dev/null \
      | grep -E '/(iga_[a-z_]*|[a-z_]*_iga)[a-z_]*\.go$'
    # Candidates by one recursive grep (comments included), confirmed by the
    # perl pass with comments stripped.
    grep -rlE --include='*.go' --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules \
        'iga_[a-z0-9_]+' . 2>/dev/null | sed 's|^\./||' | perl -e "$SQLSCAN" names
  } | grep -v '_test\.go$' | sort -u | grep -vxF -f <(printf '%s
' "${NOT_IGA[@]}")
)"
FILE_COUNT=$(printf '%s\n' "$IGA_FILES" | grep -c . || true)
echo "scanning ${FILE_COUNT} IGA source files (by package, content and name)"

mode_of() { # table -> r | rw | "" (not allowed)
  local a
  for a in "${ALLOWED_SHARED[@]}"; do
    [ "${a%%:*}" == "$1" ] && { echo "${a##*:}"; return; }
  done
  echo ""
}

write_allowed() { # file table
  local a
  for a in "${WRITE_ALLOWED[@]}"; do
    [ "$a" == "$1:$2" ] && return 0
  done
  return 1
}

VIOLATIONS="$(mktemp)"
printf '%s\n' "$IGA_FILES" | perl -e "$SQLSCAN" tables | while read -r kind f table; do
  mode="$(mode_of "$table")"
  case "$kind" in
    T)
      if [ -z "$mode" ]; then
        echo "FAIL: $f names non-IGA table '$table' (not in ALLOWED_SHARED)"
        grep -nE "((FROM|JOIN|INTO|UPDATE)[[:space:]]+(public\.)?${table}\b|\.Table\(\"${table}\")" "$f" \
          | head -3 | sed 's/^/    line /'
      fi ;;
    W)
      if [ "$mode" == "r" ] && ! write_allowed "$f" "$table"; then
        echo "FAIL: $f writes '$table', which IGA code may only read (not in WRITE_ALLOWED)"
        grep -nE "(INSERT[[:space:]]+INTO|UPDATE|DELETE[[:space:]]+FROM)[[:space:]]+(public\.)?${table}\b" "$f" \
          | head -3 | sed 's/^/    line /'
      fi ;;
  esac
done > "$VIOLATIONS"

if [ -s "$VIOLATIONS" ]; then
  fail=1
  cat "$VIOLATIONS"
else
  echo "ok: no IGA file names a table outside iga_* and ALLOWED_SHARED, or writes a read-only one"
  echo "    (allowed: ${ALLOWED_SHARED[*]})"
fi
rm -f "$VIOLATIONS"

# ---------------------------------------------------------------------------
# P2-1 -- THE PROJECTION IS ONE-WAY.
#
# cloud_* is the authoritative collected model; iga_* is a projection of it,
# rebuildable at any time by deleting every iga_* row and re-projecting. That
# guarantee holds only while NOTHING writes cloud_* from the graph side: a
# single write back makes the two mutually dependent, and "rebuildable from
# evidence" stops being true the moment a rebuild would lose something.
#
# Kept a grep on purpose. A database privilege cannot tell a designed join from
# a careless one -- the same reasoning recorded in roadmap section 2.1 and in
# this file's own header.
echo
echo "== projection is one-way =="

GRAPH_FILES=""
while IFS= read -r f; do
  GRAPH_FILES="${GRAPH_FILES}${f}
"
done < <(
  { find internal/igagraph -type f -name '*.go' 2>/dev/null
    find . -type f -name '*projector*.go' -not -path './.git/*' 2>/dev/null | sed 's|^\./||'
  } | grep -v '_test\.go$' | sort -u
)
GRAPH_COUNT=$(printf '%s' "$GRAPH_FILES" | grep -c . || true)
echo "scanning ${GRAPH_COUNT} projection source files"

ONEWAY="$(mktemp)"
printf '%s' "$GRAPH_FILES" | while IFS= read -r f; do
  [ -n "$f" ] || continue

  # Raw SQL writing a cloud_* table.
  sed -e 's://.*::' "$f" \
    | grep -nE '(INSERT[[:space:]]+INTO|UPDATE|DELETE[[:space:]]+FROM)[[:space:]]+(public\.)?cloud_[a-z0-9_]*' \
    | sed "s|^|FAIL: $f writes cloud_* in SQL: line |"

  # GORM writing a Cloud* model. Create/Save/Updates/Update/Delete on a
  # models.Cloud... value is the same write in a different costume.
  sed -e 's://.*::' "$f" \
    | grep -nE '\.(Create|Save|Updates|Update|Delete)\([^)]*models\.Cloud' \
    | sed "s|^|FAIL: $f writes a Cloud model via GORM: line |"
done > "$ONEWAY"

if [ -s "$ONEWAY" ]; then
  fail=1
  cat "$ONEWAY"
else
  echo "ok: no projection file writes cloud_*"
fi
rm -f "$ONEWAY"

# ---------------------------------------------------------------------------
# P2-1 -- NO NEW WRITERS TO iga_observation_links.
#
# That table keeps a polymorphic target_kind/target_id pair, which is the A3
# defect this phase exists to close. It survives ONLY because the GitHub
# ingestion path already writes it. Every new evidence link goes to
# iga_access_edge_evidence or iga_relationship_evidence, both of which have
# typed, workspace-qualified endpoints on both ends.
echo
echo "== no new iga_observation_links writers =="

# The one path allowed to write it, and the repository method it goes through.
OBS_LINK_ALLOWED="services/iga_service.go repository/iga_repository.go"

LINKS="$(mktemp)"
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case " $OBS_LINK_ALLOWED " in *" $f "*) continue ;; esac
  sed -e 's://.*::' "$f" \
    | grep -nE '(INSERT[[:space:]]+INTO[[:space:]]+(public\.)?iga_observation_links|\.(Create|Save|Updates)\([^)]*IGAObservationLink)' \
    | sed "s|^|FAIL: $f writes iga_observation_links: line |"
done < <(
  find . -type f -name '*.go' -not -path './.git/*' 2>/dev/null \
    | sed 's|^\./||' | grep -v '_test\.go$' | sort
) > "$LINKS"

if [ -s "$LINKS" ]; then
  fail=1
  cat "$LINKS"
else
  echo "ok: only the GitHub path writes iga_observation_links"
  echo "    (allowed: ${OBS_LINK_ALLOWED})"
fi
rm -f "$LINKS"

echo
if [ "$fail" -ne 0 ]; then
  cat <<'MSG'
IGA isolation FAILED.

One of three rules was broken:

  1. A legacy table named directly from IGA code is coupling nobody declared
     (or a read-only shared table is written). If the join is genuinely
     required, route it through a bridge table that records its own state and
     evidence, as discovered_agent_iga_links does -- then add it to
     ALLOWED_SHARED (or the write to WRITE_ALLOWED) with a sentence saying why.

  2. A projection file writes cloud_*. The projection is ONE-WAY: cloud_* is
     authoritative, iga_* is rebuildable from it. A write back makes the two
     mutually dependent and the rebuild guarantee false.

  3. A new writer to iga_observation_links. That table keeps a polymorphic
     target pair and survives only for the GitHub path. New evidence links go
     to iga_access_edge_evidence or iga_relationship_evidence, which are typed
     and workspace-qualified on both ends.
MSG
  exit 1
fi
echo "IGA isolation passed."
