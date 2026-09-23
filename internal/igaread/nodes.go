package igaread

// Node helpers every graph read shares: the list routes (lists.go) and the
// detail routes read the SAME columns through the SAME expressions, so a
// workload's account, a node's state or a resource's kind can never be one
// thing on a list row and another on the object it opens (§2.14.11 "The graph
// and the lists must agree").
//
// Everything here is either a SQL fragment with NO bind variables (so callers
// can splice it anywhere without re-ordering arguments) or a pure function.

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
)

// Node states (D-1). Node tables carry lifecycle only; state is derived from
// the node's support rows, where staleness lives (§2.10B).
const (
	StateCurrent = models.RelCurrent
	StateStale   = models.RelStale
	StateEnded   = models.RelEnded
)

// supportColumns are the iga_object_support columns a node can be supported
// through (032, 036).
var supportColumns = map[string]bool{
	"identity_account_id": true, "workload_id": true, "resource_id": true,
	"entitlement_id": true, "policy_id": true,
}

// SupportLateral is the LEFT JOIN LATERAL that derives a node's D-1 state and
// last_confirmed_at from its support rows, exposed as sup.state and
// sup.last_confirmed_at:
//
//	state             current if any support row is current, else stale if any
//	                  is stale, else ended
//	last_confirmed_at the latest last_confirmed_at over its support rows
//
// nodeAlias is the node table's alias in the enclosing query; column names the
// support column for its class. The (workspace_id, <column>) prefix of the
// uq_iga_os_* indexes serves it. It carries no bind variables.
func SupportLateral(nodeAlias, column string) string {
	if !supportColumns[column] {
		panic(fmt.Sprintf("igaread: %q is not an iga_object_support column", column))
	}
	return `LEFT JOIN LATERAL (
	        SELECT CASE WHEN bool_or(s.state = 'current') THEN 'current'
	                    WHEN bool_or(s.state = 'stale')   THEN 'stale'
	                    ELSE 'ended' END AS state,
	               max(s.last_confirmed_at) AS last_confirmed_at
	          FROM iga_object_support s
	         WHERE s.workspace_id = ` + nodeAlias + `.workspace_id AND s.` + column + ` = ` + nodeAlias + `.id) sup ON true`
}

/* -------------------------------- workloads -------------------------------- */

// WorkloadAccountSQL is a workload's own account (D-3, §2.14.10): the account of
// the connector that collected it, read from its estate scope, whose source key
// is aws␟account␟<id> (igagraph.ScopeKey). Needs iga_estate_scopes joined as
// es (WorkloadFrom does). Never the execution role's account: an unresolved
// role must not blank the workload's account or drop it from an account filter.
const WorkloadAccountSQL = `(CASE WHEN es.scope_kind = 'account' THEN split_part(es.source_key, chr(31), 3) ELSE '' END)`

// WorkloadColumns is the column list a workload row is read with; scan it into
// WorkloadRecord. Needs WorkloadFrom.
const WorkloadColumns = `w.id, w.display_name, w.runtime_kind, w.source_key, w.region, w.lifecycle,
       w.retired_reason, w.classification, w.classification_version,
       w.execution_role_state, w.execution_role_arn, w.first_seen_at,
       ` + WorkloadAccountSQL + ` AS account_id,
       sup.state, sup.last_confirmed_at,
       er.identity_id AS exec_identity_id, er.name AS exec_identity_name`

// WorkloadFrom is the FROM clause behind WorkloadColumns: the workload (alias
// w), its estate scope (es), its support-derived state (sup) and its live
// execution identity (er): the non-ended executes_as row, current before stale,
// newest first. The executes_as predicate is written against the COALESCE the
// idx_iga_relationship_source expression index is built on. No bind variables;
// the caller appends WHERE w.workspace_id = ? ...
var WorkloadFrom = `iga_workload w
  LEFT JOIN iga_estate_scopes es ON es.workspace_id = w.workspace_id AND es.id = w.estate_scope_id
  ` + SupportLateral("w", "workload_id") + `
  LEFT JOIN LATERAL (
        SELECT r.target_identity_account_id AS identity_id, ia.display_name AS name
          FROM iga_relationship r
          JOIN iga_identity_accounts ia
            ON ia.workspace_id = r.workspace_id AND ia.id = r.target_identity_account_id
         WHERE r.workspace_id = w.workspace_id AND r.relationship_type = 'executes_as'
           AND COALESCE(r.source_identity_account_id, r.source_workload_id) = w.id
           AND r.state <> 'ended'
         ORDER BY (r.state = 'current') DESC, r.valid_from DESC, r.id
         LIMIT 1) er ON true`

// WorkloadRecord is one workload as WorkloadColumns reads it.
type WorkloadRecord struct {
	ID                    uuid.UUID
	DisplayName           string
	RuntimeKind           string
	SourceKey             string
	Region                string
	Lifecycle             string
	RetiredReason         string
	Classification        string
	ClassificationVersion int64
	ExecutionRoleState    string
	ExecutionRoleARN      string `gorm:"column:execution_role_arn"`
	FirstSeenAt           time.Time
	AccountID             string
	State                 string
	LastConfirmedAt       *time.Time
	ExecIdentityID        *uuid.UUID
	ExecIdentityName      *string
}

// WorkloadRow is the §5.3 workload list row. Detail responses embed it and add
// their own fields.
type WorkloadRow struct {
	Ref                   string         `json:"ref"`
	Name                  string         `json:"name"`
	RuntimeKind           string         `json:"runtime_kind"`
	ARN                   string         `json:"arn"`
	Account               *Account       `json:"account"`
	Region                *string        `json:"region"`
	Classification        string         `json:"classification"`
	ClassificationVersion int64          `json:"classification_version"`
	ExecutionRole         map[string]any `json:"execution_role"`
	Lifecycle             string         `json:"lifecycle"`
	RetiredReason         string         `json:"retired_reason,omitempty"`
	State                 string         `json:"state"`
	FirstSeenAt           any            `json:"first_seen_at"`
	LastConfirmedAt       any            `json:"last_confirmed_at"`
	Instances             map[string]any `json:"instances"`
}

// Row renders the record as its §5.3 row. The ARN is the native segment of the
// source key (D-2); a workload's region is "" -> null ("Region not stated").
//
// instances is {state: "not_collected"} on every row: this phase collects no
// deployed instances (§2.14.4), and saying so beats an empty list that reads
// as "none running".
func (w WorkloadRecord) Row(accts *Accounts) WorkloadRow {
	return WorkloadRow{
		Ref:                   R(RefWorkload, w.ID),
		Name:                  w.DisplayName,
		RuntimeKind:           w.RuntimeKind,
		ARN:                   NativeOfKey(w.SourceKey),
		Account:               accts.Of(w.AccountID),
		Region:                strPtr(w.Region),
		Classification:        w.Classification,
		ClassificationVersion: w.ClassificationVersion,
		ExecutionRole:         ExecutionRoleOf(w.ExecutionRoleState, w.ExecutionRoleARN, w.ExecIdentityID, w.ExecIdentityName),
		Lifecycle:             w.Lifecycle,
		RetiredReason:         w.RetiredReason,
		State:                 w.State,
		FirstSeenAt:           T(w.FirstSeenAt),
		LastConfirmedAt:       TS(w.LastConfirmedAt),
		Instances:             map[string]any{"state": "not_collected"},
	}
}

// ExecutionRoleOf renders a workload's execution_role (§5.3):
//
//	resolved                     {state, identity, name} from the live executes_as row
//	not_in_scan/not_in_inventory {state, execution_role_arn}: "Runs as <arn> -- not
//	                             read in the latest scan", never nothing
//	none                         {state}
//
// state is the column the projector writes on EVERY pass (§4.6). identity and
// name are null on a resolved workload whose edge is not live, rather than a
// guess at which role it was.
func ExecutionRoleOf(state, arn string, identityID *uuid.UUID, name *string) map[string]any {
	out := map[string]any{"state": state}
	switch state {
	case models.ExecRoleResolved:
		out["identity"] = RPtr(RefIdentity, identityID)
		if name != nil && identityID != nil {
			out["name"] = *name
		} else {
			out["name"] = nil
		}
	case models.ExecRoleNotInScan, models.ExecRoleNotInInventory:
		out["execution_role_arn"] = arn
	}
	return out
}

/* -------------------------------- identities ------------------------------- */

// IdentityARNSQL is an identity's ARN: the native segment of its source key
// (D-2). Needs iga_identity_accounts as ia.
const IdentityARNSQL = `split_part(ia.source_key, chr(31), 2)`

// IdentityAccountSQL is an identity's own account: the account field of its
// ARN (§2.14.10: "From its ARN"; never unknown for a collected identity).
const IdentityAccountSQL = `(CASE WHEN ` + IdentityARNSQL + ` LIKE 'arn:%' THEN split_part(` + IdentityARNSQL + `, ':', 5) ELSE '' END)`

// IdentityColumns / IdentityFrom read an identity row into IdentityRecord. The
// caller appends WHERE ia.workspace_id = ? AND ia.provider = 'aws' ... (D-6:
// GitHub rows share the table and are never graph rows).
const IdentityColumns = `ia.id, ia.display_name, ia.account_kind, ia.source_key, ia.immutable_key,
       ia.lifecycle, ia.retired_reason, ia.first_seen_at,
       ` + IdentityAccountSQL + ` AS account_id,
       sup.state, sup.last_confirmed_at`

// IdentityFrom is the FROM clause behind IdentityColumns.
var IdentityFrom = `iga_identity_accounts ia
  ` + SupportLateral("ia", "identity_account_id")

// IdentityRecord is one identity as IdentityColumns reads it.
type IdentityRecord struct {
	ID              uuid.UUID
	DisplayName     string
	AccountKind     string
	SourceKey       string
	ImmutableKey    string
	Lifecycle       string
	RetiredReason   string
	FirstSeenAt     time.Time
	AccountID       string
	State           string
	LastConfirmedAt *time.Time
}

// IdentityRow is the §5.3 identity list row. region is "global": IAM is a
// global service, and §2.14.14 requires region on every row.
type IdentityRow struct {
	Ref             string   `json:"ref"`
	Name            string   `json:"name"`
	Kind            string   `json:"kind"`
	ARN             string   `json:"arn"`
	Account         *Account `json:"account"`
	Region          string   `json:"region"`
	UsedByCount     Exact    `json:"used_by_count"`
	Lifecycle       string   `json:"lifecycle"`
	RetiredReason   string   `json:"retired_reason,omitempty"`
	State           string   `json:"state"`
	LastConfirmedAt any      `json:"last_confirmed_at"`
}

// Row renders the record; usedBy is its used_by_count (Unknown() when the
// optional count did not run).
func (i IdentityRecord) Row(accts *Accounts, usedBy Exact) IdentityRow {
	return IdentityRow{
		Ref:             R(RefIdentity, i.ID),
		Name:            i.DisplayName,
		Kind:            i.AccountKind,
		ARN:             NativeOfKey(i.SourceKey),
		Account:         accts.Of(i.AccountID),
		Region:          "global",
		UsedByCount:     usedBy,
		Lifecycle:       i.Lifecycle,
		RetiredReason:   i.RetiredReason,
		State:           i.State,
		LastConfirmedAt: TS(i.LastConfirmedAt),
	}
}

// UsedByTypes are the relationships through which a workload uses an identity:
// the Used-by tab's workloads section (§5.3 "via executes_as and
// task_execution_role"), and so the used_by=workloads filter and the Used by
// count, which must agree with that tab.
var UsedByTypes = []string{models.RelTypeExecutesAs, models.RelTypeTaskExecutionRole}

// UsedByCounts counts, per identity, the distinct workloads with a non-ended
// UsedByTypes relationship to it. Identities with none are absent (count 0).
// Run it as OPTIONAL work: a count that did not finish is {value: null,
// exact: false}, never a number that looks exact (§2.14.6 "3+").
func UsedByCounts(tx *gorm.DB, ws uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]int64, error) {
	out := map[uuid.UUID]int64{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []struct {
		ID uuid.UUID
		N  int64
	}
	if err := tx.Raw(`SELECT r.target_identity_account_id AS id, count(DISTINCT r.source_workload_id) AS n
	                    FROM iga_relationship r
	                   WHERE r.workspace_id = ? AND r.relationship_type IN ?
	                     AND r.target_identity_account_id IN ? AND r.state <> 'ended'
	                   GROUP BY r.target_identity_account_id`, ws, UsedByTypes, ids).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ID] = r.N
	}
	return out, nil
}

/* -------------------------------- resources -------------------------------- */

// API resource kinds (D-16, §2.14.12). "discovered" is never produced this
// phase: nothing enumerates resources.
const (
	ResourceExact    = "exact"
	ResourceSelector = "selector"
	ResourceExternal = "external"
)

// ResourceAccountSQL is a resource reference's own account: what its ARN
// STATES (provider_attrs.account), ” when it states none -- every S3 ARN and
// every wildcard. NEVER iga_resources.estate_scope_id, which is whichever
// connector last scanned the reference (§2.14.10, §1.4). Needs iga_resources
// as r.
const ResourceAccountSQL = `COALESCE(r.provider_attrs->>'account', '')`

// ResourceRegionSQL is the region the reference's ARN states, ” when none
// ("Region not stated", never global: an IAM or S3 ARN carries no region).
const ResourceRegionSQL = `COALESCE(r.provider_attrs->>'region', '')`

// ResourceServiceSQL is the ARN's service field, ” when the text is not an
// ARN (`*`) or names no single service (a wildcard in the field). Not stored
// by the projector, so derived from the text; mirrors ARNService.
const ResourceServiceSQL = `(CASE WHEN r.display_name LIKE 'arn:%:%:%:%:%'
            AND split_part(r.display_name, ':', 3) <> ''
            AND translate(split_part(r.display_name, ':', 3), '*' || chr(63), '') = split_part(r.display_name, ':', 3)
       THEN split_part(r.display_name, ':', 3) ELSE '' END)`

// ResourceKindSQL is the D-16 API kind, computed in SQL so the kind filter,
// facet and sort agree with the row: selector when the stored kind is
// selector (the text has * or ?); otherwise external when the reference states
// an account that no live connector of the workspace reads (D-3, evaluated at
// read time in the request's snapshot -- the projector's frozen
// account_connected attr is not used); otherwise exact.
const ResourceKindSQL = `(CASE WHEN r.resource_kind = 'selector' THEN 'selector'
       WHEN ` + ResourceAccountSQL + ` <> '' AND NOT EXISTS (
            SELECT 1 FROM cloud_connector cc
             WHERE cc.workspace_id = r.workspace_id AND cc.provider = 'aws'
               AND cc.scope_id = r.provider_attrs->>'account' AND cc.status <> 'revoked')
       THEN 'external' ELSE 'exact' END)`

// ResourceColumns / ResourceFrom read a resource row into ResourceRecord. The
// caller appends WHERE r.workspace_id = ? AND r.provider = 'aws' ... (D-6).
const ResourceColumns = `r.id, r.display_name, r.resource_kind, r.lifecycle, r.retired_reason,
       ` + ResourceKindSQL + ` AS kind,
       ` + ResourceServiceSQL + ` AS service,
       ` + ResourceAccountSQL + ` AS account_id,
       ` + ResourceRegionSQL + ` AS region,
       sup.state, sup.last_confirmed_at`

// ResourceFrom is the FROM clause behind ResourceColumns.
var ResourceFrom = `iga_resources r
  ` + SupportLateral("r", "resource_id")

// ResourceRecord is one resource reference as ResourceColumns reads it.
type ResourceRecord struct {
	ID              uuid.UUID
	DisplayName     string
	ResourceKind    string
	Lifecycle       string
	RetiredReason   string
	Kind            string
	Service         string
	AccountID       string
	Region          string
	State           string
	LastConfirmedAt *time.Time
}

// ResourceRow is the §5.3 resource list row. text is the ARN or pattern
// exactly as a statement wrote it (D-2); type is the typed kind (D-16), so an
// S3 object selector never renders as a bucket (§2.14.12).
type ResourceRow struct {
	Ref             string   `json:"ref"`
	Text            string   `json:"text"`
	Kind            string   `json:"kind"`
	Type            string   `json:"type"`
	Service         *string  `json:"service"`
	Account         *Account `json:"account"`
	Region          *string  `json:"region"`
	NamedByCount    Exact    `json:"named_by_count"`
	ExcludedByCount Exact    `json:"excluded_by_count"`
	Lifecycle       string   `json:"lifecycle"`
	RetiredReason   string   `json:"retired_reason,omitempty"`
	State           string   `json:"state"`
	LastConfirmedAt any      `json:"last_confirmed_at"`
}

// Row renders the record with its D-17 counts.
func (r ResourceRecord) Row(accts *Accounts, namedBy, excludedBy Exact) ResourceRow {
	return ResourceRow{
		Ref:             R(RefResource, r.ID),
		Text:            r.DisplayName,
		Kind:            r.Kind,
		Type:            ResourceType(r.DisplayName),
		Service:         strPtr(r.Service),
		Account:         accts.Of(r.AccountID),
		Region:          strPtr(r.Region),
		NamedByCount:    namedBy,
		ExcludedByCount: excludedBy,
		Lifecycle:       r.Lifecycle,
		RetiredReason:   r.RetiredReason,
		State:           r.State,
		LastConfirmedAt: TS(r.LastConfirmedAt),
	}
}

// ResourceType is the typed kind of a reference's text (s3_object, s3_bucket,
// dynamodb_table ...), derived at read time for selectors too -- the stored
// resource_kind of a selector is just "selector" (D-16). "unknown" when the
// text is not an ARN.
func ResourceType(text string) string {
	if t := awsdiscovery.TypeResourceARN(text); t != nil && t.Kind != "" {
		return t.Kind
	}
	return "unknown"
}

// TargetCounts is one resource's D-17 counts.
type TargetCounts struct {
	NamedBy    int64
	ExcludedBy int64
}

// ResourceTargetCounts counts, per resource, the distinct ACTIVE ALLOW
// statements that name it as a positive target (named_by) and that exclude it
// through NotResource (excluded_by), counted separately (D-17). Deny
// statements are neither: they are restrictions, shown on /access. Resources
// with none are absent. Run it as OPTIONAL work.
func ResourceTargetCounts(tx *gorm.DB, ws uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]TargetCounts, error) {
	out := map[uuid.UUID]TargetCounts{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []struct {
		ID       uuid.UUID
		Named    int64
		Excluded int64
	}
	if err := tx.Raw(`SELECT t.resource_id AS id,
	                         count(DISTINCT t.entitlement_id) FILTER (WHERE t.target_mode = 'resource')     AS named,
	                         count(DISTINCT t.entitlement_id) FILTER (WHERE t.target_mode = 'not_resource') AS excluded
	                    FROM iga_entitlement_target t
	                    JOIN iga_entitlements e ON e.workspace_id = t.workspace_id AND e.id = t.entitlement_id
	                   WHERE t.workspace_id = ? AND t.resource_id IN ?
	                     AND e.provider = 'aws' AND e.lifecycle = 'active' AND e.effect = 'allow'
	                   GROUP BY t.resource_id`, ws, ids).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ID] = TargetCounts{NamedBy: r.Named, ExcludedBy: r.Excluded}
	}
	return out, nil
}

// strPtr is nil (JSON null) for "", else a pointer to s.
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
