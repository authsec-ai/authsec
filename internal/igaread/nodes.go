package igaread

// Node helpers every graph read shares: the list routes (lists.go) and the
// detail routes read the SAME columns through the SAME expressions, so a
// workload's account, a node's state or a resource's kind can never be one
// thing on a list row and another on the object it opens (§2.14.11 "The graph
// and the lists must agree").
//
// Everything here is either a SQL fragment with NO bind variables (so callers
// can splice it anywhere without re-ordering arguments), a pure function, or a
// query helper that takes the snapshot's transaction.

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// Node states (D-1). Node tables carry lifecycle only; state is derived from
// the node's support rows, where staleness lives (§2.10B).
const (
	StateCurrent = models.RelCurrent
	StateStale   = models.RelStale
	StateEnded   = models.RelEnded
)

// supportClasses maps each iga_object_support column (032, 036) to the object
// class igagraph partitions it under.
var supportClasses = map[string]string{
	"identity_account_id": models.ObjectIdentity,
	"workload_id":         models.ObjectWorkload,
	"resource_id":         models.ObjectResource,
	"entitlement_id":      models.ObjectEntitlement,
	"policy_id":           models.ObjectPolicy,
}

func mustSupportColumn(column string) {
	if _, ok := supportClasses[column]; !ok {
		panic(fmt.Sprintf("igaread: %q is not an iga_object_support column", column))
	}
}

// SupportedSQL is D-6's readability predicate: the node has at least one
// support row, in any state. Graph routes read only rows the projector owns --
// provider = 'aws' (the caller's own condition) AND supported -- so an AWS row
// no projection pass ever supported is not a graph row, on a list or a detail
// route. nodeAlias is the node table's alias; column its support column. The
// (workspace_id, <column>) prefix of the uq_iga_os_* indexes serves it. No bind
// variables.
func SupportedSQL(nodeAlias, column string) string {
	mustSupportColumn(column)
	return `EXISTS (SELECT 1 FROM iga_object_support s0
	         WHERE s0.workspace_id = ` + nodeAlias + `.workspace_id AND s0.` + column + ` = ` + nodeAlias + `.id)`
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
	mustSupportColumn(column)
	return `LEFT JOIN LATERAL (
	        SELECT CASE WHEN bool_or(s.state = 'current') THEN 'current'
	                    WHEN bool_or(s.state = 'stale')   THEN 'stale'
	                    ELSE 'ended' END AS state,
	               max(s.last_confirmed_at) AS last_confirmed_at
	          FROM iga_object_support s
	         WHERE s.workspace_id = ` + nodeAlias + `.workspace_id AND s.` + column + ` = ` + nodeAlias + `.id) sup ON true`
}

// CountCap bounds every per-row count (D-17): {value, exact: true} at or under
// it, {value: CountCap, exact: false} above it -- rendered "1000+", never a
// number that looks exact.
const CountCap = 1000

// CappedCount renders a count taken with LIMIT CountCap+1.
func CappedCount(n int64) Exact {
	if n > CountCap {
		return Exact{Value: ptrInt64(CountCap), Exact: false}
	}
	return ExactOf(n)
}

func ptrInt64(n int64) *int64 { return &n }

/* -------------------------------- workloads -------------------------------- */

// WorkloadAccountSQL is a workload's own account (D-3, §2.14.10): the account of
// the connector that collected it, read from its estate scope, whose source key
// is aws␟account␟<id> (igagraph.ScopeKey). Needs iga_estate_scopes joined as
// es (WorkloadFrom does). Never the execution role's account: an unresolved
// role must not blank the workload's account or drop it from an account filter.
const WorkloadAccountSQL = `(CASE WHEN es.scope_kind = 'account' THEN split_part(es.source_key, chr(31), 3) ELSE '' END)`

// WorkloadClassificationRankSQL orders classification by rank, never
// alphabetically (D-13): provider_native_agent < classified_agent <
// unclassified. Needs iga_workload as w.
const WorkloadClassificationRankSQL = `(CASE w.classification WHEN 'provider_native_agent' THEN 0
            WHEN 'classified_agent' THEN 1 ELSE 2 END)`

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
// the caller appends WHERE w.workspace_id = ? AND w.provider = 'aws' AND
// SupportedSQL("w", "workload_id") ...
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

// StaleSubject names the node for NodeStaleReasons: its id and the kind and
// region igagraph chooses its partition by.
func (w WorkloadRecord) StaleSubject() StaleSubject {
	return StaleSubject{ID: w.ID, Kind: w.RuntimeKind, Region: w.Region}
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
	StaleReason           *[]StaleReason `json:"stale_reason,omitempty"`
	FirstSeenAt           any            `json:"first_seen_at"`
	LastConfirmedAt       any            `json:"last_confirmed_at"`
	Instances             map[string]any `json:"instances"`
}

// Row renders the record as its §5.3 row. The ARN is the native segment of the
// source key (D-2); a workload's region is "" -> null ("Region not stated",
// D-63). stale is the row's D-74 stale_reason (StaleReasonOf).
//
// instances is {state: "not_collected"} on every row: this phase collects no
// deployed instances (§2.14.4), and saying so beats an empty list that reads
// as "none running".
func (w WorkloadRecord) Row(accts *Accounts, stale *[]StaleReason) WorkloadRow {
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
		StaleReason:           stale,
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

// IdentityKindRankSQL orders identity kinds by rank (D-13): iam_role <
// iam_user < iam_group. It is the default (non-v2) order. v2 uses
// identityKindRankV2SQL so the newer account kinds rank after these three
// instead of tying with iam_group.
const IdentityKindRankSQL = `(CASE ia.account_kind WHEN 'iam_role' THEN 0 WHEN 'iam_user' THEN 1 ELSE 2 END)`

// IdentityColumns / IdentityFrom read an identity row into IdentityRecord. The
// caller appends WHERE ia.workspace_id = ? AND ia.provider = 'aws' AND
// SupportedSQL("ia", "identity_account_id") ... (D-6: GitHub rows share the
// table and are never graph rows).
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

// StaleSubject names the node for NodeStaleReasons.
func (i IdentityRecord) StaleSubject() StaleSubject {
	return StaleSubject{ID: i.ID, Kind: i.AccountKind}
}

// IdentityRow is the §5.3 identity list row. region is "global": IAM is a
// global service, and §2.14.14 requires region on every row (D-63).
type IdentityRow struct {
	Ref             string         `json:"ref"`
	Name            string         `json:"name"`
	Kind            string         `json:"kind"`
	ARN             string         `json:"arn"`
	Account         *Account       `json:"account"`
	Region          string         `json:"region"`
	UsedByCount     Exact          `json:"used_by_count"`
	Lifecycle       string         `json:"lifecycle"`
	RetiredReason   string         `json:"retired_reason,omitempty"`
	State           string         `json:"state"`
	StaleReason     *[]StaleReason `json:"stale_reason,omitempty"`
	LastConfirmedAt any            `json:"last_confirmed_at"`
	// AccountState is enabled, disabled or unknown. It is set only when the
	// request opted into graph=v2; the default row omits it. It is not
	// lifecycle, state or stale_reason.
	AccountState *string `json:"account_state,omitempty"`
}

// Row renders the record; usedBy is its used_by_count (Unknown() when the
// optional count did not run), stale its D-74 stale_reason.
func (i IdentityRecord) Row(accts *Accounts, usedBy Exact, stale *[]StaleReason) IdentityRow {
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
		StaleReason:     stale,
		LastConfirmedAt: TS(i.LastConfirmedAt),
	}
}

// UsedByTypes are the relationships through which a workload uses an identity:
// the Used-by tab's workloads section (§5.3 "via executes_as and
// task_execution_role"), and so the used_by=workloads filter and the Used by
// count, which must agree with that tab (D-17).
var UsedByTypes = []string{models.RelTypeExecutesAs, models.RelTypeTaskExecutionRole}

// UsedByCounts counts, per identity, the distinct workloads with a UsedByTypes
// relationship to it in state current or stale (D-17), each count taken with
// LIMIT CountCap+1 so a hub role costs the same as a leaf. Every id asked for
// is in the result. Run it as OPTIONAL work: a count that did not finish is
// {value: null, exact: false}, never a number that looks exact (§2.14.6 "3+").
func UsedByCounts(tx *gorm.DB, ws uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]Exact, error) {
	out := map[uuid.UUID]Exact{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []struct {
		ID uuid.UUID
		N  int64
	}
	if err := tx.Raw(`SELECT ia.id, c.n
	                    FROM iga_identity_accounts ia
	                   CROSS JOIN LATERAL (
	                         SELECT count(*) AS n FROM (
	                                SELECT DISTINCT r.source_workload_id
	                                  FROM iga_relationship r
	                                 WHERE r.workspace_id = ia.workspace_id AND r.relationship_type IN ?
	                                   AND r.target_identity_account_id = ia.id
	                                   AND r.state IN ('current', 'stale')
	                                 LIMIT ?) d) c
	                   WHERE ia.workspace_id = ? AND ia.id IN ?`,
		UsedByTypes, CountCap+1, ws, ids).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ID] = CappedCount(r.N)
	}
	return out, nil
}

// identityAccountStates reads iga_identity_accounts.account_state for the
// page just loaded. It is a second statement, used only when graph=v2, so
// the default identity SELECT (IdentityColumns) stays unchanged.
func identityAccountStates(tx *gorm.DB, ws uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	out := map[uuid.UUID]string{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []struct {
		ID    uuid.UUID
		State string `gorm:"column:account_state"`
	}
	if err := tx.Raw(`SELECT id, account_state FROM iga_identity_accounts
	                   WHERE workspace_id = ? AND id IN ?`, ws, ids).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ID] = r.State
	}
	return out, nil
}

// iamIdentityKind is an AWS IAM account kind. Other kinds have no IAM-shaped
// detail sections.
func iamIdentityKind(kind string) bool {
	switch kind {
	case models.CloudIdentityIAMRole, models.CloudIdentityIAMUser, models.CloudIdentityIAMGroup:
		return true
	default:
		return false
	}
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

// ResourceAccountConnectedSQL is D-3's connectedness of a resource's account:
// the PROJECTED provider_attrs.account_connected, read in the revision's
// snapshot -- so it cannot change while the revision stays the same (§1.4,
// §4.7, §2.14.11 "a disagreement at the same revision is a bug"). Absent means
// not connected: a reference is never claimed to be inside the estate on a
// value the projector did not write.
const ResourceAccountConnectedSQL = `COALESCE(r.provider_attrs->>'account_connected' = 'true', false)`

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
// an account and the revision's projected account_connected is false (D-3);
// otherwise exact. Fixed per revision, never computed from live connector
// state: a connector added or revoked after the revision changes nothing
// until a projection pass rewrites the reference.
const ResourceKindSQL = `(CASE WHEN r.resource_kind = 'selector' THEN 'selector'
       WHEN ` + ResourceAccountSQL + ` <> '' AND NOT ` + ResourceAccountConnectedSQL + ` THEN 'external'
       ELSE 'exact' END)`

// ResourceKindRankSQL orders the API kind by rank (D-13, §2.14.6 "exact
// reference, selector, external"), never alphabetically.
const ResourceKindRankSQL = `(CASE ` + ResourceKindSQL + ` WHEN 'exact' THEN 0 WHEN 'selector' THEN 1 ELSE 2 END)`

// ResourceColumns / ResourceFrom read a resource row into ResourceRecord. The
// caller appends WHERE r.workspace_id = ? AND r.provider = 'aws' AND
// SupportedSQL("r", "resource_id") ... (D-6).
const ResourceColumns = `r.id, r.display_name, r.resource_kind, r.lifecycle, r.retired_reason,
       ` + ResourceKindSQL + ` AS kind,
       ` + ResourceServiceSQL + ` AS service,
       ` + ResourceAccountSQL + ` AS account_id,
       ` + ResourceAccountConnectedSQL + ` AS account_connected,
       ` + ResourceRegionSQL + ` AS region,
       sup.state, sup.last_confirmed_at`

// ResourceFrom is the FROM clause behind ResourceColumns.
var ResourceFrom = `iga_resources r
  ` + SupportLateral("r", "resource_id")

// ResourceRecord is one resource reference as ResourceColumns reads it.
type ResourceRecord struct {
	ID               uuid.UUID
	DisplayName      string
	ResourceKind     string
	Lifecycle        string
	RetiredReason    string
	Kind             string
	Service          string
	AccountID        string
	AccountConnected bool
	Region           string
	State            string
	LastConfirmedAt  *time.Time
}

// StaleSubject names the node for NodeStaleReasons (one resource partition per
// connector: no kind, no region).
func (r ResourceRecord) StaleSubject() StaleSubject { return StaleSubject{ID: r.ID} }

// ResourceRow is the §5.3 resource list row. text is the ARN or pattern
// exactly as a statement wrote it (D-2); type is the typed kind (D-16), so an
// S3 object selector never renders as a bucket (§2.14.12).
type ResourceRow struct {
	Ref             string         `json:"ref"`
	Text            string         `json:"text"`
	Kind            string         `json:"kind"`
	Type            string         `json:"type"`
	Service         *string        `json:"service"`
	Account         *Account       `json:"account"`
	Region          *string        `json:"region"`
	NamedByCount    Exact          `json:"named_by_count"`
	ExcludedByCount Exact          `json:"excluded_by_count"`
	Lifecycle       string         `json:"lifecycle"`
	RetiredReason   string         `json:"retired_reason,omitempty"`
	State           string         `json:"state"`
	StaleReason     *[]StaleReason `json:"stale_reason,omitempty"`
	LastConfirmedAt any            `json:"last_confirmed_at"`
}

// Row renders the record with its D-17 counts and D-74 stale_reason.
func (r ResourceRecord) Row(accts *Accounts, namedBy, excludedBy Exact, stale *[]StaleReason) ResourceRow {
	return ResourceRow{
		Ref:             R(RefResource, r.ID),
		Text:            r.DisplayName,
		Kind:            r.Kind,
		Type:            ResourceType(r.DisplayName),
		Service:         strPtr(r.Service),
		Account:         ResourceAccount(accts, r.AccountID, r.AccountConnected),
		Region:          strPtr(r.Region),
		NamedByCount:    namedBy,
		ExcludedByCount: excludedBy,
		Lifecycle:       r.Lifecycle,
		RetiredReason:   r.RetiredReason,
		State:           r.State,
		StaleReason:     stale,
		LastConfirmedAt: TS(r.LastConfirmedAt),
	}
}

// ResourceAccount is a resource's account object: labelled like every other
// account, with connected = the PROJECTED account_connected (D-3), so the
// account chip and the kind (external or exact) never disagree at one
// revision. nil (Unknown account) when the reference states no account.
func ResourceAccount(accts *Accounts, accountID string, connected bool) *Account {
	a := accts.Of(accountID)
	if a != nil {
		a.Connected = connected
	}
	return a
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
	NamedBy    Exact
	ExcludedBy Exact
}

// ResourceTargetCounts counts, per resource, the distinct ACTIVE ALLOW
// statements that name it as a positive target (named_by) and that exclude it
// through NotResource (excluded_by), counted separately (D-17), each with
// LIMIT CountCap+1. Deny statements are neither: they are restrictions, shown
// on /access. Every id asked for is in the result. Run it as OPTIONAL work.
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
	count := func(mode string) string {
		return `(SELECT count(*) FROM (
		                SELECT DISTINCT t.entitlement_id
		                  FROM iga_entitlement_target t
		                  JOIN iga_entitlements e ON e.workspace_id = t.workspace_id AND e.id = t.entitlement_id
		                 WHERE t.workspace_id = r.workspace_id AND t.resource_id = r.id AND t.target_mode = '` + mode + `'
		                   AND e.provider = 'aws' AND e.lifecycle = 'active' AND e.effect = 'allow'
		                 LIMIT ?) d)`
	}
	if err := tx.Raw(`SELECT r.id, `+count("resource")+` AS named, `+count("not_resource")+` AS excluded
	                    FROM iga_resources r
	                   WHERE r.workspace_id = ? AND r.id IN ?`,
		CountCap+1, CountCap+1, ws, ids).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ID] = TargetCounts{NamedBy: CappedCount(r.Named), ExcludedBy: CappedCount(r.Excluded)}
	}
	return out, nil
}

/* ------------------------------ stale_reason ------------------------------- */

// StaleReason is one entry of a stale row's stale_reason (D-74): a surface of
// the node's partition that the run its revision was built from did not
// reach, in the connector's account, with the state that run recorded and
// since when the surface has been in that state (null when the history
// window does not show where the streak began).
type StaleReason struct {
	AccountID string `json:"account_id"`
	Surface   string `json:"surface"`
	State     string `json:"state"`
	Since     any    `json:"since"`
}

// StaleSubject is one node whose stale_reason is wanted: its id, and the kind
// (identity account_kind, workload runtime_kind) and region (workloads) that
// igagraph.Partition.Matches chooses its partition by.
type StaleSubject struct {
	ID     uuid.UUID
	Kind   string
	Region string
}

// StaleHistoryRuns is how many published runs of a connector the since walk
// looks back over (D-72's window); a streak that fills it has since = null.
const StaleHistoryRuns = 50

// NodeStaleReasons computes D-74's stale_reason for nodes of one class, given
// by their iga_object_support column. For each STALE support row of a node:
//
//   - the run its partition was last projected from is iga_projection_state's
//     last_run_id for (connector, partition_key) -- the run the current
//     revision was built from (D-57), read in this snapshot;
//   - the partition's required surfaces and scanners come from igagraph's own
//     partition table (Partitions + Matches, the projector's membership
//     predicate), never from parsing partition_key, whose format D-57 changes;
//   - a reason is every required surface present in that run's coverage and
//     not reached, and every scanner marker present and not reached; failing
//     those, every required surface ABSENT from the report (absent means the
//     run did not look: state "unknown"); failing those, for classes whose rows
//     an unreadable document protects (resources, statements, policies), the
//     run's policy_documents surface when it is not reached.
//
// since is the start of the surface's unbroken streak in that state over the
// connector's last StaleHistoryRuns published runs, read as OPTIONAL work: a
// history read that does not finish leaves since null, never a guess.
//
// Every stale subject is in the result, with [] when no recorded coverage
// explains its staleness; non-stale subjects need not be passed.
func NodeStaleReasons(q *Query, accts *Accounts, column string, subjects []StaleSubject) (map[uuid.UUID][]StaleReason, error) {
	mustSupportColumn(column)
	class := supportClasses[column]
	out := map[uuid.UUID][]StaleReason{}
	if len(subjects) == 0 {
		return out, nil
	}
	byID := map[uuid.UUID]StaleSubject{}
	ids := make([]uuid.UUID, 0, len(subjects))
	for _, s := range subjects {
		byID[s.ID] = s
		ids = append(ids, s.ID)
		out[s.ID] = []StaleReason{}
	}

	var supports []struct {
		NodeID        uuid.UUID
		ConnectorID   uuid.UUID
		EstateScopeID *uuid.UUID
		RunID         *uuid.UUID
	}
	if err := q.DB().Raw(`SELECT s.`+column+` AS node_id, s.connector_id, ps.estate_scope_id, ps.last_run_id AS run_id
	                        FROM iga_object_support s
	                        LEFT JOIN iga_projection_state ps
	                          ON ps.workspace_id = s.workspace_id AND ps.connector_id = s.connector_id
	                         AND ps.partition_key = s.partition_key
	                       WHERE s.workspace_id = ? AND s.`+column+` IN ? AND s.state = 'stale'
	                       ORDER BY s.connector_id, s.id`, q.WS, ids).Scan(&supports).Error; err != nil {
		return nil, err
	}
	runIDs := []uuid.UUID{}
	seenRun := map[uuid.UUID]bool{}
	for _, s := range supports {
		if s.RunID != nil && !seenRun[*s.RunID] {
			seenRun[*s.RunID] = true
			runIDs = append(runIDs, *s.RunID)
		}
	}
	if len(runIDs) == 0 {
		return out, nil
	}
	var runs []staleRun
	if err := q.DB().Raw(`SELECT id, connector_id, published_at, coverage FROM cloud_scan_run
	                       WHERE workspace_id = ? AND id IN ?`, q.WS, runIDs).Scan(&runs).Error; err != nil {
		return nil, err
	}
	runByID := map[uuid.UUID]*staleRun{}
	for i := range runs {
		runs[i].decode()
		runByID[runs[i].ID] = &runs[i]
	}

	type pending struct {
		node uuid.UUID
		run  *staleRun
		gap  surfaceGap
	}
	var found []pending
	for _, s := range supports {
		if s.RunID == nil || s.EstateScopeID == nil {
			continue // no projection-state row: nothing recorded explains it
		}
		run := runByID[*s.RunID]
		if run == nil {
			continue
		}
		subj := byID[s.NodeID]
		part, ok := partitionOf(class, subj.Kind, subj.Region, *s.EstateScopeID, s.ConnectorID)
		if !ok {
			continue
		}
		for _, g := range partitionGaps(part, run.cov, class) {
			found = append(found, pending{node: s.NodeID, run: run, gap: g})
		}
	}
	if len(found) == 0 {
		return out, nil
	}

	// since: one optional read of each involved connector's recent published
	// runs, bounded by the newest run any partition of it was projected from.
	history := map[uuid.UUID][]staleRun{}
	conns := []uuid.UUID{}
	seenConn := map[uuid.UUID]bool{}
	for _, f := range found {
		if !seenConn[f.run.ConnectorID] {
			seenConn[f.run.ConnectorID] = true
			conns = append(conns, f.run.ConnectorID)
		}
	}
	var hist []staleRun
	haveHistory, err := q.Optional(func(tx *gorm.DB) error {
		return tx.Raw(`SELECT id, connector_id, published_at, coverage FROM (
		                   SELECT sr.id, sr.connector_id, sr.published_at, sr.coverage,
		                          row_number() OVER (PARTITION BY sr.connector_id
		                                             ORDER BY sr.published_at DESC, sr.id DESC) AS n
		                     FROM cloud_scan_run sr
		                    WHERE sr.workspace_id = ? AND sr.connector_id IN ? AND sr.published_at IS NOT NULL
		                      AND sr.published_at <= (
		                          SELECT max(pr.published_at)
		                            FROM iga_projection_state ps
		                            JOIN cloud_scan_run pr ON pr.workspace_id = ps.workspace_id AND pr.id = ps.last_run_id
		                           WHERE ps.workspace_id = sr.workspace_id AND ps.connector_id = sr.connector_id)) x
		                WHERE n <= ?
		                ORDER BY connector_id, published_at DESC, id DESC`,
			q.WS, conns, StaleHistoryRuns+1).Scan(&hist).Error
	})
	if err != nil {
		return nil, err
	}
	for i := range hist {
		hist[i].decode()
		history[hist[i].ConnectorID] = append(history[hist[i].ConnectorID], hist[i])
	}

	for _, f := range found {
		var since any
		if haveHistory {
			since = TS(streakSince(history[f.run.ConnectorID], f.run.ID, f.gap.surface, f.gap.state))
		}
		acct := ""
		if c := accts.Connector(f.run.ConnectorID); c != nil {
			acct = c.AccountID
		}
		out[f.node] = append(out[f.node], StaleReason{AccountID: acct, Surface: f.gap.surface, State: f.gap.state, Since: since})
	}
	for id := range out {
		rs := out[id]
		sort.Slice(rs, func(i, j int) bool {
			if rs[i].AccountID != rs[j].AccountID {
				return rs[i].AccountID < rs[j].AccountID
			}
			return rs[i].Surface < rs[j].Surface
		})
		out[id] = dedupeReasons(rs)
	}
	return out, nil
}

// StaleReasonOf is the stale_reason a row renders: the computed list for a
// stale row (possibly empty), and nothing for a row that is not stale.
func StaleReasonOf(state string, id uuid.UUID, reasons map[uuid.UUID][]StaleReason) *[]StaleReason {
	if state != StateStale {
		return nil
	}
	rs, ok := reasons[id]
	if !ok {
		rs = []StaleReason{}
	}
	return &rs
}

// staleRun is one cloud_scan_run as the stale_reason reader needs it.
type staleRun struct {
	ID          uuid.UUID
	ConnectorID uuid.UUID
	PublishedAt *time.Time
	Coverage    json.RawMessage
	cov         models.ScanCoverage
}

func (r *staleRun) decode() { r.cov = models.DecodeScanCoverage(r.Coverage) }

// surfaceGap is one surface a partition required that a run did not reach.
type surfaceGap struct{ surface, state string }

// stateIn is a surface's state in a report; absent is "unknown" -- for a
// required surface, absent means the run did not look.
func stateIn(cov models.ScanCoverage, surface string) (string, bool) {
	s, ok := cov.Surfaces[surface]
	if !ok {
		return models.CloudCoverageUnknown, false
	}
	return s.State, true
}

// partitionOf finds the node partition igagraph would put a node of this
// class, kind and region in for this scope and connector: the same Partitions
// table and the same Matches predicate the projector uses. The region's
// compute surface stands in for "this region was attempted" so Partitions
// builds that region's workload partitions.
func partitionOf(class, kind, region string, scope, connector uuid.UUID) (igagraph.Partition, bool) {
	snap := &igagraph.Snapshot{ScopeID: scope, Run: models.CloudScanRun{ConnectorID: connector}}
	if region != "" {
		snap.Coverage = map[string]models.SurfaceCoverage{models.SurfaceCompute(region): {}}
	}
	for _, p := range igagraph.Partitions(snap) {
		if p.Target == "" && p.Matches(class, kind, region) {
			return p, true
		}
	}
	return igagraph.Partition{}, false
}

// partitionGaps is what one run left unreached of one partition (see
// NodeStaleReasons for the order of the rules).
func partitionGaps(p igagraph.Partition, cov models.ScanCoverage, class string) []surfaceGap {
	var gaps []surfaceGap
	for _, name := range p.RequiredSurfaces {
		if st, present := stateIn(cov, name); present && st != models.CloudCoverageReached {
			gaps = append(gaps, surfaceGap{name, st})
		}
	}
	for _, name := range p.RequiredScanners {
		if st, present := stateIn(cov, name); present && st != models.CloudCoverageReached {
			gaps = append(gaps, surfaceGap{name, st})
		}
	}
	if len(gaps) > 0 {
		return gaps
	}
	for _, name := range p.RequiredSurfaces {
		if _, present := stateIn(cov, name); !present {
			gaps = append(gaps, surfaceGap{name, models.CloudCoverageUnknown})
		}
	}
	if len(gaps) > 0 {
		return gaps
	}
	switch class {
	case models.ObjectResource, models.ObjectEntitlement, models.ObjectPolicy:
		if st, present := stateIn(cov, models.SurfacePolicyDocuments); present && st != models.CloudCoverageReached {
			gaps = append(gaps, surfaceGap{models.SurfacePolicyDocuments, st})
		}
	}
	return gaps
}

// streakSince walks a connector's published runs (newest first) from the run
// `from`, while the surface keeps `state`, and returns the published_at of the
// oldest run in that unbroken streak. nil when `from` is not in the window, or
// the streak runs to the end of a window that was cut short (older runs may
// continue it): the start is then not known.
func streakSince(runs []staleRun, from uuid.UUID, surface, state string) *time.Time {
	start := -1
	for i := range runs {
		if runs[i].ID == from {
			start = i
			break
		}
	}
	if start < 0 {
		return nil
	}
	oldest := start
	for i := start + 1; i < len(runs); i++ {
		if st, _ := stateIn(runs[i].cov, surface); st != state {
			return runs[oldest].PublishedAt
		}
		oldest = i
	}
	if len(runs) > StaleHistoryRuns {
		return nil // the window was full: the streak may begin before it
	}
	return runs[oldest].PublishedAt
}

// dedupeReasons drops repeats of the same account and surface (two stale
// support rows of one connector naming one gap), keeping the first. rs is
// sorted.
func dedupeReasons(rs []StaleReason) []StaleReason {
	out := make([]StaleReason, 0, len(rs))
	for i, r := range rs {
		if i > 0 && r.AccountID == rs[i-1].AccountID && r.Surface == rs[i-1].Surface {
			continue
		}
		out = append(out, r)
	}
	return out
}

// strPtr is nil (JSON null) for "", else a pointer to s.
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
