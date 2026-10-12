package services

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
)

// Remediation readiness (SPEC-iga-phase3-policy.md §7.1 GET /readiness,
// §9.3 S0, A63): per role reviewed at the latest complete evaluation, ONE
// category by precedence
//
//	blocked_by_collection > ineligible > needs_owner > iac_only > direct_eligible
//
// for a role with open findings, and no_change_needed for one without; with
// every reason that applies (not only the deciding one) and the remedy link.
// Counts are computed over every role reviewed (not the page) and sum to
// the roles reviewed. No proposal is compiled.
//
// DECISION E9. "Roles reviewed" are the roles the latest complete evaluation
// wrote evidence or a finding result for. "Open" findings are those whose
// condition holds at that revision and whose current status is open,
// reopened or under_review. Each category's reasons:
//
//   - blocked_by_collection: activity not collected for the role (any
//     not_collected evidence row, or an activity_not_read finding), and --
//     only when an unused_service finding is open -- resource-policy coverage
//     of the role connector's run that is not complete;
//   - ineligible: RoleIneligibility;
//   - needs_owner: no accountable owner of the role or of any consuming
//     workload, for a workload-bound role (missing_owner open);
//   - iac_only: the workspace is findings_only, the connector has no verified
//     enforcement binding, or the role has a customer-owned boundary (§3.3);
//     with whether an IaC source is mapped;
//   - direct_eligible: none of the above.

// Readiness categories, in precedence order.
const (
	ReadinessBlockedByCollection = "blocked_by_collection"
	ReadinessIneligible          = "ineligible"
	ReadinessNeedsOwner          = "needs_owner"
	ReadinessIaCOnly             = "iac_only"
	ReadinessDirectEligible      = "direct_eligible"
	ReadinessNoChangeNeeded      = "no_change_needed"
)

// ReadinessOrder is the precedence (no_change_needed last).
var ReadinessOrder = []string{ReadinessBlockedByCollection, ReadinessIneligible, ReadinessNeedsOwner,
	ReadinessIaCOnly, ReadinessDirectEligible, ReadinessNoChangeNeeded}

// ReadinessReason is one reason a category applies.
type ReadinessReason struct {
	Category string `json:"category"`
	Code     string `json:"code"`
	Detail   string `json:"detail,omitempty"`
}

// ReadinessRole is one role's readiness.
type ReadinessRole struct {
	IdentityAccountID uuid.UUID         `json:"identity_account_id"`
	RoleID            string            `json:"role_id"`
	RoleName          string            `json:"role_name"`
	RoleARN           string            `json:"role_arn"`
	AccountID         string            `json:"account_id"`
	ConnectorID       *uuid.UUID        `json:"connector_id"`
	Category          string            `json:"category"`
	Reasons           []ReadinessReason `json:"reasons"`
	Remedy            string            `json:"remedy"`
	OpenFindings      map[string]int    `json:"open_findings"`
}

// Readiness is GET /readiness.
type Readiness struct {
	Rev           *int64          `json:"evaluated_rev"`
	RolesReviewed int             `json:"roles_reviewed"`
	Counts        map[string]int  `json:"counts"`
	Roles         []ReadinessRole `json:"roles"`
	Next          *string         `json:"-"`
}

// Readiness computes readiness at the latest complete evaluation; account
// filters by AWS account (the role ARN's); the page is ordered by identity
// id with a signed cursor.
func (r *GovReader) Readiness(ctx context.Context, ws uuid.UUID, account, cursor string, limit int) (*Readiness, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > MaxGovPage {
		return nil, GovBadParam("limit", "limit must be 1..200.")
	}
	db := r.db.WithContext(ctx)
	out := &Readiness{Counts: map[string]int{}, Roles: []ReadinessRole{}}
	for _, c := range ReadinessOrder {
		out.Counts[c] = 0
	}
	lc, err := r.repo.LatestComplete(db, ws)
	if err != nil {
		return nil, err
	}
	want := govCursor{Route: "readiness", WS: ws.String(), Q: account}
	if lc != nil {
		want.Rev = lc.Rev
	}
	after := ""
	if cursor != "" {
		if after, err = r.open(cursor, want); err != nil {
			return nil, err
		}
	}
	if lc == nil {
		return out, nil
	}
	rev := lc.Rev
	out.Rev = &rev

	// Roles reviewed, with their identity facts and connector.
	var roles []struct {
		ID            uuid.UUID
		DisplayName   string
		SourceKey     string
		ImmutableKey  string
		Continuity    string
		AccountKind   string
		ProviderAttrs json.RawMessage
		ConnectorID   *uuid.UUID
	}
	if err := db.Raw(`SELECT i.id, i.display_name, i.source_key, i.immutable_key, i.continuity, i.account_kind, i.provider_attrs,
	                           s.connector_id
	                      FROM (SELECT identity_account_id AS id FROM iga_gov_activity_evidence WHERE workspace_id = ? AND rev = ?
	                            UNION
	                            SELECT f.identity_account_id FROM iga_gov_finding_result r
	                              JOIN iga_gov_finding f ON f.workspace_id = r.workspace_id AND f.id = r.finding_id
	                             WHERE r.workspace_id = ? AND r.rev = ? AND f.identity_account_id IS NOT NULL) rv
	                      JOIN iga_identity_accounts i ON i.workspace_id = ? AND i.id = rv.id
	                      LEFT JOIN LATERAL (SELECT connector_id FROM iga_object_support
	                                          WHERE workspace_id = i.workspace_id AND identity_account_id = i.id AND state <> 'ended'
	                                          ORDER BY (state = 'current') DESC, last_confirmed_at DESC NULLS LAST, id LIMIT 1) s ON true
	                     ORDER BY i.id`, ws, rev, ws, rev, ws).Scan(&roles).Error; err != nil {
		return nil, err
	}

	// Open findings at rev, by identity and kind.
	var open []struct {
		IdentityAccountID uuid.UUID
		Kind              string
		N                 int
	}
	if err := db.Raw(`SELECT f.identity_account_id, f.kind, count(*) AS n
	                    FROM iga_gov_finding_result r
	                    JOIN iga_gov_finding f ON f.workspace_id = r.workspace_id AND f.id = r.finding_id
	                   WHERE r.workspace_id = ? AND r.rev = ? AND f.identity_account_id IS NOT NULL
	                     AND f.status IN ('open','reopened','under_review')
	                   GROUP BY f.identity_account_id, f.kind`, ws, rev).Scan(&open).Error; err != nil {
		return nil, err
	}
	openBy := map[uuid.UUID]map[string]int{}
	for _, o := range open {
		if openBy[o.IdentityAccountID] == nil {
			openBy[o.IdentityAccountID] = map[string]int{}
		}
		openBy[o.IdentityAccountID][o.Kind] = o.N
	}
	// Activity not collected at rev.
	var nc []struct {
		IdentityAccountID uuid.UUID
		Reason            string
	}
	if err := db.Raw(`SELECT DISTINCT identity_account_id, reason FROM iga_gov_activity_evidence
	                   WHERE workspace_id = ? AND rev = ? AND state = 'not_collected'`, ws, rev).Scan(&nc).Error; err != nil {
		return nil, err
	}
	notCollected := map[uuid.UUID][]string{}
	for _, n := range nc {
		notCollected[n.IdentityAccountID] = append(notCollected[n.IdentityAccountID], n.Reason)
	}
	// Resource-policy coverage of each connector's run at rev.
	coverage, err := r.coverageAt(ctx, ws, rev)
	if err != nil {
		return nil, err
	}
	// Accountable owners: of the role, or of a workload consuming it.
	var owned []uuid.UUID
	if err := db.Raw(`SELECT DISTINCT o.identity_account_id FROM iga_gov_owner o
	                   WHERE o.workspace_id = ? AND o.role = 'accountable' AND o.object_kind = 'identity_account'
	                  UNION
	                  SELECT DISTINCT r.target_identity_account_id FROM iga_gov_owner o
	                    JOIN iga_relationship r ON r.workspace_id = o.workspace_id AND r.source_workload_id = o.workload_id
	                   WHERE o.workspace_id = ? AND o.role = 'accountable' AND o.object_kind = 'workload'
	                     AND r.state <> 'ended' AND r.relationship_type IN ('executes_as','task_execution_role')`,
		ws, ws).Scan(&owned).Error; err != nil {
		return nil, err
	}
	hasOwner := map[uuid.UUID]bool{}
	for _, id := range owned {
		hasOwner[id] = true
	}
	var bound []uuid.UUID
	if err := db.Raw(`SELECT DISTINCT target_identity_account_id FROM iga_relationship
	                   WHERE workspace_id = ? AND state <> 'ended' AND relationship_type IN ('executes_as','task_execution_role')`,
		ws).Scan(&bound).Error; err != nil {
		return nil, err
	}
	isBound := map[uuid.UUID]bool{}
	for _, id := range bound {
		isBound[id] = true
	}
	// Enforcement access and IaC sources per connector; the workspace mode.
	var iac []uuid.UUID
	bindings, err := cloudReads.VerifiedEnforcementConnectors(db, ws)
	if err != nil {
		return nil, err
	}
	if err := db.Raw(`SELECT DISTINCT connector_id FROM iga_gov_iac_source WHERE workspace_id = ?`, ws).Scan(&iac).Error; err != nil {
		return nil, err
	}
	hasBinding, hasIaC := setOf(bindings), setOf(iac)
	mode := models.GovModeFindingsOnly
	var modes []string
	if err := db.Raw(`SELECT enforcement_mode FROM iga_gov_settings WHERE workspace_id = ?`, ws).Scan(&modes).Error; err != nil {
		return nil, err
	}
	if len(modes) == 1 {
		mode = modes[0]
	}

	for _, ro := range roles {
		acct := govARNField(nativeOfSourceKey(ro.SourceKey), 4)
		if account != "" && acct != account {
			continue
		}
		var attrs roleAttrs
		_ = json.Unmarshal(ro.ProviderAttrs, &attrs)
		rr := ReadinessRole{IdentityAccountID: ro.ID, RoleID: ro.ImmutableKey, RoleName: ro.DisplayName,
			RoleARN: nativeOfSourceKey(ro.SourceKey), AccountID: acct, ConnectorID: ro.ConnectorID,
			OpenFindings: openBy[ro.ID], Reasons: []ReadinessReason{}}
		if rr.OpenFindings == nil {
			rr.OpenFindings = map[string]int{}
		}
		add := func(cat, code, detail string) {
			rr.Reasons = append(rr.Reasons, ReadinessReason{Category: cat, Code: code, Detail: detail})
		}
		for _, why := range dedupeSorted(notCollected[ro.ID]) {
			add(ReadinessBlockedByCollection, "activity_not_collected", why)
		}
		if rr.OpenFindings[igagov.KindActivityNotRead] > 0 && len(notCollected[ro.ID]) == 0 {
			add(ReadinessBlockedByCollection, "activity_not_collected", "")
		}
		if rr.OpenFindings[igagov.KindUnusedService] > 0 && ro.ConnectorID != nil {
			if cov := coverage[*ro.ConnectorID]; cov != igagov.CoverageComplete {
				if cov == "" {
					cov = igagov.CoverageNotCollected
				}
				add(ReadinessBlockedByCollection, "resource_policy_coverage_"+cov, "")
			}
		}
		for _, why := range RoleIneligibility(ro.AccountKind, ro.Continuity, ro.ImmutableKey, attrs.Path, attrs.Tags) {
			add(ReadinessIneligible, why, "")
		}
		if isBound[ro.ID] && !hasOwner[ro.ID] {
			add(ReadinessNeedsOwner, "no_accountable_owner", "")
		}
		if mode != models.GovModeEnforce {
			add(ReadinessIaCOnly, "enforcement_mode_findings_only", "")
		}
		if ro.ConnectorID == nil || !hasBinding[*ro.ConnectorID] {
			detail := "no_iac_source"
			if ro.ConnectorID != nil && hasIaC[*ro.ConnectorID] {
				detail = "iac_source_mapped"
			}
			add(ReadinessIaCOnly, "no_verified_enforcement_binding", detail)
		}
		if attrs.Boundary != "" && !strings.Contains(attrs.Boundary, ":policy/authsec/") {
			add(ReadinessIaCOnly, "customer_boundary", attrs.Boundary)
		}
		openTotal := 0
		for _, n := range rr.OpenFindings {
			openTotal += n
		}
		rr.Category = ReadinessNoChangeNeeded
		if openTotal > 0 {
			rr.Category = ReadinessDirectEligible
			for _, c := range ReadinessOrder[:4] {
				if readinessHasReason(rr.Reasons, c) {
					rr.Category = c
					break
				}
			}
		}
		rr.Remedy = readinessRemedy(rr)
		out.Counts[rr.Category]++
		out.RolesReviewed++
		if after != "" && ro.ID.String() <= after {
			continue
		}
		if len(out.Roles) < limit {
			out.Roles = append(out.Roles, rr)
		} else if out.Next == nil {
			c := want
			c.After = out.Roles[len(out.Roles)-1].IdentityAccountID.String()
			s := r.sign(c)
			out.Next = &s
		}
	}
	return out, nil
}

// coverageAt is the resource-policy coverage summary of each connector's
// run in rev's manifest.
func (r *GovReader) coverageAt(ctx context.Context, ws uuid.UUID, rev int64) (map[uuid.UUID]string, error) {
	var pub struct{ Manifest json.RawMessage }
	if err := r.db.WithContext(ctx).Raw(`SELECT manifest FROM iga_publication WHERE workspace_id = ? AND rev = ?`, ws, rev).
		Scan(&pub).Error; err != nil {
		return nil, err
	}
	m := map[string]string{}
	_ = json.Unmarshal(pub.Manifest, &m)
	ids := map[uuid.UUID]bool{}
	for _, v := range m {
		if id, err := uuid.Parse(v); err == nil {
			ids[id] = true
		}
	}
	runs, metas, err := loadRunEvidence(r.db.WithContext(ctx), ws, keysOf(ids), rev)
	if err != nil {
		return nil, err
	}
	out := map[uuid.UUID]string{}
	// The newest run per connector in the manifest decides (a connector's
	// partitions normally all name one run).
	newest := map[uuid.UUID]int{}
	for id, meta := range metas {
		if g, ok := newest[meta.ConnectorID]; ok && g >= meta.Generation {
			continue
		}
		newest[meta.ConnectorID] = meta.Generation
		run := runs[id]
		out[meta.ConnectorID] = igagov.SummarizeCoverage(run.ResourcePolicy, run.EnabledRegions)
	}
	return out, nil
}

func readinessRemedy(rr ReadinessRole) string {
	switch rr.Category {
	case ReadinessBlockedByCollection:
		return connectionCoverageLink(rr.ConnectorID)
	case ReadinessNeedsOwner:
		return "/iga/policy/findings?kind=missing_owner&identity_id=" + rr.IdentityAccountID.String()
	case ReadinessIaCOnly:
		return "/iga/policy/setup"
	case ReadinessIneligible, ReadinessDirectEligible:
		return "/iga/policy/findings?identity_id=" + rr.IdentityAccountID.String()
	}
	return ""
}

func readinessHasReason(rs []ReadinessReason, cat string) bool {
	for _, r := range rs {
		if r.Category == cat {
			return true
		}
	}
	return false
}

func setOf(ids []uuid.UUID) map[uuid.UUID]bool {
	out := make(map[uuid.UUID]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}

func dedupeSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
