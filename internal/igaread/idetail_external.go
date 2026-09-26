package igaread

// GET /api/iga/v1/external-principals/:id and .../referenced-by (§5.3
// External principals, T6.3; D-1, D-3, D-6, D-42, D-47, D-87): the far end of
// a trust -- an account, principal, service or federated subject the graph
// cannot read -- and the can_assume edges from it.
//
// An external principal has no provider column and no support rows (034), so
// it is readable in its workspace without D-6's support condition, and its
// state and lifecycle are DERIVED from its can_assume edges at read time
// (D-47): it is never retired by reconciliation. Its Overview answers "which
// account it belongs to, and why it is unresolved" (§2.14.5), so the reason is
// derived here and stated, never left for the reader to infer.

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// ExternalPrincipalLabelSQL is an external principal's display name (D-87),
// over iga_external_principal as ep:
//
//	aws_account          the account id; "*" is "any AWS principal" (D-42)
//	aws_principal        the ARN (or unresolved unique id / session ARN)
//	aws_service          the service principal
//	oidc, saml           issuer · subject
//	k8s_service_account  ns/sa (the pod: prefix D-42 adds is not shown)
//
// Written in SQL so a section can page on it (D-13 name order); no bind
// variables.
const ExternalPrincipalLabelSQL = `(CASE ep.mechanism
       WHEN 'aws_account' THEN (CASE WHEN ep.subject_claim = '*' THEN 'any AWS principal' ELSE ep.subject_claim END)
       WHEN 'aws_principal' THEN ep.subject_claim
       WHEN 'aws_service' THEN ep.subject_claim
       WHEN 'k8s_service_account' THEN replace(regexp_replace(ep.subject_claim, '^(pod:){0,1}system:serviceaccount:', ''), ':', '/')
       WHEN 'oidc' THEN ep.issuer || ' · ' || ep.subject_claim
       WHEN 'saml' THEN ep.issuer || ' · ' || ep.subject_claim
       ELSE ep.subject_claim END)`

// ExternalPrincipalAccountSQL is the account an external principal names,
// parsed only for aws_account (a 12-digit subject) and aws_principal (the
// account field of its ARN), D-87; empty otherwise -- "*", a service, a
// federated subject or an unresolved unique id state no account, and none is
// guessed (§2.14.10).
const ExternalPrincipalAccountSQL = `(CASE
       WHEN ep.mechanism = 'aws_account' AND ep.subject_claim ~ '^[0-9]{12}$' THEN ep.subject_claim
       WHEN ep.mechanism = 'aws_principal' AND ep.subject_claim LIKE 'arn:%'
            AND split_part(ep.subject_claim, ':', 5) ~ '^[0-9]{12}$' THEN split_part(ep.subject_claim, ':', 5)
       ELSE '' END)`

// ExternalPrincipalStateLateral derives an external principal's D-1 state and
// last_confirmed_at from its can_assume edges (it has no support rows, D-47),
// exposed as eps.state and eps.last_confirmed_at: current if any edge from it
// is current, else stale if any is stale, else ended (also when it has no
// edge at all). idx_iga_relationship_source_external serves it.
const ExternalPrincipalStateLateral = `LEFT JOIN LATERAL (
        SELECT CASE WHEN bool_or(r.state = 'current') THEN 'current'
                    WHEN bool_or(r.state = 'stale')   THEN 'stale'
                    ELSE 'ended' END AS state,
               max(r.last_confirmed_at) AS last_confirmed_at
          FROM iga_relationship r
         WHERE r.workspace_id = ep.workspace_id AND r.source_external_principal_id = ep.id
           AND r.relationship_type = 'can_assume') eps ON true`

// Why an external principal is unresolved (§2.14.5 "why it is unresolved";
// E11 "unresolved, account not connected"). Derived, because 034 stores no
// reason.
const (
	// UnresolvedWildcard: the subject is a pattern ("*", repo:org/*), which no
	// single identity can match.
	UnresolvedWildcard = "wildcard"
	// UnresolvedServicePrincipal: an AWS service, never an identity we hold.
	UnresolvedServicePrincipal = "service_principal"
	// UnresolvedAccountNotConnected: it names an account whose inventory is
	// not in this revision (ExternalPrincipalAccount): no live connector
	// reads it, or one was onboarded but none of its runs is published yet.
	UnresolvedAccountNotConnected = "account_not_connected"
	// UnresolvedAccountPrincipal: an aws_account principal in a connected
	// account. It means "any principal that account permits" (§4.7), so no
	// single identity can ever match it; "not in inventory" would claim we
	// looked for one and found nothing.
	UnresolvedAccountPrincipal = "account_principal"
	// UnresolvedNotInInventory: everything else -- a connected account's
	// principal we hold no identity for, a federated subject, an unresolved
	// unique id, or a resolution that is not in force.
	UnresolvedNotInInventory = "not_in_inventory"
)

// ExternalRetiredNoLongerReferenced is a retired external principal's
// retired_reason (§5.2 "Every detail route returns retired objects with
// lifecycle, retired_reason and last_confirmed_at"). DERIVED like its
// lifecycle (D-47): nothing retires an external principal, it is retired
// exactly when no can_assume from it is current or stale -- every trust
// statement that named it has ended, or none was ever recorded.
const ExternalRetiredNoLongerReferenced = "no_longer_referenced"

// RevisionConnectors is the set of connectors the current revision holds a
// projected run of: every connector with an iga_projection_state row, read in
// this snapshot (D-57: at the current revision that is the manifest). A
// connector onboarded after the revision, whose first publication is still
// pending, is not in it.
func RevisionConnectors(q *Query) (map[uuid.UUID]bool, error) {
	var ids []uuid.UUID
	if err := q.DB().Raw(`SELECT DISTINCT ps.connector_id FROM iga_projection_state ps WHERE ps.workspace_id = ?`,
		q.WS).Scan(&ids).Error; err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

// ExternalPrincipalAccount is the account an external principal names, with
// connected fixed by the REVISION (§5.1 "a response cannot straddle two
// publications"; D-3, D-25): connected only when a live connector for it has
// a run in the revision (inRevision, RevisionConnectors). An identity or
// workload is connected by construction -- it exists only because its account
// was projected -- but the account an external principal names may never have
// been read, and onboarding it publishes nothing: until its first publication
// its inventory is not in the graph, so it reads not connected, exactly as it
// did before onboarding, and nothing can say "not in inventory" of it. A
// revoked connector is not connected (D-61, D-89). nil when the principal
// names no account.
func ExternalPrincipalAccount(accts *Accounts, inRevision map[uuid.UUID]bool, accountID string) *Account {
	a := accts.Of(accountID)
	if a == nil || !a.Connected {
		return a
	}
	a.Connected = false
	for _, c := range accts.All() {
		if c.AccountID == accountID && c.Status != models.CloudConnectorRevoked && inRevision[c.ID] {
			a.Connected = true
			break
		}
	}
	return a
}

// ExternalPrincipalDetail is the /external-principals/:id data object.
//
// account is {id, label, connected} (D-3; connected as of the revision,
// ExternalPrincipalAccount) or null when the principal states none;
// account_connected repeats account.connected, and is null with it -- a
// service principal is not "in an unconnected account". resolution is null
// when no resolution was ever recorded (D-87), else the stored one;
// unresolved_reason is null exactly when a resolution is in force (state
// active, with a target). lifecycle is derived (D-47): active while any
// can_assume from it is current or stale, retired once every one has ended,
// and then retired_reason says so (ExternalRetiredNoLongerReferenced).
type ExternalPrincipalDetail struct {
	Ref              string              `json:"ref"`
	Name             string              `json:"name"`
	Mechanism        string              `json:"mechanism"`
	Issuer           string              `json:"issuer"`
	Subject          string              `json:"subject"`
	Account          *Account            `json:"account"`
	AccountConnected *bool               `json:"account_connected"`
	Resolution       *ExternalResolution `json:"resolution"`
	UnresolvedReason *string             `json:"unresolved_reason"`
	Lifecycle        string              `json:"lifecycle"`
	RetiredReason    *string             `json:"retired_reason"` // null while active (§5.2; D-98)
	State            string              `json:"state"`
	FirstSeenAt      any                 `json:"first_seen_at"`
	LastSeenAt       any                 `json:"last_seen_at"`
	LastConfirmedAt  any                 `json:"last_confirmed_at"`
}

// ExternalResolution is a recorded resolution (§2.12, 034): whether it applies
// now (state), how it was reached (basis derived|asserted, rule), what it
// points at, and who asserted it. Parts not recorded are null.
type ExternalResolution struct {
	State      string  `json:"state"`
	Basis      string  `json:"basis"`
	Rule       *string `json:"rule"`
	ResolvedTo any     `json:"resolved_to"`
	ResolvedBy *string `json:"resolved_by"`
}

type idetailExternalRow struct {
	ID                        uuid.UUID
	Mechanism                 string
	Issuer                    string
	SubjectClaim              string
	ResolvedIdentityAccountID *uuid.UUID
	ResolvedWorkloadID        *uuid.UUID
	ResolutionBasis           string
	ResolutionRule            string
	ResolvedBy                string
	ResolutionState           string
	FirstSeenAt               time.Time
	LastSeenAt                time.Time
	Name                      string
	AccountID                 string
	State                     string
	LastConfirmedAt           *time.Time
}

// idetailLoadExternal reads an external principal of this workspace, or nil.
func idetailLoadExternal(q *Query, id uuid.UUID) (*idetailExternalRow, error) {
	var rows []idetailExternalRow
	if err := q.DB().Raw(`SELECT ep.id, ep.mechanism, ep.issuer, ep.subject_claim,
	                             ep.resolved_identity_account_id, ep.resolved_workload_id,
	                             ep.resolution_basis, ep.resolution_rule, ep.resolved_by, ep.resolution_state,
	                             ep.first_seen_at, ep.last_seen_at,
	                             `+ExternalPrincipalLabelSQL+` AS name,
	                             `+ExternalPrincipalAccountSQL+` AS account_id,
	                             eps.state, eps.last_confirmed_at
	                        FROM iga_external_principal ep
	                        `+ExternalPrincipalStateLateral+`
	                       WHERE ep.workspace_id = ? AND ep.id = ?`, q.WS, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// idetailExternalPairs is the (connector_id, partition_key) subquery of an
// external principal's edges, for idetailCoverage: the partitions whose runs
// its can_assume edges were projected from.
const idetailExternalPairs = `SELECT r.connector_id, r.partition_key FROM iga_relationship r
                               WHERE r.workspace_id = ? AND r.source_external_principal_id = ?
                                 AND r.connector_id IS NOT NULL`

// idetailExternalSurfaces is what bears on an external principal: the role
// listing whose trust documents name it, the permission scan its trust
// partition requires, and EKS pod identity.
var idetailExternalSurfaces = idetailSurfaces{
	exact: map[string]string{
		models.SurfaceIAMRoles:       "trust documents that may name this principal",
		models.SurfacePermissionScan: "trust relationships from this principal",
		models.SurfaceEKSPodIdentity: "EKS pod identity associations that may name this principal",
	},
	revoked: "trust relationships from this principal are no longer refreshed",
}

// GetExternalPrincipal serves GET /external-principals/:id. 404 not_found
// when nothing is published (D-4), for a malformed id or another type's
// reference (D-5), and when the principal is not this workspace's.
func (r *Reader) GetExternalPrincipal(ctx context.Context, ws uuid.UUID, rawID string, vals url.Values) (any, error) {
	rev, perr := idetailParams(vals, "rev")
	if perr != nil {
		return nil, perr
	}
	ctx, perr = bindOptIn(ctx, vals)
	if perr != nil {
		return nil, perr
	}
	id, nerr := RouteID(RefExternalPrincipal, rawID)
	if nerr != nil {
		return nil, nerr
	}
	var out Envelope
	err := r.Read(ctx, ws, Pin{Rev: rev}, func(q *Query) error {
		if !q.Published() {
			return NotFound()
		}
		ep, err := idetailLoadExternal(q, id)
		if err != nil {
			return err
		}
		if ep == nil {
			return NotFound()
		}
		accts, err := q.LoadAccounts()
		if err != nil {
			return err
		}
		inRevision, err := RevisionConnectors(q)
		if err != nil {
			return err
		}
		detail := ExternalPrincipalDetail{
			Ref:             R(RefExternalPrincipal, ep.ID),
			Name:            ep.Name,
			Mechanism:       ep.Mechanism,
			Issuer:          ep.Issuer,
			Subject:         ep.SubjectClaim,
			Account:         ExternalPrincipalAccount(accts, inRevision, ep.AccountID),
			Resolution:      ExternalResolutionOf(ep.ResolutionBasis, ep.ResolutionState, ep.ResolutionRule, ep.ResolvedBy, ep.ResolvedIdentityAccountID, ep.ResolvedWorkloadID),
			Lifecycle:       ExternalLifecycleOf(ep.State),
			State:           ep.State,
			FirstSeenAt:     T(ep.FirstSeenAt),
			LastSeenAt:      T(ep.LastSeenAt),
			LastConfirmedAt: TS(ep.LastConfirmedAt),
		}
		if detail.Lifecycle == models.IGALifecycleRetired {
			detail.RetiredReason = strPtr(ExternalRetiredNoLongerReferenced)
		}
		if detail.Account != nil {
			c := detail.Account.Connected
			detail.AccountConnected = &c
		}
		detail.UnresolvedReason = UnresolvedReasonOf(ep.Mechanism, ep.SubjectClaim, detail.Account, detail.Resolution)
		meta := IdentityTabMeta{DetailMeta: NewDetailMeta(q)}
		if meta.Coverage, err = idetailCoverage(q, accts, idetailExternalPairs, []any{q.WS, id}, idetailExternalSurfaces); err != nil {
			return err
		}
		out = Envelope{Data: detail, Meta: meta}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ExternalResolutionOf renders a stored resolution (D-87): nil when none was
// ever recorded (resolution_basis empty); otherwise every part, null where not
// recorded. resolution_state defaults to 'active' in 034 even with no
// target, which is why the basis -- not the state -- decides presence.
func ExternalResolutionOf(basis, state, rule, by string, identity, workload *uuid.UUID) *ExternalResolution {
	if basis == "" {
		return nil
	}
	res := &ExternalResolution{State: state, Basis: basis, Rule: strPtr(rule), ResolvedBy: strPtr(by)}
	switch {
	case identity != nil:
		res.ResolvedTo = R(RefIdentity, *identity)
	case workload != nil:
		res.ResolvedTo = R(RefWorkload, *workload)
	}
	return res
}

// ExternalLifecycleOf is an external principal's derived lifecycle (D-47):
// active while any can_assume from it is current or stale, else retired.
func ExternalLifecycleOf(state string) string {
	if state == StateCurrent || state == StateStale {
		return models.IGALifecycleActive
	}
	return models.IGALifecycleRetired
}

// UnresolvedReasonOf derives why an external principal is unresolved (see the
// Unresolved* constants), or nil when a resolution is in force -- recorded,
// state active, pointing at an identity or workload. Checked in this order: a
// pattern subject, a service, an unconnected account, a whole account (an
// aws_account principal names no identity even in a connected account), else
// not in inventory. account must be connected as of the revision
// (ExternalPrincipalAccount): not_in_inventory is said only of an account
// whose inventory the revision holds.
func UnresolvedReasonOf(mechanism, subject string, account *Account, res *ExternalResolution) *string {
	if res != nil && res.State == models.ResolutionActive && res.ResolvedTo != nil {
		return nil
	}
	reason := UnresolvedNotInInventory
	switch {
	case strings.ContainsAny(subject, "*?"):
		reason = UnresolvedWildcard
	case mechanism == models.ExternalPrincipalAWSService:
		reason = UnresolvedServicePrincipal
	case account != nil && !account.Connected:
		reason = UnresolvedAccountNotConnected
	case mechanism == models.ExternalPrincipalAWSAccount:
		reason = UnresolvedAccountPrincipal
	}
	return &reason
}

/* ------------------------------ referenced-by ------------------------------ */

// ReferencedByRoute is the cursor route of one principal's referenced-by
// (D-62).
func ReferencedByRoute(principalID uuid.UUID) string {
	return "external-principals/" + principalID.String() + "/referenced-by"
}

// ReferencedByEdge is one can_assume FROM the principal: the role it may
// assume, the mechanism, the declaring trust statement, and its conditions
// verbatim (recorded, never evaluated). Two statements naming the principal
// under different conditions are two rows (§4.7).
type ReferencedByEdge struct {
	ClaimFields
	Target     IdentityRef     `json:"target"`
	Mechanism  string          `json:"mechanism"`
	Statement  TrustStatement  `json:"statement"`
	Conditions json.RawMessage `json:"conditions"`
}

type idetailReferencedScan struct {
	TabKeyCols
	RelationshipClaimRow
	Mechanism    string
	Conditions   json.RawMessage
	StatementKey string
	Negated      bool
	TargetID     uuid.UUID
	DisplayName  string
	AccountKind  string
	SourceKey    string
	AccountID    string
}

// ExternalPrincipalReferencedBy serves GET /external-principals/:id/
// referenced-by: a single-collection tab in the §5.2 list envelope (D-77),
// 100 per page (limit 1-200), ordered by the target role's name, then
// account, then the claim id (D-13); include_ended adds ended edges (D-12).
func (r *Reader) ExternalPrincipalReferencedBy(ctx context.Context, ws uuid.UUID, rawID string, vals url.Values) (any, error) {
	rev, perr := idetailParams(vals, "rev", "cursor", "limit", "include_ended")
	if perr != nil {
		return nil, perr
	}
	limit, perr := idetailLimit(vals)
	if perr != nil {
		return nil, perr
	}
	includeEnded, perr := idetailIncludeEnded(vals)
	if perr != nil {
		return nil, perr
	}
	ctx, perr = bindOptIn(ctx, vals)
	if perr != nil {
		return nil, perr
	}
	id, nerr := RouteID(RefExternalPrincipal, rawID)
	if nerr != nil {
		return nil, nerr
	}
	filter := idetailFilterHash(includeEnded)
	route := ReferencedByRoute(id)
	pin := Pin{Rev: rev}
	var after *idetailAfter
	if c := vals.Get("cursor"); c != "" {
		a, crev, cerr := r.idetailOpenCursor(c, ws, route, filter)
		if cerr != nil {
			return nil, cerr
		}
		after, pin.CursorRev = a, crev
	}

	var out Envelope
	err := r.Read(ctx, ws, pin, func(q *Query) error {
		if !q.Published() {
			return NotFound()
		}
		ep, err := idetailLoadExternal(q, id)
		if err != nil {
			return err
		}
		if ep == nil {
			return NotFound()
		}
		accts, err := q.LoadAccounts()
		if err != nil {
			return err
		}
		sq := idetailSectionQuery{
			columns: idetailClaimColumns + `, r.mechanism, r.conditions, r.statement_key,
			         COALESCE((ia.provider_attrs -> '` + igagraph.TrustNegatedStatementsAttr + `') @> to_jsonb(r.statement_key), false) AS negated,
			         ia.id AS target_id, ia.display_name, ia.account_kind, ia.source_key,
			         ` + IdentityAccountSQL + ` AS account_id`,
			from: `iga_relationship r
			  JOIN iga_identity_accounts ia ON ia.workspace_id = r.workspace_id AND ia.id = r.target_identity_account_id`,
			// idx_iga_relationship_source_external.
			where: `r.workspace_id = ? AND r.source_external_principal_id = ? AND r.relationship_type = ?
			        AND r.state IN ? AND ia.provider = 'aws'`,
			args:    []any{q.WS, id, models.RelTypeCanAssume, idetailEdgeStates(includeEnded)},
			name:    "ia.display_name",
			account: IdentityAccountSQL,
			id:      "r.id",
		}
		var rows []idetailReferencedScan
		if err := idetailPage(q.DB(), sq, after, limit, &rows); err != nil {
			return err
		}
		sec, keep, err := r.idetailFinish(q, sq, route, filter, limit, len(rows),
			func(i int) (idetailNameKey, uuid.UUID) { return rows[i].key(), rows[i].RelID })
		if err != nil {
			return err
		}
		rows = rows[:keep]
		claims := make([]RelationshipClaimRow, len(rows))
		for i := range rows {
			claims[i] = rows[i].RelationshipClaimRow
		}
		reasons, err := idetailClaimReasons(q, accts, claims)
		if err != nil {
			return err
		}
		items := make([]ReferencedByEdge, 0, len(rows))
		for _, e := range rows {
			st := TrustStatementOf(e.StatementKey, nil)
			st.Negated = e.Negated
			items = append(items, ReferencedByEdge{
				ClaimFields: e.fields(reasons),
				Target: IdentityRef{Ref: R(RefIdentity, e.TargetID), Name: e.DisplayName, Kind: e.AccountKind,
					ARN: NativeOfKey(e.SourceKey), Account: accts.Of(e.AccountID)},
				Mechanism:  e.Mechanism,
				Statement:  st,
				Conditions: NullableJSON(e.Conditions),
			})
		}
		meta := NewListMeta(q, limit)
		meta.NextCursor = sec.NextCursor
		meta.TotalKnown, meta.Total, meta.TotalAtLeast = sec.TotalKnown, sec.Total, sec.TotalAtLeast
		if meta.Coverage, err = idetailCoverage(q, accts, idetailExternalPairs, []any{q.WS, id}, idetailExternalSurfaces); err != nil {
			return err
		}
		out = Envelope{Data: items, Meta: meta}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
