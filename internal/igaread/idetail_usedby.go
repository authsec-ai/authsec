package igaread

// GET /api/iga/v1/identities/:id/used-by (§5.3 Identities, T6.3; D-77, D-62,
// D-12, D-13): who uses this identity, in sections by relationship kind --
//
//	workloads   iam_role   executes_as and task_execution_role INTO it, each
//	                       with its relationship type (§2.2: the ECS execution
//	                       role is not the task's identity)
//	principals  iam_role   can_assume INTO it: identities and external
//	                       principals, with mechanism, conditions and the
//	                       declaring trust statement (§4.7)
//	members     iam_group  member_of INTO it: the users in the group
//
// A user is used by nothing (a workload runs as a role; only a role is
// assumed), so its data carries only the identity header.
//
// Each section pages on its own (D-77): with no section parameter every
// section of the identity's kind returns its first page with its own
// next_cursor; ?section=<name>&cursor= returns that section only. One row per
// CLAIM, never merged: an ECS task definition whose task role is also its
// execution role is two rows, each its own relationship. Order: name, then
// account (unknown last), then the claim id (D-13). Each section is one
// keyset-paged statement over the typed FK columns (§5.6), its total an
// optional count.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// Used-by sections.
const (
	UsedByWorkloads  = "workloads"
	UsedByPrincipals = "principals"
	UsedByMembers    = "members"
)

// UsedBySections is which sections apply to each identity kind, in the order
// the tab shows them (§2.14.6: "workloads that run as it, then principals
// that may assume it").
var UsedBySections = map[string][]string{
	models.CloudIdentityIAMRole:  {UsedByWorkloads, UsedByPrincipals},
	models.CloudIdentityIAMGroup: {UsedByMembers},
	models.CloudIdentityIAMUser:  {},
}

// UsedByRoute is the cursor route of one identity's section (D-62), so a
// cursor for one identity or section can never page another.
func UsedByRoute(identityID uuid.UUID, section string) string {
	return "identities/" + identityID.String() + "/used-by/" + section
}

// UsedByWorkload is one row of the workloads section.
type UsedByWorkload struct {
	ClaimFields
	Workload UsedByWorkloadRef `json:"workload"`
}

// UsedByWorkloadRef names the workload on a used-by row, with its account
// (D-3: its connector's) and region ("" -> null, D-63).
type UsedByWorkloadRef struct {
	Ref         string   `json:"ref"`
	Name        string   `json:"name"`
	RuntimeKind string   `json:"runtime_kind"`
	ARN         string   `json:"arn"`
	Account     *Account `json:"account"`
	Region      *string  `json:"region"`
}

// UsedByPrincipal is one row of the principals section: a can_assume INTO
// the role.
type UsedByPrincipal struct {
	ClaimFields
	Principal  PrincipalRef    `json:"principal"`
	Mechanism  string          `json:"mechanism"`
	Conditions json.RawMessage `json:"conditions"`
	Statement  TrustStatement  `json:"statement"`
}

// PrincipalRef names the source of a can_assume: an identity (kind is its
// account_kind, arn its ARN) or an external principal (kind is its mechanism
// -- aws_account, oidc ... -- name its D-87 label, arn null).
type PrincipalRef struct {
	Ref     string   `json:"ref"`
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	ARN     *string  `json:"arn"`
	Account *Account `json:"account"`
}

// TrustStatement names the trust statement that declared a can_assume
// (§4.7): its stored statement_key, the Sid when the key is Sid-keyed (else
// ""), and negated when the statement was written with NotAction -- the
// role's provider_attrs list those keys (D-88), and such an edge carries the
// negated_statement limitation.
type TrustStatement struct {
	Key     string `json:"key"`
	Sid     string `json:"sid"`
	Negated bool   `json:"negated"`
}

// UsedByMember is one row of the members section: a user's member_of INTO
// the group.
type UsedByMember struct {
	ClaimFields
	Member IdentityRef `json:"member"`
}

// IdentityRef names an identity on another object's row.
type IdentityRef struct {
	Ref     string   `json:"ref"`
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	ARN     string   `json:"arn"`
	Account *Account `json:"account"`
}

// IdentityUsedBy serves GET /identities/:id/used-by.
//
// Parameters (400 before the snapshot, D-10): section (workloads | principals
// | members), cursor (only with section), limit (1-200, default 100),
// include_ended (D-12), rev. A section that does not apply to the identity's
// kind is 400 invalid_parameter naming section, read in the snapshot.
func (r *Reader) IdentityUsedBy(ctx context.Context, ws uuid.UUID, rawID string, vals url.Values) (any, error) {
	rev, perr := idetailParams(vals, "rev", "section", "cursor", "limit", "include_ended")
	if perr != nil {
		return nil, perr
	}
	section := vals.Get("section")
	switch section {
	case "", UsedByWorkloads, UsedByPrincipals, UsedByMembers:
	default:
		return nil, InvalidParameter("section", "section must be workloads, principals or members")
	}
	cursor := vals.Get("cursor")
	if cursor != "" && section == "" {
		return nil, InvalidParameter("cursor", "a cursor pages one section: pass section with it")
	}
	limit, perr := idetailLimit(vals)
	if perr != nil {
		return nil, perr
	}
	includeEnded, perr := idetailIncludeEnded(vals)
	if perr != nil {
		return nil, perr
	}
	id, nerr := RouteID(RefIdentity, rawID)
	if nerr != nil {
		return nil, nerr
	}
	filter := idetailFilterHash(includeEnded)

	pin := Pin{Rev: rev}
	var after *idetailAfter
	if cursor != "" {
		a, crev, cerr := r.idetailOpenCursor(cursor, ws, UsedByRoute(id, section), filter)
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
		ident, err := idetailLoadIdentity(q, id)
		if err != nil {
			return err
		}
		if ident == nil {
			return NotFound()
		}
		applies := UsedBySections[ident.AccountKind]
		sections := applies
		if section != "" {
			if !contains(applies, section) {
				return InvalidParameter("section", fmt.Sprintf("section %s does not apply to an %s", section, ident.AccountKind))
			}
			sections = []string{section}
		}
		accts, err := q.LoadAccounts()
		if err != nil {
			return err
		}
		data := map[string]any{"identity": ident.header()}
		states := idetailEdgeStates(includeEnded)
		for _, s := range sections {
			var a *idetailAfter
			if s == section {
				a = after
			}
			page, err := r.idetailUsedBySection(q, accts, ident, s, states, a, limit, filter)
			if err != nil {
				return err
			}
			data[s] = page
		}
		meta := IdentityTabMeta{DetailMeta: NewDetailMeta(q)}
		if meta.Coverage, err = idetailCoverage(q, accts, idetailSupportPairs, []any{q.WS, id},
			idetailUsedBySurfaces(ident.AccountKind)); err != nil {
			return err
		}
		out = Envelope{Data: data, Meta: meta}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// idetailUsedBySurfaces is what bears on the Used-by tab: for a role, the
// regional workload surfaces (a workload missed there may run as it), the
// workload scan, the role listing and permission scan that carry its trust
// document, and EKS pod identity; for a group, the user and group listings
// its memberships come from.
func idetailUsedBySurfaces(kind string) idetailSurfaces {
	w := idetailSurfaces{exact: map[string]string{}, regional: map[string]string{},
		revoked: "who uses this identity is no longer refreshed"}
	switch kind {
	case models.CloudIdentityIAMRole:
		for prefix := range listsWorkloadSurfaces {
			w.regional[prefix] = "workloads that may run as this role"
		}
		w.regional[strings.TrimSuffix(models.SurfaceComputePrefix, ":")] = "workloads that may run as this role"
		w.exact[models.SurfaceWorkloadScan] = "workloads that may run as this role"
		w.exact[models.SurfaceIAMRoles] = "this role's trust document and the roles that may assume it"
		w.exact[models.SurfacePermissionScan] = "principals that may assume this role"
		w.exact[models.SurfaceEKSPodIdentity] = "EKS pod identities that may assume this role"
	case models.CloudIdentityIAMGroup:
		w.exact[models.SurfaceIAMUsers] = "members of this group"
		w.exact[models.SurfaceIAMGroups] = "members of this group"
	}
	return w
}

// idetailSectionQuery is one section's statement: its select list and FROM,
// its WHERE (with args), and the name / account / id expressions it pages on.
type idetailSectionQuery struct {
	columns string
	from    string
	where   string
	args    []any
	name    string
	account string
	id      string
}

// idetailPage runs one keyset page of q (limit+1 rows, so the presence of a
// next page is known without a count) into dest, which must be a pointer to
// a slice of structs embedding TabKeyCols and RelationshipClaimRow.
func idetailPage(tx *gorm.DB, sq idetailSectionQuery, after *idetailAfter, limit int, dest any) error {
	cols, afterSQL, order := idetailNameOrder(sq.name, sq.account, sq.id)
	where, args := sq.where, append([]any{}, sq.args...)
	if after != nil {
		where += ` AND ` + afterSQL
		args = append(args, after.args()...)
	}
	return tx.Raw(`SELECT `+sq.columns+`, `+cols+` FROM `+sq.from+` WHERE `+where+
		` ORDER BY `+order+` LIMIT ?`, append(args, limit+1)...).Scan(dest).Error
}

// idetailCount is a section's total, as OPTIONAL work (§5.2 Totals).
func idetailCount(q *Query, sq idetailSectionQuery) (int64, bool, error) {
	return q.CountUpTo(func(tx *gorm.DB) *gorm.DB {
		return tx.Table(sq.from).Where(sq.where, sq.args...)
	})
}

// idetailUsedBySection reads one page of one section.
func (r *Reader) idetailUsedBySection(q *Query, accts *Accounts, ident *idetailIdentityRow, section string,
	states []string, after *idetailAfter, limit int, filter string) (*Section, error) {
	switch section {
	case UsedByWorkloads:
		return r.idetailWorkloads(q, accts, ident, states, after, limit, filter)
	case UsedByPrincipals:
		return r.idetailPrincipals(q, accts, ident, states, after, limit, filter)
	default:
		return r.idetailMembers(q, accts, ident, states, after, limit, filter)
	}
}

// idetailFinish trims a page read with limit+1, signs the next cursor from
// the last kept row, and counts the section.
func (r *Reader) idetailFinish(q *Query, sq idetailSectionQuery, route, filter string, limit int,
	n int, keyOf func(i int) (idetailNameKey, uuid.UUID)) (*Section, int, error) {
	sec := &Section{}
	keep := n
	if n > limit {
		keep = limit
		k, id := keyOf(limit - 1)
		tok, err := r.idetailNextCursor(q, route, filter, k, id)
		if err != nil {
			return nil, 0, err
		}
		sec.NextCursor = tok
	}
	total, known, err := idetailCount(q, sq)
	if err != nil {
		return nil, 0, err
	}
	sec.setTotal(total, known)
	return sec, keep, nil
}

/* -------------------------------- workloads -------------------------------- */

type idetailWorkloadScan struct {
	TabKeyCols
	RelationshipClaimRow
	WorkloadID  uuid.UUID
	DisplayName string
	RuntimeKind string
	SourceKey   string
	Region      string
	AccountID   string
}

func (r *Reader) idetailWorkloads(q *Query, accts *Accounts, ident *idetailIdentityRow, states []string,
	after *idetailAfter, limit int, filter string) (*Section, error) {
	sq := idetailSectionQuery{
		columns: idetailClaimColumns + `, w.id AS workload_id, w.display_name, w.runtime_kind, w.source_key, w.region,
		         ` + WorkloadAccountSQL + ` AS account_id`,
		from: `iga_relationship r
		  JOIN iga_workload w ON w.workspace_id = r.workspace_id AND w.id = r.source_workload_id
		  LEFT JOIN iga_estate_scopes es ON es.workspace_id = w.workspace_id AND es.id = w.estate_scope_id`,
		// idx_iga_relationship_target: (workspace_id, relationship_type,
		// target_identity_account_id). The workload must be a graph row (D-6).
		where: `r.workspace_id = ? AND r.relationship_type IN ? AND r.target_identity_account_id = ?
		        AND r.state IN ? AND w.provider = 'aws' AND ` + SupportedSQL("w", "workload_id"),
		args:    []any{q.WS, UsedByTypes, ident.ID, states},
		name:    "w.display_name",
		account: WorkloadAccountSQL,
		id:      "r.id",
	}
	var rows []idetailWorkloadScan
	if err := idetailPage(q.DB(), sq, after, limit, &rows); err != nil {
		return nil, err
	}
	sec, keep, err := r.idetailFinish(q, sq, UsedByRoute(ident.ID, UsedByWorkloads), filter, limit, len(rows),
		func(i int) (idetailNameKey, uuid.UUID) { return rows[i].key(), rows[i].RelID })
	if err != nil {
		return nil, err
	}
	rows = rows[:keep]
	claims := make([]RelationshipClaimRow, len(rows))
	for i := range rows {
		claims[i] = rows[i].RelationshipClaimRow
	}
	reasons, err := idetailClaimReasons(q, accts, claims)
	if err != nil {
		return nil, err
	}
	items := make([]UsedByWorkload, 0, len(rows))
	for _, w := range rows {
		items = append(items, UsedByWorkload{
			ClaimFields: w.fields(reasons),
			Workload: UsedByWorkloadRef{
				Ref: R(RefWorkload, w.WorkloadID), Name: w.DisplayName, RuntimeKind: w.RuntimeKind,
				ARN: NativeOfKey(w.SourceKey), Account: accts.Of(w.AccountID), Region: strPtr(w.Region),
			},
		})
	}
	sec.Items = items
	return sec, nil
}

/* -------------------------------- principals ------------------------------- */

type idetailPrincipalScan struct {
	TabKeyCols
	RelationshipClaimRow
	Mechanism    string
	Conditions   json.RawMessage
	StatementKey string
	IdentityID   *uuid.UUID
	IdentityKind string
	IdentityKey  string
	ExternalID   *uuid.UUID
	ExternalKind string
	Name         string
	AccountID    string
}

// idetailPrincipalName and idetailPrincipalAccount are a can_assume source's
// name and account: an identity's display name and ARN account, or an
// external principal's D-87 label and parsed account.
const (
	idetailPrincipalName    = `COALESCE(ia.display_name, ` + ExternalPrincipalLabelSQL + `, '')`
	idetailPrincipalAccount = `COALESCE(CASE WHEN ia.id IS NOT NULL THEN ` + IdentityAccountSQL +
		` ELSE ` + ExternalPrincipalAccountSQL + ` END, '')`
)

func (r *Reader) idetailPrincipals(q *Query, accts *Accounts, ident *idetailIdentityRow, states []string,
	after *idetailAfter, limit int, filter string) (*Section, error) {
	sq := idetailSectionQuery{
		columns: idetailClaimColumns + `, r.mechanism, r.conditions, r.statement_key,
		         ia.id AS identity_id, COALESCE(ia.account_kind, '') AS identity_kind,
		         COALESCE(ia.source_key, '') AS identity_key,
		         ep.id AS external_id, COALESCE(ep.mechanism, '') AS external_kind,
		         ` + idetailPrincipalName + ` AS name, ` + idetailPrincipalAccount + ` AS account_id`,
		from: `iga_relationship r
		  LEFT JOIN iga_identity_accounts ia ON ia.workspace_id = r.workspace_id AND ia.id = r.source_identity_account_id
		  LEFT JOIN iga_external_principal ep ON ep.workspace_id = r.workspace_id AND ep.id = r.source_external_principal_id`,
		where: `r.workspace_id = ? AND r.relationship_type = ? AND r.target_identity_account_id = ?
		        AND r.state IN ? AND (r.source_identity_account_id IS NULL OR ia.provider = 'aws')`,
		args:    []any{q.WS, models.RelTypeCanAssume, ident.ID, states},
		name:    idetailPrincipalName,
		account: idetailPrincipalAccount,
		id:      "r.id",
	}
	var rows []idetailPrincipalScan
	if err := idetailPage(q.DB(), sq, after, limit, &rows); err != nil {
		return nil, err
	}
	sec, keep, err := r.idetailFinish(q, sq, UsedByRoute(ident.ID, UsedByPrincipals), filter, limit, len(rows),
		func(i int) (idetailNameKey, uuid.UUID) { return rows[i].key(), rows[i].RelID })
	if err != nil {
		return nil, err
	}
	rows = rows[:keep]
	claims := make([]RelationshipClaimRow, len(rows))
	for i := range rows {
		claims[i] = rows[i].RelationshipClaimRow
	}
	reasons, err := idetailClaimReasons(q, accts, claims)
	if err != nil {
		return nil, err
	}
	negated := TrustNegatedStatements(ident.ProviderAttrs)
	// A NotPrincipal trust statement ("everyone except X") names no one an
	// edge could come from (D-44), so this section cannot list who it lets
	// in: say so, or an empty section would read "nobody may assume it".
	if TrustHasNotPrincipal(ident.ProviderAttrs) {
		sec.Limitations = []string{LimitationNotPrincipalUnresolved}
	}
	items := make([]UsedByPrincipal, 0, len(rows))
	for _, p := range rows {
		ref := PrincipalRef{Name: p.Name, Account: accts.Of(p.AccountID)}
		switch {
		case p.IdentityID != nil:
			arn := NativeOfKey(p.IdentityKey)
			ref.Ref, ref.Kind, ref.ARN = R(RefIdentity, *p.IdentityID), p.IdentityKind, &arn
		case p.ExternalID != nil:
			ref.Ref, ref.Kind = R(RefExternalPrincipal, *p.ExternalID), p.ExternalKind
		}
		items = append(items, UsedByPrincipal{
			ClaimFields: p.fields(reasons),
			Principal:   ref,
			Mechanism:   p.Mechanism,
			Conditions:  NullableJSON(p.Conditions),
			Statement:   TrustStatementOf(p.StatementKey, negated),
		})
	}
	sec.Items = items
	return sec, nil
}

/* --------------------------------- members --------------------------------- */

type idetailMemberScan struct {
	TabKeyCols
	RelationshipClaimRow
	UserID      uuid.UUID
	DisplayName string
	AccountKind string
	SourceKey   string
	AccountID   string
}

func (r *Reader) idetailMembers(q *Query, accts *Accounts, ident *idetailIdentityRow, states []string,
	after *idetailAfter, limit int, filter string) (*Section, error) {
	sq := idetailSectionQuery{
		columns: idetailClaimColumns + `, ia.id AS user_id, ia.display_name, ia.account_kind, ia.source_key,
		         ` + IdentityAccountSQL + ` AS account_id`,
		from: `iga_relationship r
		  JOIN iga_identity_accounts ia ON ia.workspace_id = r.workspace_id AND ia.id = r.source_identity_account_id`,
		where: `r.workspace_id = ? AND r.relationship_type = ? AND r.target_identity_account_id = ?
		        AND r.state IN ? AND ia.provider = 'aws'`,
		args:    []any{q.WS, models.RelTypeMemberOf, ident.ID, states},
		name:    "ia.display_name",
		account: IdentityAccountSQL,
		id:      "r.id",
	}
	var rows []idetailMemberScan
	if err := idetailPage(q.DB(), sq, after, limit, &rows); err != nil {
		return nil, err
	}
	sec, keep, err := r.idetailFinish(q, sq, UsedByRoute(ident.ID, UsedByMembers), filter, limit, len(rows),
		func(i int) (idetailNameKey, uuid.UUID) { return rows[i].key(), rows[i].RelID })
	if err != nil {
		return nil, err
	}
	rows = rows[:keep]
	claims := make([]RelationshipClaimRow, len(rows))
	for i := range rows {
		claims[i] = rows[i].RelationshipClaimRow
	}
	reasons, err := idetailClaimReasons(q, accts, claims)
	if err != nil {
		return nil, err
	}
	items := make([]UsedByMember, 0, len(rows))
	for _, m := range rows {
		items = append(items, UsedByMember{
			ClaimFields: m.fields(reasons),
			Member: IdentityRef{Ref: R(RefIdentity, m.UserID), Name: m.DisplayName, Kind: m.AccountKind,
				ARN: NativeOfKey(m.SourceKey), Account: accts.Of(m.AccountID)},
		})
	}
	sec.Items = items
	return sec, nil
}

/* ------------------------------ trust helpers ------------------------------ */

// TrustNegatedStatements reads the statement keys a role's provider_attrs
// lists as NotAction trust statements (igagraph.TrustNegatedStatementsAttr,
// D-88). It feeds negated_statement; it is not in D-85's rendered allowlist.
func TrustNegatedStatements(providerAttrs json.RawMessage) map[string]bool {
	var in map[string]any
	_ = json.Unmarshal(providerAttrs, &in)
	out := map[string]bool{}
	if list, ok := in[igagraph.TrustNegatedStatementsAttr].([]any); ok {
		for _, v := range list {
			if s, ok := v.(string); ok {
				out[s] = true
			}
		}
	}
	return out
}

// LimitationNotPrincipalUnresolved is §5.3's limitation code for a role whose
// trust document uses NotPrincipal (D-35, D-44).
const LimitationNotPrincipalUnresolved = "not_principal_unresolved"

// TrustHasNotPrincipal reports what a role's provider_attrs say about
// NotPrincipal in its trust document (D-44); false when the flag is absent or
// false.
func TrustHasNotPrincipal(providerAttrs json.RawMessage) bool {
	var in map[string]any
	_ = json.Unmarshal(providerAttrs, &in)
	v, _ := in[igagraph.TrustHasNotPrincipalAttr].(bool)
	return v
}

// TrustStatementOf names a can_assume's trust statement from its stored key
// (§4.7: "Sid, else content hash"): the Sid is read back from the key's LAST
// segment when that segment is sid:<Sid> -- reading a segment back, never
// formatting a key (D-2). A content-hash or pod-identity key has no Sid.
func TrustStatementOf(statementKey string, negated map[string]bool) TrustStatement {
	st := TrustStatement{Key: statementKey, Negated: negated[statementKey]}
	segs := strings.Split(statementKey, igagraph.Sep)
	if last := segs[len(segs)-1]; strings.HasPrefix(last, "sid:") && len(segs) > 1 && segs[len(segs)-2] == "trust" {
		st.Sid = strings.TrimPrefix(last, "sid:")
	}
	return st
}

// NullableJSON is a stored jsonb value as the response writes it: verbatim,
// or JSON null when absent -- conditions are recorded, never evaluated.
func NullableJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return raw
}
