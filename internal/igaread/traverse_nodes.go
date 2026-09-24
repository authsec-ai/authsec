package igaread

// The traversal's node reads (§5.4 "Node rows are fetched in one query per
// node type per level"): what a level reached, read with the SAME columns and
// expressions the lists and details use (nodes.go), so a node's name, kind,
// account and state on the canvas are exactly what its list row says
// (§2.14.11 "The graph and the lists must agree").
//
// Then each node type's decorations, one statement per type per level:
//
//	identity   restrictions (Deny statements held directly or through a live
//	           group membership; a live boundary assignment, D-78) -- by
//	           loadRestrictions, /evidence's reader (D-35) -- used_by_count
//	           (UsedByCounts, the list's count), the NotPrincipal trust flag
//	statement  its policy, its label, group_key (D-37) and exclusions (the
//	           NotResource entries -- never edges, §5.4)
//	every type stale_reason for stale nodes (NodeStaleReasons, D-74; an
//	           external principal's from its stale can_assume edges)
//
// Their limitations are decorateLimitations' (traverse_limits.go).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// fetchNodes reads every node in nodes, one statement per node type, and
// marks the ones it found (fetched). Each read carries D-6's readability
// predicate, so the root of a request and every node a level reaches are held
// to the same rule.
func (t *graphTraversal) fetchNodes(lv *graphLevel, nodes []*GraphNode) error {
	byType := map[string]map[uuid.UUID]*GraphNode{}
	for _, n := range nodes {
		if byType[n.typ] == nil {
			byType[n.typ] = map[uuid.UUID]*GraphNode{}
		}
		byType[n.typ][n.id] = n
	}
	for _, typ := range graphNodeTypes {
		set := byType[typ]
		if len(set) == 0 {
			continue
		}
		ids := make([]uuid.UUID, 0, len(set))
		for id := range set {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
		var err error
		switch typ {
		case RefWorkload:
			err = t.fetchWorkloads(lv, ids, set)
		case RefIdentity:
			err = t.fetchIdentities(lv, ids, set)
		case RefExternalPrincipal:
			err = t.fetchExternal(lv, ids, set)
		case RefStatement:
			err = t.fetchStatements(lv, ids, set)
		case RefResource:
			err = t.fetchResources(lv, ids, set)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *graphTraversal) fetchWorkloads(lv *graphLevel, ids []uuid.UUID, set map[uuid.UUID]*GraphNode) error {
	tx, err := lv.db()
	if err != nil {
		return err
	}
	var rows []WorkloadRecord
	if err := tx.Raw(`SELECT `+WorkloadColumns+` FROM `+WorkloadFrom+`
	                   WHERE w.workspace_id = ? AND w.provider = 'aws' AND `+SupportedSQL("w", "workload_id")+`
	                     AND w.id IN ?`, t.q.WS, ids).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		n := set[r.ID]
		n.Kind, n.Label, n.key = RefWorkload, r.DisplayName, r.SourceKey
		n.ARN, n.RuntimeKind = NativeOfKey(r.SourceKey), r.RuntimeKind
		t.ownAccount(n, r.AccountID)
		n.State, n.Lifecycle, n.LastConfirmedAt = r.State, r.Lifecycle, TS(r.LastConfirmedAt)
		n.stale = r.StaleSubject()
		n.fetched = true
	}
	return nil
}

// graphIdentityRow is an identity with the NotPrincipal trust flag its
// provider_attrs carry (D-44).
type graphIdentityRow struct {
	IdentityRecord
	TrustNotPrincipal bool
}

func (t *graphTraversal) fetchIdentities(lv *graphLevel, ids []uuid.UUID, set map[uuid.UUID]*GraphNode) error {
	tx, err := lv.db()
	if err != nil {
		return err
	}
	var rows []graphIdentityRow
	if err := tx.Raw(`SELECT `+IdentityColumns+`,
	                         COALESCE(ia.provider_attrs->>'`+igagraph.TrustHasNotPrincipalAttr+`', '') = 'true' AS trust_not_principal
	                    FROM `+IdentityFrom+`
	                   WHERE ia.workspace_id = ? AND ia.provider = 'aws' AND `+SupportedSQL("ia", "identity_account_id")+`
	                     AND ia.id IN ?`, t.q.WS, ids).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		n := set[r.ID]
		n.Kind, n.Label, n.key = r.AccountKind, r.DisplayName, r.SourceKey
		n.ARN = NativeOfKey(r.SourceKey)
		t.ownAccount(n, r.AccountID)
		n.State, n.Lifecycle, n.LastConfirmedAt = r.State, r.Lifecycle, TS(r.LastConfirmedAt)
		n.stale = r.StaleSubject()
		n.notPrincipal = r.TrustNotPrincipal
		n.Restrictions = &GraphRestrictions{}
		n.fetched = true
	}
	return nil
}

// graphExternalRow is an external principal with its D-1 state: current if
// any of its can_assume edges is current, else stale if any is stale, else
// ended -- it has no support rows (D-47).
type graphExternalRow struct {
	ID                        uuid.UUID
	Issuer                    string
	SubjectClaim              string
	Mechanism                 string
	SourceKey                 string
	ResolvedIdentityAccountID *uuid.UUID
	ResolvedWorkloadID        *uuid.UUID
	ResolutionBasis           string
	ResolutionRule            string
	ResolvedBy                string
	ResolutionState           string
	State                     string
	LastConfirmedAt           *time.Time
}

func (t *graphTraversal) fetchExternal(lv *graphLevel, ids []uuid.UUID, set map[uuid.UUID]*GraphNode) error {
	tx, err := lv.db()
	if err != nil {
		return err
	}
	var rows []graphExternalRow
	if err := tx.Raw(`SELECT ep.id, ep.issuer, ep.subject_claim, ep.mechanism, ep.source_key,
	                         ep.resolved_identity_account_id, ep.resolved_workload_id, ep.resolution_basis,
	                         ep.resolution_rule, ep.resolved_by, ep.resolution_state,
	                         st.state, st.last_confirmed_at
	                    FROM iga_external_principal ep
	                    LEFT JOIN LATERAL (
	                          SELECT CASE WHEN bool_or(r.state = 'current') THEN 'current'
	                                      WHEN bool_or(r.state = 'stale') THEN 'stale'
	                                      ELSE 'ended' END AS state,
	                                 max(r.last_confirmed_at) FILTER (WHERE r.state <> 'ended') AS last_confirmed_at
	                            FROM iga_relationship r
	                           WHERE r.workspace_id = ep.workspace_id AND r.source_external_principal_id = ep.id
	                             AND r.relationship_type = 'can_assume') st ON true
	                   WHERE ep.workspace_id = ? AND ep.id IN ?`, t.q.WS, ids).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		n := set[r.ID]
		n.Kind, n.key = RefExternalPrincipal, r.SourceKey
		n.Label = GraphExternalLabel(r.Mechanism, r.Issuer, r.SubjectClaim)
		n.Mechanism, n.Issuer, n.Subject = r.Mechanism, r.Issuer, r.SubjectClaim
		t.ownAccount(n, graphExternalAccount(r.Mechanism, r.SubjectClaim))
		// lifecycle is derived, by the detail route's own rule (D-47,
		// ExternalLifecycleOf): every node on the canvas states one (D-96).
		n.State, n.Lifecycle, n.LastConfirmedAt = r.State, ExternalLifecycleOf(r.State), TS(r.LastConfirmedAt)
		if r.ResolutionBasis != "" {
			// D-87. A resolution is DISPLAYED, never followed: an external
			// principal is a terminal node (§5.4), and its edges keep their
			// own source.
			var to any
			switch {
			case r.ResolvedIdentityAccountID != nil:
				to = R(RefIdentity, *r.ResolvedIdentityAccountID)
			case r.ResolvedWorkloadID != nil:
				to = R(RefWorkload, *r.ResolvedWorkloadID)
			}
			n.Resolution = map[string]any{
				"state": r.ResolutionState, "basis": r.ResolutionBasis, "rule": nullIfBlank(r.ResolutionRule),
				"resolved_to": to, "resolved_by": nullIfBlank(r.ResolvedBy),
			}
			if ref, ok := to.(string); ok && r.ResolutionState == graphResolutionActive {
				n.resolvedTo = ref
			}
		}
		n.fetched = true
	}
	return nil
}

// GraphExternalLabel is an external principal's label (D-87): the account id,
// "any AWS principal" for *, the ARN, the service principal, issuer and
// subject for OIDC and SAML, ns/sa for a Kubernetes service account.
func GraphExternalLabel(mechanism, issuer, subject string) string {
	switch mechanism {
	case models.ExternalPrincipalAWSAccount:
		if subject == "*" {
			return "any AWS principal"
		}
		return subject
	case models.ExternalPrincipalAWSPrincipal, models.ExternalPrincipalAWSService:
		return subject
	case models.ExternalPrincipalK8sServiceAccount:
		s := strings.TrimPrefix(subject, "pod:") // D-42's provisional prefix
		s = strings.TrimPrefix(s, "system:serviceaccount:")
		if ns, sa, ok := strings.Cut(s, ":"); ok {
			return ns + "/" + sa
		}
		return s
	}
	if issuer == "" {
		return subject
	}
	return issuer + " " + subject
}

// graphExternalAccount is the account an external principal names (D-87):
// parsed only for aws_account (its subject is the account id, or * for any
// principal, which names none) and aws_principal (the ARN's account field).
func graphExternalAccount(mechanism, subject string) string {
	switch mechanism {
	case models.ExternalPrincipalAWSAccount:
		if isAccountID(subject) {
			return subject
		}
	case models.ExternalPrincipalAWSPrincipal:
		return ARNAccount(subject)
	}
	return ""
}

// graphStatementRow is one statement with its policy and D-1 state.
type graphStatementRow struct {
	ID              uuid.UUID
	SourceKey       string
	Sid             string
	StatementIndex  *int
	Effect          string
	Negated         bool
	Conditional     bool
	NativeRights    string
	Lifecycle       string
	PolicyID        *uuid.UUID
	PolicyName      string
	State           string
	LastConfirmedAt *time.Time
}

func (t *graphTraversal) fetchStatements(lv *graphLevel, ids []uuid.UUID, set map[uuid.UUID]*GraphNode) error {
	tx, err := lv.db()
	if err != nil {
		return err
	}
	var rows []graphStatementRow
	if err := tx.Raw(`SELECT e.id, e.source_key, e.sid, e.statement_index, e.effect, e.negated, e.conditional,
	                         COALESCE(e.native_rights::text, '') AS native_rights, e.lifecycle,
	                         p.id AS policy_id, COALESCE(p.display_name, '') AS policy_name,
	                         sup.state, sup.last_confirmed_at
	                    FROM iga_entitlements e
	                    LEFT JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id
	                    `+SupportLateral("e", "entitlement_id")+`
	                   WHERE e.workspace_id = ? AND e.provider = 'aws' AND `+SupportedSQL("e", "entitlement_id")+`
	                     AND e.id IN ?`, t.q.WS, ids).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		n := set[r.ID]
		st := graphParseStatement(r.NativeRights)
		n.Kind, n.key = RefStatement, r.SourceKey
		n.Label = GraphStatementLabel(st.Actions, st.NotActions)
		sid := r.Sid
		n.Policy, n.Effect, n.Sid = r.PolicyName, r.Effect, &sid
		if r.PolicyID != nil {
			n.PolicyRef = R(RefPolicy, *r.PolicyID)
		}
		if r.StatementIndex != nil {
			i := *r.StatementIndex + 1 // D-84: the API's index is 1-based
			n.Index = &i
		}
		n.State, n.Lifecycle, n.LastConfirmedAt = r.State, r.Lifecycle, TS(r.LastConfirmedAt)
		n.stale = StaleSubject{ID: r.ID}
		n.conditional, n.negated = r.Conditional, r.Negated
		n.text = parseStatementText(json.RawMessage(r.NativeRights))
		n.groupActions = graphGroupActions(st.Actions, st.NotActions)
		n.groupCondition = graphCanonicalJSON(st.Condition)
		empty := []GraphExclusion{}
		n.Exclusions = &empty
		n.fetched = true
	}
	return nil
}

// graphResourceRow is a resource reference with its source key.
type graphResourceRow struct {
	ResourceRecord
	SourceKey string
}

func (t *graphTraversal) fetchResources(lv *graphLevel, ids []uuid.UUID, set map[uuid.UUID]*GraphNode) error {
	tx, err := lv.db()
	if err != nil {
		return err
	}
	var rows []graphResourceRow
	if err := tx.Raw(`SELECT `+ResourceColumns+`, r.source_key FROM `+ResourceFrom+`
	                   WHERE r.workspace_id = ? AND r.provider = 'aws' AND `+SupportedSQL("r", "resource_id")+`
	                     AND r.id IN ?`, t.q.WS, ids).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		n := set[r.ID]
		n.Kind, n.key = r.Kind, r.SourceKey
		n.Label, n.Text, n.Type = GraphResourceLabel(r.DisplayName), r.DisplayName, ResourceType(r.DisplayName)
		// D-3: a resource's connectedness is the PROJECTED value, never the
		// live connector list, so the canvas and the list agree at one rev.
		acct := ResourceAccount(t.accts, r.AccountID, r.AccountConnected)
		n.Account, n.acct, n.connected = acct, r.AccountID, acct != nil && acct.Connected
		n.State, n.Lifecycle, n.LastConfirmedAt = r.State, r.Lifecycle, TS(r.LastConfirmedAt)
		n.stale = r.StaleSubject()
		n.fetched = true
	}
	return nil
}

// ownAccount sets a workload's, identity's or external principal's account
// object, and whether it is a connected account (D-3, D-89).
func (t *graphTraversal) ownAccount(n *GraphNode, accountID string) {
	a := t.accts.Of(accountID)
	n.Account, n.acct, n.connected = a, accountID, a != nil && a.Connected
}

// GraphResourceLabel is a resource reference's short text: the ARN's
// resource field (arn:aws:s3:::support-tickets/* -> support-tickets/*), or the
// text itself when it is not an ARN (*). The full text is beside it.
func GraphResourceLabel(text string) string {
	parts := strings.SplitN(text, ":", 6)
	if len(parts) == 6 && parts[0] == "arn" && parts[5] != "" {
		return parts[5]
	}
	return text
}

// graphStatement is what the traversal reads from a statement's verbatim
// native_rights: its actions, NotActions and Condition.
type graphStatement struct {
	Actions    []string
	NotActions []string
	Condition  json.RawMessage
}

// graphParseStatement reads a statement's native_rights: the verbatim AWS
// statement, parsed by the SAME parser the projector used (awsdiscovery), or
// the projector's fallback shape (models.NativeRights) when no verbatim form
// was kept. Nothing is evaluated.
func graphParseStatement(native string) graphStatement {
	if native == "" {
		return graphStatement{}
	}
	if sts, _, err := awsdiscovery.ParsePolicyDocument(`{"Statement":[` + native + `]}`); err == nil && len(sts) == 1 {
		st := sts[0]
		var cond json.RawMessage
		if st.Condition != "" {
			cond = json.RawMessage(st.Condition)
		}
		return graphStatement{Actions: st.Actions, NotActions: st.NotActions, Condition: cond}
	}
	var nr models.NativeRights
	if err := json.Unmarshal([]byte(native), &nr); err == nil {
		return graphStatement{Actions: nr.Actions, NotActions: nr.NotActions, Condition: nr.Condition}
	}
	return graphStatement{}
}

// GraphStatementLabel is a statement node's label: its actions as written
// (s3:GetObject), or "all actions except ..." for NotAction (§2.6).
func GraphStatementLabel(actions, notActions []string) string {
	if len(actions) > 0 {
		return strings.Join(graphDedupe(actions), ", ")
	}
	if len(notActions) > 0 {
		return "all actions except " + strings.Join(graphDedupe(notActions), ", ")
	}
	return ""
}

// graphGroupActions is the action half of a group_key: sorted, NotActions
// prefixed "!" (D-37).
func graphGroupActions(actions, notActions []string) []string {
	out := append([]string{}, actions...)
	for _, a := range notActions {
		out = append(out, "!"+a)
	}
	out = graphDedupe(out)
	sort.Strings(out)
	return out
}

// GraphGroupKey is a statement's group_key (D-37, §5.3): its sorted actions,
// "→", its sorted positive target refs -- plus, when the statement has a
// Condition, NotResource exclusions or is not an Allow, a digest of them, so
// that statements differing in any of those NEVER share a key. It lets the
// canvas draw two statements declaring the same grant as one line; nothing in
// the response merges them.
func GraphGroupKey(actions []string, targets []string, effect string, condition string, exclusions []string) string {
	ts := append([]string{}, targets...)
	sort.Strings(ts)
	key := strings.Join(actions, ",") + "→" + strings.Join(ts, ",")
	ex := append([]string{}, exclusions...)
	sort.Strings(ex)
	if condition == "" && len(ex) == 0 && (effect == "" || effect == models.EffectAllow) {
		return key
	}
	h := sha256.New()
	h.Write([]byte(effect))
	h.Write([]byte{0})
	h.Write([]byte(condition))
	h.Write([]byte{0})
	h.Write([]byte(strings.Join(ex, ",")))
	return key + "#" + hex.EncodeToString(h.Sum(nil))[:16]
}

// graphCanonicalJSON re-encodes JSON with sorted keys ("" for none), so two
// conditions that say the same thing in another key order digest the same.
func graphCanonicalJSON(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	out, _ := json.Marshal(v)
	return string(out)
}

// graphDedupe keeps the first of each value, in order.
func graphDedupe(xs []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

/* ------------------------------- decorations ------------------------------- */

// decorateNodes completes the nodes a level (or the root read) found:
// identity restrictions and used-by counts, statement targets, group keys and
// exclusions, and stale reasons. Their limitations follow
// (decorateLimitations), in one call with the level's edges.
func (t *graphTraversal) decorateNodes(lv *graphLevel, nodes []*GraphNode) error {
	byType := map[string][]*GraphNode{}
	for _, n := range nodes {
		byType[n.typ] = append(byType[n.typ], n)
	}
	if err := t.decorateIdentities(lv, byType[RefIdentity]); err != nil {
		return err
	}
	if err := t.decorateStatements(lv, byType[RefStatement]); err != nil {
		return err
	}
	for typ, column := range map[string]string{
		RefWorkload: "workload_id", RefIdentity: "identity_account_id",
		RefStatement: "entitlement_id", RefResource: "resource_id",
	} {
		if err := t.nodeStaleReasons(lv, byType[typ], column); err != nil {
			return err
		}
	}
	// External principals have no support rows: theirs come from their edges.
	return t.principalStaleReasons(lv, byType[RefExternalPrincipal])
}

func graphIDs(nodes []*GraphNode) []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(nodes))
	for _, n := range nodes {
		ids = append(ids, n.id)
	}
	return ids
}

// decorateIdentities reads the identities' restrictions and their used-by
// counts.
//
// The restrictions are read by HolderRestrictions -- loadRestrictions, the
// SAME reader /evidence's deny_statements_present and
// permissions_boundary_present come from (D-35) -- so the node's restrictions,
// its limitations and the Evidence panel of each of its grants count the same
// statements: the ACTIVE Deny statements of live attached or inline
// assignments of the identity AND of its live (not ended) groups -- a group's
// Deny applies to its members (§5.3 deny_statements_present "the holder (or
// its groups)") -- and the identity's own live boundary assignments. A
// group's member boundaries (D-22) are its grants' limitation, not the
// group's.
func (t *graphTraversal) decorateIdentities(lv *graphLevel, nodes []*GraphNode) error {
	if len(nodes) == 0 {
		return nil
	}
	ids := graphIDs(nodes)
	if _, err := lv.db(); err != nil { // the level's allowance is spent
		return err
	}
	deny, boundary, err := lv.query().HolderRestrictions(ids)
	if err != nil {
		return err
	}
	tx, err := lv.db()
	if err != nil {
		return err
	}
	used, err := UsedByCounts(tx, t.q.WS, ids)
	if err != nil {
		return err
	}
	for _, n := range nodes {
		n.denyIDs, n.boundaryPolicies = deny[n.id], boundary[n.id]
		n.Restrictions = &GraphRestrictions{DenyStatements: int64(len(n.denyIDs)), PermissionsBoundary: len(n.boundaryPolicies) > 0}
		c, ok := used[n.id]
		if !ok {
			c = Unknown()
		}
		n.UsedByCount = &c
	}
	return nil
}

// decorateStatements reads the statements' targets, both modes, in one
// statement: the positive ones make the group_key, the NotResource ones are
// the node's exclusions -- which never become edges, frontier entries or path
// steps (§5.4, B19).
func (t *graphTraversal) decorateStatements(lv *graphLevel, nodes []*GraphNode) error {
	if len(nodes) == 0 {
		return nil
	}
	byID := map[uuid.UUID]*GraphNode{}
	for _, n := range nodes {
		byID[n.id] = n
	}
	tx, err := lv.db()
	if err != nil {
		return err
	}
	var rows []struct {
		EntitlementID uuid.UUID
		TargetMode    string
		ResourceID    uuid.UUID
		DisplayName   string
	}
	if err := tx.Raw(`SELECT t.entitlement_id, t.target_mode, r.id AS resource_id, r.display_name
	                    FROM iga_entitlement_target t
	                    JOIN iga_resources r ON r.workspace_id = t.workspace_id AND r.id = t.resource_id
	                   WHERE t.workspace_id = ? AND t.entitlement_id IN ?
	                   ORDER BY t.entitlement_id, t.target_mode, t.ordinal, r.id`,
		t.q.WS, graphIDs(nodes)).Scan(&rows).Error; err != nil {
		return err
	}
	targets := map[uuid.UUID][]string{}
	exclusions := map[uuid.UUID][]string{}
	for _, r := range rows {
		n := byID[r.EntitlementID]
		ref := R(RefResource, r.ResourceID)
		switch r.TargetMode {
		case models.TargetResource:
			targets[n.id] = append(targets[n.id], ref)
		case models.TargetNotResource:
			*n.Exclusions = append(*n.Exclusions, GraphExclusion{Ref: ref, Text: r.DisplayName})
			exclusions[n.id] = append(exclusions[n.id], ref)
		}
	}
	for _, n := range nodes {
		n.GroupKey = GraphGroupKey(n.groupActions, targets[n.id], n.Effect, n.groupCondition, exclusions[n.id])
	}
	return nil
}

// nodeStaleReasons fills stale_reason (D-74) on the stale nodes of one class
// through NodeStaleReasons -- the lists' function.
func (t *graphTraversal) nodeStaleReasons(lv *graphLevel, nodes []*GraphNode, column string) error {
	var subjects []StaleSubject
	for _, n := range nodes {
		if n.State == StateStale {
			subjects = append(subjects, n.stale)
		}
	}
	if len(subjects) == 0 {
		return nil
	}
	if _, err := lv.db(); err != nil { // the level's allowance is spent
		return err
	}
	// The level's query: every statement NodeStaleReasons issues, and its
	// nested optional history read, is held to the level's allowance.
	reasons, err := NodeStaleReasons(lv.query(), t.accts, column, subjects)
	if err != nil {
		return err
	}
	for _, n := range nodes {
		n.StaleReason = StaleReasonOf(n.State, n.id, reasons)
	}
	return nil
}
