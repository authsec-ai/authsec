package igagraph

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
)

// Trust (SPEC-iga-phase2-graph.md §4.7 "Trust and external principals", §2.12,
// §2.3; P2-DECISIONS D-41..D-47, D-88):
//
//	principal ──can_assume──▶ role        declared by an Allow statement of
//	                                       the ROLE's trust document, or an EKS
//	                                       pod-identity association
//
// A principal is an identity in the workspace (a live role or user in a
// connected account) or an EXTERNAL PRINCIPAL -- another account, a service, an
// OIDC or SAML issuer and subject, a Kubernetes service account. The claim is
// "the trust policy permits it", NEVER that assumption succeeds (§2.3): the
// caller also needs its own permission, and the conditions are recorded, not
// evaluated.
//
// What is never an edge: a Deny statement (a restriction on the role) and a
// NotPrincipal statement ("everyone except X" names no one we could draw an
// edge from). Both are recorded on the role instead, as provider_attrs
// trust_has_deny / trust_has_not_principal (D-44).
//
// NO EDGE IS EVER RE-POINTED IN PLACE (D-41). Every can_assume key names the
// statement, the source ENDPOINT and the target endpoint (CanAssumeKey), and
// UpsertRelationship never writes a source column. What survives a far account
// connecting is the external principal NODE: it stays the source of its edges,
// and gains a derived resolution to the identity it now matches (§2.12 "the
// edge keeps its identity and its whole history"). An identity source that
// retires or is recreated ends its edges (subject_retired / subject_recreated,
// the ordinary cascade); what the trusting role's document still names is
// re-sourced by the next pass that reads it, as a NEW edge.

// TrustPartitionKind is the can_assume partition's kind for trust-document
// edges; pod-identity edges use models.MechanismEKSPodIdentity (§4.10).
const TrustPartitionKind = "trust"

// provider_attrs keys a role carries about its trust document (028, §5.3,
// D-85).
const (
	TrustHasDenyAttr         = "trust_has_deny"
	TrustHasNotPrincipalAttr = "trust_has_not_principal"
	// TrustNegatedStatementsAttr lists the statement_key of every Allow trust
	// statement written with NotAction, in document order; absent when there
	// is none. D-88: such a statement's edges carry `negated_statement`, and a
	// can_assume row has no column that could say so (031) -- the read side
	// marks an edge whose statement_key is listed on its target role. Not in
	// D-85's rendered allowlist: it feeds limitations, not the detail panel.
	TrustNegatedStatementsAttr = "trust_negated_statements"
)

// trustSource is the ONE source an edge gets (iga_relationship_source_chk):
// an identity or an external principal, and the endpoint key the edge key is
// built from.
type trustSource struct {
	endpoint string
	identity *uuid.UUID
	external *uuid.UUID
}

// projectTrust writes every can_assume edge this run's trust documents and
// pod-identity associations declare, the external principals they name, and
// the derived resolutions of those principals (§4.7). It runs after every
// node pass, so each endpoint it needs is in r, and before attachEvidence.
func (p *Projector) projectTrust(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	live, err := liveExternalPrincipals(tx, snap.Run.WorkspaceID)
	if err != nil {
		return err
	}
	r.liveExternal = live

	// One timestamp for every row this pass writes -- edges, external
	// principals, pod-identity edges -- so they join on it (D-26).
	now := p.now()
	part := snap.EdgePartitionFor(models.RelTypeCanAssume, TrustPartitionKind, "")
	for _, role := range snap.Roles() {
		target, ok := r.identity[role.ID]
		if !ok {
			continue // every snapshot identity is projected; defensive only
		}
		if snap.UnreadableTrust[role.ID] {
			// NOTHING is written for this role. Its existing trust edges are
			// protected by reconciliation (Exclusions.UnreadableTrust): stale,
			// never ended -- we did not read what they declare.
			continue
		}
		doc, err := r.trustDocument(role)
		if err != nil {
			return err
		}
		roleEP := EndpointKey(role)
		stKeys := trustStatementKeys(roleEP, doc)
		for i, st := range doc.Statements {
			stKey := stKeys[i]
			if st.Effect == models.EffectDeny || st.HasNotPrincipal() {
				continue // D-44: recorded on the role (trustFlags), never an edge
			}
			for _, sub := range st.Subjects() {
				src, err := p.trustSourceFor(tx, snap, r, sub, now)
				if err != nil {
					return fmt.Errorf("trust principal %q of %s: %w", sub.Entry.Value, role.NativeID, err)
				}
				rel := trustEdge(snap, part, target, now, sub.Mechanism, stKey, st.Condition,
					CanAssumeKey(src.endpoint, roleEP, stKey))
				rel.SourceIdentityAccountID, rel.SourceExternalPrincipalID = src.identity, src.external
				id, err := p.repo.UpsertRelationship(tx, rel)
				if err != nil {
					return fmt.Errorf("upsert can_assume %q -> %s: %w", sub.Entry.Value, role.NativeID, err)
				}
				// Evidence: the role's observation -- it is the read of the
				// trust document (§4.8).
				r.canAssume = append(r.canAssume, relRef{ID: id, SubjectKind: "identity", SubjectNativ: role.NativeID})
			}
		}
	}
	if err := p.projectPodIdentity(tx, snap, r, now); err != nil {
		return err
	}
	return p.deriveResolutions(tx, snap, r)
}

// trustStatementKeys keys EVERY statement of a trust document, in document
// order -- Deny and NotPrincipal statements included, so the #n numbering of
// identical Sid-less statements never depends on which of them are edges. The
// one spelling projectTrust and trustFlags both use.
func trustStatementKeys(roleEP string, doc *awsdiscovery.TrustDocument) []string {
	sids, seen := CountTrustSids(doc.Statements), map[string]int{}
	out := make([]string, len(doc.Statements))
	for i, st := range doc.Statements {
		out[i], _ = TrustStatementKey(roleEP, st, sids, seen)
	}
	return out
}

// trustEdge is the can_assume row both declarations write. Stamped with the
// partition it reconciles in and this run -- a row without them is invisible
// to reconciliation and never ends (§4.10). The caller sets its one source.
func trustEdge(snap *Snapshot, part Partition, target uuid.UUID, now time.Time,
	mechanism, statementKey string, conditions json.RawMessage, key string) *models.IGARelationship {
	tgt := target
	return &models.IGARelationship{
		WorkspaceID: snap.Run.WorkspaceID, RelationshipType: models.RelTypeCanAssume,
		TargetIdentityAccountID: &tgt,
		Basis:                   models.BasisDeclared, State: models.RelCurrent,
		ValidFrom: now, LastConfirmedAt: now, LastConfirmedBy: &snap.Run.ID,
		ConnectorID: &snap.Run.ConnectorID, PartitionKey: part.Key(),
		SourceKey: key, StatementKey: statementKey,
		// nil (SQL NULL) when the statement had no Condition (031).
		Conditions: conditions,
		Mechanism:  mechanism,
	}
}

// trustSourceFor chooses the edge's source (§4.7's table, in D-41's order):
//
//  1. A LIVE external principal already exists for this principal (issuer,
//     subject): it stays the source, so its edges keep their keys and their
//     history. If it now exactly matches a live identity, that is recorded on
//     the node (deriveResolutions), never by re-sourcing an edge.
//  2. Otherwise an exact role or user ARN of a live identity in a connected
//     account is that identity (basis declared, §4.7 l.4411).
//  3. Otherwise an external principal of the principal's kind (D-42):
//     another account, a service, a federation, a session, a unique id, "*",
//     or an ARN in an account that is not connected or whose identity is not
//     live (not scanned yet, its read denied, deleted -- including one this
//     run's own complete listing no longer names) -- unresolved.
//
// Only an exact identity ARN can reach rule 2, so only it consults rule 1;
// every other principal is external whichever way it is asked.
func (p *Projector) trustSourceFor(tx *gorm.DB, snap *Snapshot, r *resolved,
	sub awsdiscovery.TrustSubject, now time.Time) (trustSource, error) {
	extKey := ExternalPrincipalKey(sub.Issuer, sub.Subject)
	if sub.IdentityARN != "" && !r.liveExternal[extKey] {
		if gid, endpoint, ok := p.trustIdentity(snap, r, sub.IdentityARN, sub.Account); ok {
			return trustSource{endpoint: endpoint, identity: &gid}, nil
		}
	}
	ext, err := p.upsertExternal(tx, snap, r, sub.Issuer, sub.Subject, sub.Kind, now)
	if err != nil {
		return trustSource{}, err
	}
	return trustSource{endpoint: extKey, external: &ext}, nil
}

// liveExternalPrincipals is rule 1's set: the source keys of the workspace's
// aws_principal nodes that are live -- D-1's derived state, not ended: at
// least one can_assume edge from them has not ended. External principals have
// no lifecycle of their own (D-47); a node whose every edge ended is history,
// and a principal named again after that starts afresh under rule 2 or 3.
//
// Read once per pass, inside the projection transaction, so it already
// reflects the recreation cascade projectIdentities just ran. Only
// aws_principal nodes can be named by an identity ARN, so no other kind is
// read.
func liveExternalPrincipals(tx *gorm.DB, ws uuid.UUID) (map[string]bool, error) {
	var keys []string
	if err := tx.Raw(`
		SELECT ep.source_key
		  FROM iga_external_principal ep
		 WHERE ep.workspace_id = ? AND ep.issuer = ? AND ep.mechanism = ?
		   AND EXISTS (SELECT 1 FROM iga_relationship r
		                WHERE r.workspace_id = ep.workspace_id
		                  AND r.source_external_principal_id = ep.id
		                  AND r.relationship_type = ? AND r.state <> ?)`,
		ws, awsdiscovery.IssuerAWS, models.ExternalPrincipalAWSPrincipal,
		models.RelTypeCanAssume, models.RelEnded).Scan(&keys).Error; err != nil {
		return nil, fmt.Errorf("load live external principals: %w", err)
	}
	out := make(map[string]bool, len(keys))
	for _, k := range keys {
		out[k] = true
	}
	return out, nil
}

// trustIdentity finds the live identity an exact role or user ARN names, in a
// connected account (§4.7; D-61: a revoked connector's account is not read, so
// nothing in it resolves), and its endpoint key.
//
// THIS RUN'S OWN IDENTITIES FIRST. After a recreation in this pass, the
// prefetched graph still holds the OLD row under the ARN -- just retired
// `recreated` -- and an edge from it would claim a principal that no longer
// exists. The row this pass projected for the ARN is the one the document
// means, and its endpoint is the NEW incarnation's. Anything else -- another
// account, or an identity this run did not list -- is the workspace's live
// graph (lifecycle <> 'retired', every connector's).
func (p *Projector) trustIdentity(snap *Snapshot, r *resolved, arn, account string) (uuid.UUID, string, bool) {
	if account == "" || !snap.ConnectedAccounts[account] {
		return uuid.Nil, "", false
	}
	if r.principalByARN == nil {
		r.principalByARN = map[string]*models.CloudIdentity{}
		for i := range snap.Identities {
			ci := &snap.Identities[i]
			if ci.Kind == models.CloudIdentityIAMRole || ci.Kind == models.CloudIdentityIAMUser {
				r.principalByARN[ci.NativeID] = ci
			}
		}
	}
	if ci := r.principalByARN[arn]; ci != nil {
		if gid, ok := r.identity[ci.ID]; ok {
			return gid, EndpointKey(*ci), true
		}
	}
	// THIS RUN LISTED ITS OWN ACCOUNT IN FULL AND DID NOT NAME IT. The
	// prefetched graph still holds the row as live -- reconciliation retires it
	// later in this same pass -- so an edge sourced from it would begin and end
	// in one pass, claiming as its source a principal this run proved gone. It
	// is an unresolved aws_principal instead (rule 3). Only when that kind's
	// listing was REACHED: a denied or partial iam_users read proves nothing,
	// and the live row stands.
	if account == snap.Connector.ScopeID && listedInFull(snap, arn) {
		return uuid.Nil, "", false
	}
	live := r.existing.identity[IdentityARNKey(arn)]
	if live == nil || (live.AccountKind != models.CloudIdentityIAMRole && live.AccountKind != models.CloudIdentityIAMUser) {
		return uuid.Nil, "", false
	}
	return live.ID, IdentityAccountEndpointKey(*live), true
}

// listedInFull reports whether this run's listing of the identity kind an
// exact role or user ARN names was complete (its surface reached), so that an
// ARN of this account absent from the snapshot is absent from the account.
func listedInFull(snap *Snapshot, arn string) bool {
	surface := models.SurfaceIAMRoles
	if parts := strings.SplitN(arn, ":", 6); len(parts) == 6 && strings.HasPrefix(parts[5], "user/") {
		surface = models.SurfaceIAMUsers
	}
	cov, ok := snap.Coverage[surface]
	return ok && cov.State == models.CloudCoverageReached
}

// upsertExternal writes (or re-sights) one external principal, once per pass.
// Workspace-scoped and shared across connectors: lambda.amazonaws.com is ONE
// node however many roles in however many accounts trust it. No support row,
// no lifecycle (D-47): its state is derived at read time from its edges.
func (p *Projector) upsertExternal(tx *gorm.DB, snap *Snapshot, r *resolved,
	issuer, subject, kind string, now time.Time) (uuid.UUID, error) {
	key := ExternalPrincipalKey(issuer, subject)
	if id, ok := r.external[key]; ok {
		return id, nil
	}
	id, err := p.repo.UpsertExternalPrincipal(tx, &models.IGAExternalPrincipal{
		WorkspaceID: snap.Run.WorkspaceID, Issuer: issuer, SubjectClaim: subject,
		Mechanism: kind, SourceKey: key, FirstSeenAt: now, LastSeenAt: now,
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("upsert external principal %s/%s: %w", issuer, subject, err)
	}
	r.external[key] = id
	return id, nil
}

// projectPodIdentity writes one can_assume per EKS pod-identity association:
// the Kubernetes service account -- a k8s_service_account external principal,
// issuer = the cluster's scheme-less OIDC issuer, subject =
// PodIdentitySubject(system:serviceaccount:<ns>:<sa>) -- to the role (§1.4,
// §4.7, D-42). An IRSA trust statement naming the same service account is a
// separate `oidc` node with its own edge.
func (p *Projector) projectPodIdentity(tx *gorm.DB, snap *Snapshot, r *resolved, now time.Time) error {
	part := snap.EdgePartitionFor(models.RelTypeCanAssume, models.MechanismEKSPodIdentity, "")
	for _, pi := range snap.PodIdentity {
		// §4.7's loop passes these without looking: a role outside this
		// snapshot would write a uuid.Nil target. Skip it instead -- the role
		// was not collected this run, so there is nothing to attach to.
		role := snap.IdentityByID(&pi.IdentityID)
		target, ok := r.identity[pi.IdentityID]
		if role == nil || !ok {
			continue
		}
		issuer := ""
		if pi.Issuer != nil {
			issuer = *pi.Issuer
		}
		if issuer == "" || pi.Subject == "" {
			// No cluster issuer for this association (a failed DescribeCluster):
			// it stays UNRESOLVED (D-42, no cluster-ARN fallback -- the key must
			// not change between scans). An issuer-less node would MERGE this
			// service account with the same namespace/name in every other
			// cluster, claiming one principal where there may be several. So no
			// edge is written, and the role's pod-identity edges are protected:
			// stale, never ended on the strength of a read we could not
			// attribute.
			r.podUnattributed = append(r.podUnattributed, target)
			continue
		}
		subject := PodIdentitySubject(pi.Subject)
		ext, err := p.upsertExternal(tx, snap, r, issuer, subject, models.ExternalPrincipalK8sServiceAccount, now)
		if err != nil {
			return err
		}
		roleEP := EndpointKey(*role)
		stKey := PodIdentityStatementKey(roleEP, issuer, pi.Subject)
		rel := trustEdge(snap, part, target, now, models.MechanismEKSPodIdentity, stKey, nil,
			CanAssumeKey(ExternalPrincipalKey(issuer, subject), roleEP, stKey))
		rel.SourceExternalPrincipalID = &ext
		id, err := p.repo.UpsertRelationship(tx, rel)
		if err != nil {
			return fmt.Errorf("upsert pod-identity can_assume %s -> %s: %w", pi.Subject, role.NativeID, err)
		}
		// Evidence: the association's own observation (§4.8), keyed beside
		// the role's (PodIdentitySubjectKey).
		r.canAssume = append(r.canAssume, relRef{ID: id, SubjectKind: "identity",
			SubjectNativ: PodIdentitySubjectKey(role.NativeID, issuer, pi.Subject)})
	}
	return nil
}

// deriveResolutions is the resolution pass §4.10 places in projection, before
// reconciliation (§2.3, 034, D-41 rule 1): an aws_principal whose subject is
// EXACTLY the ARN of a live role or user in a connected account resolves to
// it, basis 'derived', rule exact_arn_match. After a recreation the exact match
// points at the NEW object, which is correct for a mechanical fact (§2.12).
//
// Every such node in the workspace, not only those this run named: the far
// account connecting is exactly the run that names none of them.
//
// It never CLEARS a resolution. A derived resolution whose target could not be
// found this run is kept -- "collection becomes incomplete: kept" (§2.12) --
// and one whose target retired is re-derived by retireUnsupported. Asserted
// rows are never read here, and SetDerivedResolution refuses them again.
func (p *Projector) deriveResolutions(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	var eps []models.IGAExternalPrincipal
	if err := tx.Where("workspace_id = ? AND mechanism = ? AND issuer = ? AND resolution_basis IN ?",
		snap.Run.WorkspaceID, models.ExternalPrincipalAWSPrincipal, awsdiscovery.IssuerAWS,
		[]string{"", models.BasisDerived}).
		Find(&eps).Error; err != nil {
		return fmt.Errorf("load derivable external principals: %w", err)
	}
	for _, ep := range eps {
		account, ok := awsdiscovery.IdentityPrincipalARN(ep.SubjectClaim)
		if !ok {
			continue // a session, a unique id: never an identity
		}
		gid, _, ok := p.trustIdentity(snap, r, ep.SubjectClaim, account)
		if !ok {
			continue
		}
		if ep.ResolutionBasis == models.BasisDerived && ep.ResolvedIdentityAccountID != nil &&
			*ep.ResolvedIdentityAccountID == gid {
			continue
		}
		if err := p.repo.SetDerivedResolution(tx, snap.Run.WorkspaceID, ep.ID, gid,
			models.ResolutionRuleExactARN); err != nil {
			return fmt.Errorf("derive resolution of %s: %w", ep.SubjectClaim, err)
		}
	}
	return nil
}

// trustDocument parses a role's collected trust document once per pass.
//
// The collector validated it with the SAME parser (ValidateTrustDocument), so
// a document it recorded readable that fails here -- whole, or one statement
// -- is an inconsistency, and fails the pass loudly rather than projecting a
// guess (§4.7).
func (r *resolved) trustDocument(role models.CloudIdentity) (*awsdiscovery.TrustDocument, error) {
	if doc, ok := r.trustDocs[role.ID]; ok {
		return doc, nil
	}
	doc, err := awsdiscovery.ParseTrustDocument(role.TrustDocument)
	if err != nil {
		return nil, fmt.Errorf("trust document of %s parsed at collection, failed now: %w", role.NativeID, err)
	}
	if n := len(doc.Skipped); n > 0 {
		return nil, fmt.Errorf("trust document of %s parsed at collection, now %d statement(s) unusable: %s",
			role.NativeID, n, doc.Skipped[0].Reason)
	}
	r.trustDocs[role.ID] = doc
	return doc, nil
}

// trustFlags returns what a role's provider_attrs say about its trust document
// (D-44, D-85, D-88): trust_has_deny and trust_has_not_principal, as booleans,
// and trust_negated_statements when a NotAction statement exists. nil for
// anything that is not a role.
//
// An UNREADABLE document says nothing new, so what this SAME incarnation
// already carried stands -- its protected edges keep the limitations they
// had. A recreated role (different immutable key) inherits nothing: its flags
// are unknown until its document is read.
func (p *Projector) trustFlags(r *resolved, snap *Snapshot, ci models.CloudIdentity,
	live *models.IGAIdentityAccount) (map[string]any, error) {
	if ci.Kind != models.CloudIdentityIAMRole {
		return nil, nil
	}
	if snap.UnreadableTrust[ci.ID] {
		if live == nil || live.ImmutableKey != ImmutableKey(ci) {
			return nil, nil
		}
		var prev map[string]any
		_ = json.Unmarshal(live.ProviderAttrs, &prev)
		out := map[string]any{}
		for _, k := range []string{TrustHasDenyAttr, TrustHasNotPrincipalAttr} {
			if v, ok := prev[k].(bool); ok {
				out[k] = v
			}
		}
		if v, ok := prev[TrustNegatedStatementsAttr].([]any); ok && len(v) > 0 {
			out[TrustNegatedStatementsAttr] = v
		}
		return out, nil
	}
	doc, err := r.trustDocument(ci)
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		TrustHasDenyAttr:         doc.HasDeny(),
		TrustHasNotPrincipalAttr: doc.HasNotPrincipal(),
	}
	// D-88: the statement keys of the Allow statements written with
	// NotAction -- the only ones whose edges are "every action except ...".
	// Keyed exactly as projectTrust keys the edges.
	var negated []string
	for i, key := range trustStatementKeys(EndpointKey(ci), doc) {
		st := doc.Statements[i]
		if st.Effect == models.EffectAllow && len(st.NotActions) > 0 && !st.HasNotPrincipal() {
			negated = append(negated, key)
		}
	}
	if len(negated) > 0 {
		out[TrustNegatedStatementsAttr] = negated
	}
	return out, nil
}

// trustExclusions names, in graph ids, the roles whose trust edges
// reconciliation must never END this run (§4.10): roles whose trust document
// was unreadable (D-45), and roles with a pod-identity association no cluster
// issuer could be named for (D-42).
func trustExclusions(snap *Snapshot, r *resolved) (unreadable, unattributedPod []uuid.UUID) {
	for _, role := range snap.Roles() {
		if snap.UnreadableTrust[role.ID] {
			if id, ok := r.identity[role.ID]; ok {
				unreadable = append(unreadable, id)
			}
		}
	}
	return unreadable, r.podUnattributed
}
