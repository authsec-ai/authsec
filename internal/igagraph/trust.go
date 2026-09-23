package igagraph

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
)

// Trust (SPEC-iga-phase2-graph.md §4.7 "Trust and external principals", §2.12,
// §2.3; P2-DECISIONS D-41..D-47):
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

// TrustPartitionKind is the can_assume partition's kind for trust-document
// edges; pod-identity edges use models.MechanismEKSPodIdentity (§4.10).
const TrustPartitionKind = "trust"

// provider_attrs keys a role carries about its trust document (028, §5.3).
const (
	TrustHasDenyAttr         = "trust_has_deny"
	TrustHasNotPrincipalAttr = "trust_has_not_principal"
)

// podIdentityAttrs is what cloud_assume_edge.attrs may carry for a pod-identity
// association. cluster_arn is the issuer fallback for a cluster with no OIDC
// issuer (D-42); the collector does not write it yet (T3.5), and a row without
// either is not attributable to a cluster -- see projectPodIdentity.
type podIdentityAttrs struct {
	ClusterARN string `json:"cluster_arn"`
}

// projectTrust writes every can_assume edge this run's trust documents and
// pod-identity associations declare, the external principals they name, and
// the derived resolutions of those principals (§4.7). It runs after every
// node pass, so each endpoint it needs is in r, and before attachEvidence.
func (p *Projector) projectTrust(tx *gorm.DB, snap *Snapshot, r *resolved) error {
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
		sids, seen := CountTrustSids(doc.Statements), map[string]int{}
		for _, st := range doc.Statements {
			// Keyed for EVERY statement, in document order, so #n numbering of
			// identical Sid-less statements never depends on which are skipped.
			stKey, _ := TrustStatementKey(roleEP, st, sids, seen)
			if st.Effect == models.EffectDeny || st.HasNotPrincipal() {
				continue // D-44: recorded on the role (trustFlags), never an edge
			}
			for _, sub := range st.Subjects() {
				rel := trustEdge(snap, part, target, now, sub.Mechanism, stKey, st.Condition,
					CanAssumeKey(ExternalPrincipalKey(sub.Issuer, sub.Subject), roleEP, stKey))
				if err := p.trustSource(tx, snap, r, rel, sub); err != nil {
					return fmt.Errorf("trust principal %q of %s: %w", sub.Entry.Value, role.NativeID, err)
				}
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
	if err := p.projectPodIdentity(tx, snap, r); err != nil {
		return err
	}
	return p.deriveResolutions(tx, snap, r)
}

// trustEdge is the can_assume row both declarations write. Stamped with the
// partition it reconciles in and this run -- a row without them is invisible
// to reconciliation and never ends (§4.10).
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

// trustSource sets the edge's ONE source (§4.7's table, D-41): the identity an
// exact role or user ARN names, when that identity is live in a connected
// account; otherwise an external principal. Either way the edge's KEY is the
// principal's recognition key (CanAssumeKey), so which one it is can change
// in place.
func (p *Projector) trustSource(tx *gorm.DB, snap *Snapshot, r *resolved,
	rel *models.IGARelationship, sub awsdiscovery.TrustSubject) error {
	if sub.IdentityARN != "" {
		if gid, ok := p.trustIdentity(snap, r, sub.IdentityARN, sub.Account); ok {
			rel.SourceIdentityAccountID = &gid
			return nil
		}
	}
	// Not connected, connected with no live identity of that ARN (not scanned
	// yet, its read denied, deleted), or no identity at all -- an account, a
	// service, a federation, a session, a unique id, "*": unresolved.
	ext, err := p.upsertExternal(tx, snap, r, sub.Issuer, sub.Subject, sub.Kind)
	if err != nil {
		return err
	}
	rel.SourceExternalPrincipalID = &ext
	return nil
}

// trustIdentity finds the live identity an exact role or user ARN names, in a
// connected account (§4.7; D-61: a revoked connector's account is not read, so
// nothing in it resolves).
//
// THIS RUN'S OWN IDENTITIES FIRST. After a recreation in this pass, the
// prefetched graph still holds the OLD row under the ARN -- just retired
// `recreated` -- and an edge pointed at it would claim a principal that no
// longer exists. The row this pass projected for the ARN is the one the
// document means. Anything else -- another account, or a role this run did
// not list -- is the workspace's live graph; a row about to retire
// unsupported is re-pointed to an external principal when it does
// (downgradeTrustSources).
func (p *Projector) trustIdentity(snap *Snapshot, r *resolved, arn, account string) (uuid.UUID, bool) {
	if account == "" || !snap.ConnectedAccounts[account] {
		return uuid.Nil, false
	}
	if r.principalByARN == nil {
		r.principalByARN = map[string]uuid.UUID{}
		for _, ci := range snap.Identities {
			if ci.Kind != models.CloudIdentityIAMRole && ci.Kind != models.CloudIdentityIAMUser {
				continue
			}
			if gid, ok := r.identity[ci.ID]; ok {
				r.principalByARN[ci.NativeID] = gid
			}
		}
	}
	if gid, ok := r.principalByARN[arn]; ok {
		return gid, true
	}
	live := r.existing.identity[IdentityARNKey(arn)]
	if live == nil || (live.AccountKind != models.CloudIdentityIAMRole && live.AccountKind != models.CloudIdentityIAMUser) {
		return uuid.Nil, false
	}
	return live.ID, true
}

// upsertExternal writes (or re-sights) one external principal, once per pass.
// Workspace-scoped and shared across connectors: lambda.amazonaws.com is ONE
// node however many roles in however many accounts trust it. No support row,
// no lifecycle (D-47): its state is derived at read time from its edges.
func (p *Projector) upsertExternal(tx *gorm.DB, snap *Snapshot, r *resolved, issuer, subject, kind string) (uuid.UUID, error) {
	key := ExternalPrincipalKey(issuer, subject)
	if id, ok := r.external[key]; ok {
		return id, nil
	}
	now := p.now()
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
// issuer = the cluster's OIDC issuer (else its ARN), subject =
// system:serviceaccount:<ns>:<sa> -- to the role (§1.4, D-42). The same
// service account an IRSA trust statement names is the SAME node: one node,
// one edge per declaration.
func (p *Projector) projectPodIdentity(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	now := p.now()
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
		var attrs podIdentityAttrs
		_ = json.Unmarshal(pi.Attrs, &attrs)
		issuer, subject := "", pi.Subject
		if pi.Issuer != nil {
			issuer = *pi.Issuer
		}
		issuer = PodIdentityIssuer(issuer, attrs.ClusterARN)
		if issuer == "" || subject == "" {
			// No cluster can be named for this association (a failed
			// DescribeCluster, or a cluster without OIDC and no ARN collected).
			// An issuer-less node would MERGE this service account with the
			// same namespace/name in every other cluster -- claiming one
			// principal where there may be several. So no edge is written, and
			// the role's pod-identity edges are protected instead: stale,
			// never ended on the strength of a read we could not attribute.
			r.podUnattributed = append(r.podUnattributed, target)
			continue
		}
		roleEP := EndpointKey(*role)
		stKey := PodIdentityStatementKey(roleEP, issuer, subject)
		ext, err := p.upsertExternal(tx, snap, r, issuer, subject, models.ExternalPrincipalK8sServiceAccount)
		if err != nil {
			return err
		}
		rel := trustEdge(snap, part, target, now, models.MechanismEKSPodIdentity, stKey, nil,
			CanAssumeKey(ExternalPrincipalKey(issuer, subject), roleEP, stKey))
		rel.SourceExternalPrincipalID = &ext
		id, err := p.repo.UpsertRelationship(tx, rel)
		if err != nil {
			return fmt.Errorf("upsert pod-identity can_assume %s -> %s: %w", subject, role.NativeID, err)
		}
		// Evidence: the association's own observation (§4.8), keyed beside
		// the role's (PodIdentitySubjectKey).
		r.canAssume = append(r.canAssume, relRef{ID: id, SubjectKind: "identity",
			SubjectNativ: PodIdentitySubjectKey(role.NativeID, issuer, subject)})
	}
	return nil
}

// deriveResolutions is the resolution pass §4.10 places in projection, before
// reconciliation (§2.3, 034): an aws_principal whose subject is EXACTLY the ARN
// of a live role or user in a connected account resolves to it, basis
// 'derived', rule exact_arn_match. After a recreation the exact match points
// at the NEW object, which is correct for a mechanical fact (§2.12).
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
			continue // "*", a session, a unique id, a root: never an identity
		}
		gid, ok := p.trustIdentity(snap, r, ep.SubjectClaim, account)
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
// (D-44): trust_has_deny and trust_has_not_principal, as booleans. nil for
// anything that is not a role.
//
// An UNREADABLE document says nothing new, so the flags this SAME incarnation
// already carried stand. A recreated role (different immutable key) inherits
// nothing: its flags are unknown until its document is read.
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
		return out, nil
	}
	doc, err := r.trustDocument(ci)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		TrustHasDenyAttr:         doc.HasDeny(),
		TrustHasNotPrincipalAttr: doc.HasNotPrincipal(),
	}, nil
}

// trustExclusions names, in graph ids, the roles whose trust edges
// reconciliation must never END this run (§4.10): roles whose trust document
// was unreadable, and roles with a pod-identity association no cluster could
// be named for.
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

// downgradeTrustSources re-points, IN PLACE, every live can_assume edge whose
// SOURCE is one of these identities -- about to retire or be replaced by a
// recreation -- to the external principal its ARN names (D-41, corrected).
//
// Such an edge is declared by the TRUSTING role's policy, often in another
// account; the source identity going away says nothing about that
// declaration, which was read by the trusting role's own scan. Ending it here
// would end what this run did not read. Re-pointed instead, it keeps its id
// and history: the trusting role's next projection confirms or ends it, and a
// principal that resolves again (the same ARN, recreated or reconnected)
// becomes that identity -- the same row, since the key is the principal's.
//
// Edges whose TARGET is also going away are left to the cascade: the role
// that declares them is itself gone. Reads and writes go through tx, as the
// rest of reconciliation does; the external-principal write has
// UpsertExternalPrincipal's contract -- keyed on (workspace_id, source_key),
// never touching the resolution columns.
func downgradeTrustSources(tx *gorm.DB, ws uuid.UUID, identities []uuid.UUID, now time.Time) error {
	if len(identities) == 0 {
		return nil
	}
	var sources []struct {
		ID        uuid.UUID
		SourceKey string
	}
	if err := tx.Raw(`
		SELECT DISTINCT i.id, i.source_key
		  FROM iga_identity_accounts i
		  JOIN iga_relationship r
		    ON r.workspace_id = i.workspace_id AND r.source_identity_account_id = i.id
		 WHERE i.workspace_id = ? AND i.id IN ?
		   AND r.relationship_type = ? AND r.state <> ?
		   AND r.target_identity_account_id NOT IN ?`,
		ws, identities, models.RelTypeCanAssume, models.RelEnded, identities).
		Scan(&sources).Error; err != nil {
		return fmt.Errorf("find trust edges sourced from retiring identities: %w", err)
	}
	for _, src := range sources {
		arn, ok := ARNOfIdentityKey(src.SourceKey)
		if !ok {
			continue // nothing to name the principal by: the cascade ends it
		}
		ext := &models.IGAExternalPrincipal{
			WorkspaceID: ws, Issuer: awsdiscovery.IssuerAWS, SubjectClaim: arn,
			Mechanism:   models.ExternalPrincipalAWSPrincipal,
			SourceKey:   ExternalPrincipalKey(awsdiscovery.IssuerAWS, arn),
			FirstSeenAt: now, LastSeenAt: now,
		}
		// DoUpdates names mechanism alone -- a no-op, since the kind is a
		// function of the key -- so RETURNING yields the surviving row's id.
		// last_seen_at is NOT bumped: no trust document was read here.
		if err := tx.Clauses(clause.Returning{Columns: []clause.Column{{Name: "id"}}},
			clause.OnConflict{
				Columns:   []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
				DoUpdates: clause.AssignmentColumns([]string{"mechanism"}),
			}).Create(ext).Error; err != nil {
			return fmt.Errorf("external principal for retiring %s: %w", arn, err)
		}
		if err := tx.Model(&models.IGARelationship{}).
			Where(`workspace_id = ? AND relationship_type = ? AND state <> ?
			       AND source_identity_account_id = ? AND target_identity_account_id NOT IN ?`,
				ws, models.RelTypeCanAssume, models.RelEnded, src.ID, identities).
			Updates(map[string]any{
				"source_identity_account_id":   nil,
				"source_external_principal_id": ext.ID,
				"updated_at":                   now,
			}).Error; err != nil {
			return fmt.Errorf("re-point trust edges from retiring %s: %w", arn, err)
		}
	}
	return nil
}
