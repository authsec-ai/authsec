package igagraph

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
)

// The permission graph (SPEC-iga-phase2-graph.md §2.6, §4.7):
//
//	iga_policy ─1:n─▶ iga_entitlements (statement) ─1:n─▶ iga_entitlement_target ─▶ iga_resources
//	    │ 1:n                    ▲ n:1
//	    ▼                        │
//	iga_policy_assignment ─1:n─▶ iga_access_edges (grant, ALLOW ONLY) ◀─ holder identity
//
// Four identities, because four things change independently: a policy (new
// PolicyId or inline name), a statement (Sid, else content), an assignment
// (attach/detach), and a grant (its assignment or its statement).

// policyImmutable is the incarnation boundary to key this policy by, and false
// when it cannot be keyed at all.
//
// An UNREADABLE managed policy whose GetPolicy failed has no PolicyId this run.
// It keeps the incarnation the graph already holds for its ARN -- we did not
// observe a recreation, and its assignments must stay current (§1.4). With no
// live object either, there is nothing to protect and nothing to key it by.
func (p *Projector) policyImmutable(snap *Snapshot, r *resolved, cp models.CloudPolicy) (string, bool) {
	holder := snap.IdentityByID(cp.HolderIdentityID)
	if cp.PolicyKind == models.CloudPolicyInline && holder == nil {
		return "", false // the holder was not in this run; the policy cannot be keyed
	}
	imm := PolicyImmutableKey(cp, holder)
	if imm != "" {
		return imm, true
	}
	if live := r.existing.policy[PolicyKey(cp, holder)]; live != nil && live.ImmutableKey != "" {
		return live.ImmutableKey, true
	}
	return "", false
}

// projectPolicies: recreate / continue / restore / new, as identities. A
// recreation CASCADES in this same transaction (§4.7): the old incarnation's
// statements retire policy_recreated, its assignments and grants end
// policy_recreated, and its live revisions close.
func (p *Projector) projectPolicies(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	now := p.now()
	part := snap.PartitionFor(models.ObjectPolicy, "", "")
	for _, cp := range snap.Policies {
		holder := snap.IdentityByID(cp.HolderIdentityID)
		imm, ok := p.policyImmutable(snap, r, cp)
		if !ok {
			continue
		}
		key := PolicyKey(cp, holder)
		cont := Continuity(PolicyContinuityKind(cp))
		desc := models.IGAPolicy{
			WorkspaceID: snap.Run.WorkspaceID, Provider: models.ProviderAWS,
			PolicyKind: PolicyKind(cp), DisplayName: cp.Name,
			SourceKey: key, Continuity: cont, ImmutableKey: imm,
			VersionID: cp.VersionID, DocumentHash: cp.DocumentHash,
			Lifecycle: models.IGALifecycleActive, LastSeenAt: now,
		}
		if cp.PolicyKind == models.CloudPolicyManaged {
			desc.NativeRef = cp.NativeID
		}
		live := r.existing.policy[key]
		if cp.Unreadable() && live != nil {
			// Nothing about the document was read: keep what the graph knew.
			desc.DocumentHash, desc.VersionID = live.DocumentHash, live.VersionID
		}

		var id uuid.UUID
		var err error
		switch {
		case live != nil && imm != "" && live.ImmutableKey != "" && live.ImmutableKey != imm:
			// RECREATION: same ARN (or holder+name), a different incarnation.
			retiredStmts, rerr := p.repo.RetirePolicyIncarnation(tx, snap.Run.WorkspaceID, live.ID, now)
			if rerr != nil {
				return fmt.Errorf("retire recreated policy %s: %w", key, rerr)
			}
			p.events.Retired(models.ObjectPolicy, live.ID, models.RetiredRecreated)
			for _, sid := range retiredStmts {
				p.events.Retired(models.ObjectEntitlement, sid, models.RetiredPolicyRecreated)
			}
			row := desc
			row.FirstSeenAt = now
			if id, err = p.repo.UpsertPolicy(tx, &row); err != nil {
				return fmt.Errorf("insert recreated policy %s: %w", key, err)
			}
			p.events.FirstSeen(models.ObjectPolicy, id)
		case live != nil:
			desc.FirstSeenAt = live.FirstSeenAt
			if id, err = p.repo.UpsertPolicy(tx, &desc); err != nil {
				return fmt.Errorf("upsert policy %s: %w", key, err)
			}
		case r.existing.retiredPolicy[retiredKey(key, imm)] != nil:
			// RESTORATION keeps the incarnation key, so its statements are
			// matched by key and continue.
			prev := r.existing.retiredPolicy[retiredKey(key, imm)]
			if id, err = p.repo.RestorePolicy(tx, snap.Run.WorkspaceID, prev.ID, imm, &desc, now); err != nil {
				return fmt.Errorf("restore policy %s: %w", key, err)
			}
			p.events.Restored(models.ObjectPolicy, id)
		default:
			row := desc
			row.FirstSeenAt = now
			if id, err = p.repo.UpsertPolicy(tx, &row); err != nil {
				return fmt.Errorf("insert policy %s: %w", key, err)
			}
			p.events.FirstSeen(models.ObjectPolicy, id)
		}
		if err := p.support(tx, snap, models.ObjectPolicy, id, part); err != nil {
			return err
		}
		r.policy[cp.ID] = id
		r.incarnKey[cp.ID] = PolicyIncarnationKey(cp, holder, imm)
	}
	return nil
}

// projectStatements writes each READABLE policy's statements, their
// revisions, resource references and targets. An unreadable document
// contributes no statements this run; what it declared before is protected by
// reconciliation (Exclusions), never re-derived from a guess.
func (p *Projector) projectStatements(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	part := snap.PartitionFor(models.ObjectEntitlement, "", "")
	for _, cp := range snap.Policies {
		polID, ok := r.policy[cp.ID]
		if !ok || snap.UnreadablePolicy[cp.ID] {
			continue
		}
		stmts, _, err := awsdiscovery.ParsePolicyDocument(string(cp.Document))
		if err != nil {
			// The collector recorded it readable with the same parser.
			return fmt.Errorf("policy %s parsed at collection, failed now: %w", cp.NativeID, err)
		}
		incarn := r.incarnKey[cp.ID]
		imm, _ := p.policyImmutable(snap, r, cp)
		cont := Continuity(PolicyContinuityKind(cp))
		sids, seen := CountSids(stmts), map[string]int{}
		for i := range stmts {
			st := stmts[i]
			key, hash := StatementKey(incarn, st, sids, seen)
			id, err := p.upsertStatement(tx, snap, r, polID, key, hash, cont, imm, st)
			if err != nil {
				return err
			}
			if SidKeyed(key) {
				// A Sid-keyed statement whose content changed gains a revision:
				// the live revision closes and a new one opens.
				if err := p.repo.RecordRevision(tx, snap.Run.WorkspaceID, id, hash, st.Raw,
					cp.VersionID, snap.Run.ID, p.now()); err != nil {
					return fmt.Errorf("revision for %s: %w", key, err)
				}
			}
			if err := p.projectTargets(tx, snap, r, id, st); err != nil {
				return err
			}
			if err := p.support(tx, snap, models.ObjectEntitlement, id, part); err != nil {
				return err
			}
			r.statements[cp.ID] = append(r.statements[cp.ID], projectedStatement{ID: id, Key: key, Effect: st.Effect})
		}
	}
	return nil
}

func (p *Projector) upsertStatement(
	tx *gorm.DB, snap *Snapshot, r *resolved, policyID uuid.UUID,
	key, hash, continuity, immutable string, st awsdiscovery.PolicyStatement,
) (uuid.UUID, error) {
	now := p.now()
	idx := st.Index
	row := &models.IGAEntitlement{
		WorkspaceID: snap.Run.WorkspaceID, Provider: models.ProviderAWS,
		PolicyID: &policyID, SourceKey: key, StatementKey: key,
		Sid: st.Sid, StatementIndex: &idx, Effect: st.Effect, // lowercase
		ContentHash: hash,
		Negated:     len(st.NotActions) > 0 || len(st.NotResources) > 0,
		Conditional: st.Condition != "",
		// A statement inherits its policy's continuity (§2.4), and with it the
		// creation boundary 028's CHECK requires alongside 'immutable'.
		Continuity: continuity, ImmutableKey: immutable,
		NativeGrantKind:  "aws_statement",
		NativeRights:     verbatim(st),
		NormalizedRights: normalizedRights(st),
		Lifecycle:        models.IGALifecycleActive,
		LastSeenAt:       now,
	}
	live := r.existing.entitlement[key]
	switch {
	case live != nil:
		row.FirstSeenAt = live.FirstSeenAt
		return p.repo.UpsertStatement(tx, row)
	case immutable != "" && r.existing.retiredEntitlement[retiredKey(key, immutable)] != nil:
		prev := r.existing.retiredEntitlement[retiredKey(key, immutable)]
		id, err := p.repo.RestoreStatement(tx, snap.Run.WorkspaceID, prev.ID, immutable, now)
		if err != nil {
			return uuid.Nil, fmt.Errorf("restore statement %s: %w", key, err)
		}
		p.events.Restored(models.ObjectEntitlement, id)
		// The content may have moved while it was gone.
		row.FirstSeenAt = prev.FirstSeenAt
		return p.repo.UpsertStatement(tx, row)
	default:
		row.FirstSeenAt = now
		id, err := p.repo.UpsertStatement(tx, row)
		if err != nil {
			return uuid.Nil, fmt.Errorf("insert statement %s: %w", key, err)
		}
		p.events.FirstSeen(models.ObjectEntitlement, id)
		return id, nil
	}
}

// verbatim is exactly what AWS returned for the statement; our reading lives
// in normalizedRights, beside it, never instead of it (§2.13 bet 1).
func verbatim(st awsdiscovery.PolicyStatement) json.RawMessage {
	if len(st.Raw) > 0 && json.Valid(st.Raw) {
		return st.Raw
	}
	raw, err := json.Marshal(models.NativeRights{
		Effect: st.Effect, Actions: st.Actions, NotActions: st.NotActions,
		Resources: st.Resources, NotResources: st.NotResources,
		Condition: json.RawMessage(nullableJSON(st.Condition)),
	})
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

func nullableJSON(s string) []byte {
	if s == "" {
		return nil
	}
	return []byte(s)
}

func normalizedRights(st awsdiscovery.PolicyStatement) json.RawMessage {
	raw, err := json.Marshal(models.NormalizedRights{
		Verbs:       st.Actions,
		Constrained: st.Condition != "" || len(st.NotActions) > 0 || len(st.NotResources) > 0,
	})
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

// projectTargets sets the statement's target set to what its CURRENT content
// names. A NotResource entry is an EXCLUSION (mode not_resource), never a
// destination; "everything except" is scoped by the implicit "*" selector.
func (p *Projector) projectTargets(tx *gorm.DB, snap *Snapshot, r *resolved,
	stmtID uuid.UUID, st awsdiscovery.PolicyStatement) error {
	var rows []models.IGAEntitlementTarget
	add := func(resource, mode string, ord int) error {
		id, err := p.resourceRef(tx, snap, r, resource)
		if err != nil {
			return err
		}
		rows = append(rows, models.IGAEntitlementTarget{
			WorkspaceID: snap.Run.WorkspaceID, EntitlementID: stmtID,
			ResourceID: id, TargetMode: mode, Ordinal: ord,
		})
		return nil
	}
	for i, res := range st.Resources {
		if err := add(res, models.TargetResource, i); err != nil {
			return err
		}
	}
	for i, res := range st.NotResources {
		if err := add(res, models.TargetNotResource, i); err != nil {
			return err
		}
	}
	if len(st.NotResources) > 0 && len(st.Resources) == 0 {
		if err := add("*", models.TargetResource, 0); err != nil {
			return err
		}
	}
	// Written only when the set differs from what is stored, so an unchanged
	// statement's targets keep their ids.
	return p.repo.ReplaceTargets(tx, snap.Run.WorkspaceID, stmtID, rows)
}

// resourceRef upserts one iga_resources row per distinct resource text, with a
// support row for THIS connector -- so a bucket two accounts name has two
// supports and survives either one dropping it (§2.10B).
func (p *Projector) resourceRef(tx *gorm.DB, snap *Snapshot, r *resolved, text string) (uuid.UUID, error) {
	key := ResourceRefKey(text)
	if id, ok := r.resource[key]; ok {
		return id, nil
	}
	kind, attrs := describeResource(text, snap.ConnectedAccounts)
	live := r.existing.resource[key]
	row := &models.IGAResource{
		WorkspaceID: snap.Run.WorkspaceID, EstateScopeID: &snap.ScopeID,
		Provider: models.ProviderAWS, ResourceKind: kind, DisplayName: text,
		SourceKey: key, Continuity: ContinuityRecognitionOnly,
		Stage: "unknown", Lifecycle: models.IGALifecycleActive,
		ProviderAttrs: attrs, LastSeenAt: p.now(),
	}
	if live == nil {
		row.FirstSeenAt = p.now()
	} else {
		row.FirstSeenAt = live.FirstSeenAt
	}
	id, err := p.repo.UpsertResource(tx, row)
	if err != nil {
		return uuid.Nil, fmt.Errorf("upsert resource %s: %w", text, err)
	}
	if live == nil {
		p.events.FirstSeen(models.ObjectResource, id)
	}
	if err := p.support(tx, snap, models.ObjectResource, id, snap.PartitionFor(models.ObjectResource, "", "")); err != nil {
		return uuid.Nil, err
	}
	r.resource[key] = id
	return id, nil
}

// describeResource types a reference and records what its text STATES. Account
// and region come from the ARN only when the ARN carries them: an S3 ARN
// carries neither, and is never assigned the scanning account (§1.4).
func describeResource(text string, connected map[string]bool) (string, json.RawMessage) {
	attrs := map[string]any{"existence": "not_verified"}
	kind := "unknown"
	switch {
	case strings.ContainsAny(text, "*?"):
		kind = "selector"
		attrs["reference"] = "selector"
	case strings.HasPrefix(text, "arn:"):
		attrs["reference"] = "exact"
		if typed := awsdiscovery.TypeResourceARN(text); typed != nil && typed.Kind != "" {
			kind = typed.Kind
		}
	default:
		attrs["reference"] = "exact"
	}
	if parts := strings.SplitN(text, ":", 6); len(parts) == 6 && parts[0] == "arn" {
		if parts[3] != "" && !strings.ContainsAny(parts[3], "*?") {
			attrs["region"] = parts[3]
		}
		if acct := parts[4]; acct != "" && !strings.ContainsAny(acct, "*?") {
			attrs["account"] = acct
			attrs["account_connected"] = connected[acct]
		}
	}
	raw, err := json.Marshal(attrs)
	if err != nil {
		return kind, json.RawMessage(`{}`)
	}
	return kind, raw
}

// projectAssignments writes policy -> holder for EVERY attachment, readable or
// not: an attachment list is read independently of the document (§1.4), so
// an unreadable policy's assignments stay current.
func (p *Projector) projectAssignments(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	now := p.now()
	part := snap.EdgePartitionFor("assignment", "", "")
	for _, at := range snap.Attachments {
		holderID, ok := r.identity[at.PrincipalIdentityID]
		if !ok {
			continue // the holder was not projected
		}
		polID, ok := r.policy[at.PolicyRowID]
		if !ok {
			continue // the policy could not be keyed
		}
		holder := snap.IdentityByID(&at.PrincipalIdentityID)
		pol := snap.PolicyByID(at.PolicyRowID)
		if holder == nil || pol == nil {
			continue
		}
		key := AssignmentKey(r.incarnKey[at.PolicyRowID], EndpointKey(*holder), at.AttachmentKind)
		id, err := p.repo.UpsertAssignment(tx, &models.IGAPolicyAssignment{
			WorkspaceID: snap.Run.WorkspaceID, PolicyID: polID,
			HolderIdentityAccountID: holderID, AssignmentKind: at.AttachmentKind,
			Basis: models.BasisDeclared, State: models.RelCurrent,
			SourceKey: key, ConnectorID: &snap.Run.ConnectorID, PartitionKey: part.Key(),
			LastConfirmedAt: now, LastConfirmedBy: &snap.Run.ID,
		})
		if err != nil {
			return fmt.Errorf("upsert assignment %s: %w", key, err)
		}
		r.assignment[at.ID] = id
		r.assignKey[at.ID] = key
		r.assignRefs = append(r.assignRefs, assignRef{ID: id, PolicyNative: pol.NativeID, HolderNative: holder.NativeID})
	}
	return nil
}

// projectGrants writes holder -> statement, through one assignment, for ALLOW
// statements only. A Deny is a restriction and a boundary a ceiling; neither
// is ever a grant (§2.6). UpsertGrant re-checks the effect at the write.
func (p *Projector) projectGrants(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	now := p.now()
	part := snap.EdgePartitionFor("access_edge", "", "")
	for _, at := range snap.Attachments {
		asg, ok := r.assignment[at.ID]
		if !ok || at.AttachmentKind == models.CloudAttachmentBoundary {
			continue // a boundary limits; it never grants
		}
		holder := r.identity[at.PrincipalIdentityID]
		holderCI := snap.IdentityByID(&at.PrincipalIdentityID)
		pol := snap.PolicyByID(at.PolicyRowID)
		for _, st := range r.statements[at.PolicyRowID] {
			if st.Effect != models.EffectAllow {
				continue // a Deny statement is a restriction, never a grant
			}
			stmtID := st.ID
			holderCopy := holder
			id, err := p.repo.UpsertGrant(tx, &models.IGAAccessEdge{
				WorkspaceID: snap.Run.WorkspaceID, Provider: models.ProviderAWS,
				SubjectIdentityAccountID: &holderCopy,
				// The legacy pair, still written until 037 (030 is expand only).
				SubjectKind: "identity_account", SubjectID: holder,
				EntitlementID: &stmtID, AssignmentID: &asg,
				Direction: "outbound", PathKind: "aws_policy",
				Basis: models.BasisDeclared, State: models.RelCurrent,
				// Nothing is evaluated: the honesty check (004) requires
				// unknown unless the calculation is complete, and it never is.
				CalculationState: models.CalcPartial, EffectiveConclusion: models.ConclusionUnknown,
				SourceKey:       GrantKey(r.assignKey[at.ID], st.Key),
				ConnectorID:     &snap.Run.ConnectorID,
				PartitionKey:    part.Key(),
				LastConfirmedAt: now, LastConfirmedBy: &snap.Run.ID,
			}, st.Effect)
			if err != nil {
				return fmt.Errorf("upsert grant %s: %w", st.Key, err)
			}
			r.grants = append(r.grants, grantRef{ID: id, PolicyNative: pol.NativeID, HolderNative: holderCI.NativeID})
		}
	}
	return nil
}

// Exclusions name what an unreadable document declared, in graph ids, so
// reconciliation can never end it (§4.10).
type Exclusions struct {
	UnreadablePolicies []uuid.UUID // iga_policy ids whose document was unreadable this run
	UnreadableTrust    []uuid.UUID // iga_identity_accounts ids of roles whose trust did not parse
	// UnattributedPodIdentity: iga_identity_accounts ids of roles with a
	// pod-identity association whose cluster issuer this run could not read
	// (trust.go, projectPodIdentity). Their pod-identity edges go stale, never
	// ended.
	UnattributedPodIdentity []uuid.UUID
}

func exclusionsOf(snap *Snapshot, r *resolved) Exclusions {
	var ex Exclusions
	for _, cp := range snap.Policies {
		if snap.UnreadablePolicy[cp.ID] {
			if id, ok := r.policy[cp.ID]; ok {
				ex.UnreadablePolicies = append(ex.UnreadablePolicies, id)
			}
		}
	}
	return ex
}
