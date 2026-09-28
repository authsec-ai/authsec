package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/authsec-ai/authsec/internal/runtimepolicy/compile"
	"github.com/authsec-ai/authsec/internal/runtimepolicy/opa"
	"github.com/authsec-ai/authsec/internal/runtimepolicy/precedence"
	"github.com/authsec-ai/authsec/internal/runtimepolicy/sign"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type publishRequest struct {
	Mode              string   `json:"mode"`
	CanaryWorkloadIDs []string `json:"canary_workload_ids"`
	WindowSeconds     int      `json:"window_seconds"`
	FailureThreshold  int      `json:"failure_threshold"`
	Reason            string   `json:"reason"`
	phaseOverride     string
	epochOverride     *int64
}

type publicationTarget struct {
	WorkloadID        uuid.UUID
	RuntimeInstanceID *uuid.UUID
	CollectorID       uuid.UUID
	Digest            string
}

// Publish signs an approved revision and records the desired delivery.
// mode=enforce is refused unless IGA_V2_ENFORCE is on, and then only when
// every target digest supports the required controls.
func (s *RuntimePolicyService) Publish(ctx context.Context, actor Actor, id uuid.UUID, key, ifMatch string, body []byte) (int, []byte, error) {
	if models.IsRuntimePolicyCandidateSystem(actor.UserID, actor.Kind) {
		return 0, nil, statusErr(http.StatusForbidden, "candidate_system_forbidden", "The candidate generator cannot approve or enforce.")
	}
	var req publishRequest
	if len(body) > 0 && string(body) != "null" {
		if err := json.Unmarshal(body, &req); err != nil {
			return 0, nil, statusErr(http.StatusBadRequest, "invalid_document", "The publication body is not JSON.")
		}
	}
	if req.Mode == "" {
		req.Mode = "observe"
	}
	if req.Mode != "observe" && req.Mode != "enforce" {
		return 0, nil, statusErr(http.StatusBadRequest, "invalid_document", "mode must be observe or enforce.")
	}
	if req.Mode == "enforce" && !V2EnforceEnabled() {
		return 0, nil, statusErr(http.StatusForbidden, "enforce_disabled", "Enforce publication is disabled.")
	}
	if req.WindowSeconds <= 0 {
		req.WindowSeconds = int(CanaryWindow() / time.Second)
	}
	if req.FailureThreshold <= 0 {
		req.FailureThreshold = 1
	}
	route := "POST /api/iga/v2/runtime-policies/:id/publications"
	return s.onceLocked(ctx, actor, id, key, route, ifMatch, body, func(tx *gorm.DB, head policyHead, cur revisionHead) (int, []byte, error) {
		if etag(cur.Revision, cur.ContentHash) != ifMatch {
			return 0, nil, statusErr(http.StatusPreconditionFailed, "precondition_failed", "If-Match does not match the current revision.")
		}
		if !RuntimePolicyTransitionAllowed(cur.State, models.RuntimePolicyStatePublished) {
			return 0, nil, statusErr(http.StatusConflict, "invalid_transition", "Publication requires an approved revision.")
		}
		return s.insertPublication(ctx, tx, actor, id, cur, req, route, ifMatch, body, true)
	})
}

// Rollback publishes the previous good publication as a new delivery revision.
// The delivery revision increases. The superseded revision is not moved back
// to published.
func (s *RuntimePolicyService) Rollback(ctx context.Context, actor Actor, id uuid.UUID, key, ifMatch string, body []byte) (int, []byte, error) {
	if models.IsRuntimePolicyCandidateSystem(actor.UserID, actor.Kind) {
		return 0, nil, statusErr(http.StatusForbidden, "candidate_system_forbidden", "The candidate generator cannot approve or enforce.")
	}
	route := "POST /api/iga/v2/runtime-policies/:id/rollback"
	return s.onceLocked(ctx, actor, id, key, route, ifMatch, body, func(tx *gorm.DB, head policyHead, cur revisionHead) (int, []byte, error) {
		if etag(cur.Revision, cur.ContentHash) != ifMatch {
			return 0, nil, statusErr(http.StatusPreconditionFailed, "precondition_failed", "If-Match does not match the current revision.")
		}
		var current []struct {
			ID uuid.UUID
		}
		if err := tx.Raw(`SELECT id FROM runtime_policy_publications
			WHERE workspace_id = ? AND policy_id = ? ORDER BY created_at DESC LIMIT 1`,
			actor.WorkspaceID, id).Scan(&current).Error; err != nil {
			return 0, nil, err
		}
		if len(current) == 0 {
			return 0, nil, statusErr(http.StatusConflict, "no_previous_publication", "This policy has no publication to roll back.")
		}
		var prev []struct {
			Revision     int
			RevisionHash string
			Mode         string
			Epoch        int64
		}
		if err := tx.Raw(`SELECT revision, revision_hash, mode, revocation_epoch AS epoch
			FROM runtime_policy_publications
			WHERE workspace_id = ? AND policy_id = ? AND id <> ?
			  AND COALESCE(rollout_plan->>'phase', 'complete') NOT IN ('paused', 'revoked')
			ORDER BY created_at DESC LIMIT 1`,
			actor.WorkspaceID, id, current[0].ID).Scan(&prev).Error; err != nil {
			return 0, nil, err
		}
		if len(prev) == 0 {
			return 0, nil, statusErr(http.StatusConflict, "no_previous_publication", "There is no previous good publication.")
		}
		var revs []revisionHead
		if err := tx.Raw(`SELECT revision, document::text AS document, content_hash, author_user_id, state, graph_revision
			FROM runtime_policy_revisions WHERE workspace_id = ? AND policy_id = ? AND revision = ?`,
			actor.WorkspaceID, id, prev[0].Revision).Scan(&revs).Error; err != nil {
			return 0, nil, err
		}
		if len(revs) == 0 || revs[0].ContentHash != prev[0].RevisionHash {
			return 0, nil, statusErr(http.StatusConflict, "no_previous_publication", "The previous publication has no revision.")
		}
		if err := tx.Exec(`UPDATE runtime_policy_publications
			SET rollout_plan = jsonb_set(rollout_plan, '{phase}', '"rolled_back"')
			WHERE workspace_id = ? AND id = ?`,
			actor.WorkspaceID, current[0].ID).Error; err != nil {
			return 0, nil, err
		}
		if cur.State == models.RuntimePolicyStatePublished {
			if err := tx.Exec(`UPDATE runtime_policy_revisions SET state = 'superseded' WHERE workspace_id = ? AND policy_id = ? AND revision = ?`,
				actor.WorkspaceID, id, cur.Revision).Error; err != nil {
				return 0, nil, err
			}
		}
		req := publishRequest{Mode: prev[0].Mode, Reason: "rollback", WindowSeconds: int(CanaryWindow() / time.Second), FailureThreshold: 1}
		status, payload, err := s.insertPublication(ctx, tx, actor, id, revs[0], req, route, ifMatch, body, false)
		if err != nil {
			return 0, nil, err
		}
		return status, payload, nil
	})
}

// Revoke bumps the revocation epoch and publishes that as the next delivery
// revision. The publication stays desired so agents observe the new epoch.
func (s *RuntimePolicyService) Revoke(ctx context.Context, actor Actor, id uuid.UUID, key, ifMatch string, body []byte) (int, []byte, error) {
	if models.IsRuntimePolicyCandidateSystem(actor.UserID, actor.Kind) {
		return 0, nil, statusErr(http.StatusForbidden, "candidate_system_forbidden", "The candidate generator cannot approve or enforce.")
	}
	route := "POST /api/iga/v2/runtime-policies/:id/revoke"
	return s.onceLocked(ctx, actor, id, key, route, ifMatch, body, func(tx *gorm.DB, head policyHead, cur revisionHead) (int, []byte, error) {
		if etag(cur.Revision, cur.ContentHash) != ifMatch {
			return 0, nil, statusErr(http.StatusPreconditionFailed, "precondition_failed", "If-Match does not match the current revision.")
		}
		if !RuntimePolicyTransitionAllowed(cur.State, models.RuntimePolicyStateRevoked) {
			return 0, nil, statusErr(http.StatusConflict, "invalid_transition", "Only a published revision can be revoked.")
		}
		var epoch int64
		if err := tx.Raw(`SELECT COALESCE(MAX(revocation_epoch), 0) FROM runtime_policy_publications WHERE workspace_id = ? AND policy_id = ?`,
			actor.WorkspaceID, id).Scan(&epoch).Error; err != nil {
			return 0, nil, err
		}
		next := epoch + 1
		req := publishRequest{
			Mode: "observe", Reason: "revoke", WindowSeconds: int(CanaryWindow() / time.Second), FailureThreshold: 1,
			phaseOverride: "revoked", epochOverride: &next,
		}
		status, payload, err := s.insertPublication(ctx, tx, actor, id, cur, req, route, ifMatch, body, false)
		if err != nil {
			return 0, nil, err
		}
		if err := tx.Exec(`UPDATE runtime_policy_revisions SET state = 'revoked' WHERE workspace_id = ? AND policy_id = ? AND revision = ?`,
			actor.WorkspaceID, id, cur.Revision).Error; err != nil {
			return 0, nil, err
		}
		if err := tx.Exec(`UPDATE runtime_policies SET lifecycle = 'revoked', updated_at = now() WHERE workspace_id = ? AND id = ?`,
			actor.WorkspaceID, id).Error; err != nil {
			return 0, nil, err
		}
		return status, payload, nil
	})
}

// advanceRevision moves approved to published and supersedes an older
// published revision of the same policy. Rollback and revoke pass false and
// set the revision state themselves.
func (s *RuntimePolicyService) insertPublication(ctx context.Context, tx *gorm.DB, actor Actor, policyID uuid.UUID, cur revisionHead, req publishRequest, route, ifMatch string, body []byte, advance bool) (int, []byte, error) {
	doc, err := compile.Parse([]byte(cur.Document))
	if err != nil {
		return 0, nil, statusFrom(err)
	}
	result, err := compile.Compile(ctx, s.reg, dbCatalog{tx: tx}, actor.WorkspaceID, cur.Revision, doc)
	if err != nil {
		return 0, nil, statusFrom(err)
	}
	targets, err := resolvePublicationTargets(tx, actor.WorkspaceID, result)
	if err != nil {
		return 0, nil, err
	}
	if len(targets) == 0 {
		return 0, nil, statusErr(http.StatusUnprocessableEntity, "no_collector", "No active collector can deliver this policy.")
	}
	checkDoc := doc
	checkDoc.Mode = req.Mode
	refs := make([]compile.TargetRef, 0, len(targets))
	for _, t := range targets {
		refs = append(refs, compile.TargetRef{WorkloadID: t.WorkloadID, CapabilityDigest: t.Digest, Profile: doc.Profile})
	}
	report, err := compile.CheckEnforceable(s.reg, checkDoc, refs)
	if err != nil {
		extra := map[string]any{"semantic_report": report}
		var ce *compile.Error
		if errorsAsCompile(err, &ce) {
			for k, v := range ce.Details {
				extra[k] = v
			}
			return 0, nil, &StatusError{Status: http.StatusUnprocessableEntity, Code: ce.Code, Message: ce.Message, Extra: extra}
		}
		return 0, nil, statusFrom(err)
	}
	for _, canary := range req.CanaryWorkloadIDs {
		found := false
		for _, t := range targets {
			if t.WorkloadID.String() == canary {
				found = true
			}
		}
		if !found {
			return 0, nil, statusErr(http.StatusUnprocessableEntity, "invalid_canary", "A canary workload is not a target of this revision.")
		}
	}
	keys, err := LoadPolicyKeys(s.clock())
	if err != nil {
		return 0, nil, statusErr(http.StatusServiceUnavailable, "signing_unavailable", err.Error())
	}
	pubID := uuid.New()
	if err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended(CAST(? AS text), 0))`, actor.WorkspaceID.String()).Error; err != nil {
		return 0, nil, err
	}
	var maxRev int64
	if err := tx.Raw(`SELECT COALESCE(MAX(desired_delivery_revision), 0) FROM runtime_policy_targets WHERE workspace_id = ?`,
		actor.WorkspaceID).Scan(&maxRev).Error; err != nil {
		return 0, nil, err
	}
	delivery := maxRev + 1
	phase := "complete"
	if len(req.CanaryWorkloadIDs) > 0 {
		phase = "canary"
	}
	if !advance && req.Reason == "rollback" {
		phase = "rest"
	}
	if req.phaseOverride != "" {
		phase = req.phaseOverride
	}
	epoch := int64(0)
	if req.epochOverride != nil {
		epoch = *req.epochOverride
	}
	effects := make([]sign.TargetEffect, 0, len(targets))
	seenWorkload := map[string]bool{}
	for _, t := range targets {
		if seenWorkload[t.WorkloadID.String()] {
			continue
		}
		seenWorkload[t.WorkloadID.String()] = true
		facts, err := loadPrecedence(tx, actor.WorkspaceID, t.WorkloadID.String(), doc, s.clock())
		if err != nil {
			return 0, nil, err
		}
		outcome := precedence.Resolve(s.clock(), facts)
		effects = append(effects, sign.TargetEffect{WorkloadID: t.WorkloadID.String(), Effect: outcome.Effect, Source: outcome.Source})
	}
	sort.Slice(effects, func(i, j int) bool { return effects[i].WorkloadID < effects[j].WorkloadID })
	dataRaw, err := json.Marshal(result.Data)
	if err != nil {
		return 0, nil, err
	}
	bundle, err := sign.SignBundle([]sign.File{
		{Name: "policy.rego", Body: []byte(result.Rego)},
		{Name: "data.json", Body: dataRaw},
	}, keys.SigningKeys())
	if err != nil {
		return 0, nil, statusErr(http.StatusServiceUnavailable, "signing_unavailable", "policy signing key could not be parsed")
	}
	controlsHash := sign.SHA256Hex(result.Controls)
	digest := ""
	for _, t := range targets {
		if digest == "" || t.Digest < digest {
			digest = t.Digest
		}
	}
	manifest := sign.Manifest{
		WorkspaceID: actor.WorkspaceID.String(), PublicationID: pubID.String(),
		DeliveryRevision: delivery, PolicyRevisionHash: cur.ContentHash,
		GraphRevision: cur.GraphRevision, TargetDigest: result.TargetDigest,
		CapabilityDigest: digest, CompilerBuild: opa.Version,
		OPABundleSHA256: bundle.SHA256, ControlsSHA256: controlsHash,
		KeyID: keys.Current.ID, CreatedAt: s.clock().Format(time.RFC3339),
		Targets: effects,
	}
	signed, manifestHash, err := sign.SignManifest(manifest, keys.SigningKeys())
	if err != nil {
		return 0, nil, statusErr(http.StatusServiceUnavailable, "signing_unavailable", "policy signing key could not be parsed")
	}
	var previous []uuid.UUID
	if err := tx.Raw(`SELECT id FROM runtime_policy_publications WHERE workspace_id = ? AND policy_id = ? ORDER BY created_at DESC LIMIT 1`,
		actor.WorkspaceID, policyID).Scan(&previous).Error; err != nil {
		return 0, nil, err
	}
	var superseded *uuid.UUID
	if len(previous) == 1 {
		superseded = &previous[0]
	}
	planDoc := rolloutPlan{
		Phase: phase, Canary: req.CanaryWorkloadIDs, Window: req.WindowSeconds,
		Threshold: req.FailureThreshold, Started: s.clock().Format(time.RFC3339),
		Artifacts: map[string]planArtifact{
			"opa_bundle": {ID: uuid.NewString(), SHA256: bundle.SHA256, Body: base64.StdEncoding.EncodeToString(bundle.Bytes)},
			"controls":   {ID: uuid.NewString(), SHA256: controlsHash, Body: base64.StdEncoding.EncodeToString(result.Controls)},
			"manifest":   {ID: uuid.NewString(), SHA256: sign.SHA256Hex([]byte(signed)), Body: base64.StdEncoding.EncodeToString([]byte(signed))},
		},
	}
	plan, err := json.Marshal(planDoc)
	if err != nil {
		return 0, nil, err
	}
	if err := tx.Exec(`INSERT INTO runtime_policy_publications
		(id, workspace_id, policy_id, revision, revision_hash, rollout_plan, signed_manifest_hash, author_user_id, superseded_publication_id, mode, revocation_epoch)
		VALUES (?, ?, ?, ?, ?, CAST(? AS jsonb), ?, ?, ?, ?, ?)`,
		pubID, actor.WorkspaceID, policyID, cur.Revision, cur.ContentHash, string(plan), manifestHash, actor.UserID, superseded, req.Mode, epoch,
	).Error; err != nil {
		return 0, nil, err
	}
	need := requiredControlList(doc, result)
	needJSON, _ := json.Marshal(need)
	for _, t := range targets {
		if err := tx.Exec(`INSERT INTO runtime_policy_targets
			(id, workspace_id, publication_id, workload_id, runtime_instance_id, collector_id, desired_delivery_revision, capability_digest, required_controls)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS jsonb))`,
			uuid.New(), actor.WorkspaceID, pubID, t.WorkloadID, t.RuntimeInstanceID, t.CollectorID, delivery, t.Digest, string(needJSON),
		).Error; err != nil {
			return 0, nil, err
		}
	}
	if advance {
		if err := tx.Exec(`UPDATE runtime_policy_revisions SET state = 'superseded'
			WHERE workspace_id = ? AND policy_id = ? AND state = 'published'`,
			actor.WorkspaceID, policyID).Error; err != nil {
			return 0, nil, err
		}
		if err := tx.Exec(`UPDATE runtime_policy_revisions SET state = 'published' WHERE workspace_id = ? AND policy_id = ? AND revision = ?`,
			actor.WorkspaceID, policyID, cur.Revision).Error; err != nil {
			return 0, nil, err
		}
		if err := tx.Exec(`UPDATE runtime_policies SET lifecycle = 'published', updated_at = now() WHERE workspace_id = ? AND id = ?`,
			actor.WorkspaceID, policyID).Error; err != nil {
			return 0, nil, err
		}
	}
	if err := writeAudit(tx, actor, &policyID, routeAction(req, advance), req.Reason, requestHash(route, ifMatch, body), doc.Targets.WorkloadIDs,
		map[string]any{"state": cur.State}, map[string]any{
			"publication_id": pubID, "delivery_revision": delivery, "mode": req.Mode, "rollout_phase": phase,
		}); err != nil {
		return 0, nil, err
	}
	out, _ := json.Marshal(map[string]any{
		"etag": etag(cur.Revision, cur.ContentHash),
		"data": map[string]any{
			"policy_id": policyID, "publication_id": pubID, "revision": cur.Revision,
			"delivery_revision": delivery, "mode": req.Mode, "rollout_phase": phase,
			"content_hash": cur.ContentHash, "target_digest": result.TargetDigest,
			"semantic_report": report,
		},
	})
	return http.StatusCreated, out, nil
}

func routeAction(req publishRequest, advance bool) string {
	if !advance && req.Reason == "rollback" {
		return "rollback"
	}
	if !advance && req.Reason == "revoke" {
		return "revoke"
	}
	return "publish"
}

func errorsAsCompile(err error, target **compile.Error) bool {
	ce, ok := err.(*compile.Error)
	if !ok || ce == nil {
		return false
	}
	*target = ce
	return true
}

func requiredControlList(doc compile.Document, result *compile.Result) []string {
	set := map[string]bool{}
	for _, c := range doc.RequiredControls {
		if c != "" {
			set[c] = true
		}
	}
	for _, rule := range result.Semantic.Rules {
		for _, c := range rule.RequiredCapabilities {
			set[c] = true
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func resolvePublicationTargets(tx *gorm.DB, ws uuid.UUID, result *compile.Result) ([]publicationTarget, error) {
	if result == nil {
		return nil, nil
	}
	var out []publicationTarget
	for _, entry := range result.Manifest {
		wid, err := uuid.Parse(entry.WorkloadID)
		if err != nil {
			return nil, statusErr(http.StatusUnprocessableEntity, "unresolved_target", "A target workload is not a uuid.")
		}
		var rows []struct {
			ID     string
			Digest string
		}
		err = tx.Raw(`SELECT c.id::text AS id,
			COALESCE(NULLIF(c.capability_digest, ''), (
				SELECT r.capability_digest FROM collector_capability_reports r
				WHERE r.workspace_id = c.workspace_id AND r.collector_id = c.id AND r.capability_digest <> ''
				ORDER BY r.last_seen_at DESC NULLS LAST LIMIT 1
			), '') AS digest
			FROM collector_instances c
			JOIN iga_workload w ON w.workspace_id = c.workspace_id AND w.id = ?
			WHERE c.workspace_id = ? AND c.status = 'active'
			  AND (w.estate_scope_id IS NULL OR c.estate_scope_id = w.estate_scope_id)
			  AND (
			    c.capability_digest <> ''
			    OR EXISTS (
			      SELECT 1 FROM collector_capability_reports r
			      WHERE r.workspace_id = c.workspace_id AND r.collector_id = c.id AND r.capability_digest <> ''
			    )
			  )
			ORDER BY c.id
			LIMIT 1`, wid, ws).Scan(&rows).Error
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 || rows[0].Digest == "" {
			return nil, statusErr(http.StatusUnprocessableEntity, "no_collector", "No active collector can deliver this policy.")
		}
		cid, err := uuid.Parse(rows[0].ID)
		if err != nil {
			return nil, err
		}
		var inst *uuid.UUID
		if entry.RuntimeInstanceID != "" {
			id, err := uuid.Parse(entry.RuntimeInstanceID)
			if err != nil {
				return nil, statusErr(http.StatusUnprocessableEntity, "unresolved_target", "A runtime instance is not a uuid.")
			}
			inst = &id
		}
		out = append(out, publicationTarget{
			WorkloadID: wid, RuntimeInstanceID: inst, CollectorID: cid, Digest: rows[0].Digest,
		})
	}
	return out, nil
}

func loadPrecedence(tx *gorm.DB, ws uuid.UUID, workloadID string, doc compile.Document, now time.Time) ([]precedence.Fact, error) {
	var facts []precedence.Fact
	var quarantined []struct{ N int }
	if err := tx.Raw(`SELECT 1 AS n FROM discovered_agent_workloads w
		JOIN discovered_agents a ON a.workspace_id = w.workspace_id AND a.id = w.discovered_agent_id
		WHERE w.workspace_id = ? AND w.workload_id = ? AND w.link_state = 'accepted' AND a.status = 'quarantined'
		LIMIT 1`, ws, workloadID).Scan(&quarantined).Error; err != nil {
		return nil, err
	}
	if len(quarantined) == 1 {
		facts = append(facts, precedence.Fact{Source: precedence.SourceQuarantine, Effect: "deny", Emergency: true})
	}
	var guard []struct{ N int }
	if err := tx.Raw(`SELECT 1 AS n FROM agent_policies p
		JOIN discovered_agent_workloads w
		  ON w.workspace_id = p.workspace_id AND w.discovered_agent_id = p.discovered_agent_id
		WHERE p.workspace_id = ? AND w.workload_id = ? AND p.enabled AND p.desired_state = 'quarantined'
		  AND w.link_state = 'accepted'
		LIMIT 1`, ws, workloadID).Scan(&guard).Error; err != nil {
		return nil, err
	}
	if len(guard) == 1 {
		facts = append(facts, precedence.Fact{Source: precedence.SourceGuardrail, Effect: "deny"})
	}
	var agents []string
	if err := tx.Raw(`SELECT discovered_agent_id::text FROM discovered_agent_workloads
		WHERE workspace_id = ? AND workload_id = ? AND link_state = 'accepted'`, ws, workloadID).Scan(&agents).Error; err != nil {
		return nil, err
	}
	if len(agents) > 0 {
		var plans []string
		if err := tx.Raw(`SELECT p.plan::text FROM enforcement_plans p
			JOIN (
				SELECT discovery_source_id, MAX(version) AS version
				FROM enforcement_plans WHERE workspace_id = ? GROUP BY discovery_source_id
			) latest ON latest.discovery_source_id = p.discovery_source_id AND latest.version = p.version
			WHERE p.workspace_id = ?`, ws, ws).Scan(&plans).Error; err != nil {
			return nil, err
		}
		agentSet := map[string]bool{}
		for _, id := range agents {
			agentSet[id] = true
		}
		for _, raw := range plans {
			var plan models.EnforcementPlanDoc
			if json.Unmarshal([]byte(raw), &plan) != nil {
				continue
			}
			for _, entry := range plan.Deny {
				if agentSet[entry.DecisionID] {
					facts = append(facts, precedence.Fact{Source: precedence.SourceEnforcementPlan, Effect: "deny"})
					break
				}
			}
		}
	}
	var exp *time.Time
	var approvals []struct {
		Expires *time.Time
	}
	if err := tx.Raw(`SELECT expires_at AS expires FROM runtime_policy_approvals
		WHERE workspace_id = ? AND revision_hash = ? AND invalidated_at IS NULL
		ORDER BY created_at DESC LIMIT 1`, ws, mustHash(doc)).Scan(&approvals).Error; err != nil {
		return nil, err
	}
	if len(approvals) == 1 {
		exp = approvals[0].Expires
	}
	unexpired := len(approvals) == 1 && (exp == nil || exp.After(now))
	for _, rule := range doc.Rules {
		switch rule.Effect {
		case "deny":
			facts = append(facts, precedence.Fact{Source: precedence.SourceRuntimeDeny, Effect: "deny"})
		case "allow":
			if unexpired {
				facts = append(facts, precedence.Fact{Source: precedence.SourceException, Effect: "allow", ExpiresAt: exp})
			} else {
				facts = append(facts, precedence.Fact{Source: precedence.SourceRuntimeAllow, Effect: "allow"})
			}
		}
	}
	return facts, nil
}

func mustHash(doc compile.Document) string {
	_, hash, err := compile.Canonical(doc)
	if err != nil {
		return ""
	}
	return hash
}
