package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/runtimepolicy/candidates"
	"github.com/authsec-ai/authsec/internal/runtimepolicy/compile"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RunRuntimePolicyDiscovery projects every sighting that carries activity into
// a draft runtime policy, then repeats. A sighting with no activity is skipped.
// An administrator's edit of a draft is left in place.
func RunRuntimePolicyDiscovery(ctx context.Context, db *gorm.DB, every time.Duration) {
	if db == nil || !V2PolicyEnabled() {
		return
	}
	if every <= 0 {
		every = time.Minute
	}
	svc := NewRuntimePolicyService(db)
	svc.SetIGAAudit(NewIGAAuditService(db))
	run := func() {
		if err := svc.DiscoverAll(ctx); err != nil {
			log.Printf("[runtime-policy] discovery: %v", err)
		}
	}
	run()
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

// DiscoverAll builds or refreshes one draft for every discovered agent that
// has published activity.
func (s *RuntimePolicyService) DiscoverAll(ctx context.Context) error {
	if s == nil || s.db == nil || !V2PolicyEnabled() {
		return nil
	}
	var rows []struct {
		ID                uuid.UUID
		WorkspaceID       uuid.UUID
		Source            string
		DiscoverySourceID *uuid.UUID
		Fingerprint       string
		DisplayName       string
		Metadata          string
	}
	err := s.db.WithContext(ctx).Raw(`SELECT id, workspace_id, source, discovery_source_id, fingerprint,
		display_name, metadata::text AS metadata
		FROM discovered_agents
		WHERE jsonb_typeof(metadata->'activity') = 'array'
		  AND jsonb_array_length(metadata->'activity') > 0`).Scan(&rows).Error
	if err != nil {
		return err
	}
	for _, row := range rows {
		agent := models.DiscoveredAgent{
			ID: row.ID, WorkspaceID: row.WorkspaceID, Source: row.Source,
			DiscoverySourceID: row.DiscoverySourceID, Fingerprint: row.Fingerprint,
			DisplayName: row.DisplayName, Metadata: json.RawMessage(row.Metadata),
		}
		if err := s.DiscoverFromAgent(ctx, &agent); err != nil {
			log.Printf("[runtime-policy] discovery for %s: %v", agent.ID, err)
		}
	}
	return nil
}

// DiscoverFromAgent projects one agent's activity and upserts its draft.
// It does not overwrite a draft an administrator has edited.
func (s *RuntimePolicyService) DiscoverFromAgent(ctx context.Context, agent *models.DiscoveredAgent) error {
	if s == nil || s.db == nil || agent == nil || !V2PolicyEnabled() {
		return nil
	}
	facts := parseActivityFacts(agent.Metadata)
	if len(facts) == 0 {
		return nil
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext(?)::bigint)`,
			agent.WorkspaceID.String()+":"+agent.ID.String()).Error; err != nil {
			return err
		}
		workloadID, err := projectActivity(tx, agent, facts)
		if err != nil || workloadID == uuid.Nil {
			return err
		}
		end := time.Now().UTC().Add(time.Minute)
		start := end.Add(-candidates.BaselineWindow)
		in, err := loadCandidateInput(tx, agent.WorkspaceID, []string{workloadID.String()}, 0, start, end)
		if err != nil {
			return err
		}
		gen, err := candidates.Generate(in)
		if err != nil {
			return err
		}
		doc := assembleObservedDocument(gen, workloadID.String(), observedPolicyName(agent.ID))
		if len(doc.Rules) == 0 {
			return nil
		}
		existing, err := findObservedPolicy(tx, agent.WorkspaceID, workloadID)
		if err != nil {
			return err
		}
		if existing != nil {
			doc.Name = existing.Name
		}
		canonical, hash, err := compile.Canonical(doc)
		if err != nil {
			return err
		}
		sys := Actor{
			UserID: models.RuntimePolicyCandidateSystemUserID, WorkspaceID: agent.WorkspaceID,
			Kind: models.RuntimePolicyActorCandidateSystem,
		}
		if existing != nil {
			if existing.Hash == hash {
				return nil
			}
			if existing.Owner != sys.UserID || existing.Author != sys.UserID || existing.State != models.RuntimePolicyStateDraft || existing.Lifecycle != models.RuntimePolicyStateDraft {
				return nil
			}
			revision := existing.Revision + 1
			if err := insertRevision(tx, sys, existing.ID, revision, canonical, hash, 0, models.RuntimePolicyStateDraft, nil); err != nil {
				return err
			}
			if err := tx.Exec(`UPDATE runtime_policies SET current_draft_revision = ?, lifecycle = 'draft', updated_at = now()
				WHERE workspace_id = ? AND id = ?`, revision, agent.WorkspaceID, existing.ID).Error; err != nil {
				return err
			}
			if err := writeAudit(tx, sys, &existing.ID, "candidate", "", hash, doc.Targets.WorkloadIDs,
				map[string]any{"revision": existing.Revision}, map[string]any{"revision": revision, "state": "draft"}); err != nil {
				return err
			}
			s.recordIGAPolicyAudit(tx, sys, &existing.ID, IGAAuditEventPolicyEdit, revision, hash, "candidate_revised", "", map[string]any{
				"input_hash": gen.InputHash, "partial": gen.Partial,
			})
			log.Printf("[runtime-policy] revised draft %s to v%d (%s)", existing.Name, revision, agent.DisplayName)
			return nil
		}
		policyID := uuid.New()
		if err := tx.Exec(`INSERT INTO runtime_policies
			(id, workspace_id, name, owner_user_id, current_draft_revision, lifecycle)
			VALUES (?, ?, ?, ?, 1, 'draft')`,
			policyID, agent.WorkspaceID, doc.Name, sys.UserID).Error; err != nil {
			return err
		}
		if err := insertRevision(tx, sys, policyID, 1, canonical, hash, 0, models.RuntimePolicyStateDraft, nil); err != nil {
			return err
		}
		if err := writeAudit(tx, sys, &policyID, "candidate", "", hash, doc.Targets.WorkloadIDs,
			map[string]any{}, map[string]any{"revision": 1, "state": "draft"}); err != nil {
			return err
		}
		s.recordIGAPolicyAudit(tx, sys, &policyID, IGAAuditEventPolicyCreation, 1, hash, "candidate_created", "", map[string]any{
			"input_hash": gen.InputHash, "partial": gen.Partial,
		})
		log.Printf("[runtime-policy] created draft %s for %s", doc.Name, agent.DisplayName)
		return nil
	})
}

type observedPolicy struct {
	ID        uuid.UUID
	Name      string
	Owner     uuid.UUID
	Lifecycle string
	Revision  int
	State     string
	Hash      string
	Author    uuid.UUID
}

func findObservedPolicy(tx *gorm.DB, ws, workload uuid.UUID) (*observedPolicy, error) {
	var rows []observedPolicy
	err := tx.Raw(`SELECT p.id, p.name, p.owner_user_id AS owner, p.lifecycle,
		r.revision, r.state, r.content_hash AS hash, r.author_user_id AS author
		FROM runtime_policies p
		JOIN runtime_policy_revisions r
		  ON r.workspace_id = p.workspace_id AND r.policy_id = p.id AND r.revision = p.current_draft_revision
		WHERE p.workspace_id = ?
		  AND r.document->'targets'->'workload_ids' @> jsonb_build_array(?::text)
		ORDER BY (p.owner_user_id = ?::uuid) DESC, p.updated_at DESC
		LIMIT 1`, ws, workload.String(), models.RuntimePolicyCandidateSystemUserID).Scan(&rows).Error
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}

func observedPolicyName(agentID uuid.UUID) string {
	compact := strings.ReplaceAll(agentID.String(), "-", "")
	if len(compact) > 20 {
		compact = compact[:20]
	}
	return "observed-" + compact
}

// assembleObservedDocument is the candidate allow set plus one editable deny
// rule for each review item and each denied call. Review and denied calls are
// not allows. Putting them on the document is what makes them visible.
func assembleObservedDocument(gen candidates.Result, workloadID, name string) compile.Document {
	doc := candidateDocument(gen, []string{workloadID}, "linux-managed-v1", 0)
	doc.Name = name
	seen := map[string]bool{}
	for _, rule := range doc.Rules {
		seen[rule.Effect+"\x00"+rule.Action+"\x00"+rule.ResourceID+"\x00"+rule.Path] = true
	}
	add := func(prefix string, rec candidates.Record) {
		if rec.Action == "" {
			return
		}
		rule := compile.Rule{
			ID:     observedRuleID(prefix, rec.Action, rec.ResourceID, rec.Path),
			Action: rec.Action, ResourceID: rec.ResourceID, Path: rec.Path, Effect: "deny",
		}
		key := rule.Effect + "\x00" + rule.Action + "\x00" + rule.ResourceID + "\x00" + rule.Path
		if seen[key] {
			return
		}
		seen[key] = true
		doc.Rules = append(doc.Rules, rule)
	}
	for _, rec := range gen.Review {
		add("review", rec)
	}
	for _, rec := range gen.Denied {
		add("denied", rec)
	}
	doc.RequiredControls = controlsForRules(doc.Rules)
	return doc
}

func controlsForRules(rules []compile.Rule) []string {
	controls := map[string]bool{}
	for _, rule := range rules {
		for _, c := range controlsForAction(rule.Action) {
			controls[c] = true
		}
	}
	need := make([]string, 0, len(controls))
	for c := range controls {
		need = append(need, c)
	}
	sort.Strings(need)
	return need
}

func observedRuleID(prefix, action, resource, path string) string {
	sum := sha256.Sum256([]byte(prefix + "\x00" + action + "\x00" + resource + "\x00" + path))
	return prefix + "-" + hex.EncodeToString(sum[:])[:12]
}

type activityFact struct {
	Service       string
	AccessAction  string
	AccessOutcome string
	Path          string
	Address       string
	Port          int
	Protocol      string
	Internet      bool
	SourceKey     string
	ResourceKind  string
	NativeKind    string
	DisplayName   string
	ObservedAt    time.Time
	Raw           map[string]string
}

func parseActivityFacts(metadata json.RawMessage) []activityFact {
	var envelope struct {
		Activity []map[string]any `json:"activity"`
	}
	if len(metadata) == 0 || json.Unmarshal(metadata, &envelope) != nil {
		return nil
	}
	out := make([]activityFact, 0, len(envelope.Activity))
	for _, row := range envelope.Activity {
		kind, _ := row["kind"].(string)
		service, _ := row["service"].(string)
		action, _ := row["action"].(string)
		target, _ := row["target"].(string)
		detail, _ := row["detail"].(string)
		outcome, _ := row["outcome"].(string)
		var accessAction, accessOutcome, path, address string
		internet, ok := classifyActivity(kind, action, target, detail, outcome, &accessAction, &accessOutcome, &path, &address)
		if !ok {
			continue
		}
		at := time.Now().UTC()
		if raw, _ := row["observed_at"].(string); raw != "" {
			if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
				at = parsed.UTC()
			}
		}
		if at.IsZero() || time.Since(at) > candidates.BaselineWindow || at.After(time.Now().Add(time.Minute)) {
			at = time.Now().UTC()
		}
		sourceKey := "file:" + path
		resourceKind, nativeKind := "linux.file", "linux.file"
		port := 0
		protocol := ""
		if accessAction == "network.connect" {
			sourceKey = "network:" + address + path
			resourceKind, nativeKind = "network.endpoint", "network.http"
			port, protocol = 443, "tcp"
		} else if accessAction == "exec" {
			sourceKey = "exec:" + path
		}
		display := path
		if address != "" {
			switch service {
			case "grok":
				display = "Grok API " + address
			case "github":
				display = "GitHub API " + address
			case "x":
				display = "X API " + address
			default:
				display = address + path
			}
		}
		out = append(out, activityFact{
			Service: service, AccessAction: accessAction, AccessOutcome: accessOutcome,
			Path: path, Address: address, Port: port, Protocol: protocol, Internet: internet, SourceKey: sourceKey,
			ResourceKind: resourceKind, NativeKind: nativeKind, DisplayName: display,
			ObservedAt: at,
			Raw: map[string]string{
				"kind": kind, "service": service, "action": action,
				"target": target, "detail": detail, "outcome": outcome,
			},
		})
	}
	return out
}

func classifyActivity(kind, action, target, detail, outcome string, accessAction, accessOutcome, path, address *string) (internet, ok bool) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	action = strings.ToLower(strings.TrimSpace(action))
	target = strings.TrimSpace(target)
	detail = strings.TrimSpace(detail)
	outcome = strings.ToLower(strings.TrimSpace(outcome))
	if target == "" || outcome == "" {
		return false, false
	}
	switch {
	case kind == "network" || action == "get" || action == "connect" || action == "network.connect" || action == "network_connect":
		*accessAction = "network.connect"
		*address = target
		*path = detail
		internet = true
	case action == "read" || action == "file.read" || action == "open":
		*accessAction = "file.read"
		*path = target
	case action == "write" || action == "file.write":
		*accessAction = "file.write"
		*path = target
	case action == "exec":
		*accessAction = "exec"
		*path = target
	default:
		return false, false
	}
	switch {
	case outcome == "ok" || outcome == "success":
		*accessOutcome = "success"
	case outcome == "denied" || outcome == "attempted":
		*accessOutcome = outcome
	case len(outcome) == 3 && outcome[0] == '2' && isDigits(outcome):
		*accessOutcome = "success"
	case len(outcome) == 3 && (outcome[0] == '4' || outcome[0] == '5') && isDigits(outcome):
		*accessOutcome = "denied"
	default:
		*accessOutcome = "attempted"
	}
	return internet, true
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func projectActivity(tx *gorm.DB, agent *models.DiscoveredAgent, facts []activityFact) (uuid.UUID, error) {
	integrationID, err := ensureActivityIntegration(tx, agent.WorkspaceID)
	if err != nil {
		return uuid.Nil, err
	}
	workloadID, err := ensureActivityWorkload(tx, agent)
	if err != nil {
		return uuid.Nil, err
	}
	runtimeID, err := ensureActivityRuntime(tx, agent, workloadID, facts)
	if err != nil {
		return uuid.Nil, err
	}
	scanID := stableUUID("scan:" + agent.ID.String())
	sourceID := stableUUID("source:" + agent.ID.String())
	if err := ensureActivityProvenance(tx, agent, integrationID, scanID, sourceID, facts); err != nil {
		return uuid.Nil, err
	}
	resources := map[string]uuid.UUID{}
	for _, fact := range facts {
		if _, ok := resources[fact.SourceKey]; ok {
			continue
		}
		id, err := ensureActivityResource(tx, agent.WorkspaceID, fact)
		if err != nil {
			return uuid.Nil, err
		}
		resources[fact.SourceKey] = id
	}
	for _, fact := range facts {
		if err := ensureActivityObservation(tx, agent, sourceID, scanID, runtimeID, workloadID, resources[fact.SourceKey], fact); err != nil {
			return uuid.Nil, err
		}
	}
	return workloadID, nil
}

func ensureActivityIntegration(tx *gorm.DB, ws uuid.UUID) (uuid.UUID, error) {
	id, ok, err := scanOneID(tx, `SELECT id FROM iga_integrations
		WHERE workspace_id = ? AND status = 'active'
		ORDER BY created_at LIMIT 1`, ws)
	if err != nil {
		return uuid.Nil, err
	}
	if ok {
		return id, nil
	}
	id = stableUUID("integration:" + ws.String())
	err = tx.Exec(`INSERT INTO iga_integrations
		(id, workspace_id, provider, provider_host, app_registration_id, installation_id, status, created_by)
		SELECT ?, ?, 'kubernetes', 'local', 'runtime-policy-discovery', 'local', 'active', 'runtime-policy-discovery'
		WHERE NOT EXISTS (
			SELECT 1 FROM iga_integrations WHERE workspace_id = ? AND id = ?
		)`, id, ws, ws, id).Error
	return id, err
}

func activityProvider(source string) (provider, runtimeKind string) {
	switch source {
	case "github", "linux", "kubernetes", "ad":
		return source, source
	default:
		return "kubernetes", "k8s.deployment"
	}
}

func ensureActivityWorkload(tx *gorm.DB, agent *models.DiscoveredAgent) (uuid.UUID, error) {
	sourceKey := "discovered-agent:" + agent.ID.String()
	id, ok, err := scanOneID(tx, `SELECT id FROM iga_workload
		WHERE workspace_id = ? AND source_key = ? AND lifecycle <> 'retired'`,
		agent.WorkspaceID, sourceKey)
	if err != nil {
		return uuid.Nil, err
	}
	if ok {
		if err := tx.Exec(`UPDATE iga_workload SET last_seen_at = now(), updated_at = now()
			WHERE workspace_id = ? AND id = ?`, agent.WorkspaceID, id).Error; err != nil {
			return uuid.Nil, err
		}
		return id, nil
	}
	id, ok, err = scanOneID(tx, `SELECT id FROM iga_workload
		WHERE workspace_id = ? AND display_name = ? AND lifecycle = 'active'
		  AND source_key NOT LIKE 'discovered-agent:%'
		ORDER BY first_seen_at LIMIT 1`, agent.WorkspaceID, agent.DisplayName)
	if err != nil {
		return uuid.Nil, err
	}
	provider, runtimeKind := activityProvider(agent.Source)
	if ok {
		if err := tx.Exec(`UPDATE iga_workload
			SET source_key = ?, provider = ?, runtime_kind = ?, last_seen_at = now(), updated_at = now()
			WHERE workspace_id = ? AND id = ?`,
			sourceKey, provider, runtimeKind, agent.WorkspaceID, id).Error; err != nil {
			return uuid.Nil, err
		}
		return id, nil
	}
	id = stableUUID("workload:" + agent.ID.String())
	err = tx.Exec(`INSERT INTO iga_workload
		(id, workspace_id, provider, runtime_kind, display_name, stage, lifecycle, source_key,
		 continuity, execution_role_state, classification, first_seen_at, last_seen_at)
		SELECT ?, ?, ?, ?, ?, 'non_production', 'active', ?, 'recognition_only', 'none', 'classified_agent', now(), now()
		WHERE NOT EXISTS (
			SELECT 1 FROM iga_workload WHERE workspace_id = ? AND source_key = ? AND lifecycle <> 'retired'
		)`, id, agent.WorkspaceID, provider, runtimeKind, agent.DisplayName, sourceKey, agent.WorkspaceID, sourceKey).Error
	if err != nil {
		return uuid.Nil, err
	}
	id, ok, err = scanOneID(tx, `SELECT id FROM iga_workload
		WHERE workspace_id = ? AND source_key = ? AND lifecycle <> 'retired'`,
		agent.WorkspaceID, sourceKey)
	if err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("workload %s was not stored", sourceKey)
		}
		return uuid.Nil, err
	}
	return id, nil
}

func ensureActivityRuntime(tx *gorm.DB, agent *models.DiscoveredAgent, workloadID uuid.UUID, facts []activityFact) (uuid.UUID, error) {
	id, ok, err := scanOneID(tx, `SELECT id FROM iga_runtime_instances
		WHERE workspace_id = ? AND workload_id = ? ORDER BY last_observed_at DESC LIMIT 1`,
		agent.WorkspaceID, workloadID)
	if err != nil {
		return uuid.Nil, err
	}
	observed := time.Now().UTC()
	if len(facts) > 0 {
		observed = facts[0].ObservedAt
	}
	if ok {
		if err := tx.Exec(`UPDATE iga_runtime_instances SET last_observed_at = ?
			WHERE workspace_id = ? AND id = ?`, observed, agent.WorkspaceID, id).Error; err != nil {
			return uuid.Nil, err
		}
		return id, nil
	}
	id = stableUUID("runtime:" + agent.ID.String())
	runtimeKey := "discovered-agent:" + agent.ID.String() + ":runtime"
	_, kind := activityProvider(agent.Source)
	if agent.Source == "" || agent.Source == "k8s_webhook" {
		kind = "k8s.pod"
	}
	attrs, _ := json.Marshal(map[string]string{"exe": agent.DisplayName, "env": kind})
	err = tx.Exec(`INSERT INTO iga_runtime_instances
		(id, workspace_id, workload_id, runtime_key, runtime_kind, last_observed_at, native_attributes)
		SELECT ?, ?, ?, ?, ?, ?, CAST(? AS jsonb)
		WHERE NOT EXISTS (
			SELECT 1 FROM iga_runtime_instances WHERE workspace_id = ? AND runtime_key = ?
		)`, id, agent.WorkspaceID, workloadID, runtimeKey, kind, observed, string(attrs), agent.WorkspaceID, runtimeKey).Error
	if err != nil {
		return uuid.Nil, err
	}
	id, ok, err = scanOneID(tx, `SELECT id FROM iga_runtime_instances WHERE workspace_id = ? AND runtime_key = ?`,
		agent.WorkspaceID, runtimeKey)
	if err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("runtime %s was not stored", runtimeKey)
		}
		return uuid.Nil, err
	}
	return id, nil
}

func ensureActivityProvenance(tx *gorm.DB, agent *models.DiscoveredAgent, integrationID, scanID, sourceID uuid.UUID, facts []activityFact) error {
	var n int64
	if err := tx.Raw(`SELECT count(*) FROM iga_scan_runs WHERE workspace_id = ? AND id = ?`,
		agent.WorkspaceID, scanID).Scan(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		if err := tx.Exec(`INSERT INTO iga_scan_runs
			(id, workspace_id, integration_id, mode, generation, status, requested_by, normalizer_version,
			 started_at, completed_at, is_authoritative)
			SELECT ?, ?, ?, 'runtime_batch',
				COALESCE((SELECT MAX(generation) FROM iga_scan_runs WHERE workspace_id = ? AND integration_id = ?), 0) + 1,
				'succeeded', 'runtime-policy-discovery', 'runtime-policy-autodiscover-1', now(), now(), false`,
			scanID, agent.WorkspaceID, integrationID, agent.WorkspaceID, integrationID).Error; err != nil {
			return err
		}
	}
	locator, _ := json.Marshal(map[string]string{
		"source": agent.Source, "fingerprint": agent.Fingerprint, "display_name": agent.DisplayName,
	})
	return tx.Exec(`INSERT INTO iga_source_objects
		(id, workspace_id, integration_id, object_type, recognition_key, native_id, locator, lifecycle, first_seen_at, last_seen_at)
		SELECT ?, ?, ?, 'discovered_agent', ?, ?, CAST(? AS jsonb), 'active', now(), now()
		WHERE NOT EXISTS (
			SELECT 1 FROM iga_source_objects
			WHERE workspace_id = ? AND integration_id = ? AND object_type = 'discovered_agent' AND recognition_key = ?
		)`,
		sourceID, agent.WorkspaceID, integrationID, agent.ID.String(), agent.ID.String(), string(locator),
		agent.WorkspaceID, integrationID, agent.ID.String()).Error
}

func ensureActivityResource(tx *gorm.DB, ws uuid.UUID, fact activityFact) (uuid.UUID, error) {
	id, ok, err := scanOneID(tx, `SELECT id FROM iga_resources
		WHERE workspace_id = ? AND source_key = ? AND lifecycle <> 'retired'`,
		ws, fact.SourceKey)
	if err != nil {
		return uuid.Nil, err
	}
	metaFields := map[string]any{
		"path": fact.Path, "address": fact.Address, "internet": fact.Internet, "service": fact.Service,
	}
	if fact.Protocol != "" {
		metaFields["port"] = fact.Port
		metaFields["protocol"] = fact.Protocol
	}
	meta, _ := json.Marshal(metaFields)
	if ok {
		if err := tx.Exec(`UPDATE iga_resources
			SET kind_metadata = CAST(? AS jsonb), native_kind = ?, reference_status = 'observed', last_seen_at = now(), updated_at = now()
			WHERE workspace_id = ? AND id = ?`,
			string(meta), fact.NativeKind, ws, id).Error; err != nil {
			return uuid.Nil, err
		}
		return id, nil
	}
	id = stableUUID("resource:" + ws.String() + ":" + fact.SourceKey)
	err = tx.Exec(`INSERT INTO iga_resources
		(id, workspace_id, resource_kind, display_name, stage, lifecycle, provider, source_key, continuity,
		 reference_status, native_kind, kind_metadata, first_seen_at, last_seen_at)
		SELECT ?, ?, ?, ?, 'non_production', 'active', 'kubernetes', ?, 'recognition_only',
			'observed', ?, CAST(? AS jsonb), ?, ?
		WHERE NOT EXISTS (
			SELECT 1 FROM iga_resources WHERE workspace_id = ? AND source_key = ? AND lifecycle <> 'retired'
		)`,
		id, ws, fact.ResourceKind, fact.DisplayName, fact.SourceKey, fact.NativeKind, string(meta),
		fact.ObservedAt, fact.ObservedAt, ws, fact.SourceKey).Error
	if err != nil {
		return uuid.Nil, err
	}
	id, ok, err = scanOneID(tx, `SELECT id FROM iga_resources
		WHERE workspace_id = ? AND source_key = ? AND lifecycle <> 'retired'`,
		ws, fact.SourceKey)
	if err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("resource %s was not stored", fact.SourceKey)
		}
		return uuid.Nil, err
	}
	return id, nil
}

func ensureActivityObservation(tx *gorm.DB, agent *models.DiscoveredAgent, sourceID, scanID, runtimeID, workloadID, resourceID uuid.UUID, fact activityFact) error {
	dedupe := "activity:" + agent.ID.String() + ":" + fact.AccessAction + ":" + fact.SourceKey + ":" + fact.AccessOutcome
	payload, _ := json.Marshal(map[string]string{
		"kind": "agent.activity", "service": fact.Raw["service"], "raw_action": fact.Raw["action"],
		"target": fact.Raw["target"], "detail": fact.Raw["detail"], "raw_outcome": fact.Raw["outcome"],
		"action": fact.AccessAction, "outcome": fact.AccessOutcome,
	})
	obsID := stableUUID("obs:" + dedupe)
	var discoverySource any
	if agent.DiscoverySourceID != nil {
		discoverySource = *agent.DiscoverySourceID
	}
	if err := tx.Exec(`INSERT INTO iga_observations
		(id, workspace_id, source_object_id, scan_run_id, mode, fact_payload, evidence_ref, observed_at,
		 normalizer_version, dedupe_key, evidence_trust, schema_version, discovery_source_id)
		SELECT ?, ?, ?, ?, 'observed', CAST(? AS jsonb), ?, ?, 'runtime-policy-autodiscover-1', ?,
			'authenticated_collector', 'iga-activity-1', ?
		WHERE NOT EXISTS (
			SELECT 1 FROM iga_observations WHERE workspace_id = ? AND dedupe_key = ?
		)`,
		obsID, agent.WorkspaceID, sourceID, scanID, string(payload),
		"discovered_agents/"+agent.ID.String()+"/metadata.activity", fact.ObservedAt, dedupe, discoverySource,
		agent.WorkspaceID, dedupe).Error; err != nil {
		return err
	}
	if err := tx.Exec(`UPDATE iga_observations SET observed_at = ?
		WHERE workspace_id = ? AND dedupe_key = ?`, fact.ObservedAt, agent.WorkspaceID, dedupe).Error; err != nil {
		return err
	}
	obsID, ok, err := scanOneID(tx, `SELECT id FROM iga_observations WHERE workspace_id = ? AND dedupe_key = ?`,
		agent.WorkspaceID, dedupe)
	if err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("observation %s was not stored", dedupe)
		}
		return err
	}
	if err := tx.Exec(`INSERT INTO iga_observed_access
		(id, workspace_id, workload_id, runtime_instance_id, resource_id, observation_id, action, outcome, observed_at, attribution)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ''
		WHERE NOT EXISTS (
			SELECT 1 FROM iga_observed_access
			WHERE workspace_id = ? AND observation_id = ? AND action = ? AND resource_id = ?
		)`,
		stableUUID("access:"+dedupe), agent.WorkspaceID, workloadID, runtimeID, resourceID, obsID,
		fact.AccessAction, fact.AccessOutcome, fact.ObservedAt,
		agent.WorkspaceID, obsID, fact.AccessAction, resourceID).Error; err != nil {
		return err
	}
	return tx.Exec(`UPDATE iga_observed_access SET observed_at = ?, outcome = ?
		WHERE workspace_id = ? AND observation_id = ? AND action = ? AND resource_id = ?`,
		fact.ObservedAt, fact.AccessOutcome, agent.WorkspaceID, obsID, fact.AccessAction, resourceID).Error
}

func scanOneID(tx *gorm.DB, query string, args ...any) (uuid.UUID, bool, error) {
	var rows []struct {
		ID uuid.UUID `gorm:"column:id"`
	}
	if err := tx.Raw(query, args...).Scan(&rows).Error; err != nil {
		return uuid.Nil, false, err
	}
	if len(rows) == 0 || rows[0].ID == uuid.Nil {
		return uuid.Nil, false, nil
	}
	return rows[0].ID, true, nil
}

func stableUUID(seed string) uuid.UUID {
	sum := sha256.Sum256([]byte(seed))
	sum[6] = (sum[6] & 0x0f) | 0x40
	sum[8] = (sum[8] & 0x3f) | 0x80
	id, _ := uuid.FromBytes(sum[:16])
	return id
}
