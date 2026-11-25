package services

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// Agent instances (SPEC-secops-backend-upgrade.md W7, P12; migration 178).
//
// An instance is one running version of an agent: its workload and artifact
// (Lambda CodeSha256, a container image digest or reference, an AgentCore
// runtime version), model and version, environment, deployer and what
// spawned it. Projection writes them: the AWS agents mirror (inference) for
// every AWS workload the graph calls an agent, from the attributes the
// workload scan collected; a Kubernetes or Azure sighting where its metadata
// carries an image digest (RecordSightingInstance).
//
// Deployers: the agent's first instance records its deployer. A later NEW
// instance from a deployer outside the recorded set opens an
// unknown_deployer hygiene finding and writes agent.instance_unknown_deployer
// and agent.ask_needed (TODO(W4): an ask; TODO(F8): an agent_alert once the
// alert pipeline takes non-CloudTrail detections) until a person records the
// deployer (RecordDeployer).

// AgentInstanceObservation is one observed instance.
type AgentInstanceObservation struct {
	SourceTable      string
	SourceID         string
	NativeWorkloadID string
	RuntimeKind      string
	Stage            string
	ArtifactDigest   string
	ArtifactVersion  string
	Model            string
	ModelVersion     string
	Environment      string
	Deployer         string
	SpawnedBy        string
	CloudIdentityID  *uuid.UUID
	ObservedAt       time.Time
}

// AgentInstanceOutcome says what RecordAgentInstance did.
type AgentInstanceOutcome struct {
	AgentID         *uuid.UUID
	Created         bool
	UnknownDeployer bool
}

func clipText(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// RecordAgentInstance upserts one instance of the agent the observation's
// source row is an alias of (nothing when it is none), in tx (a transaction
// under row-level security for ws).
func RecordAgentInstance(tx *gorm.DB, ws uuid.UUID, obs AgentInstanceObservation) (AgentInstanceOutcome, error) {
	var out AgentInstanceOutcome
	if !agentIdentityReady(tx) {
		return out, nil
	}
	aid, err := agentIDForSource(tx, ws, obs.SourceTable, obs.SourceID)
	if err != nil || aid == nil {
		return out, err
	}
	out.AgentID = aid
	if obs.ObservedAt.IsZero() {
		obs.ObservedAt = time.Now()
	}
	stage := obs.Stage
	if stage != "production" && stage != "non_production" {
		stage = "unknown"
	}
	var rows []struct{ Inserted bool }
	if err := tx.Raw(`INSERT INTO iga_agent_instances (workspace_id, agent_ref, source_table, source_id, native_workload_id, runtime_kind,
	          stage, artifact_digest, artifact_version, model, model_version, environment, deployer, spawned_by, cloud_identity_id,
	          first_seen_at, last_seen_at)
	        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	        ON CONFLICT (workspace_id, agent_ref, native_workload_id, artifact_digest) WHERE agent_ref IS NOT NULL
	        DO UPDATE SET last_seen_at = GREATEST(iga_agent_instances.last_seen_at, EXCLUDED.last_seen_at),
	                      artifact_version = EXCLUDED.artifact_version, model = EXCLUDED.model,
	                      model_version = EXCLUDED.model_version, environment = EXCLUDED.environment,
	                      cloud_identity_id = COALESCE(EXCLUDED.cloud_identity_id, iga_agent_instances.cloud_identity_id),
	                      lifecycle = 'active'
	        RETURNING (xmax = 0) AS inserted`,
		ws, *aid, obs.SourceTable, obs.SourceID, clipText(obs.NativeWorkloadID, 2048), clipText(obs.RuntimeKind, 100), stage,
		clipText(obs.ArtifactDigest, 2048), clipText(obs.ArtifactVersion, 200), clipText(obs.Model, 300), clipText(obs.ModelVersion, 200),
		clipText(obs.Environment, 100), clipText(obs.Deployer, 2048), clipText(obs.SpawnedBy, 2048), obs.CloudIdentityID,
		obs.ObservedAt, obs.ObservedAt).Scan(&rows).Error; err != nil {
		return out, err
	}
	if len(rows) == 0 || !rows[0].Inserted {
		return out, nil
	}
	out.Created = true
	payload := map[string]any{"agent_id": *aid, "native_workload_id": obs.NativeWorkloadID,
		"artifact_digest": obs.ArtifactDigest, "artifact_version": obs.ArtifactVersion, "deployer": obs.Deployer}
	if err := appendGovEvent(tx, ws, GovEventAgentInstanceNew, models.GovActorSystem, "", govEventRefs{}, payload); err != nil {
		return out, err
	}
	dep := clipText(obs.Deployer, 2048)
	if dep == "" {
		return out, nil
	}
	var known []string
	if err := tx.Raw(`SELECT deployer FROM agent_deployer WHERE workspace_id = ? AND agent_id = ?`, ws, *aid).Scan(&known).Error; err != nil {
		return out, err
	}
	if len(known) == 0 {
		return out, tx.Exec(`INSERT INTO agent_deployer (workspace_id, agent_id, deployer, recorded_by) VALUES (?, ?, ?, 'first_instance')
		        ON CONFLICT (workspace_id, agent_id, deployer) DO NOTHING`, ws, *aid, dep).Error
	}
	for _, k := range known {
		if k == dep {
			return out, nil
		}
	}
	out.UnknownDeployer = true
	subj, _ := json.Marshal(map[string]any{"agent_id": *aid, "deployer": dep, "known_deployers": known})
	ev, _ := json.Marshal(payload)
	if err := tx.Exec(`INSERT INTO agent_hygiene_finding (workspace_id, kind, subject_key, agent_id, subject, evidence)
	        VALUES (?, 'unknown_deployer', ?, ?, ?::jsonb, ?::jsonb)
	        ON CONFLICT (workspace_id, kind, subject_key) DO UPDATE SET state = 'open', resolved_at = NULL,
	          last_seen = now(), evidence = EXCLUDED.evidence`,
		ws, aid.String()+"|"+dep, *aid, string(subj), string(ev)).Error; err != nil {
		return out, err
	}
	if err := appendGovEvent(tx, ws, GovEventAgentUnknownDeployer, models.GovActorSystem, "", govEventRefs{}, payload); err != nil {
		return out, err
	}
	return out, appendGovEvent(tx, ws, GovEventAgentAskNeeded, models.GovActorSystem, "", govEventRefs{},
		map[string]any{"agent_id": *aid, "reason": AskReasonUnknownDeployer, "subject": map[string]any{"deployer": dep}})
}

// awsAgentInstance is the instance an AWS agent workload's scan attributes
// describe.
func awsAgentInstance(w *arWorkload, now time.Time) AgentInstanceObservation {
	var attrs models.AWSWorkloadAttrs
	_ = json.Unmarshal(w.Attrs, &attrs)
	obs := AgentInstanceObservation{
		SourceTable: "iga_workload", NativeWorkloadID: w.NativeID, RuntimeKind: w.RuntimeKind,
		ArtifactDigest: attrs.ArtifactDigest, ArtifactVersion: attrs.ArtifactVersion,
		Model: attrs.FoundationModel, Deployer: attrs.Deployer, Environment: w.Region,
		CloudIdentityID: w.IdentityID, ObservedAt: now,
	}
	if w.GraphID != nil {
		obs.SourceID = w.GraphID.String()
	}
	return obs
}

// recordAWSAgentInstances links the connector's agents to agent ids and
// writes their instances, in the inference transaction (mirrorAWSAgents).
func recordAWSAgentInstances(tx *gorm.DB, ws uuid.UUID, wls []*arWorkload, now time.Time) error {
	if !agentIdentityReady(tx) {
		return nil
	}
	if _, err := LinkAgentSources(tx, ws, "", ""); err != nil {
		return err
	}
	for _, w := range wls {
		if w.GraphID == nil || !w.isAgent() {
			continue
		}
		if _, err := RecordAgentInstance(tx, ws, awsAgentInstance(w, now)); err != nil {
			return err
		}
	}
	return nil
}

// sightingInstance is the instance a sighting's metadata describes, when it
// names an artifact (image_digest, image, artifact_digest) -- the Kubernetes
// connector and Azure sightings where available. ok is false otherwise.
func sightingInstance(a *models.DiscoveredAgent) (AgentInstanceObservation, bool) {
	var md map[string]any
	if len(a.Metadata) == 0 || json.Unmarshal(a.Metadata, &md) != nil {
		return AgentInstanceObservation{}, false
	}
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := md[k].(string); ok && strings.TrimSpace(v) != "" {
				return v
			}
		}
		return ""
	}
	digest := str("image_digest", "artifact_digest", "image")
	if digest == "" {
		return AgentInstanceObservation{}, false
	}
	return AgentInstanceObservation{
		SourceTable: "discovered_agents", SourceID: a.ID.String(),
		NativeWorkloadID: a.Fingerprint, RuntimeKind: a.Source,
		ArtifactDigest: digest, ArtifactVersion: str("version", "artifact_version"),
		Model: str("model"), ModelVersion: str("model_version"), Environment: str("environment", "namespace", "region"),
		Deployer: str("deployer", "created_by_user"), SpawnedBy: str("spawned_by", "owner_kind"),
		ObservedAt: time.Now(),
	}, true
}

// RecordSightingInstance links a sighting to its agent and writes the
// instance its metadata describes. Best-effort hook for the discovery path.
func RecordSightingInstance(ctx context.Context, db *gorm.DB, a *models.DiscoveredAgent) error {
	if db == nil || a == nil {
		return nil
	}
	return tenancy.InWorkspace(ctx, db, a.WorkspaceID, func(tx *gorm.DB) error {
		if _, err := LinkAgentSources(tx, a.WorkspaceID, "discovered_agents", a.ID.String()); err != nil {
			return err
		}
		obs, ok := sightingInstance(a)
		if !ok {
			return nil
		}
		_, err := RecordAgentInstance(tx, a.WorkspaceID, obs)
		return err
	})
}

// RecordDeployer records a deployer for an agent (a person's decision) and
// resolves the agent's unknown_deployer finding for it.
func (s *AgentIdentityService) RecordDeployer(ctx context.Context, ws, id, actor uuid.UUID, deployer string) ([]string, error) {
	deployer = strings.TrimSpace(deployer)
	if deployer == "" || len(deployer) > 2048 {
		return nil, GovBadParam("deployer", "deployer is required (at most 2048 characters).")
	}
	var out []string
	err := s.inWS(ctx, ws, func(tx *gorm.DB) error {
		if _, err := loadAgent(tx, ws, id, true); err != nil {
			return err
		}
		if err := tx.Exec(`INSERT INTO agent_deployer (workspace_id, agent_id, deployer, recorded_by) VALUES (?, ?, ?, ?)
		        ON CONFLICT (workspace_id, agent_id, deployer) DO NOTHING`, ws, id, deployer, actor.String()).Error; err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE agent_hygiene_finding SET state = 'resolved', resolved_at = now()
		        WHERE workspace_id = ? AND kind = 'unknown_deployer' AND subject_key = ? AND state = 'open'`,
			ws, id.String()+"|"+deployer).Error; err != nil {
			return err
		}
		if err := appendGovEvent(tx, ws, GovEventAgentDeployerAdded, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"agent_id": id, "deployer": deployer}); err != nil {
			return err
		}
		return tx.Raw(`SELECT deployer FROM agent_deployer WHERE workspace_id = ? AND agent_id = ? ORDER BY deployer`, ws, id).Scan(&out).Error
	})
	return out, err
}
