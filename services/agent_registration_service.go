package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/models"
)

// agentRegistrationRoute is the stable route identity stored with an
// idempotency row. The workload id is part of the hash, not of this string,
// so two workloads cannot share a stored response.
const agentRegistrationRoute = "POST /api/iga/v1/workloads/:id/agent-registration"

// WorkloadAgentRegistration is one registration, already parsed. ActorUserID is
// the verified human. IdempotencyKey may be empty: the service reports that
// only after it has established the workload is in this workspace, so a
// cross-workspace id is 404 rather than 400.
type WorkloadAgentRegistration struct {
	WorkloadID         uuid.UUID
	ActorUserID        uuid.UUID
	IdempotencyKey     string
	RawBody            []byte
	ExpectedVersion    int64
	Purpose            string
	OwnerUserID        uuid.UUID
	AgentID            *uuid.UUID
	CreateDisplayName  *string
	ObservationID      *uuid.UUID
	CloudObservationID *uuid.UUID
}

// AgentRegistrationResult is the stored registration. A replay returns the
// JSON of this value as it was written, byte for byte after PostgreSQL's
// jsonb rendering, including created_* from the first request.
type AgentRegistrationResult struct {
	WorkloadID            uuid.UUID  `json:"workload_id"`
	AgentID               uuid.UUID  `json:"agent_id"`
	InstanceID            uuid.UUID  `json:"instance_id"`
	CreatedAgent          bool       `json:"created_agent"`
	CreatedInstance       bool       `json:"created_instance"`
	ClassificationVersion int64      `json:"classification_version"`
	Purpose               string     `json:"purpose"`
	OwnerUserID           uuid.UUID  `json:"owner_user_id"`
	ObservationID         *uuid.UUID `json:"observation_id,omitempty"`
	CloudObservationID    *uuid.UUID `json:"cloud_observation_id,omitempty"`
	LinkBasis             string     `json:"link_basis"`
}

type agentRegistrationEnvelope struct {
	Data AgentRegistrationResult `json:"data"`
}

// AgentRegistrationService registers a confirmed agent instance on a workload.
type AgentRegistrationService struct {
	db          *gorm.DB
	lockTimeout time.Duration
}

// NewAgentRegistrationService builds the registration service over db.
func NewAgentRegistrationService(db *gorm.DB) *AgentRegistrationService {
	return &AgentRegistrationService{db: db, lockTimeout: ClassificationLockTimeout}
}

type lockedRegWorkload struct {
	ID                    uuid.UUID
	ClassificationVersion int64
	Classification        string
	SourceKey             string
	RuntimeKind           string
}

type idemHit struct {
	Hash string
	Body string
}

// Register links or creates an agent instance. The workload row is locked
// before the idempotency lookup, for the same reason classification locks
// first: a lookup before the lock can miss a commit that landed while this
// request waited.
//
// Idempotency rule: the key is Idempotency-Key, scoped to the workspace.
// The hash is sha256 of the route, the workload id and the raw body. The
// same key and the same hash return the stored JSON. The same key and a
// different hash is 409 idempotency_key_reused, and that 409 is not stored.
// The row is inserted in this transaction, after the workload lock, with
// the registration itself.
func (s *AgentRegistrationService) Register(ctx context.Context, ws uuid.UUID, in WorkloadAgentRegistration) ([]byte, bool, error) {
	hash := agentRegistrationHash(in.WorkloadID, in.RawBody)
	var (
		out      []byte
		replayed bool
	)
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(fmt.Sprintf("SET LOCAL lock_timeout = %d", s.lockTimeout.Milliseconds())).Error; err != nil {
			return err
		}
		var locked []lockedRegWorkload
		if err := tx.Raw(`SELECT id, classification_version, classification, source_key, runtime_kind
			FROM iga_workload
			WHERE workspace_id = ? AND id = ?
			FOR UPDATE`, ws, in.WorkloadID).Scan(&locked).Error; err != nil {
			return err
		}
		if len(locked) == 0 {
			return igaread.NotFound()
		}
		w := locked[0]

		key := strings.TrimSpace(in.IdempotencyKey)
		if key == "" {
			return igaread.InvalidParameter("Idempotency-Key", "Idempotency-Key is required")
		}
		if len(key) > 200 {
			return igaread.InvalidParameter("Idempotency-Key", "Idempotency-Key must be at most 200 characters")
		}

		var prior []idemHit
		if err := tx.Raw(`SELECT request_hash AS hash, response_body::text AS body
			FROM iga_idempotency_keys
			WHERE workspace_id = ? AND idempotency_key = ?`, ws, key).Scan(&prior).Error; err != nil {
			return err
		}
		if len(prior) > 0 {
			if prior[0].Hash != hash {
				return idempotencyReused()
			}
			out = []byte(prior[0].Body)
			replayed = true
			return nil
		}

		if w.ClassificationVersion != in.ExpectedVersion {
			conflict, err := igaread.ClassificationConflict(tx, ws, w.ID, "", w.ClassificationVersion)
			if err != nil {
				return err
			}
			return conflict
		}
		// The vocabulary has no classified_not_agent. unclassified is the
		// not-agent state. provider_native_agent is already an agent class
		// and may be registered. The check is after expected_version so a
		// stale version is still classification_conflict. 409 is not stored
		// in the idempotency row.
		if w.Classification != models.ClassificationClassified && w.Classification != models.ClassificationProviderAgent {
			return igaread.Conflict("classification_not_agent",
				"Registration requires classified_agent or provider_native_agent. unclassified is not an agent.")
		}

		var owners int64
		if err := tx.Raw(`SELECT count(*) FROM users WHERE id = ? AND workspace_id = ?`,
			in.OwnerUserID, ws).Scan(&owners).Error; err != nil {
			return err
		}
		if owners != 1 {
			return igaread.Unprocessable("invalid_owner", "owner_user_id must be a user in this workspace.")
		}

		if err := registrationEvidence(tx, ws, w.ID, in.ObservationID, in.CloudObservationID); err != nil {
			return err
		}

		agentID, createdAgent, err := registrationAgent(tx, ws, in)
		if err != nil {
			return err
		}

		// The basis is fixed here. RejectWorkloadAuthority is the Go gate;
		// the CHECK is what makes any other writer fail.
		if err := RejectWorkloadAuthority(models.WorkloadLinkBasisHuman); err != nil {
			return err
		}

		instanceID, createdInstance, stored, err := registrationInstance(tx, ws, w, in, agentID)
		if err != nil {
			return err
		}
		if !createdInstance {
			// Linking an existing instance does not rewrite its registration.
			createdAgent = false
		}
		result := stored
		if createdInstance {
			result = AgentRegistrationResult{
				WorkloadID:            w.ID,
				AgentID:               agentID,
				InstanceID:            instanceID,
				CreatedAgent:          createdAgent,
				CreatedInstance:       true,
				ClassificationVersion: w.ClassificationVersion,
				Purpose:               in.Purpose,
				OwnerUserID:           in.OwnerUserID,
				ObservationID:         in.ObservationID,
				CloudObservationID:    in.CloudObservationID,
				LinkBasis:             models.WorkloadLinkBasisHuman,
			}
		}
		payload, err := json.Marshal(agentRegistrationEnvelope{Data: result})
		if err != nil {
			return err
		}
		var inserted []idemHit
		if err := tx.Raw(`INSERT INTO iga_idempotency_keys
			(workspace_id, idempotency_key, route, request_hash, response_status, response_body)
			VALUES (?, ?, ?, ?, 200, CAST(? AS jsonb))
			ON CONFLICT (workspace_id, idempotency_key) DO NOTHING
			RETURNING request_hash AS hash, response_body::text AS body`,
			ws, key, agentRegistrationRoute, hash, string(payload)).Scan(&inserted).Error; err != nil {
			return err
		}
		if len(inserted) == 1 {
			out = []byte(inserted[0].Body)
			return nil
		}
		// A concurrent request stored this key first. Same hash: their body
		// is the result, and this transaction rolls nothing back that they
		// own. A different hash is a conflict and rolls our writes back.
		var won []idemHit
		if err := tx.Raw(`SELECT request_hash AS hash, response_body::text AS body
			FROM iga_idempotency_keys
			WHERE workspace_id = ? AND idempotency_key = ?`, ws, key).Scan(&won).Error; err != nil {
			return err
		}
		if len(won) == 0 || won[0].Hash != hash {
			return idempotencyReused()
		}
		out = []byte(won[0].Body)
		replayed = true
		return nil
	}, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		if isLockTimeout(err) {
			return nil, false, igaread.QueryTimeout(err)
		}
		return nil, false, igaread.AsError(err)
	}
	return out, replayed, nil
}

func agentRegistrationHash(workloadID uuid.UUID, raw []byte) string {
	buf := make([]byte, 0, len(agentRegistrationRoute)+len(workloadID.String())+len(raw)+2)
	buf = append(buf, agentRegistrationRoute...)
	buf = append(buf, '|')
	buf = append(buf, workloadID.String()...)
	buf = append(buf, '|')
	buf = append(buf, raw...)
	return HashBody(buf)
}

func idempotencyReused() *igaread.Error {
	return igaread.Conflict("idempotency_key_reused",
		"This Idempotency-Key was already used for a different request.")
}

// registrationEvidence requires the cited observation to share the confirming
// run of an iga_object_support row for this canonical workload. The cloud
// arm joins cloud_observation to that support on the connector and the scan
// run. cloud_observation.workload_id names cloud_workload, not iga_workload,
// so those ids are not compared.
func registrationEvidence(tx *gorm.DB, ws, workloadID uuid.UUID, observationID, cloudID *uuid.UUID) error {
	var hit []struct{ N int }
	var err error
	switch {
	case observationID != nil && cloudID == nil:
		err = tx.Raw(`SELECT 1 AS n
			FROM iga_observations o
			JOIN iga_object_support s
			  ON s.workspace_id = o.workspace_id
			 AND s.workload_id = ?
			 AND s.integration_id IS NOT NULL
			 AND s.confirming_iga_scan_run_id = o.scan_run_id
			WHERE o.workspace_id = ? AND o.id = ?
			LIMIT 1`, workloadID, ws, *observationID).Scan(&hit).Error
	case cloudID != nil && observationID == nil:
		err = tx.Raw(`SELECT 1 AS n
			FROM cloud_observation o
			JOIN iga_object_support s
			  ON s.workspace_id = o.workspace_id
			 AND s.workload_id = ?
			 AND s.connector_id = o.connector_id
			 AND s.last_confirmed_run_id = o.scan_run_id
			WHERE o.workspace_id = ? AND o.id = ?
			LIMIT 1`, workloadID, ws, *cloudID).Scan(&hit).Error
	default:
		return igaread.InvalidParameter("observation_id",
			"set exactly one of observation_id and cloud_observation_id")
	}
	if err != nil {
		return err
	}
	if len(hit) == 0 {
		return igaread.Unprocessable("workload_evidence",
			"The cited observation is not evidence for this workload.")
	}
	return nil
}

func registrationAgent(tx *gorm.DB, ws uuid.UUID, in WorkloadAgentRegistration) (uuid.UUID, bool, error) {
	if in.AgentID != nil && in.CreateDisplayName != nil {
		return uuid.Nil, false, igaread.InvalidParameter("agent_id", "set agent_id or create_agent, not both")
	}
	if in.CreateDisplayName != nil {
		var created []struct{ ID uuid.UUID }
		if err := tx.Raw(`INSERT INTO iga_agents (workspace_id, display_name, rollup_state)
			VALUES (?, ?, ?)
			RETURNING id`, ws, *in.CreateDisplayName, models.RollupConfirmed).Scan(&created).Error; err != nil {
			return uuid.Nil, false, err
		}
		if len(created) != 1 {
			return uuid.Nil, false, fmt.Errorf("agent insert returned %d rows", len(created))
		}
		return created[0].ID, true, nil
	}
	if in.AgentID == nil {
		return uuid.Nil, false, igaread.InvalidParameter("agent_id", "set agent_id or create_agent")
	}
	var found []struct{ ID uuid.UUID }
	if err := tx.Raw(`SELECT id FROM iga_agents WHERE workspace_id = ? AND id = ?`,
		ws, *in.AgentID).Scan(&found).Error; err != nil {
		return uuid.Nil, false, err
	}
	if len(found) == 0 {
		return uuid.Nil, false, igaread.NotFound()
	}
	return found[0].ID, false, nil
}

type storedInstance struct {
	ID                    uuid.UUID
	AgentID               uuid.UUID
	ClassificationVersion int64
	LinkPurpose           string
	OwnerUserID           uuid.UUID
	ObservationID         *uuid.UUID
	CloudObservationID    *uuid.UUID
}

func registrationInstance(tx *gorm.DB, ws uuid.UUID, w lockedRegWorkload, in WorkloadAgentRegistration, agentID uuid.UUID) (uuid.UUID, bool, AgentRegistrationResult, error) {
	var none AgentRegistrationResult
	var have []storedInstance
	if err := tx.Raw(`SELECT id, agent_id, classification_version, link_purpose, owner_user_id,
			observation_id, cloud_observation_id
		FROM iga_agent_instances
		WHERE workspace_id = ? AND workload_id = ?
		  AND observation_id IS NOT DISTINCT FROM ?
		  AND cloud_observation_id IS NOT DISTINCT FROM ?`,
		ws, w.ID, in.ObservationID, in.CloudObservationID).Scan(&have).Error; err != nil {
		return uuid.Nil, false, none, err
	}
	if len(have) > 0 {
		row := have[0]
		if row.AgentID != agentID {
			return uuid.Nil, false, none, igaread.Conflict("instance_evidence_taken",
				"This workload's evidence is already a confirmed instance of another agent.")
		}
		return row.ID, false, AgentRegistrationResult{
			WorkloadID:            w.ID,
			AgentID:               row.AgentID,
			InstanceID:            row.ID,
			CreatedAgent:          false,
			CreatedInstance:       false,
			ClassificationVersion: row.ClassificationVersion,
			Purpose:               row.LinkPurpose,
			OwnerUserID:           row.OwnerUserID,
			ObservationID:         row.ObservationID,
			CloudObservationID:    row.CloudObservationID,
			LinkBasis:             models.WorkloadLinkBasisHuman,
		}, nil
	}
	var created []struct{ ID uuid.UUID }
	err := tx.Raw(`INSERT INTO iga_agent_instances
		(workspace_id, agent_id, workload_id, observation_id, cloud_observation_id,
		 workload_link_basis, linked_by, owner_user_id, link_purpose, classification_version,
		 native_workload_id, runtime_kind)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		RETURNING id`,
		ws, agentID, w.ID, in.ObservationID, in.CloudObservationID,
		models.WorkloadLinkBasisHuman, in.ActorUserID, in.OwnerUserID, in.Purpose, w.ClassificationVersion,
		w.SourceKey, w.RuntimeKind).Scan(&created).Error
	if err != nil {
		if sqlState(err) == "23505" && strings.Contains(err.Error(), "uq_iga_agent_instances_workload_") {
			return uuid.Nil, false, none, igaread.Conflict("instance_evidence_taken",
				"This workload's evidence is already a confirmed instance of another agent.")
		}
		return uuid.Nil, false, none, err
	}
	if len(created) != 1 {
		return uuid.Nil, false, none, fmt.Errorf("instance insert returned %d rows", len(created))
	}
	return created[0].ID, true, none, nil
}

// RecordCandidateLink writes a candidate join from a discovered agent to a
// workload. It does not set iga_agent_instances.workload_id. link_strength
// is candidate, which the table CHECK will not store as authority.
func (s *AgentRegistrationService) RecordCandidateLink(ctx context.Context, ws, discoveredAgentID, workloadID uuid.UUID, observationID, cloudObservationID *uuid.UUID) error {
	if observationID != nil && cloudObservationID != nil {
		return igaread.InvalidParameter("observation_id", "set only one of observation_id and cloud_observation_id")
	}
	if err := RejectWorkloadAuthority("candidate"); err == nil {
		return fmt.Errorf("candidate basis was accepted as workload authority")
	}
	return s.db.WithContext(ctx).Exec(`INSERT INTO discovered_agent_workloads
		(workspace_id, discovered_agent_id, workload_id, observation_id, cloud_observation_id,
		 link_strength, link_state)
		VALUES (?, ?, ?, ?, ?, 'candidate', 'proposed')
		ON CONFLICT ON CONSTRAINT discovered_agent_workloads_pair_key DO NOTHING`,
		ws, discoveredAgentID, workloadID, observationID, cloudObservationID).Error
}
