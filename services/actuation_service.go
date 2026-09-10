package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ActuationManager is the control-plane half of in-cluster actuation.
//
// WHY THIS IS NOT CREDENTIAL DELIVERY
// AuthSec's workload identity model is secretless: a workload authenticates with a
// `spiffe-svid` client assertion using an SVID it already holds, so governance grants
// access to an identity the workload HAS rather than shipping one to it. Nothing has to
// be delivered.
//
// What genuinely needs in-cluster action is enforcement and verification:
//
//   - quarantine — `discovered_agents.status='quarantined'` was advisory, enforced by
//     nothing anywhere in the codebase. A NetworkPolicy makes it real.
//   - verify_uptake — confirm the workload actually runs as the ServiceAccount its
//     entitlements were anchored to. If it does not, the grant is attached to an
//     identity the workload does not have.
//
// PULL, NOT PUSH. The control plane cannot reach into a customer's cluster and should
// not want to: an inbound connection is a hole in their network, an outbound poll is
// not.
type ActuationManager interface {
	// EnableActuation mints a per-connector actuation token, returning it ONCE. Only a
	// hash is stored.
	EnableActuation(workspaceID, sourceID uuid.UUID) (token string, err error)

	// AuthenticateAgent resolves a presented token to its connector. The token
	// identifies WHICH cluster is calling, so an agent never asserts its own identity.
	AuthenticateAgent(token string) (*models.DiscoverySource, error)

	// Enqueue queues one instruction, collapsing a repeat onto the open row.
	Enqueue(workspaceID uuid.UUID, in EnqueueInstructionInput) (*models.ProvisioningInstruction, bool, error)

	// Lease claims up to max pending instructions for a connector, with a time-bounded
	// lease so a crashed agent's work returns to the queue.
	Lease(sourceID uuid.UUID, leasedBy string, max int, ttl time.Duration) ([]models.ProvisioningInstruction, error)

	// Report records an outcome and folds it into the agent's state.
	Report(sourceID, instructionID uuid.UUID, in ReportInput) (*models.ProvisioningInstruction, error)

	// ReclaimExpiredLeases returns work abandoned by a dead agent to the queue.
	ReclaimExpiredLeases() (int, error)

	ListInstructions(workspaceID uuid.UUID, openOnly bool, limit, offset int) ([]models.ProvisioningInstruction, int64, error)
}

// EnqueueInstructionInput describes work for a cluster.
type EnqueueInstructionInput struct {
	DiscoverySourceID uuid.UUID
	Kind              string
	DiscoveredAgentID *uuid.UUID
	Fingerprint       string
	Payload           map[string]interface{}
	// IdempotencyKey collapses a re-issued instruction onto the existing open row.
	// Defaults to kind+fingerprint, which is what makes "quarantine an
	// already-quarantined agent" a no-op rather than a second NetworkPolicy write.
	IdempotencyKey string
	CreatedBy      string
}

// ReportInput is an agent's outcome for one instruction.
type ReportInput struct {
	// Success false records a failure with Error; the instruction may be retried until
	// maxAttempts.
	Success bool
	Error   string
	Result  map[string]interface{}
}

// maxAttempts bounds retries. A permanently failing instruction — a NetworkPolicy the
// cluster refuses, say — must stop consuming the queue and become visible instead.
const maxActuationAttempts = 5

type actuationManager struct{ db *gorm.DB }

// NewActuationManager constructs an ActuationManager.
func NewActuationManager(db *gorm.DB) ActuationManager { return &actuationManager{db: db} }

/* --------------------------------- auth ---------------------------------- */

// hashActuationToken hashes a token for storage and lookup.
//
// SHA-256 rather than bcrypt on purpose: this is a high-entropy random token, not a
// password, so there is nothing to brute-force and a per-request bcrypt cost on the
// agent's poll would be pure latency. What matters is that the plaintext is never
// stored, so a leaked backup yields nothing usable.
func hashActuationToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (m *actuationManager) EnableActuation(workspaceID, sourceID uuid.UUID) (string, error) {
	var src models.DiscoverySource
	if err := m.db.First(&src, "id = ? AND workspace_id = ?", sourceID, workspaceID).Error; err != nil {
		return "", err
	}
	if !src.SelfRegistered {
		// An admin-configured connector row has no agent behind it to do the actuating.
		return "", errors.New("actuation can only be enabled on a self-registered connector: " +
			"there must be an agent in the cluster to act")
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate actuation token: %w", err)
	}
	token := "authsec_act_" + base64.RawURLEncoding.EncodeToString(raw)

	now := time.Now()
	if err := m.db.Model(&models.DiscoverySource{}).
		Where("id = ? AND workspace_id = ?", sourceID, workspaceID).
		Updates(map[string]interface{}{
			"actuation_token_hash": hashActuationToken(token),
			"actuation_enabled_at": now,
			"updated_at":           now,
		}).Error; err != nil {
		return "", err
	}
	// Returned once. Re-enabling mints a new token and invalidates the old one, which is
	// the rotation path.
	return token, nil
}

func (m *actuationManager) AuthenticateAgent(token string) (*models.DiscoverySource, error) {
	if token == "" {
		return nil, errors.New("actuation token required")
	}
	var src models.DiscoverySource
	err := m.db.First(&src, "actuation_token_hash = ? AND actuation_token_hash <> ''",
		hashActuationToken(token)).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Deliberately vague: a distinguishable "unknown token" versus "disabled
			// connector" would let a caller probe which tokens exist.
			return nil, errors.New("invalid actuation token")
		}
		return nil, err
	}
	if !src.Enabled {
		return nil, errors.New("this connector is disabled")
	}
	return &src, nil
}

/* -------------------------------- enqueue -------------------------------- */

func (m *actuationManager) Enqueue(workspaceID uuid.UUID,
	in EnqueueInstructionInput) (*models.ProvisioningInstruction, bool, error) {

	if !containsString(models.ValidInstructionKinds(), in.Kind) {
		return nil, false, fmt.Errorf("unknown instruction kind %q", in.Kind)
	}
	if in.DiscoverySourceID == uuid.Nil {
		return nil, false, errors.New("discovery_source_id is required: an instruction " +
			"nobody owns is one nobody applies")
	}

	// The connector must exist in this workspace, and must have an agent behind it.
	// Queuing work for a cluster with no agent is worse than refusing: it looks like
	// enforcement is pending when nothing will ever pick it up.
	var src models.DiscoverySource
	if err := m.db.First(&src, "id = ? AND workspace_id = ?",
		in.DiscoverySourceID, workspaceID).Error; err != nil {
		return nil, false, fmt.Errorf("unknown connector for this workspace: %w", err)
	}
	if src.ActuationTokenHash == "" {
		return nil, false, errors.New("actuation is not enabled for this cluster: enable it " +
			"and install the agent with the actuation role before queuing work")
	}

	key := in.IdempotencyKey
	if key == "" {
		key = in.Kind + ":" + in.Fingerprint
	}
	payload, err := marshalDiscoveryConfig(in.Payload)
	if err != nil {
		return nil, false, err
	}

	inst := &models.ProvisioningInstruction{
		ID:                uuid.New(),
		WorkspaceID:       workspaceID,
		DiscoverySourceID: in.DiscoverySourceID,
		Kind:              in.Kind,
		Payload:           json.RawMessage(payload),
		DiscoveredAgentID: in.DiscoveredAgentID,
		Fingerprint:       in.Fingerprint,
		IdempotencyKey:    key,
		Status:            models.InstructionPending,
		CreatedBy:         in.CreatedBy,
	}

	// ON CONFLICT against the partial unique index over OPEN instructions: a repeat
	// collapses onto the row already queued rather than queuing the same action twice.
	res := m.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "discovery_source_id"}, {Name: "idempotency_key"}},
		TargetWhere: clause.Where{
			Exprs: []clause.Expression{gorm.Expr("status IN ('pending','leased')")},
		},
		DoNothing: true,
	}).Create(inst)
	if res.Error != nil {
		return nil, false, res.Error
	}
	if res.RowsAffected == 0 {
		// Already queued. Return the existing row so the caller can report honestly.
		var existing models.ProvisioningInstruction
		if err := m.db.First(&existing,
			`discovery_source_id = ? AND idempotency_key = ? AND status IN ('pending','leased')`,
			in.DiscoverySourceID, key).Error; err != nil {
			return nil, false, err
		}
		return &existing, false, nil
	}
	return inst, true, nil
}

/* --------------------------------- lease --------------------------------- */

func (m *actuationManager) Lease(sourceID uuid.UUID, leasedBy string, max int,
	ttl time.Duration) ([]models.ProvisioningInstruction, error) {

	if max <= 0 || max > 100 {
		max = 20
	}
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	now := time.Now()
	expires := now.Add(ttl)

	var leased []models.ProvisioningInstruction

	// One statement, so two agent replicas polling simultaneously cannot lease the same
	// instruction. SKIP LOCKED rather than a plain UPDATE ... LIMIT: without it,
	// concurrent pollers serialise behind each other's row locks and one blocks on work
	// it will not get.
	err := m.db.Raw(`
		UPDATE provisioning_instructions
		   SET status = 'leased', lease_expires_at = ?, leased_by = ?,
		       attempts = attempts + 1, updated_at = ?
		 WHERE id IN (
		       SELECT id FROM provisioning_instructions
		        WHERE discovery_source_id = ? AND status = 'pending'
		        ORDER BY created_at
		        LIMIT ?
		        FOR UPDATE SKIP LOCKED)
		RETURNING *`, expires, leasedBy, now, sourceID, max).Scan(&leased).Error
	if err != nil {
		return nil, fmt.Errorf("lease instructions: %w", err)
	}
	return leased, nil
}

func (m *actuationManager) ReclaimExpiredLeases() (int, error) {
	// Back to pending, unless it has already burned its attempts — at which point it
	// becomes visibly failed rather than looping forever.
	res := m.db.Exec(`
		UPDATE provisioning_instructions
		   SET status = CASE WHEN attempts >= ? THEN 'failed' ELSE 'pending' END,
		       applied_at = CASE WHEN attempts >= ? THEN NOW() ELSE NULL END,
		       error = CASE WHEN attempts >= ?
		                    THEN 'abandoned: the agent stopped responding after '
		                         || attempts || ' attempt(s)'
		                    ELSE error END,
		       lease_expires_at = NULL, leased_by = '', updated_at = NOW()
		 WHERE status = 'leased' AND lease_expires_at < NOW()`,
		maxActuationAttempts, maxActuationAttempts, maxActuationAttempts)
	return int(res.RowsAffected), res.Error
}

/* -------------------------------- report --------------------------------- */

func (m *actuationManager) Report(sourceID, instructionID uuid.UUID,
	in ReportInput) (*models.ProvisioningInstruction, error) {

	var inst models.ProvisioningInstruction
	// Scoped to the calling connector: an agent must not be able to report on another
	// cluster's work.
	if err := m.db.First(&inst, "id = ? AND discovery_source_id = ?",
		instructionID, sourceID).Error; err != nil {
		return nil, err
	}
	if inst.Status == models.InstructionApplied {
		return &inst, nil // idempotent; a duplicate report is not an error
	}

	resultJSON, err := marshalDiscoveryConfig(in.Result)
	if err != nil {
		return nil, err
	}
	now := time.Now()

	updates := map[string]interface{}{
		"result":           json.RawMessage(resultJSON),
		"lease_expires_at": nil,
		"leased_by":        "",
		"updated_at":       now,
	}

	switch {
	case in.Success:
		updates["status"] = models.InstructionApplied
		updates["applied_at"] = now
		updates["error"] = ""
	case inst.Attempts >= maxActuationAttempts:
		// Out of retries. Terminal and visible rather than an endless loop.
		updates["status"] = models.InstructionFailed
		updates["applied_at"] = now
		updates["error"] = defaultString(in.Error, "failed after maximum attempts")
	default:
		// Back to pending for another agent, or another try by this one.
		updates["status"] = models.InstructionPending
		updates["error"] = defaultString(in.Error, "unspecified failure")
	}

	if err := m.db.Model(&models.ProvisioningInstruction{}).
		Where("id = ?", instructionID).Updates(updates).Error; err != nil {
		return nil, err
	}

	// Fold the outcome into the agent's state, so the console can distinguish "I
	// quarantined it" from "it is actually blocked".
	if inst.DiscoveredAgentID != nil {
		if err := m.applyToAgent(&inst, in, now); err != nil {
			// The instruction outcome is already recorded; failing here would lose it.
			// Surfaced through the instruction's error field instead.
			_ = m.db.Model(&models.ProvisioningInstruction{}).Where("id = ?", instructionID).
				Update("error", fmt.Sprintf("%s (could not update agent state: %v)",
					in.Error, err)).Error
		}
	}

	var out models.ProvisioningInstruction
	if err := m.db.First(&out, "id = ?", instructionID).Error; err != nil {
		return nil, err
	}
	return &out, nil
}

// applyToAgent folds an instruction outcome into discovered_agents.
func (m *actuationManager) applyToAgent(inst *models.ProvisioningInstruction,
	in ReportInput, now time.Time) error {

	updates := map[string]interface{}{"updated_at": now}

	switch inst.Kind {
	case models.InstructionQuarantine:
		if in.Success {
			updates["quarantine_enforced_at"] = now
			updates["quarantine_enforcement_error"] = ""
		} else {
			// The decision stands; only the enforcement failed. Recording the error
			// rather than reverting the status is the honest split: an admin needs to
			// see "quarantined but NOT blocked", which is the dangerous state.
			updates["quarantine_enforcement_error"] = defaultString(in.Error, "enforcement failed")
		}
	case models.InstructionUnquarantine:
		if in.Success {
			updates["quarantine_enforced_at"] = nil
			updates["quarantine_enforcement_error"] = ""
		} else {
			updates["quarantine_enforcement_error"] = defaultString(in.Error, "release failed")
		}
	case models.InstructionVerifyUptake:
		if !in.Success {
			return nil
		}
		// The answer, not just an acknowledgement.
		if sa, ok := in.Result["service_account"].(string); ok && sa != "" {
			updates["observed_service_account"] = sa
		}
		updates["identity_verified_at"] = now
	}

	if len(updates) == 1 {
		return nil
	}
	return m.db.Model(&models.DiscoveredAgent{}).
		Where("id = ?", *inst.DiscoveredAgentID).Updates(updates).Error
}

/* --------------------------------- reads --------------------------------- */

func (m *actuationManager) ListInstructions(workspaceID uuid.UUID, openOnly bool,
	limit, offset int) ([]models.ProvisioningInstruction, int64, error) {

	q := m.db.Model(&models.ProvisioningInstruction{}).Where("workspace_id = ?", workspaceID)
	if openOnly {
		q = q.Where("status IN ('pending','leased')")
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	var out []models.ProvisioningInstruction
	// Failures first: an instruction that will never apply is the one an operator needs
	// to see, and it would otherwise sink below routine successes.
	err := q.Order(`CASE status WHEN 'failed' THEN 0 WHEN 'pending' THEN 1
	                            WHEN 'leased' THEN 2 ELSE 3 END`).
		Order("created_at DESC").Limit(limit).Offset(offset).Find(&out).Error
	return out, total, err
}

/* -------------------------- enforcement helpers -------------------------- */

// EnforceQuarantine queues a network-deny for a quarantined agent, and returns whether
// anything was queued.
//
// Best-effort BY DESIGN. The quarantine DECISION is already committed by the time this
// runs; if the cluster has no actuation agent, or the enqueue fails, the decision must
// still stand. Refusing the quarantine because enforcement could not be queued would
// mean an admin cannot even record that an agent is untrusted — strictly worse than
// recording it and reporting that enforcement is pending.
//
// The gap is visible rather than hidden: quarantine_enforced_at stays null, so the
// console can show "quarantined but NOT blocked", which is the state that matters.
func EnforceQuarantine(db *gorm.DB, workspaceID uuid.UUID, agent *models.DiscoveredAgent,
	release bool, actor string) (queued bool, reason string) {

	if agent == nil {
		return false, "no agent"
	}
	// Only the connector that reported it can act on it: a Kubernetes agent cannot
	// apply a NetworkPolicy for a workload in a cluster it does not run in.
	if agent.DiscoverySourceID == nil {
		return false, "this agent is not attributed to a cluster connector, so there is " +
			"nowhere to enforce it"
	}

	kind := models.InstructionQuarantine
	if release {
		kind = models.InstructionUnquarantine
	}

	// The workload coordinate the NetworkPolicy needs, taken from the sighting metadata
	// rather than re-derived, so enforcement targets exactly what discovery saw.
	var meta struct {
		Kubernetes struct {
			Namespace    string            `json:"namespace"`
			WorkloadKind string            `json:"workload_kind"`
			WorkloadName string            `json:"workload_name"`
			Labels       map[string]string `json:"labels"`
		} `json:"kubernetes"`
	}
	if len(agent.Metadata) > 0 {
		_ = json.Unmarshal(agent.Metadata, &meta)
	}
	if meta.Kubernetes.Namespace == "" || meta.Kubernetes.WorkloadName == "" {
		return false, "the sighting carries no workload coordinate, so a NetworkPolicy " +
			"selector cannot be built"
	}

	// A quarantine and its release must never sit open at once, contradicting each
	// other. The original implementation enforced that by giving BOTH kinds the same
	// idempotency key — but Enqueue resolves a key conflict with DoNothing, so the
	// OLDER decision won: releasing an agent before the cluster agent next polled
	// collapsed the release onto the still-pending quarantine and silently dropped it.
	// The stale quarantine then applied, and the console showed a released agent that
	// was still blocked.
	//
	// So the key is per-kind, and the contradiction is resolved explicitly below in
	// favour of the NEWER decision, which is the only correct direction.
	opposite := models.InstructionUnquarantine
	if release {
		opposite = models.InstructionQuarantine
	}
	supersedeOpenInstruction(db, workspaceID,
		*agent.DiscoverySourceID, opposite+":"+agent.Fingerprint)

	agentID := agent.ID
	_, created, err := NewActuationManager(db).Enqueue(workspaceID, EnqueueInstructionInput{
		DiscoverySourceID: *agent.DiscoverySourceID,
		Kind:              kind,
		DiscoveredAgentID: &agentID,
		Fingerprint:       agent.Fingerprint,
		Payload: map[string]interface{}{
			"namespace":     meta.Kubernetes.Namespace,
			"workload_kind": meta.Kubernetes.WorkloadKind,
			"workload_name": meta.Kubernetes.WorkloadName,
			"labels":        meta.Kubernetes.Labels,
			"reason":        agent.QuarantineReason,
		},
		IdempotencyKey: kind + ":" + agent.Fingerprint,
		CreatedBy:      actor,
	})
	if err != nil {
		return false, err.Error()
	}

	// EVICTION: the half that stops the process.
	//
	// A NetworkPolicy cuts an agent's network and leaves it running. For a
	// quarantine to mean what an operator thinks it means, the pods have to stop
	// too — so a quarantine also queues an eviction, and a release does not (there
	// is nothing to un-evict; the controller has already rescheduled).
	//
	// Gated on what the CLUSTER said it can do (EN-5). Queuing an eviction for a
	// connector whose agent has the switch off would accumulate instructions that
	// fail on every attempt and fill the console with enforcement errors that are
	// really a configuration choice.
	if !release {
		enqueueEviction(db, workspaceID, agent, meta.Kubernetes.Namespace,
			meta.Kubernetes.WorkloadKind, meta.Kubernetes.WorkloadName,
			meta.Kubernetes.Labels, actor)
	}

	if !created {
		return true, "already queued"
	}
	return true, ""
}

// enqueueEviction queues the stop-the-process half of a quarantine.
//
// Best-effort and deliberately non-fatal: the NetworkPolicy is the containment that
// must not be lost, and failing the whole quarantine because the eviction could not
// be queued would trade a working half for nothing.
func enqueueEviction(db *gorm.DB, workspaceID uuid.UUID, agent *models.DiscoveredAgent,
	namespace, workloadKind, workloadName string, labels map[string]string, actor string) {

	if agent == nil || agent.DiscoverySourceID == nil {
		return
	}
	var src models.DiscoverySource
	if err := db.First(&src, "id = ?", *agent.DiscoverySourceID).Error; err != nil {
		return
	}
	if !src.EnforcementEvict {
		// The cluster has not enabled eviction. Not an error and not silent: the
		// console shows enforcement_evict=false on the connector, which is the
		// honest answer to "why is the pod still running".
		return
	}

	agentID := agent.ID
	_, _, _ = NewActuationManager(db).Enqueue(workspaceID, EnqueueInstructionInput{
		DiscoverySourceID: *agent.DiscoverySourceID,
		Kind:              models.InstructionEvictPods,
		DiscoveredAgentID: &agentID,
		Fingerprint:       agent.Fingerprint,
		Payload: map[string]interface{}{
			"namespace":     namespace,
			"workload_kind": workloadKind,
			"workload_name": workloadName,
			"labels":        labels,
			"reason":        agent.QuarantineReason,
		},
		// Keyed on the QUARANTINE DECISION, not just the fingerprint: re-quarantining
		// an agent that was released must evict again, and sharing a key with the
		// first quarantine would collapse the second onto a row already applied.
		IdempotencyKey: models.InstructionEvictPods + ":" + agent.Fingerprint + ":" +
			quarantineEpoch(agent),
		CreatedBy: actor,
	})
}

// quarantineEpoch identifies WHICH quarantine this is, so a re-quarantine after a
// release is a distinct instruction rather than a duplicate of the first.
func quarantineEpoch(agent *models.DiscoveredAgent) string {
	if agent.QuarantinedAt != nil {
		return agent.QuarantinedAt.UTC().Format(time.RFC3339Nano)
	}
	return "0"
}

// supersedeOpenInstruction retires a PENDING instruction that a newer, contradicting
// decision has overtaken, and returns how many rows it retired.
//
// Only 'pending' is touched. A 'leased' instruction is already in the cluster agent's
// hands and will be reported against by id, so rewriting it underneath would record an
// outcome for an action nobody asked for. Leaving it is safe because both kinds are
// idempotent state assertions on the same NetworkPolicy: the leased one may land
// first, then the newer instruction lands after it and the cluster converges on the
// newer decision either way.
func supersedeOpenInstruction(db *gorm.DB, workspaceID, sourceID uuid.UUID, key string) int64 {
	if db == nil {
		return 0
	}
	res := db.Model(&models.ProvisioningInstruction{}).
		Where(`workspace_id = ? AND discovery_source_id = ? AND idempotency_key = ?
		       AND status = ?`,
			workspaceID, sourceID, key, models.InstructionPending).
		Updates(map[string]interface{}{
			"status":     models.InstructionSuperseded,
			"error":      "",
			"updated_at": time.Now(),
		})
	if res.Error != nil {
		return 0
	}
	return res.RowsAffected
}

/* --------------------------- force-delete escalation --------------------- */

// ForceEvictInput is an explicit human decision to override a disruption budget.
type ForceEvictInput struct {
	// Actor is who is answerable for this. Required — the schema refuses an
	// unattributed force-delete outright.
	Actor string
	// Reason is why the budget is being overruled. Required for the same reason.
	Reason string
}

// ForceEvictResult reports what was queued.
type ForceEvictResult struct {
	InstructionID uuid.UUID `json:"instruction_id"`
	BlockedPods   []string  `json:"blocked_pods"`
	Queued        bool      `json:"queued"`
}

// ForceEvict queues the override for an eviction a PodDisruptionBudget refused.
//
// THE MOST DANGEROUS OPERATION IN THIS SYSTEM, and the only one that deliberately
// overrules something the cluster owner declared. Eviction uses the Eviction API
// precisely so budgets are honoured (EN-6); this bypasses that, by deleting the pod
// with a zero grace period.
//
// So it is fenced on four sides, and none of them is a convention:
//
//  1. NEVER AUTOMATIC. Nothing calls this but an explicit endpoint. No reconciler,
//     no policy expiry, no retry path can reach it.
//  2. ATTRIBUTED AND JUSTIFIED, enforced by a database CHECK rather than by
//     whichever code path remembered.
//  3. ONLY AS AN ESCALATION. There must be a PDB-blocked eviction on record for
//     this agent. You cannot force-delete something that was never refused —
//     that would make it a first resort, and a first resort is not an escalation.
//  4. ONLY WHERE THE CLUSTER PERMITS IT. The agent reports the capability
//     separately from deletion, because permitting a workload to be deleted is not
//     the same as permitting a budget to be overruled.
func ForceEvict(db *gorm.DB, workspaceID uuid.UUID, agent *models.DiscoveredAgent,
	in ForceEvictInput) (*ForceEvictResult, error) {

	if agent == nil {
		return nil, errors.New("no agent")
	}
	if strings.TrimSpace(in.Actor) == "" {
		return nil, errors.New("a force-delete must name who authorised it")
	}
	if strings.TrimSpace(in.Reason) == "" {
		return nil, errors.New("a force-delete must say why a PodDisruptionBudget is " +
			"being overruled: the cluster owner declared that budget, and overriding it " +
			"without a recorded reason is exactly the boundary violation this system " +
			"exists to prevent elsewhere")
	}
	if agent.DiscoverySourceID == nil {
		return nil, errors.New("this agent is not attributed to a cluster connector")
	}

	var src models.DiscoverySource
	if err := db.First(&src, "id = ? AND workspace_id = ?",
		*agent.DiscoverySourceID, workspaceID).Error; err != nil {
		return nil, fmt.Errorf("unknown connector: %w", err)
	}
	if !src.EnforcementForceEvict {
		return nil, errors.New("this cluster's agent does not permit overriding a " +
			"PodDisruptionBudget (--set enforcement.forceEvict=true). Permitting a " +
			"workload to be deleted is not the same as permitting a budget to be " +
			"overruled, so the two are separate switches")
	}

	// THE ESCALATION PRECONDITION. Read from what the agent actually reported, not
	// from an operator's assertion that something is stuck.
	blocked, err := pdbBlockedPods(db, workspaceID, agent.ID)
	if err != nil {
		return nil, err
	}
	if len(blocked) == 0 {
		return nil, errors.New("no eviction for this agent has been refused by a " +
			"PodDisruptionBudget. Force-delete is an escalation of a blocked eviction, " +
			"not a way to skip one — quarantine the agent first and let the ordinary " +
			"eviction run")
	}

	ns, kind, name, _ := k8sCoordinatesForActuation(agent.Metadata)
	if ns == "" || name == "" {
		return nil, errors.New("the sighting carries no workload coordinate")
	}

	agentID := agent.ID
	inst, created, err := NewActuationManager(db).Enqueue(workspaceID, EnqueueInstructionInput{
		DiscoverySourceID: *agent.DiscoverySourceID,
		Kind:              models.InstructionForceDeletePods,
		DiscoveredAgentID: &agentID,
		Fingerprint:       agent.Fingerprint,
		Payload: map[string]interface{}{
			"namespace":     ns,
			"workload_kind": kind,
			"workload_name": name,
			"reason":        in.Reason,
			// The pods the agent itself reported as blocked. Naming them bounds
			// the override to what was actually refused, rather than handing the
			// agent a licence to delete whatever it finds under that workload now.
			"pods": blocked,
		},
		// Time-keyed, so a second override after a second refusal is a second
		// decision with its own record rather than a silent no-op.
		IdempotencyKey: models.InstructionForceDeletePods + ":" + agent.Fingerprint +
			":" + time.Now().UTC().Format(time.RFC3339),
		CreatedBy: in.Actor,
	})
	if err != nil {
		return nil, err
	}
	return &ForceEvictResult{InstructionID: inst.ID, BlockedPods: blocked, Queued: created}, nil
}

// pdbBlockedPods reads the pods a PodDisruptionBudget refused, from the results the
// agent reported on its own eviction instructions.
//
// The agent's report is the evidence. An operator saying "it is stuck" is not: the
// point of the precondition is that the cluster refused, and only the cluster can
// say that.
func pdbBlockedPods(db *gorm.DB, workspaceID, agentID uuid.UUID) ([]string, error) {
	var rows []models.ProvisioningInstruction
	err := db.Where(`workspace_id = ? AND discovered_agent_id = ? AND kind = ?
	                 AND status = ?`,
		workspaceID, agentID, models.InstructionEvictPods, models.InstructionApplied).
		Order("applied_at DESC").Limit(5).Find(&rows).Error
	if err != nil {
		return nil, err
	}
	for i := range rows {
		var res struct {
			PDBBlocked     int      `json:"pdb_blocked"`
			PDBBlockedPods []string `json:"pdb_blocked_pods"`
		}
		if len(rows[i].Result) == 0 {
			continue
		}
		if err := json.Unmarshal(rows[i].Result, &res); err != nil {
			continue
		}
		if res.PDBBlocked > 0 && len(res.PDBBlockedPods) > 0 {
			// The most recent refusal only. An older one may name pods that have
			// since been replaced, and force-deleting a pod by a stale name is at
			// best a no-op and at worst the wrong pod.
			return res.PDBBlockedPods, nil
		}
	}
	return nil, nil
}

// k8sCoordinatesForActuation reads the workload coordinate from sighting metadata.
func k8sCoordinatesForActuation(raw json.RawMessage) (namespace, kind, name, container string) {
	if len(raw) == 0 {
		return
	}
	var md struct {
		Kubernetes struct {
			Namespace     string `json:"namespace"`
			WorkloadKind  string `json:"workload_kind"`
			WorkloadName  string `json:"workload_name"`
			ContainerName string `json:"container_name"`
		} `json:"kubernetes"`
	}
	if err := json.Unmarshal(raw, &md); err != nil {
		return
	}
	return md.Kubernetes.Namespace, md.Kubernetes.WorkloadKind,
		md.Kubernetes.WorkloadName, md.Kubernetes.ContainerName
}
