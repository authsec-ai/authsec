package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentcore"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// R3 runtime policies, settings, routing proofs, AgentCore push / coverage and
// broker roles (SPEC-iga-phase3-policy.md §12.4; DECISION R3-2, R3-11,
// R3-12 in internal/igagov/r3.go). Every mutation writes its iga_gov_event in
// the same transaction; the routes write audit_events. Every read and write
// is bound to the token's workspace; another workspace's id is 404.

// R3 event names (vocabulary: iga_gov_event_vocabulary.go).
const (
	GovEventRuntimePolicyCreated    = "runtime_policy.created"
	GovEventRuntimeVersionCreated   = "runtime_version.created"
	GovEventRuntimeVersionApproved  = "runtime_version.approved"
	GovEventRuntimeVersionRejected  = "runtime_version.rejected"
	GovEventRuntimeVersionWithdrawn = "runtime_version.withdrawn"
	GovEventRuntimeSettingsUpdated  = "runtime_settings.updated"
	GovEventRoutingProofRecorded    = "routing_proof.recorded"
	GovEventRoutingProofRevoked     = "routing_proof.revoked"
	GovEventAgentCorePushed         = "agentcore_policy.pushed"
	GovEventAgentCorePushFailed     = "agentcore_policy.push_failed"
	GovEventBrokerRoleBound         = "broker_role.bound"
	GovEventBrokerRoleDisabled      = "broker_role.disabled"
)

// R3 error codes.
const (
	GovCodeRuntimeNotRuntime     = "not_a_runtime_policy"
	GovCodeRuntimeIntentChanged  = "intent_changed"
	GovCodeAgentCoreUnavailable  = "agentcore_unavailable"
	GovCodeAgentCoreFailed       = "agentcore_push_failed"
	GovCodeGatewayNotInPolicy    = "gateway_not_in_policy"
	GovCodeNoApprovedVersion     = "no_approved_version"
	GovCodeBrokerConnector       = "broker_connector_invalid"
	GovCodeBrokerRoleExists      = "broker_role_exists"
	GovCodeRoutingProofInvalid   = "routing_proof_invalid"
	runtimeFamily                = "runtime"
	runtimeProvider              = "aws"
	runtimeStatusInReview        = "in_review"
	runtimeStatusApproved        = "approved"
	runtimeStatusSuperseded      = "superseded"
	runtimeStatusWithdrawn       = "withdrawn"
	runtimeStatusRejected        = "rejected"
	runtimeCoverageAdvisory      = "advisory"
	runtimeCoverageEnforced      = "enforced"
	runtimeCoverageNotConfigured = "not_configured"
	runtimeSystemActor           = "runtime-pdp"
)

// GovR3 is the R3 service.
type GovR3 struct {
	db  *gorm.DB
	now func() time.Time
}

// NewGovR3 builds the service.
func NewGovR3(db *gorm.DB) *GovR3 { return &GovR3{db: db, now: time.Now} }

// WithClock replaces the clock (tests).
func (s *GovR3) WithClock(now func() time.Time) *GovR3 { s.now = now; return s }

// event appends one R3 event. It is named "event" so the vocabulary walker
// (tests/integration/p3_events_test.go) reads its third argument.
func (s *GovR3) event(tx *gorm.DB, ws uuid.UUID, name string, actor *uuid.UUID, policy, version *uuid.UUID, payload map[string]any) error {
	kind, id := models.GovActorSystem, runtimeSystemActor
	if actor != nil {
		kind, id = userActor(*actor)
	}
	return appendGovEvent(tx, ws, name, kind, id, govEventRefs{PolicyID: policy, VersionID: version}, payload)
}

/* ---------------------------------------------------------------------------- */
/*                               Runtime policies                               */
/* ---------------------------------------------------------------------------- */

// RuntimePolicyRequest is POST /runtime/policies.
type RuntimePolicyRequest struct {
	Name    string          `json:"name"`
	Purpose string          `json:"purpose"`
	Intent  json.RawMessage `json:"intent"`
}

// RuntimeVersionRequest is POST /runtime/policies/:id/versions.
type RuntimeVersionRequest struct {
	BaseVersionNo int             `json:"base_version_no"`
	Intent        json.RawMessage `json:"intent"`
}

// RuntimeDecisionRequest is approve / reject / withdraw of a version.
type RuntimeDecisionRequest struct {
	IntentHash string `json:"intent_hash"`
	Reason     string `json:"reason"`
}

// RuntimePolicyView is a runtime policy with its versions.
type RuntimePolicyView struct {
	models.IGAGovPolicy
	Versions []models.IGAGovRuntimeVersion `json:"versions"`
	Approved *models.IGAGovRuntimeVersion  `json:"approved_version,omitempty"`
	InReview *models.IGAGovRuntimeVersion  `json:"version_in_review,omitempty"`
}

func runtimeIntentError(err error) error {
	var ie igagov.IntentErrors
	if errors.As(err, &ie) {
		return govUnprocessable(GovCodeInvalidIntent, "The runtime_controls intent is not valid.", map[string]any{"problems": ie})
	}
	return govUnprocessable(GovCodeInvalidIntent, "The runtime_controls intent is not valid.", map[string]any{"problems": err.Error()})
}

// loadRuntimePolicy loads a runtime-family policy of ws (404 otherwise; a
// policy of another family is 404 on the runtime routes too).
func (s *GovR3) loadRuntimePolicy(tx *gorm.DB, ws, id uuid.UUID, lock bool) (*models.IGAGovPolicy, error) {
	var p models.IGAGovPolicy
	q := tx.Where("workspace_id = ? AND id = ? AND family = ?", ws, id, runtimeFamily)
	if lock {
		q = q.Clauses(lockForUpdate())
	}
	if err := q.Take(&p).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	return &p, nil
}

// CreateRuntimePolicy creates a runtime policy and its first version, in
// review (DECISION R3-2).
func (s *GovR3) CreateRuntimePolicy(ctx context.Context, ws, actor uuid.UUID, req RuntimePolicyRequest) (*RuntimePolicyView, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 200 {
		return nil, GovBadParam("name", "A name of 1..200 characters is required.")
	}
	in, canon, hash, err := igagov.ParseRuntimeIntent(req.Intent)
	if err != nil {
		return nil, runtimeIntentError(err)
	}
	_ = in
	var out *RuntimePolicyView
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		owner := actor
		pol := models.IGAGovPolicy{ID: uuid.New(), WorkspaceID: ws, Name: name, Purpose: req.Purpose, Family: runtimeFamily,
			Provider: runtimeProvider, Lifecycle: "active", OwnerUserID: &owner, CreatedBy: actor}
		if err := tx.Omit("CurrentVersionID").Create(&pol).Error; err != nil {
			if isUniqueViolation(err, "iga_gov_policy_workspace_id_name_key") {
				return govConflict(GovCodePolicyNameTaken, "A policy with this name exists.", nil)
			}
			return err
		}
		v := models.IGAGovRuntimeVersion{ID: uuid.New(), WorkspaceID: ws, PolicyID: pol.ID, VersionNo: 1, Intent: canon,
			IntentHash: hash, Status: runtimeStatusInReview, CreatedBy: actor}
		if err := tx.Create(&v).Error; err != nil {
			return err
		}
		if err := s.event(tx, ws, GovEventRuntimePolicyCreated, &actor, &pol.ID, nil, map[string]any{"name": pol.Name, "family": pol.Family}); err != nil {
			return err
		}
		if err := s.event(tx, ws, GovEventRuntimeVersionCreated, &actor, &pol.ID, &v.ID, map[string]any{"version_no": 1, "intent_hash": hash}); err != nil {
			return err
		}
		var err error
		out, err = s.policyView(tx, ws, pol)
		return err
	})
	return out, err
}

func (s *GovR3) policyView(tx *gorm.DB, ws uuid.UUID, p models.IGAGovPolicy) (*RuntimePolicyView, error) {
	out := &RuntimePolicyView{IGAGovPolicy: p, Versions: []models.IGAGovRuntimeVersion{}}
	if err := tx.Where("workspace_id = ? AND policy_id = ?", ws, p.ID).Order("version_no DESC").Find(&out.Versions).Error; err != nil {
		return nil, err
	}
	for i := range out.Versions {
		v := &out.Versions[i]
		switch v.Status {
		case runtimeStatusApproved:
			out.Approved = v
		case runtimeStatusInReview:
			out.InReview = v
		}
	}
	return out, nil
}

// ListRuntimePolicies lists the workspace's runtime policies.
func (s *GovR3) ListRuntimePolicies(ctx context.Context, ws uuid.UUID) ([]RuntimePolicyView, error) {
	db := s.db.WithContext(ctx)
	var ps []models.IGAGovPolicy
	if err := db.Where("workspace_id = ? AND family = ?", ws, runtimeFamily).Order("name, id").Limit(MaxGovPage).Find(&ps).Error; err != nil {
		return nil, err
	}
	out := make([]RuntimePolicyView, 0, len(ps))
	for _, p := range ps {
		v, err := s.policyView(db, ws, p)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, nil
}

// GetRuntimePolicy reads one runtime policy.
func (s *GovR3) GetRuntimePolicy(ctx context.Context, ws, id uuid.UUID) (*RuntimePolicyView, error) {
	db := s.db.WithContext(ctx)
	p, err := s.loadRuntimePolicy(db, ws, id, false)
	if err != nil {
		return nil, err
	}
	return s.policyView(db, ws, *p)
}

// CreateRuntimeVersion adds the next version (in review), withdrawing the
// version in review it replaces. base_version_no must be the latest.
func (s *GovR3) CreateRuntimeVersion(ctx context.Context, ws, actor, policyID uuid.UUID, req RuntimeVersionRequest) (*models.IGAGovRuntimeVersion, error) {
	_, canon, hash, err := igagov.ParseRuntimeIntent(req.Intent)
	if err != nil {
		return nil, runtimeIntentError(err)
	}
	var out models.IGAGovRuntimeVersion
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		p, err := s.loadRuntimePolicy(tx, ws, policyID, true)
		if err != nil {
			return err
		}
		if p.Lifecycle == "archived" {
			return govConflict(GovCodePolicyArchived, "The policy is archived and read-only.", nil)
		}
		var latest models.IGAGovRuntimeVersion
		if err := tx.Where("workspace_id = ? AND policy_id = ?", ws, policyID).Order("version_no DESC").Limit(1).Take(&latest).Error; err != nil {
			return err
		}
		if req.BaseVersionNo != latest.VersionNo {
			return govConflict(GovCodeVersionConflict, "The policy has a newer version; re-read it and edit that.",
				map[string]any{"base_version_no": req.BaseVersionNo, "current_version_no": latest.VersionNo})
		}
		now := s.now()
		res := tx.Model(&models.IGAGovRuntimeVersion{}).
			Where("workspace_id = ? AND policy_id = ? AND status = ?", ws, policyID, runtimeStatusInReview).
			Updates(map[string]any{"status": runtimeStatusWithdrawn, "status_changed_at": now,
				"decision_reason": fmt.Sprintf("replaced by version %d", latest.VersionNo+1)})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected > 0 {
			if err := s.event(tx, ws, GovEventRuntimeVersionWithdrawn, &actor, &policyID, nil,
				map[string]any{"reason": fmt.Sprintf("replaced by version %d", latest.VersionNo+1)}); err != nil {
				return err
			}
		}
		out = models.IGAGovRuntimeVersion{ID: uuid.New(), WorkspaceID: ws, PolicyID: policyID, VersionNo: latest.VersionNo + 1,
			Intent: canon, IntentHash: hash, Status: runtimeStatusInReview, CreatedBy: actor}
		if err := tx.Create(&out).Error; err != nil {
			return err
		}
		return s.event(tx, ws, GovEventRuntimeVersionCreated, &actor, &policyID, &out.ID,
			map[string]any{"version_no": out.VersionNo, "base_version_no": req.BaseVersionNo, "intent_hash": hash})
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *GovR3) loadRuntimeVersion(tx *gorm.DB, ws, policyID uuid.UUID, no int, lock bool) (*models.IGAGovRuntimeVersion, error) {
	var v models.IGAGovRuntimeVersion
	q := tx.Where("workspace_id = ? AND policy_id = ? AND version_no = ?", ws, policyID, no)
	if lock {
		q = q.Clauses(lockForUpdate())
	}
	if err := q.Take(&v).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	return &v, nil
}

// DecideRuntimeVersion approves or rejects a version in review: the approver
// is never its author (403 self_approval), the intent hash the approver saw
// must be the version's (409 intent_changed), and approving supersedes the
// previously approved version (DECISION R3-2). The route requires
// governance:approve; it is re-read from the database here, as R1a does.
func (s *GovR3) DecideRuntimeVersion(ctx context.Context, ws, approver, policyID uuid.UUID, no int, approve bool, req RuntimeDecisionRequest) (*models.IGAGovRuntimeVersion, error) {
	if !approve && strings.TrimSpace(req.Reason) == "" {
		return nil, GovBadParam("reason", "A rejection needs a reason.")
	}
	if approve && req.IntentHash == "" {
		return nil, GovBadParam("intent_hash", "intent_hash is required (the hash of the version you reviewed).")
	}
	var out *models.IGAGovRuntimeVersion
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		p, err := s.loadRuntimePolicy(tx, ws, policyID, true)
		if err != nil {
			return err
		}
		if p.Lifecycle == "archived" {
			return govConflict(GovCodePolicyArchived, "The policy is archived and read-only.", nil)
		}
		v, err := s.loadRuntimeVersion(tx, ws, policyID, no, true)
		if err != nil {
			return err
		}
		if v.CreatedBy == approver {
			return govErr(http.StatusForbidden, GovCodeSelfApproval, "You authored this version; another approver must decide.", nil)
		}
		if v.Status != runtimeStatusInReview {
			return govConflict(GovCodeVersionConflict, "Only a version in review can be decided.", map[string]any{"status": v.Status})
		}
		ok, err := WorkspaceUserHoldsPermission(tx, ws, approver, "governance", "approve")
		if err != nil {
			return err
		}
		if !ok {
			return GovForbidden("governance:approve is required.")
		}
		now := s.now()
		if !approve {
			if err := tx.Model(&models.IGAGovRuntimeVersion{}).Where("workspace_id = ? AND id = ?", ws, v.ID).
				Updates(map[string]any{"status": runtimeStatusRejected, "decided_by": approver, "decided_at": now,
					"decision_reason": strings.TrimSpace(req.Reason), "status_changed_at": now}).Error; err != nil {
				return err
			}
			if err := s.event(tx, ws, GovEventRuntimeVersionRejected, &approver, &policyID, &v.ID,
				map[string]any{"version_no": no, "reason": strings.TrimSpace(req.Reason)}); err != nil {
				return err
			}
		} else {
			if req.IntentHash != v.IntentHash {
				return govConflict(GovCodeRuntimeIntentChanged, "The version is not the one you reviewed.",
					map[string]any{"intent_hash": v.IntentHash})
			}
			var prev []models.IGAGovRuntimeVersion
			if err := tx.Where("workspace_id = ? AND policy_id = ? AND status = ?", ws, policyID, runtimeStatusApproved).
				Clauses(lockForUpdate()).Find(&prev).Error; err != nil {
				return err
			}
			for _, pv := range prev {
				if err := tx.Model(&models.IGAGovRuntimeVersion{}).Where("workspace_id = ? AND id = ?", ws, pv.ID).
					Updates(map[string]any{"status": runtimeStatusSuperseded, "status_changed_at": now}).Error; err != nil {
					return err
				}
			}
			if err := tx.Model(&models.IGAGovRuntimeVersion{}).Where("workspace_id = ? AND id = ?", ws, v.ID).
				Updates(map[string]any{"status": runtimeStatusApproved, "decided_by": approver, "decided_at": now,
					"decision_reason": req.Reason, "approved_intent_hash": v.IntentHash, "status_changed_at": now}).Error; err != nil {
				return err
			}
			superseded := make([]int, 0, len(prev))
			for _, pv := range prev {
				superseded = append(superseded, pv.VersionNo)
			}
			if err := s.event(tx, ws, GovEventRuntimeVersionApproved, &approver, &policyID, &v.ID,
				map[string]any{"version_no": no, "intent_hash": v.IntentHash, "superseded_version_nos": superseded, "reason": req.Reason}); err != nil {
				return err
			}
		}
		var err2 error
		out, err2 = s.loadRuntimeVersion(tx, ws, policyID, no, false)
		return err2
	})
	return out, err
}

// WithdrawRuntimeVersion withdraws a version in review (governance:author).
func (s *GovR3) WithdrawRuntimeVersion(ctx context.Context, ws, actor, policyID uuid.UUID, no int, reason string) (*models.IGAGovRuntimeVersion, error) {
	var out *models.IGAGovRuntimeVersion
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := s.loadRuntimePolicy(tx, ws, policyID, true); err != nil {
			return err
		}
		v, err := s.loadRuntimeVersion(tx, ws, policyID, no, true)
		if err != nil {
			return err
		}
		if v.Status != runtimeStatusInReview {
			return govConflict(GovCodeVersionConflict, "Only a version in review can be withdrawn.", map[string]any{"status": v.Status})
		}
		if err := tx.Model(&models.IGAGovRuntimeVersion{}).Where("workspace_id = ? AND id = ?", ws, v.ID).
			Updates(map[string]any{"status": runtimeStatusWithdrawn, "decision_reason": reason, "status_changed_at": s.now()}).Error; err != nil {
			return err
		}
		if err := s.event(tx, ws, GovEventRuntimeVersionWithdrawn, &actor, &policyID, &v.ID, map[string]any{"version_no": no, "reason": reason}); err != nil {
			return err
		}
		out, err = s.loadRuntimeVersion(tx, ws, policyID, no, false)
		return err
	})
	return out, err
}

// approvedRuntimeVersion is a policy's approved version and its intent.
func (s *GovR3) approvedRuntimeVersion(tx *gorm.DB, ws, policyID uuid.UUID) (*models.IGAGovRuntimeVersion, *igagov.RuntimeIntent, error) {
	var v models.IGAGovRuntimeVersion
	if err := tx.Where("workspace_id = ? AND policy_id = ? AND status = ?", ws, policyID, runtimeStatusApproved).Take(&v).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, govConflict(GovCodeNoApprovedVersion, "The policy has no approved version.", nil)
		}
		return nil, nil, err
	}
	in, _, _, err := igagov.ParseRuntimeIntent(v.Intent)
	if err != nil {
		return nil, nil, err
	}
	return &v, in, nil
}

// RuntimeCedar is the compiled Cedar of one version for one gateway.
type RuntimeCedar struct {
	PolicyID    uuid.UUID            `json:"policy_id"`
	VersionNo   int                  `json:"version_no"`
	IntentHash  string               `json:"intent_hash"`
	GatewayARN  string               `json:"gateway_arn"`
	CedarHash   string               `json:"cedar_hash"`
	Policies    []igagov.CedarPolicy `json:"policies"`
	NotCompiled []string             `json:"not_compiled"`
	Verified    bool                 `json:"verified"`
}

// CompileRuntimeCedar compiles a version's allow-list for a gateway (an
// export the customer may apply themselves). UNVERIFIED Cedar shape.
func (s *GovR3) CompileRuntimeCedar(ctx context.Context, ws, policyID uuid.UUID, no int, gatewayARN string) (*RuntimeCedar, error) {
	db := s.db.WithContext(ctx)
	if _, err := s.loadRuntimePolicy(db, ws, policyID, false); err != nil {
		return nil, err
	}
	v, err := s.loadRuntimeVersion(db, ws, policyID, no, false)
	if err != nil {
		return nil, err
	}
	in, _, _, err := igagov.ParseRuntimeIntent(v.Intent)
	if err != nil {
		return nil, err
	}
	if igagov.GatewayAccount(gatewayARN) == "" {
		return nil, GovBadParam("gateway_arn", "gateway_arn must be an AgentCore gateway ARN.")
	}
	return runtimeCedar(policyID, v, in, gatewayARN)
}

func runtimeCedar(policyID uuid.UUID, v *models.IGAGovRuntimeVersion, in *igagov.RuntimeIntent, gatewayARN string) (*RuntimeCedar, error) {
	ps := igagov.CompileCedar(policyID.String(), in, gatewayARN)
	raw, err := igagov.CanonicalizeValue(ps)
	if err != nil {
		return nil, err
	}
	var not []string
	for _, t := range in.Tools {
		if len(t.Actions) > 0 || len(t.Targets) > 0 {
			not = append(not, t.Tool+": actions/targets narrowing (enforced at AuthSec's decide only)")
		}
		if t.RequireApproval {
			not = append(not, t.Tool+": require_approval (enforced at AuthSec's decide only)")
		}
	}
	if len(in.Budgets) > 0 {
		not = append(not, "budgets (enforced at AuthSec's decide only)")
	}
	if not == nil {
		not = []string{}
	}
	return &RuntimeCedar{PolicyID: policyID, VersionNo: v.VersionNo, IntentHash: v.IntentHash, GatewayARN: gatewayARN,
		CedarHash: igagov.ContentHash(raw), Policies: ps, NotCompiled: not, Verified: false}, nil
}

/* ---------------------------------------------------------------------------- */
/*                                   Settings                                   */
/* ---------------------------------------------------------------------------- */

// RuntimeSettingsPatch is PUT /runtime/settings (absent fields unchanged).
type RuntimeSettingsPatch struct {
	ArgumentRetention    *string   `json:"argument_retention"`
	RedactKeys           *[]string `json:"redact_keys"`
	RetentionDays        *int      `json:"retention_days"`
	DecisionTTLSeconds   *int      `json:"decision_ttl_seconds"`
	HoldTimeoutMinutes   *int      `json:"hold_timeout_minutes"`
	ApprovalValidMinutes *int      `json:"approval_valid_minutes"`
}

func defaultRuntimeSettings(ws uuid.UUID) models.IGAGovRuntimeSettings {
	return models.IGAGovRuntimeSettings{WorkspaceID: ws, ArgumentRetention: "digest_only", RedactKeys: json.RawMessage(`[]`),
		RetentionDays: 30, DecisionTTLSeconds: 60, HoldTimeoutMinutes: 60, ApprovalValidMinutes: 15}
}

// RuntimeSettings reads the workspace's runtime settings (defaults when
// none were saved).
func (s *GovR3) RuntimeSettings(ctx context.Context, ws uuid.UUID) (models.IGAGovRuntimeSettings, error) {
	return s.runtimeSettingsTx(s.db.WithContext(ctx), ws)
}

func (s *GovR3) runtimeSettingsTx(tx *gorm.DB, ws uuid.UUID) (models.IGAGovRuntimeSettings, error) {
	var st models.IGAGovRuntimeSettings
	err := tx.Where("workspace_id = ?", ws).Take(&st).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return defaultRuntimeSettings(ws), nil
	}
	return st, err
}

// PutRuntimeSettings updates the settings (governance:enforce).
func (s *GovR3) PutRuntimeSettings(ctx context.Context, ws, actor uuid.UUID, p RuntimeSettingsPatch) (before, after models.IGAGovRuntimeSettings, err error) {
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		cur, err := s.runtimeSettingsTx(tx.Clauses(lockForUpdate()), ws)
		if err != nil {
			return err
		}
		before = cur
		if p.ArgumentRetention != nil {
			if *p.ArgumentRetention != "digest_only" && *p.ArgumentRetention != "redacted" {
				return GovBadParam("argument_retention", "digest_only or redacted.")
			}
			cur.ArgumentRetention = *p.ArgumentRetention
		}
		if p.RedactKeys != nil {
			if len(*p.RedactKeys) > 100 {
				return GovBadParam("redact_keys", "At most 100 keys.")
			}
			raw, _ := json.Marshal(*p.RedactKeys)
			cur.RedactKeys = raw
		}
		rng := func(v *int, field string, lo, hi int, dst *int) error {
			if v == nil {
				return nil
			}
			if *v < lo || *v > hi {
				return GovBadParam(field, fmt.Sprintf("%s must be %d..%d.", field, lo, hi))
			}
			*dst = *v
			return nil
		}
		for _, e := range []error{
			rng(p.RetentionDays, "retention_days", 1, 400, &cur.RetentionDays),
			rng(p.DecisionTTLSeconds, "decision_ttl_seconds", 5, 300, &cur.DecisionTTLSeconds),
			rng(p.HoldTimeoutMinutes, "hold_timeout_minutes", 1, 10080, &cur.HoldTimeoutMinutes),
			rng(p.ApprovalValidMinutes, "approval_valid_minutes", 1, 1440, &cur.ApprovalValidMinutes),
		} {
			if e != nil {
				return e
			}
		}
		cur.UpdatedBy, cur.UpdatedAt = &actor, s.now()
		if err := tx.Save(&cur).Error; err != nil {
			return err
		}
		after = cur
		return s.event(tx, ws, GovEventRuntimeSettingsUpdated, &actor, nil, nil, map[string]any{
			"argument_retention": cur.ArgumentRetention, "retention_days": cur.RetentionDays,
			"decision_ttl_seconds": cur.DecisionTTLSeconds, "hold_timeout_minutes": cur.HoldTimeoutMinutes,
			"approval_valid_minutes": cur.ApprovalValidMinutes, "redact_key_count": len(redactKeys(cur))})
	})
	return before, after, err
}

func redactKeys(st models.IGAGovRuntimeSettings) []string {
	var keys []string
	_ = json.Unmarshal(st.RedactKeys, &keys)
	return keys
}

/* ---------------------------------------------------------------------------- */
/*                                Routing proofs                                */
/* ---------------------------------------------------------------------------- */

// RoutingProofRequest is POST /runtime/routing-proofs.
type RoutingProofRequest struct {
	GatewayARN string          `json:"gateway_arn"`
	Method     string          `json:"method"`
	Statement  string          `json:"statement"`
	Evidence   json.RawMessage `json:"evidence"`
	ValidDays  int             `json:"valid_days"`
}

// RecordRoutingProof records that a gateway is the only route to its tools
// (governance:enforce). AuthSec does not verify the evidence; it records who
// asserted what, when, and until when (§12.4 lab contract 3).
func (s *GovR3) RecordRoutingProof(ctx context.Context, ws, actor uuid.UUID, req RoutingProofRequest) (*models.IGAGovRuntimeRoutingProof, error) {
	acct := igagov.GatewayAccount(req.GatewayARN)
	if acct == "" {
		return nil, GovBadParam("gateway_arn", "gateway_arn must be an AgentCore gateway ARN.")
	}
	switch req.Method {
	case "lab_probe", "network_isolation", "customer_attestation":
	default:
		return nil, GovBadParam("method", "lab_probe, network_isolation or customer_attestation.")
	}
	if strings.TrimSpace(req.Statement) == "" || len(req.Statement) > 4000 {
		return nil, GovBadParam("statement", "A statement of what was proven (1..4000 characters) is required.")
	}
	if req.ValidDays == 0 {
		req.ValidDays = 30
	}
	if req.ValidDays < 1 || req.ValidDays > 90 {
		return nil, GovBadParam("valid_days", "valid_days must be 1..90.")
	}
	ev := req.Evidence
	if len(ev) == 0 {
		ev = json.RawMessage(`{}`)
	}
	canon, err := igagov.Canonicalize(ev)
	if err != nil || !strings.HasPrefix(string(canon), "{") || len(canon) > 65536 {
		return nil, govUnprocessable(GovCodeRoutingProofInvalid, "evidence must be a JSON object of at most 64 KiB.", nil)
	}
	now := s.now()
	p := models.IGAGovRuntimeRoutingProof{ID: uuid.New(), WorkspaceID: ws, GatewayARN: req.GatewayARN, AccountID: acct,
		Method: req.Method, Statement: strings.TrimSpace(req.Statement), Evidence: canon, EvidenceHash: igagov.ContentHash(canon),
		RecordedBy: actor, RecordedAt: now, ValidUntil: now.Add(time.Duration(req.ValidDays) * 24 * time.Hour)}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&p).Error; err != nil {
			return err
		}
		return s.event(tx, ws, GovEventRoutingProofRecorded, &actor, nil, nil, map[string]any{"routing_proof_id": p.ID,
			"gateway_arn": p.GatewayARN, "method": p.Method, "evidence_hash": p.EvidenceHash, "valid_until": p.ValidUntil})
	})
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// ListRoutingProofs lists the workspace's routing proofs.
func (s *GovR3) ListRoutingProofs(ctx context.Context, ws uuid.UUID, gatewayARN string) ([]models.IGAGovRuntimeRoutingProof, error) {
	q := s.db.WithContext(ctx).Where("workspace_id = ?", ws)
	if gatewayARN != "" {
		q = q.Where("gateway_arn = ?", gatewayARN)
	}
	out := []models.IGAGovRuntimeRoutingProof{}
	err := q.Order("recorded_at DESC").Limit(MaxGovPage).Find(&out).Error
	return out, err
}

// RevokeRoutingProof revokes a proof (governance:enforce).
func (s *GovR3) RevokeRoutingProof(ctx context.Context, ws, actor, id uuid.UUID, reason string) (*models.IGAGovRuntimeRoutingProof, error) {
	var p models.IGAGovRuntimeRoutingProof
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("workspace_id = ? AND id = ?", ws, id).Clauses(lockForUpdate()).Take(&p).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return GovNotFound()
			}
			return err
		}
		if p.RevokedAt != nil {
			return govConflict(GovCodeNotPending, "The proof is already revoked.", nil)
		}
		now := s.now()
		if err := tx.Model(&p).Where("workspace_id = ? AND id = ?", ws, id).
			Updates(map[string]any{"revoked_at": now, "revoked_by": actor, "revoke_reason": reason}).Error; err != nil {
			return err
		}
		p.RevokedAt, p.RevokedBy, p.RevokeReason = &now, &actor, reason
		return s.event(tx, ws, GovEventRoutingProofRevoked, &actor, nil, nil, map[string]any{"routing_proof_id": id,
			"gateway_arn": p.GatewayARN, "reason": reason})
	})
	if err != nil {
		return nil, err
	}
	return &p, nil
}

/* ---------------------------------------------------------------------------- */
/*                           AgentCore push and coverage                         */
/* ---------------------------------------------------------------------------- */

// AgentCoreFactory builds the AgentCore client for one account and region.
type AgentCoreFactory func(ctx context.Context, ws uuid.UUID, accountID, region string) (agentcore.Client, error)

var (
	agentCoreMu      sync.RWMutex
	agentCoreFactory AgentCoreFactory
)

// SetRuntimeAgentCoreFactory installs the AgentCore client factory (nil
// uninstalls). DECISION R3-11: production installs NONE in this build -- no
// AuthSec role template grants bedrock-agentcore policy writes, and the API
// surface is lab contract 1 -- so a push answers 422 agentcore_unavailable and
// the compiled Cedar is offered as an export instead. Tests and lab runs
// install a factory (agentcore.NewFake, or agentcore.NewLiveFromConfig).
func SetRuntimeAgentCoreFactory(f AgentCoreFactory) {
	agentCoreMu.Lock()
	defer agentCoreMu.Unlock()
	agentCoreFactory = f
}

func currentAgentCoreFactory() AgentCoreFactory {
	agentCoreMu.RLock()
	defer agentCoreMu.RUnlock()
	return agentCoreFactory
}

// RuntimeAgentCoreAvailable reports whether this process can push to
// AgentCore.
func RuntimeAgentCoreAvailable() (bool, string) {
	if currentAgentCoreFactory() == nil {
		return false, "No AgentCore write credential is configured on this server (no AuthSec role template grants bedrock-agentcore policy writes; §12.4 lab contract 1 is open). Export the compiled Cedar instead."
	}
	return true, ""
}

// AgentCorePushRequest is POST /runtime/policies/:id/agentcore/push.
type AgentCorePushRequest struct {
	GatewayARN string `json:"gateway_arn"`
}

func gatewayRegion(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 4 {
		return ""
	}
	return parts[3]
}

// PushAgentCore compiles the approved version's allow-list, pushes it to the
// gateway's policy engine (named in the intent), reads it back and records
// the result (governance:enforce). UNVERIFIED against AWS.
func (s *GovR3) PushAgentCore(ctx context.Context, ws, actor, policyID uuid.UUID, req AgentCorePushRequest) (*models.IGAGovRuntimeAgentCorePush, error) {
	f := currentAgentCoreFactory()
	if f == nil {
		_, why := RuntimeAgentCoreAvailable()
		return nil, govUnprocessable(GovCodeAgentCoreUnavailable, "AgentCore push is not available on this server.", map[string]any{"reason": why})
	}
	db := s.db.WithContext(ctx)
	if _, err := s.loadRuntimePolicy(db, ws, policyID, false); err != nil {
		return nil, err
	}
	v, in, err := s.approvedRuntimeVersion(db, ws, policyID)
	if err != nil {
		return nil, err
	}
	var gw *igagov.RuntimeGateway
	for i := range in.Gateways {
		if in.Gateways[i].GatewayARN == req.GatewayARN {
			gw = &in.Gateways[i]
		}
	}
	if gw == nil {
		return nil, govUnprocessable(GovCodeGatewayNotInPolicy, "The approved version does not name this gateway.", nil)
	}
	compiled, err := runtimeCedar(policyID, v, in, gw.GatewayARN)
	if err != nil {
		return nil, err
	}
	cedarRaw, _ := json.Marshal(compiled.Policies)
	row := models.IGAGovRuntimeAgentCorePush{ID: uuid.New(), WorkspaceID: ws, PolicyID: policyID, VersionID: v.ID,
		GatewayARN: gw.GatewayARN, PolicyEngineID: gw.PolicyEngineID, Cedar: cedarRaw, CedarHash: compiled.CedarHash,
		Remote: json.RawMessage(`[]`), PushedBy: actor}
	client, err := f(ctx, ws, igagov.GatewayAccount(gw.GatewayARN), gatewayRegion(gw.GatewayARN))
	var pushRes *agentcore.PushResult
	if err == nil {
		pushRes, err = agentcore.Push(ctx, client, gw.PolicyEngineID, igagov.CedarPolicyPrefix(policyID.String()),
			"AuthSec runtime policy "+policyID.String()+" v"+fmt.Sprint(v.VersionNo), compiled.Policies)
	}
	event := GovEventAgentCorePushed
	if err != nil {
		row.State, row.Error, event = "failed", truncate(err.Error(), 2000), GovEventAgentCorePushFailed
	} else {
		match, remote, diffs, rerr := agentcore.Readback(ctx, client, gw.PolicyEngineID, igagov.CedarPolicyPrefix(policyID.String()), compiled.Policies)
		now := s.now()
		row.ReadbackAt = &now
		switch {
		case rerr != nil:
			row.State, row.Error = "pushed", "readback failed: "+truncate(rerr.Error(), 1900)
		case match:
			row.State = "readback_match"
		default:
			row.State, row.Error = "readback_mismatch", strings.Join(diffs, "; ")
		}
		if raw, merr := json.Marshal(remote); merr == nil && remote != nil {
			row.Remote = raw
		}
		if g, gerr := client.GetGateway(ctx, igagov.GatewayID(gw.GatewayARN)); gerr == nil {
			row.GatewayMode = g.Mode
		}
	}
	terr := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		payload := map[string]any{"push_id": row.ID, "gateway_arn": row.GatewayARN, "policy_engine_id": row.PolicyEngineID,
			"cedar_hash": row.CedarHash, "state": row.State, "gateway_mode": row.GatewayMode, "verified_against_aws": false}
		if pushRes != nil {
			payload["created"], payload["updated"], payload["deleted"] = pushRes.Created, pushRes.Updated, pushRes.Deleted
		}
		if row.Error != "" {
			payload["error"] = row.Error
		}
		return s.event(tx, ws, event, &actor, &policyID, &v.ID, payload)
	})
	if terr != nil {
		return nil, terr
	}
	if err != nil {
		return &row, govErr(http.StatusBadGateway, GovCodeAgentCoreFailed, "The AgentCore push failed; nothing is claimed.",
			map[string]any{"push_id": row.ID, "error": row.Error})
	}
	return &row, nil
}

// RuntimeControlCoverage is one control's coverage (R-04).
type RuntimeControlCoverage struct {
	Control    string   `json:"control"`
	Coverage   string   `json:"coverage"`
	EnforcedAt string   `json:"enforced_at"`
	Reasons    []string `json:"reasons"`
}

// RuntimeGatewayCoverage is one gateway of a policy.
type RuntimeGatewayCoverage struct {
	GatewayARN     string                             `json:"gateway_arn"`
	PolicyEngineID string                             `json:"policy_engine_id"`
	LastPush       *models.IGAGovRuntimeAgentCorePush `json:"last_push,omitempty"`
	RoutingProof   *models.IGAGovRuntimeRoutingProof  `json:"routing_proof,omitempty"`
	Controls       []RuntimeControlCoverage           `json:"controls"`
}

// RuntimePolicyCoverage is the coverage of one approved runtime policy.
type RuntimePolicyCoverage struct {
	PolicyID   uuid.UUID                `json:"policy_id"`
	Name       string                   `json:"name"`
	VersionNo  int                      `json:"version_no"`
	IntentHash string                   `json:"intent_hash"`
	Lifecycle  string                   `json:"lifecycle"`
	Gateways   []RuntimeGatewayCoverage `json:"gateways"`
	// AuthSecDecide is what AuthSec's own decide endpoint covers: every
	// control, but only for agents that call it (advisory, R-04).
	AuthSecDecide  []RuntimeControlCoverage `json:"authsec_decide"`
	AlternatePaths []string                 `json:"alternate_paths"`
}

// RuntimeCoverage reports, per approved runtime policy and gateway, whether
// each control is enforced or advisory (DECISION R3-11). It never claims
// enforcement without a recorded, unexpired, unrevoked routing proof.
func (s *GovR3) RuntimeCoverage(ctx context.Context, ws uuid.UUID) ([]RuntimePolicyCoverage, error) {
	db := s.db.WithContext(ctx)
	var ps []models.IGAGovPolicy
	if err := db.Where("workspace_id = ? AND family = ?", ws, runtimeFamily).Order("name, id").Limit(MaxGovPage).Find(&ps).Error; err != nil {
		return nil, err
	}
	now := s.now()
	out := []RuntimePolicyCoverage{}
	for _, p := range ps {
		v, in, err := s.approvedRuntimeVersion(db, ws, p.ID)
		if err != nil {
			var ge *GovError
			if errors.As(err, &ge) {
				continue
			}
			return nil, err
		}
		pc := RuntimePolicyCoverage{PolicyID: p.ID, Name: p.Name, VersionNo: v.VersionNo, IntentHash: v.IntentHash,
			Lifecycle: p.Lifecycle, Gateways: []RuntimeGatewayCoverage{},
			AlternatePaths: []string{
				"An agent holding its own cloud or tool credentials can call tools without the gateway or AuthSec; unless a routing proof covers the gateway, every control is advisory (R-01, R-04).",
				"AuthSec's decide endpoint is consulted only by agents (or SDKs) that call it; an optional SDK is not mandatory enforcement.",
			}}
		controls := []string{"allow_list"}
		hasApproval := false
		for _, t := range in.Tools {
			hasApproval = hasApproval || t.RequireApproval
		}
		if hasApproval {
			controls = append(controls, "approval")
		}
		if len(in.Budgets) > 0 {
			controls = append(controls, "budget")
		}
		for _, c := range controls {
			pc.AuthSecDecide = append(pc.AuthSecDecide, RuntimeControlCoverage{Control: c, Coverage: runtimeCoverageAdvisory,
				EnforcedAt: "authsec_decide", Reasons: []string{"enforced only for agents that call AuthSec's decide endpoint (no proven mandatory interceptor)"}})
		}
		for _, gw := range in.Gateways {
			gc := RuntimeGatewayCoverage{GatewayARN: gw.GatewayARN, PolicyEngineID: gw.PolicyEngineID}
			var push models.IGAGovRuntimeAgentCorePush
			perr := db.Where("workspace_id = ? AND policy_id = ? AND gateway_arn = ?", ws, p.ID, gw.GatewayARN).
				Order("created_at DESC").Limit(1).Take(&push).Error
			if perr == nil {
				gc.LastPush = &push
			} else if !errors.Is(perr, gorm.ErrRecordNotFound) {
				return nil, perr
			}
			var proof models.IGAGovRuntimeRoutingProof
			rerr := db.Where("workspace_id = ? AND gateway_arn = ? AND revoked_at IS NULL AND valid_until > ?", ws, gw.GatewayARN, now).
				Order("recorded_at DESC").Limit(1).Take(&proof).Error
			if rerr == nil {
				gc.RoutingProof = &proof
			} else if !errors.Is(rerr, gorm.ErrRecordNotFound) {
				return nil, rerr
			}
			for _, c := range controls {
				cc := RuntimeControlCoverage{Control: c, Coverage: runtimeCoverageAdvisory, EnforcedAt: "agentcore_gateway", Reasons: []string{}}
				if c != "allow_list" {
					cc.EnforcedAt = "authsec_decide"
					cc.Reasons = append(cc.Reasons, c+" is not expressible in the gateway's Cedar policy; it is enforced only at AuthSec's decide endpoint")
					gc.Controls = append(gc.Controls, cc)
					continue
				}
				switch {
				case gc.LastPush == nil:
					cc.Coverage = runtimeCoverageNotConfigured
					cc.Reasons = append(cc.Reasons, "the allow-list has not been pushed to this gateway's policy engine")
				case gc.LastPush.VersionID != v.ID:
					cc.Reasons = append(cc.Reasons, "the last push was of another version")
				case gc.LastPush.State != "readback_match":
					cc.Reasons = append(cc.Reasons, "the last push did not read back equal ("+gc.LastPush.State+")")
				case gc.LastPush.GatewayMode != "ENFORCE":
					cc.Reasons = append(cc.Reasons, "the gateway's policy engine is not in ENFORCE mode ("+r3OrNone(gc.LastPush.GatewayMode)+")")
				case gc.RoutingProof == nil:
					cc.Reasons = append(cc.Reasons, "no routing proof shows the gateway is the only route to its tools")
				default:
					cc.Coverage = runtimeCoverageEnforced
					cc.Reasons = append(cc.Reasons, "pushed and read back equal, ENFORCE mode, routing proof "+gc.RoutingProof.ID.String()+
						" ("+gc.RoutingProof.Method+") valid until "+gc.RoutingProof.ValidUntil.UTC().Format(time.RFC3339))
				}
				if p.Lifecycle != "active" {
					cc.Coverage = runtimeCoverageAdvisory
					cc.Reasons = append(cc.Reasons, "the policy is "+p.Lifecycle)
				}
				gc.Controls = append(gc.Controls, cc)
			}
			pc.Gateways = append(pc.Gateways, gc)
		}
		out = append(out, pc)
	}
	return out, nil
}

func r3OrNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

/* ---------------------------------------------------------------------------- */
/*                                  Broker roles                                */
/* ---------------------------------------------------------------------------- */

// BrokerRoleRequest is POST /runtime/broker-roles.
type BrokerRoleRequest struct {
	ConnectorID       string `json:"connector_id"`
	RoleARN           string `json:"role_arn"`
	MaxSessionSeconds int    `json:"max_session_seconds"`
}

// BindBrokerRole opts a role in to brokered sessions (governance:enforce):
// the role must be in the account of an active AWS connector of the
// workspace (DECISION R3-12).
func (s *GovR3) BindBrokerRole(ctx context.Context, ws, actor uuid.UUID, req BrokerRoleRequest) (*models.IGAGovRuntimeBrokerRole, error) {
	cid, err := uuid.Parse(req.ConnectorID)
	if err != nil {
		return nil, GovBadParam("connector_id", "connector_id must be a uuid.")
	}
	acct := igagov.RoleAccount(req.RoleARN)
	if acct == "" {
		return nil, GovBadParam("role_arn", "role_arn must be an IAM role ARN.")
	}
	if req.MaxSessionSeconds == 0 {
		req.MaxSessionSeconds = 900
	}
	if req.MaxSessionSeconds < 900 || req.MaxSessionSeconds > igagov.MaxBrokerSeconds {
		return nil, GovBadParam("max_session_seconds", "max_session_seconds must be 900..3600.")
	}
	c, err := repositories.NewCloudConnectorRepository(s.db.WithContext(ctx)).Get(ws, cid)
	if err != nil {
		if errors.Is(err, repositories.ErrCloudConnectorNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	if c.Provider != models.CloudProviderAWS || c.Status != models.CloudConnectorActive || c.ScopeID != acct {
		return nil, govUnprocessable(GovCodeBrokerConnector, "The role must be in the account of an active AWS connector.",
			map[string]any{"connector_account": c.ScopeID, "role_account": acct, "connector_status": c.Status})
	}
	row := models.IGAGovRuntimeBrokerRole{ID: uuid.New(), WorkspaceID: ws, ConnectorID: cid, AccountID: acct, RoleARN: req.RoleARN,
		MaxSessionSeconds: req.MaxSessionSeconds, State: "active", CreatedBy: actor}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&row).Error; err != nil {
			if isUniqueViolation(err, "uq_iga_gov_runtime_broker_role_live") {
				return govConflict(GovCodeBrokerRoleExists, "The role is already bound for brokered sessions.", nil)
			}
			return err
		}
		return s.event(tx, ws, GovEventBrokerRoleBound, &actor, nil, nil, map[string]any{"broker_role_id": row.ID,
			"role_arn": row.RoleARN, "account_id": acct, "max_session_seconds": row.MaxSessionSeconds})
	})
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// ListBrokerRoles lists the workspace's broker roles.
func (s *GovR3) ListBrokerRoles(ctx context.Context, ws uuid.UUID) ([]models.IGAGovRuntimeBrokerRole, error) {
	out := []models.IGAGovRuntimeBrokerRole{}
	err := s.db.WithContext(ctx).Where("workspace_id = ?", ws).Order("created_at DESC").Limit(MaxGovPage).Find(&out).Error
	return out, err
}

// DisableBrokerRole stops brokering for a role (governance:enforce). Sessions
// already issued live until their expiry (at most one hour).
func (s *GovR3) DisableBrokerRole(ctx context.Context, ws, actor, id uuid.UUID, reason string) (*models.IGAGovRuntimeBrokerRole, error) {
	var row models.IGAGovRuntimeBrokerRole
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("workspace_id = ? AND id = ?", ws, id).Clauses(lockForUpdate()).Take(&row).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return GovNotFound()
			}
			return err
		}
		if row.State != "active" {
			return govConflict(GovCodeNotPending, "The broker role is already disabled.", nil)
		}
		now := s.now()
		if err := tx.Model(&row).Where("workspace_id = ? AND id = ?", ws, id).
			Updates(map[string]any{"state": "disabled", "disabled_by": actor, "disabled_at": now, "updated_at": now}).Error; err != nil {
			return err
		}
		row.State, row.DisabledBy, row.DisabledAt = "disabled", &actor, &now
		return s.event(tx, ws, GovEventBrokerRoleDisabled, &actor, nil, nil, map[string]any{"broker_role_id": id,
			"role_arn": row.RoleARN, "reason": reason})
	})
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// r3SHA256 is "sha256:<hex>" of s.
func r3SHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}
