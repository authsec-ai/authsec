package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// R2 temporary grants and session revocations (SPEC-iga-phase3-policy.md
// §12.3, requirements C-10, E-09; DECISION R2-8..R2-12, R2-17, R2-18).
//
//	temporary grant      requested --approve (governance:grant, not the requester)--> approved
//	                     --temp_grant job: binding v2 gate--> deploying --CreatePolicy, AttachRolePolicy,
//	                     readback--> active (verified; drift checked every 10 min) --expires_at, or revoke-->
//	                     expiring --DetachRolePolicy, DeletePolicy, readback--> expired | revoked
//	session revocation   requested --approve (governance:approve, not the requester), or the emergency
//	                     path (governance:emergency, reason, notified)--> approved (cutoff fixed)
//	                     --session_revoke job--> deploying --> active --remove_after, or lift--> removing --> removed
//
// Any state may meet outcome_unknown (a write without an answer, held until
// settle_after) and failed (terminal, with the reason). Every mutation writes
// an iga_gov_event in its transaction; the routes write audit_events.

// Event names (vocabulary: iga_gov_event_vocabulary.go).
const (
	GovEventGrantRequested   = "temporary_grant.requested"
	GovEventGrantApproved    = "temporary_grant.approved"
	GovEventGrantRejected    = "temporary_grant.rejected"
	GovEventGrantCancelled   = "temporary_grant.cancelled"
	GovEventGrantRevokeReq   = "temporary_grant.revoke_requested"
	GovEventGrantActive      = "temporary_grant.active"
	GovEventGrantEnded       = "temporary_grant.ended"
	GovEventGrantFailed      = "temporary_grant.failed"
	GovEventGrantUnknown     = "temporary_grant.outcome_unknown"
	GovEventGrantDrifted     = "temporary_grant.drifted"
	GovEventRevocationReq    = "session_revocation.requested"
	GovEventRevocationEmerg  = "session_revocation.emergency"
	GovEventRevocationAppr   = "session_revocation.approved"
	GovEventRevocationRej    = "session_revocation.rejected"
	GovEventRevocationCancel = "session_revocation.cancelled"
	GovEventRevocationLift   = "session_revocation.lift_requested"
	GovEventRevocationActive = "session_revocation.active"
	GovEventRevocationEnded  = "session_revocation.removed"
	GovEventRevocationFailed = "session_revocation.failed"
	GovEventRevocationUnk    = "session_revocation.outcome_unknown"
	GovEventRevocationDrift  = "session_revocation.drifted"
)

// R2 error codes.
const (
	GovCodeGrantExists       = "grant_exists"
	GovCodeRevocationExists  = "revocation_exists"
	GovCodeNotPending        = "not_pending"
	GovCodeNotEndable        = "not_endable"
	GovCodeEscalationAck     = "escalation_acknowledgement_required"
	GovCodeGrantInvalid      = "grant_invalid"
	GovCodeGrantExpired      = "grant_expired"
	GovCodeRoleIneligible    = "role_ineligible"
	GovCodeRequestTampered   = "request_hash_mismatch"
	r2ActiveCheckEvery       = 10 * time.Minute
	r2MinLeadBeforeApproval  = 5 * time.Minute
	r2EndReasonExpired       = "expired"
	r2EndReasonRevoked       = "revoked"
	r2EndReasonLifted        = "lifted"
	r2EndReasonNeverDeployed = "expired_before_deploy"
)

// GovR2 is the R2 service (requests, decisions, jobs). Every statement runs
// in a transaction under row-level security for one workspace: the token's
// (tenancy.InWorkspace / InWorkspaceRead) or the job's (run.InTx / ReadTx).
// Only the schedules' due scans span workspaces.
type GovR2 struct {
	db      *gorm.DB
	targets *GovTargets
	now     func() time.Time
}

// NewGovR2 builds the service.
func NewGovR2(db *gorm.DB) *GovR2 {
	return &GovR2{db: db, targets: NewGovTargets(db), now: time.Now}
}

// GovR2RoleKey names the role an R2 request is about: a graph identity, or
// an AWS role ARN with its account.
type GovR2RoleKey struct {
	IdentityAccountID string `json:"identity_account_id,omitempty"`
	RoleARN           string `json:"role_arn,omitempty"`
	AccountID         string `json:"account_id,omitempty"`
}

type r2Role struct {
	Identity  ResolvedIdentity
	Connector uuid.UUID
}

// resolveRole resolves the key in the TOKEN's workspace (§2.12): another
// workspace's role is 404; an ineligible role (service-linked, AWS reserved,
// AuthSec's own, authsec:protected, recognition-only) is 422.
func (s *GovR2) resolveRole(ctx context.Context, ws uuid.UUID, k GovR2RoleKey) (*r2Role, error) {
	key := TargetKey{ObjectID: k.IdentityAccountID}
	if k.IdentityAccountID == "" {
		if k.RoleARN == "" || k.AccountID == "" {
			return nil, GovBadParam("role", "Name the role by identity_account_id, or by role_arn and account_id.")
		}
		key = TargetKey{Provider: "aws", RoleARN: k.RoleARN, AccountID: k.AccountID}
	} else if _, err := uuid.Parse(k.IdentityAccountID); err != nil {
		return nil, GovBadParam("identity_account_id", "identity_account_id must be a uuid.")
	}
	res, err := s.targets.Resolve(ctx, ws, []TargetKey{key})
	if err != nil {
		return nil, err
	}
	if len(res) != 1 || res[0].Status != TargetResolved || res[0].Identity == nil {
		return nil, GovNotFound()
	}
	t := res[0]
	if !t.Eligible {
		return nil, govUnprocessable(GovCodeRoleIneligible, "AuthSec does not change this role.", map[string]any{"reasons": t.IneligibleReasons})
	}
	var conn uuid.UUID
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		conn, err = connectorForAccount(tx, ws, t.Identity.AccountID)
		return err
	}); err != nil {
		return nil, err
	}
	if conn == uuid.Nil {
		return nil, govUnprocessable(GovCodeRoleIneligible, "The role's AWS account has no connector.", map[string]any{"reasons": []string{"no_connector_for_account"}})
	}
	return &r2Role{Identity: *t.Identity, Connector: conn}, nil
}

// appendEvent is the R2 event writer (the vocabulary scan reads its third
// argument, as for appendGovEvent).
func appendEvent(tx *gorm.DB, ws uuid.UUID, name string, actor *uuid.UUID, payload map[string]any) error {
	kind, id := models.GovActorSystem, "policy-worker"
	if actor != nil {
		kind, id = userActor(*actor)
	}
	return appendGovEvent(tx, ws, name, kind, id, govEventRefs{}, payload)
}

// r2EnqueueTx asks for the row's job to run at `at`. A row already has an
// open job while it is active (the 10-minute check, queued for later); the
// enqueue then keeps that job, so it is pulled forward to `at` -- an End,
// Pause, revoke or edit takes effect now, not at the next check.
func r2EnqueueTx(tx *gorm.DB, ws uuid.UUID, k r2Kind, id uuid.UUID, at time.Time) error {
	sub := id
	key := k.Name + ":" + id.String()
	created, err := repositories.NewIGAGovJobRepository(tx).EnqueueTx(tx, &models.IGAGovJob{WorkspaceID: ws, Kind: k.Job, SubjectID: &sub,
		DedupeKey: key, RunAfter: at})
	if err != nil || created {
		return err
	}
	return tx.Model(&models.IGAGovJob{}).
		Where("workspace_id = ? AND kind = ? AND dedupe_key = ? AND status = ? AND run_after > ?", ws, k.Job, key, "queued", at).
		Update("run_after", at).Error
}

// r2NotifyTx enqueues an R2 notice for the users and the workspace webhook
// (resend: each lifecycle step is a new delivery cycle of the same subject).
func r2NotifyTx(tx *gorm.DB, ws uuid.UUID, subjectKind string, subject uuid.UUID, users []uuid.UUID) error {
	if t, err := GovWorkspaceWebhookTarget(tx, ws); err != nil {
		return err
	} else if t != nil {
		if _, err := EnqueueGovNotificationTx(tx, ws, subjectKind, subject, GovChannelWebhook, GovRecipientWorkspaceWebhook, true); err != nil {
			return err
		}
	}
	if !govChannels(tx, ws).EmailEnabled {
		return nil
	}
	seen := map[uuid.UUID]bool{}
	for _, u := range users {
		if u == uuid.Nil || seen[u] {
			continue
		}
		seen[u] = true
		if _, err := EnqueueGovNotificationTx(tx, ws, subjectKind, subject, GovChannelEmail, GovUserRecipient(u), true); err != nil {
			return err
		}
	}
	return nil
}

/* ---------------------------------------------------------------------------- */
/*                               Temporary grants                               */
/* ---------------------------------------------------------------------------- */

// GovGrantRequest is POST /temporary-grants.
type GovGrantRequest struct {
	GovR2RoleKey
	Actions                   []string   `json:"actions"`
	Resources                 []string   `json:"resources"`
	ExpiresAt                 *time.Time `json:"expires_at"`
	DurationMinutes           int        `json:"duration_minutes"`
	Reason                    string     `json:"reason"`
	EscalationAcknowledgement string     `json:"escalation_acknowledgement"`
}

// GovDecisionRequest is approve / reject / revoke.
type GovDecisionRequest struct {
	Reason string `json:"reason"`
}

// CreateGrant is POST /temporary-grants (governance:author).
func (s *GovR2) CreateGrant(ctx context.Context, ws, actor uuid.UUID, req GovGrantRequest) (*models.IGAGovTempGrant, error) {
	if err := RequirePolicyR2(); err != nil {
		return nil, err
	}
	now := s.now().UTC().Truncate(time.Second)
	if strings.TrimSpace(req.Reason) == "" {
		return nil, GovBadParam("reason", "A temporary grant needs a reason.")
	}
	var exp time.Time
	switch {
	case req.ExpiresAt != nil:
		exp = req.ExpiresAt.UTC().Truncate(time.Second)
	case req.DurationMinutes > 0:
		exp = now.Add(time.Duration(req.DurationMinutes) * time.Minute)
	default:
		return nil, GovBadParam("expires_at", "Give expires_at or duration_minutes.")
	}
	if exp.Before(now.Add(igagov.MinGrantDuration)) || exp.After(now.Add(igagov.MaxGrantDuration)) {
		return nil, govUnprocessable(GovCodeGrantInvalid, "A temporary grant lasts 15 minutes to 30 days (DECISION R2-10).", map[string]any{"expires_at": exp})
	}
	acts, res, err := igagov.NormalizeGrant(req.Actions, req.Resources)
	if err != nil {
		return nil, govUnprocessable(GovCodeGrantInvalid, err.Error(), nil)
	}
	esc := igagov.GrantEscalations(acts, res)
	if len(esc) > 0 && strings.TrimSpace(req.EscalationAcknowledgement) == "" {
		return nil, govUnprocessable(GovCodeEscalationAck, "These actions can escalate privilege; acknowledge it explicitly to request them.",
			map[string]any{"escalations": esc})
	}
	role, err := s.resolveRole(ctx, ws, req.GovR2RoleKey)
	if err != nil {
		return nil, err
	}
	id := uuid.New()
	name := igagov.GrantPolicyName(role.Identity.RoleID, id.String())
	arn := igagov.GrantPolicyARN(arnPartition(role.Identity.ARN), role.Identity.AccountID, name)
	doc, hash, err := igagov.TemporaryGrantDocument(acts, res, exp)
	if err != nil {
		return nil, govUnprocessable(GovCodeGrantInvalid, err.Error(), nil)
	}
	reqHash, err := igagov.GrantRequestHash(role.Identity.RoleID, role.Identity.AccountID, acts, res, exp, hash)
	if err != nil {
		return nil, err
	}
	key, err := igagov.GrantRequestKey(role.Identity.RoleID, role.Identity.AccountID, acts, res)
	if err != nil {
		return nil, err
	}
	actsRaw, _ := json.Marshal(acts)
	resRaw, _ := json.Marshal(res)
	if esc == nil {
		esc = []string{}
	}
	escRaw, _ := json.Marshal(esc)
	g := models.IGAGovTempGrant{ID: id, WorkspaceID: ws, ConnectorID: role.Connector, IdentityAccountID: role.Identity.ID,
		AccountID: role.Identity.AccountID, RoleID: role.Identity.RoleID, RoleARN: role.Identity.ARN, Actions: actsRaw, Resources: resRaw,
		Escalations: escRaw, EscalationAck: strings.TrimSpace(req.EscalationAcknowledgement), Reason: strings.TrimSpace(req.Reason),
		ExpiresAt: exp, PolicyName: name, PolicyARN: arn, DocumentHash: hash, RequestHash: reqHash, RequestKey: key,
		State: models.R2StateRequested, RequestedBy: actor, Ops: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now}
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if err := archiveDocumentTx(tx, ws, string(doc), hash); err != nil {
			return err
		}
		if err := tx.Create(&g).Error; err != nil {
			if isUniqueViolation(err, "uq_iga_gov_temp_grant_live") {
				return govConflict(GovCodeGrantExists, "The same grant for this role is already requested or live.", nil)
			}
			return err
		}
		return appendEvent(tx, ws, GovEventGrantRequested, &actor, map[string]any{"grant_id": id, "role_id": g.RoleID,
			"actions": acts, "resources": res, "expires_at": exp, "escalations": esc, "policy_arn": arn, "request_hash": reqHash})
	})
	if err != nil {
		return nil, err
	}
	return &g, nil
}

func (s *GovR2) loadGrant(db *gorm.DB, ws, id uuid.UUID, lock bool) (*models.IGAGovTempGrant, error) {
	q := db.Where("workspace_id = ? AND id = ?", ws, id)
	if lock {
		q = q.Clauses(lockForUpdate())
	}
	var rows []models.IGAGovTempGrant
	if err := q.Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	return &rows[0], nil
}

// GetGrant is GET /temporary-grants/:id (404 across workspaces).
func (s *GovR2) GetGrant(ctx context.Context, ws, id uuid.UUID) (*models.IGAGovTempGrant, error) {
	var out *models.IGAGovTempGrant
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		out, err = s.loadGrant(tx, ws, id, false)
		return err
	})
	return out, err
}

// ListGrants is GET /temporary-grants (?state, ?role_id; newest first, <= 200).
func (s *GovR2) ListGrants(ctx context.Context, ws uuid.UUID, state, roleID string, limit int) ([]models.IGAGovTempGrant, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	out := []models.IGAGovTempGrant{}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		q := tx.Where("workspace_id = ?", ws)
		if state != "" {
			q = q.Where("state = ?", state)
		}
		if roleID != "" {
			q = q.Where("role_id = ?", roleID)
		}
		return q.Order("created_at DESC").Limit(limit).Find(&out).Error
	})
	return out, err
}

// ApproveGrant is POST /temporary-grants/:id/approve (governance:grant):
// separation of duties (never the requester, 403 self_approval), the
// request hash recomputed from the row, and an expiry still ahead.
func (s *GovR2) ApproveGrant(ctx context.Context, ws, actor, id uuid.UUID, req GovDecisionRequest) (*models.IGAGovTempGrant, error) {
	if err := RequirePolicyR2(); err != nil {
		return nil, err
	}
	var out *models.IGAGovTempGrant
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		g, err := s.loadGrant(tx, ws, id, true)
		if err != nil {
			return err
		}
		if g.State != models.R2StateRequested {
			return govConflict(GovCodeNotPending, "The grant is not awaiting a decision.", map[string]any{"state": g.State})
		}
		if g.RequestedBy == actor {
			return govErr(http.StatusForbidden, GovCodeSelfApproval, "You requested this grant; another approver must decide.", nil)
		}
		var acts, res []string
		_ = json.Unmarshal(g.Actions, &acts)
		_ = json.Unmarshal(g.Resources, &res)
		h, err := igagov.GrantRequestHash(g.RoleID, g.AccountID, acts, res, g.ExpiresAt, g.DocumentHash)
		if err != nil {
			return err
		}
		if h != g.RequestHash {
			return govConflict(GovCodeRequestTampered, "The stored request no longer matches its hash.", nil)
		}
		now := s.now().UTC()
		if g.ExpiresAt.Before(now.Add(r2MinLeadBeforeApproval)) {
			return govConflict(GovCodeGrantExpired, "The grant would expire before it could be deployed.", nil)
		}
		if err := tx.Model(&models.IGAGovTempGrant{}).Where("workspace_id = ? AND id = ? AND state = ?", ws, id, models.R2StateRequested).
			Updates(map[string]any{"state": models.R2StateApproved, "decided_by": actor, "decided_at": now,
				"decision_reason": strings.TrimSpace(req.Reason), "approved_request_hash": g.RequestHash, "updated_at": now}).Error; err != nil {
			return err
		}
		if err := appendEvent(tx, ws, GovEventGrantApproved, &actor, map[string]any{"grant_id": id, "request_hash": g.RequestHash,
			"role_id": g.RoleID, "escalations": json.RawMessage(g.Escalations)}); err != nil {
			return err
		}
		if err := r2EnqueueTx(tx, ws, r2GrantKind, id, now); err != nil {
			return err
		}
		if err := r2NotifyTx(tx, ws, GovNoticeTemporaryGrant, id, []uuid.UUID{g.RequestedBy}); err != nil {
			return err
		}
		out, err = s.loadGrant(tx, ws, id, false)
		return err
	})
	return out, err
}

// RejectGrant is POST /temporary-grants/:id/reject (governance:grant).
func (s *GovR2) RejectGrant(ctx context.Context, ws, actor, id uuid.UUID, req GovDecisionRequest) (*models.IGAGovTempGrant, error) {
	if err := RequirePolicyR2(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Reason) == "" {
		return nil, GovBadParam("reason", "A rejection needs a reason.")
	}
	var out *models.IGAGovTempGrant
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		g, err := s.loadGrant(tx, ws, id, true)
		if err != nil {
			return err
		}
		if g.State != models.R2StateRequested {
			return govConflict(GovCodeNotPending, "The grant is not awaiting a decision.", map[string]any{"state": g.State})
		}
		if g.RequestedBy == actor {
			return govErr(http.StatusForbidden, GovCodeSelfApproval, "You requested this grant; another approver must decide.", nil)
		}
		now := s.now().UTC()
		if err := tx.Model(&models.IGAGovTempGrant{}).Where("workspace_id = ? AND id = ? AND state = ?", ws, id, models.R2StateRequested).
			Updates(map[string]any{"state": models.R2StateRejected, "decided_by": actor, "decided_at": now,
				"decision_reason": strings.TrimSpace(req.Reason), "updated_at": now}).Error; err != nil {
			return err
		}
		if err := appendEvent(tx, ws, GovEventGrantRejected, &actor, map[string]any{"grant_id": id, "reason": strings.TrimSpace(req.Reason)}); err != nil {
			return err
		}
		if err := r2NotifyTx(tx, ws, GovNoticeTemporaryGrant, id, []uuid.UUID{g.RequestedBy}); err != nil {
			return err
		}
		out, err = s.loadGrant(tx, ws, id, false)
		return err
	})
	return out, err
}

// RevokeGrant is POST /temporary-grants/:id/revoke (governance:enforce):
// a pending request is cancelled; an approved one that never deployed ends
// revoked; a deploying / active / unknown one is detached and deleted now
// (the undo of a grant).
func (s *GovR2) RevokeGrant(ctx context.Context, ws, actor, id uuid.UUID, req GovDecisionRequest) (*models.IGAGovTempGrant, error) {
	if err := RequirePolicyR2(); err != nil {
		return nil, err
	}
	var out *models.IGAGovTempGrant
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		g, err := s.loadGrant(tx, ws, id, true)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		set := map[string]any{"ended_by": actor, "end_reason": r2EndReasonRevoked, "updated_at": now}
		name := GovEventGrantRevokeReq
		switch g.State {
		case models.R2StateRequested:
			set = map[string]any{"state": models.R2StateCancelled, "ended_by": actor, "end_reason": "cancelled", "ended_at": now, "updated_at": now}
			name = GovEventGrantCancelled
		case models.R2StateApproved:
			set["state"], set["ended_at"] = models.R2StateRevoked, now
		case models.R2StateDeploying, models.R2StateActive, models.R2StateOutcomeUnknown:
			set["state"] = models.R2StateExpiring
		default:
			return govConflict(GovCodeNotEndable, "The grant has already ended or is ending.", map[string]any{"state": g.State})
		}
		if err := tx.Model(&models.IGAGovTempGrant{}).Where("workspace_id = ? AND id = ? AND state = ?", ws, id, g.State).Updates(set).Error; err != nil {
			return err
		}
		if err := appendEvent(tx, ws, name, &actor, map[string]any{"grant_id": id, "from": g.State, "reason": strings.TrimSpace(req.Reason)}); err != nil {
			return err
		}
		if set["state"] == models.R2StateExpiring {
			if err := r2EnqueueTx(tx, ws, r2GrantKind, id, now); err != nil {
				return err
			}
		}
		if err := r2NotifyTx(tx, ws, GovNoticeTemporaryGrant, id, []uuid.UUID{g.RequestedBy}); err != nil {
			return err
		}
		out, err = s.loadGrant(tx, ws, id, false)
		return err
	})
	return out, err
}

func grantRow(g *models.IGAGovTempGrant) r2Row {
	return r2Row{Kind: r2GrantKind, ID: g.ID, WorkspaceID: g.WorkspaceID, ConnectorID: g.ConnectorID, AccountID: g.AccountID,
		RoleID: g.RoleID, RoleARN: g.RoleARN, PolicyName: g.PolicyName, PolicyARN: g.PolicyARN, DocumentHash: g.DocumentHash,
		Due: g.ExpiresAt, PendingOp: g.PendingOp, SettleAfter: g.SettleAfter}
}

// TempGrantHandler is the temp_grant job (subject: the grant).
func (s *GovR2) TempGrantHandler(ctx context.Context, run *PolicyJobRun) error {
	if run.Job.SubjectID == nil {
		return PolicyJobAbandon("temp_grant needs a grant subject")
	}
	if !PolicyR2On() {
		return PolicyJobRetryLater(10*time.Minute, GovCodeR2Unavailable)
	}
	ws := run.Job.WorkspaceID
	var g *models.IGAGovTempGrant
	err := run.ReadTx(ctx, func(tx *gorm.DB) error {
		var err error
		g, err = s.loadGrant(tx, ws, *run.Job.SubjectID, false)
		return err
	})
	if err != nil {
		var ge *GovError
		if errors.As(err, &ge) {
			return PolicyJobAbandon("grant not found")
		}
		return err
	}
	now := s.now().UTC()
	h := r2Handler{s: s, run: run, kind: r2GrantKind, ws: ws, id: g.ID, row: grantRow(g), users: []uuid.UUID{g.RequestedBy}}
	if g.PolicyID != nil {
		// An access policy's deployment (iga_gov_access_policy.go).
		h.kind, h.row = r2AccessKind, accessRow(g)
		h.refs = govEventRefs{PolicyID: g.PolicyID, VersionID: g.VersionID}
	}
	h.endReason = g.EndReason
	if g.DecidedBy != nil && *g.DecidedBy != g.RequestedBy {
		h.users = append(h.users, *g.DecidedBy)
	}
	ending := g.EndReason != "" || g.State == models.R2StateExpiring
	switch g.State {
	case models.R2StateApproved:
		if !now.Before(g.ExpiresAt) {
			return h.finish(ctx, g.State, models.R2StateExpired, r2EndReasonNeverDeployed, nil)
		}
		return h.deploy(ctx, g.State)
	case models.R2StateDeploying:
		return h.present(ctx, g.State)
	case models.R2StateOutcomeUnknown:
		if ending {
			return h.absent(ctx, g.State, grantFinal(g.EndReason))
		}
		return h.present(ctx, g.State)
	case models.R2StateActive:
		if !now.Before(g.ExpiresAt) {
			if err := h.move(ctx, g.State, models.R2StateExpiring, map[string]any{"end_reason": r2EndReasonExpired}); err != nil {
				return err
			}
			h.endReason = r2EndReasonExpired
			return h.absent(ctx, models.R2StateExpiring, models.R2StateExpired)
		}
		return h.check(ctx, g.Drift, g.ExpiresAt)
	case models.R2StateExpiring:
		return h.absent(ctx, g.State, grantFinal(g.EndReason))
	}
	return nil
}

// grantFinal is the terminal state of an ending grant: expired at its
// expiry, revoked for any early end (revoke; an access policy's paused,
// ended or superseded).
func grantFinal(endReason string) string {
	if endReason == "" || endReason == r2EndReasonExpired || endReason == r2EndReasonNeverDeployed {
		return models.R2StateExpired
	}
	return models.R2StateRevoked
}

/* ---------------------------------------------------------------------------- */
/*                              Session revocations                             */
/* ---------------------------------------------------------------------------- */

// GovRevocationRequest is POST /session-revocations.
type GovRevocationRequest struct {
	GovR2RoleKey
	Reason string `json:"reason"`
	// KeepHours: how long the deny stays after the cutoff (13..168, default
	// 13: the 12-hour maximum session lifetime plus a margin).
	KeepHours int `json:"keep_hours"`
	// Emergency: governance:emergency, decided at once (DECISION R2-12).
	Emergency bool `json:"emergency"`
}

func revocationRequestHash(roleID, account, policy, reason string, keep int, emergency bool) (string, error) {
	return igagov.HashCanonicalTagged("authsec.igagov.r2.session_revocation_request.v1", struct {
		RoleID    string `json:"role_id"`
		AccountID string `json:"account_id"`
		Policy    string `json:"policy_name"`
		Reason    string `json:"reason"`
		KeepHours int    `json:"keep_hours"`
		Emergency bool   `json:"emergency"`
	}{roleID, account, policy, reason, keep, emergency})
}

// fixCutoff fixes the cutoff at now (DECISION R2-12): the deny document,
// archived, and the automatic removal time.
func fixCutoff(tx *gorm.DB, ws uuid.UUID, r *models.IGAGovSessionRevocation, now time.Time) (map[string]any, error) {
	cut := now.UTC().Truncate(time.Second)
	doc, hash, err := igagov.RevokeSessionsDocument(cut)
	if err != nil {
		return nil, err
	}
	if err := archiveDocumentTx(tx, ws, string(doc), hash); err != nil {
		return nil, err
	}
	rm := igagov.RevocationRemoveAfter(cut, time.Duration(r.KeepHours)*time.Hour)
	return map[string]any{"issued_before": cut, "document_hash": hash, "remove_after": rm}, nil
}

// CreateRevocation is POST /session-revocations (governance:enforce; with
// emergency, governance:emergency, checked by the route).
func (s *GovR2) CreateRevocation(ctx context.Context, ws, actor uuid.UUID, req GovRevocationRequest) (*models.IGAGovSessionRevocation, error) {
	if err := RequirePolicyR2(); err != nil {
		return nil, err
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		return nil, GovBadParam("reason", "A session revocation needs a reason.")
	}
	keep := req.KeepHours
	if keep == 0 {
		keep = 13
	}
	if keep < 13 || keep > 168 {
		return nil, GovBadParam("keep_hours", "keep_hours is 13 to 168.")
	}
	role, err := s.resolveRole(ctx, ws, req.GovR2RoleKey)
	if err != nil {
		return nil, err
	}
	id := uuid.New()
	name := igagov.RevokePolicyName(role.Identity.RoleID, id.String())
	arn := igagov.GrantPolicyARN(arnPartition(role.Identity.ARN), role.Identity.AccountID, name)
	h, err := revocationRequestHash(role.Identity.RoleID, role.Identity.AccountID, name, reason, keep, req.Emergency)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	r := models.IGAGovSessionRevocation{ID: id, WorkspaceID: ws, ConnectorID: role.Connector, IdentityAccountID: role.Identity.ID,
		AccountID: role.Identity.AccountID, RoleID: role.Identity.RoleID, RoleARN: role.Identity.ARN, Reason: reason,
		Emergency: req.Emergency, KeepHours: keep, PolicyName: name, PolicyARN: arn, RequestHash: h, State: models.R2StateRequested,
		RequestedBy: actor, Ops: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now}
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if req.Emergency {
			set, err := fixCutoff(tx, ws, &r, now)
			if err != nil {
				return err
			}
			cut, rm, dh := set["issued_before"].(time.Time), set["remove_after"].(time.Time), set["document_hash"].(string)
			r.State, r.DecidedBy, r.DecidedAt, r.ApprovedRequestHash = models.R2StateApproved, &actor, &now, &h
			r.IssuedBefore, r.RemoveAfter, r.DocumentHash, r.DecisionReason = &cut, &rm, &dh, "emergency"
		}
		if err := tx.Create(&r).Error; err != nil {
			if isUniqueViolation(err, "uq_iga_gov_session_revocation_live") {
				return govConflict(GovCodeRevocationExists, "This role already has a session revocation requested or in force.", nil)
			}
			return err
		}
		name := GovEventRevocationReq
		if req.Emergency {
			name = GovEventRevocationEmerg
		}
		if err := appendEvent(tx, ws, name, &actor, map[string]any{"revocation_id": id, "role_id": r.RoleID, "keep_hours": keep,
			"emergency": req.Emergency, "issued_before": r.IssuedBefore, "remove_after": r.RemoveAfter, "policy_arn": arn,
			"reason": reason}); err != nil {
			return err
		}
		if req.Emergency {
			if err := r2EnqueueTx(tx, ws, r2RevokeKind, id, now); err != nil {
				return err
			}
			// An emergency revocation is always notified.
			return r2NotifyTx(tx, ws, GovNoticeSessionRevocation, id, []uuid.UUID{actor})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *GovR2) loadRevocation(db *gorm.DB, ws, id uuid.UUID, lock bool) (*models.IGAGovSessionRevocation, error) {
	q := db.Where("workspace_id = ? AND id = ?", ws, id)
	if lock {
		q = q.Clauses(lockForUpdate())
	}
	var rows []models.IGAGovSessionRevocation
	if err := q.Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	return &rows[0], nil
}

// GetRevocation is GET /session-revocations/:id.
func (s *GovR2) GetRevocation(ctx context.Context, ws, id uuid.UUID) (*models.IGAGovSessionRevocation, error) {
	var out *models.IGAGovSessionRevocation
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		out, err = s.loadRevocation(tx, ws, id, false)
		return err
	})
	return out, err
}

// HoldsPermission is WorkspaceUserHoldsPermission read under row-level
// security for ws (the emergency revocation's governance:emergency check).
func (s *GovR2) HoldsPermission(ctx context.Context, ws, user uuid.UUID, resource, action string) (bool, error) {
	var ok bool
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		ok, err = WorkspaceUserHoldsPermission(tx, ws, user, resource, action)
		return err
	})
	return ok, err
}

// ListRevocations is GET /session-revocations.
func (s *GovR2) ListRevocations(ctx context.Context, ws uuid.UUID, state, roleID string, limit int) ([]models.IGAGovSessionRevocation, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	out := []models.IGAGovSessionRevocation{}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		q := tx.Where("workspace_id = ?", ws)
		if state != "" {
			q = q.Where("state = ?", state)
		}
		if roleID != "" {
			q = q.Where("role_id = ?", roleID)
		}
		return q.Order("created_at DESC").Limit(limit).Find(&out).Error
	})
	return out, err
}

// DecideRevocation is approve / reject (governance:approve; never the
// requester). Approval fixes the cutoff now (DECISION R2-12).
func (s *GovR2) DecideRevocation(ctx context.Context, ws, actor, id uuid.UUID, approve bool, req GovDecisionRequest) (*models.IGAGovSessionRevocation, error) {
	if err := RequirePolicyR2(); err != nil {
		return nil, err
	}
	reason := strings.TrimSpace(req.Reason)
	if !approve && reason == "" {
		return nil, GovBadParam("reason", "A rejection needs a reason.")
	}
	var out *models.IGAGovSessionRevocation
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		r, err := s.loadRevocation(tx, ws, id, true)
		if err != nil {
			return err
		}
		if r.State != models.R2StateRequested {
			return govConflict(GovCodeNotPending, "The revocation is not awaiting a decision.", map[string]any{"state": r.State})
		}
		if r.RequestedBy == actor {
			return govErr(http.StatusForbidden, GovCodeSelfApproval, "You requested this revocation; another approver must decide.", nil)
		}
		h, err := revocationRequestHash(r.RoleID, r.AccountID, r.PolicyName, r.Reason, r.KeepHours, r.Emergency)
		if err != nil {
			return err
		}
		if h != r.RequestHash {
			return govConflict(GovCodeRequestTampered, "The stored request no longer matches its hash.", nil)
		}
		now := s.now().UTC()
		set := map[string]any{"decided_by": actor, "decided_at": now, "decision_reason": reason, "updated_at": now}
		name := GovEventRevocationRej
		if approve {
			cut, err := fixCutoff(tx, ws, r, now)
			if err != nil {
				return err
			}
			for k, v := range cut {
				set[k] = v
			}
			set["state"], set["approved_request_hash"] = models.R2StateApproved, r.RequestHash
			name = GovEventRevocationAppr
		} else {
			set["state"] = models.R2StateRejected
		}
		if err := tx.Model(&models.IGAGovSessionRevocation{}).Where("workspace_id = ? AND id = ? AND state = ?", ws, id, models.R2StateRequested).
			Updates(set).Error; err != nil {
			return err
		}
		if err := appendEvent(tx, ws, name, &actor, map[string]any{"revocation_id": id, "role_id": r.RoleID, "reason": reason,
			"issued_before": set["issued_before"], "remove_after": set["remove_after"]}); err != nil {
			return err
		}
		if approve {
			if err := r2EnqueueTx(tx, ws, r2RevokeKind, id, now); err != nil {
				return err
			}
		}
		if err := r2NotifyTx(tx, ws, GovNoticeSessionRevocation, id, []uuid.UUID{r.RequestedBy}); err != nil {
			return err
		}
		out, err = s.loadRevocation(tx, ws, id, false)
		return err
	})
	return out, err
}

// LiftRevocation is POST /session-revocations/:id/revoke (governance:enforce):
// a pending request is cancelled; an approved, deploying, active or unknown
// revocation has its deny removed now. Lifting before remove_after lets
// sessions issued before the cutoff work again while they are valid.
func (s *GovR2) LiftRevocation(ctx context.Context, ws, actor, id uuid.UUID, req GovDecisionRequest) (*models.IGAGovSessionRevocation, error) {
	if err := RequirePolicyR2(); err != nil {
		return nil, err
	}
	var out *models.IGAGovSessionRevocation
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		r, err := s.loadRevocation(tx, ws, id, true)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		set := map[string]any{"ended_by": actor, "end_reason": r2EndReasonLifted, "updated_at": now}
		name := GovEventRevocationLift
		switch r.State {
		case models.R2StateRequested:
			set = map[string]any{"state": models.R2StateCancelled, "ended_by": actor, "end_reason": "cancelled", "ended_at": now, "updated_at": now}
			name = GovEventRevocationCancel
		case models.R2StateApproved, models.R2StateDeploying, models.R2StateActive, models.R2StateOutcomeUnknown:
			set["state"] = models.R2StateRemoving
		default:
			return govConflict(GovCodeNotEndable, "The revocation has already ended or is being removed.", map[string]any{"state": r.State})
		}
		if err := tx.Model(&models.IGAGovSessionRevocation{}).Where("workspace_id = ? AND id = ? AND state = ?", ws, id, r.State).Updates(set).Error; err != nil {
			return err
		}
		if err := appendEvent(tx, ws, name, &actor, map[string]any{"revocation_id": id, "from": r.State, "reason": strings.TrimSpace(req.Reason)}); err != nil {
			return err
		}
		if set["state"] == models.R2StateRemoving {
			if err := r2EnqueueTx(tx, ws, r2RevokeKind, id, now); err != nil {
				return err
			}
		}
		if err := r2NotifyTx(tx, ws, GovNoticeSessionRevocation, id, []uuid.UUID{r.RequestedBy}); err != nil {
			return err
		}
		out, err = s.loadRevocation(tx, ws, id, false)
		return err
	})
	return out, err
}

func revocationRow(r *models.IGAGovSessionRevocation) r2Row {
	row := r2Row{Kind: r2RevokeKind, ID: r.ID, WorkspaceID: r.WorkspaceID, ConnectorID: r.ConnectorID, AccountID: r.AccountID,
		RoleID: r.RoleID, RoleARN: r.RoleARN, PolicyName: r.PolicyName, PolicyARN: r.PolicyARN, PendingOp: r.PendingOp,
		SettleAfter: r.SettleAfter}
	if r.DocumentHash != nil {
		row.DocumentHash = *r.DocumentHash
	}
	if r.RemoveAfter != nil {
		row.Due = *r.RemoveAfter
	}
	return row
}

// SessionRevokeHandler is the session_revoke job (subject: the revocation).
func (s *GovR2) SessionRevokeHandler(ctx context.Context, run *PolicyJobRun) error {
	if run.Job.SubjectID == nil {
		return PolicyJobAbandon("session_revoke needs a revocation subject")
	}
	if !PolicyR2On() {
		return PolicyJobRetryLater(10*time.Minute, GovCodeR2Unavailable)
	}
	ws := run.Job.WorkspaceID
	var r *models.IGAGovSessionRevocation
	err := run.ReadTx(ctx, func(tx *gorm.DB) error {
		var err error
		r, err = s.loadRevocation(tx, ws, *run.Job.SubjectID, false)
		return err
	})
	if err != nil {
		var ge *GovError
		if errors.As(err, &ge) {
			return PolicyJobAbandon("revocation not found")
		}
		return err
	}
	now := s.now().UTC()
	h := r2Handler{s: s, run: run, kind: r2RevokeKind, ws: ws, id: r.ID, row: revocationRow(r), users: []uuid.UUID{r.RequestedBy}}
	if r.DecidedBy != nil {
		h.users = append(h.users, *r.DecidedBy)
	}
	ending := r.EndReason != "" || r.State == models.R2StateRemoving
	switch r.State {
	case models.R2StateApproved:
		return h.deploy(ctx, r.State)
	case models.R2StateDeploying:
		return h.present(ctx, r.State)
	case models.R2StateOutcomeUnknown:
		if ending {
			return h.absent(ctx, r.State, models.R2StateRemoved)
		}
		return h.present(ctx, r.State)
	case models.R2StateActive:
		if r.RemoveAfter != nil && !now.Before(*r.RemoveAfter) {
			if err := h.move(ctx, r.State, models.R2StateRemoving, map[string]any{"end_reason": r2EndReasonExpired}); err != nil {
				return err
			}
			return h.absent(ctx, models.R2StateRemoving, models.R2StateRemoved)
		}
		due := now.Add(r2ActiveCheckEvery)
		if r.RemoveAfter != nil {
			due = *r.RemoveAfter
		}
		return h.check(ctx, r.Drift, due)
	case models.R2StateRemoving:
		return h.absent(ctx, r.State, models.R2StateRemoved)
	}
	return nil
}

/* ---------------------------------------------------------------------------- */
/*                         The shared lifecycle steps                           */
/* ---------------------------------------------------------------------------- */

type r2Handler struct {
	s     *GovR2
	run   *PolicyJobRun
	kind  r2Kind
	ws    uuid.UUID
	id    uuid.UUID
	row   r2Row
	users []uuid.UUID
	// refs: the event's policy / version (access policies).
	refs      govEventRefs
	endReason string
}

// event appends a system event of the row.
func (h r2Handler) event(tx *gorm.DB, ws uuid.UUID, name string, payload map[string]any) error {
	return appendGovEvent(tx, ws, name, models.GovActorSystem, "policy-worker", h.refs, payload)
}


// move changes the row's state from `from`, fenced on the job and on the
// state (0 rows: someone moved it -- a revoke or lift -- and the next run
// reloads).
func (h r2Handler) move(ctx context.Context, from, to string, set map[string]any) error {
	return h.run.InTx(ctx, func(tx *gorm.DB) error {
		return h.moveTx(tx, from, to, set)
	})
}

func (h r2Handler) moveTx(tx *gorm.DB, from, to string, set map[string]any) error {
	if set == nil {
		set = map[string]any{}
	}
	set["state"], set["updated_at"] = to, time.Now().UTC()
	res := tx.Table(h.kind.Table).Where("workspace_id = ? AND id = ? AND state = ?", h.ws, h.id, from).Updates(set)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		return errStateMoved
	}
	return nil
}

func (h r2Handler) settled(err error) error {
	if errors.Is(err, errStateMoved) {
		return PolicyJobRetryLater(time.Second, "the row's state moved; reloading")
	}
	return err
}

// deploy is approved -> deploying behind the binding gate.
func (h r2Handler) deploy(ctx context.Context, from string) error {
	if err := r2BindingGate(ctx, h.run, h.ws, h.row.ConnectorID, h.kind.Feature); err != nil {
		code, msg := errCode(err)
		return h.fail(ctx, from, code, msg)
	}
	if err := h.move(ctx, from, models.R2StateDeploying, map[string]any{"state_reason": ""}); err != nil {
		return h.settled(err)
	}
	return h.present(ctx, models.R2StateDeploying)
}

func (h r2Handler) fail(ctx context.Context, from, code, detail string) error {
	err := h.run.InTx(ctx, func(tx *gorm.DB) error {
		if err := h.moveTx(tx, from, models.R2StateFailed, map[string]any{"state_reason": code + ": " + detail,
			"ended_at": time.Now().UTC()}); err != nil {
			return err
		}
		if err := h.event(tx, h.ws, h.kind.EvFailed, map[string]any{h.kind.IDKey: h.id, "from": from, "reason": code, "detail": detail}); err != nil {
			return err
		}
		return r2NotifyTx(tx, h.ws, h.kind.Notice, h.id, h.users)
	})
	return h.settled(err)
}

func (h r2Handler) unknown(ctx context.Context, from string, out *r2Outcome) error {
	if from != models.R2StateOutcomeUnknown {
		err := h.run.InTx(ctx, func(tx *gorm.DB) error {
			if err := h.moveTx(tx, from, models.R2StateOutcomeUnknown, map[string]any{"state_reason": "a write had no answer; held until " +
				igagov.AWSTime(out.SettleAt)}); err != nil {
				return err
			}
			return h.event(tx, h.ws, h.kind.EvUnknown, map[string]any{h.kind.IDKey: h.id, "from": from, "settle_after": out.SettleAt,
				"ops": out.Ops})
		})
		if err != nil {
			return h.settled(err)
		}
	}
	return PolicyJobRetryLater(out.RetryAfter, "outcome unknown until settle_after")
}

// present converges toward the policy attached; done -> active (verified).
func (h r2Handler) present(ctx context.Context, from string) error {
	out, err := h.row.converge(ctx, h.run, true)
	if err != nil {
		return err
	}
	switch {
	case out.Fail != "":
		return h.fail(ctx, from, out.Fail, out.FailDetail)
	case out.Unknown:
		return h.unknown(ctx, from, out)
	case !out.Done:
		_ = h.run.InTx(ctx, func(tx *gorm.DB) error {
			return tx.Table(h.kind.Table).Where("workspace_id = ? AND id = ?", h.ws, h.id).
				Updates(map[string]any{"state_reason": out.FailDetail, "updated_at": time.Now().UTC()}).Error
		})
		return PolicyJobRetryLater(out.RetryAfter, "not yet in place: "+out.FailDetail)
	}
	now := time.Now().UTC()
	err = h.run.InTx(ctx, func(tx *gorm.DB) error {
		if err := h.moveTx(tx, from, models.R2StateActive, map[string]any{"deployed_at": gorm.Expr("COALESCE(deployed_at, ?)", now),
			"verified_at": now, "last_readback_at": now, "drift": out.Drift, "state_reason": "",
			"pending_op": "", "pending_op_at": nil, "settle_after": nil}); err != nil {
			return err
		}
		if err := h.event(tx, h.ws, h.kind.EvActive, map[string]any{h.kind.IDKey: h.id, "policy_arn": h.row.PolicyARN,
			"role_id": h.row.RoleID, "readback": out.Readback, "ops": out.Ops, "drift": out.Drift, "until": h.row.Due}); err != nil {
			return err
		}
		if h.kind.Name == r2AccessKind.Name {
			// The new version is in place: older versions' deployments end
			// now, never before (an edit leaves no gap).
			if err := accessAfterActiveTx(tx, h.ws, h.id); err != nil {
				return err
			}
		}
		return r2NotifyTx(tx, h.ws, h.kind.Notice, h.id, h.users)
	})
	if err != nil {
		return h.settled(err)
	}
	return PolicyJobRetryLater(r2Wait(h.row.Due), "active until "+igagov.AWSTime(h.row.Due))
}

// absent converges toward the policy gone; done -> final.
func (h r2Handler) absent(ctx context.Context, from, final string) error {
	out, err := h.row.converge(ctx, h.run, false)
	if err != nil {
		return err
	}
	switch {
	case out.Unknown:
		return h.unknown(ctx, from, out)
	case out.Fail != "" || !out.Done:
		// Ending is retried: never a terminal failure while AuthSec's policy
		// may still be on the role (a grant's document is inert after its
		// expiry anyway, DECISION R2-8).
		reason := out.Fail
		if out.FailDetail != "" {
			reason += ": " + out.FailDetail
		}
		_ = h.run.InTx(ctx, func(tx *gorm.DB) error {
			return tx.Table(h.kind.Table).Where("workspace_id = ? AND id = ?", h.ws, h.id).
				Updates(map[string]any{"state_reason": strings.TrimPrefix(reason, ": "), "updated_at": time.Now().UTC()}).Error
		})
		wait := out.RetryAfter
		if wait <= 0 {
			wait = 30 * time.Minute
		}
		return PolicyJobRetryLater(wait, "removal not complete: "+reason)
	}
	return h.finish(ctx, from, final, "", out)
}

func (h r2Handler) finish(ctx context.Context, from, final, endReason string, out *r2Outcome) error {
	now := time.Now().UTC()
	err := h.run.InTx(ctx, func(tx *gorm.DB) error {
		set := map[string]any{"ended_at": now, "state_reason": "", "pending_op": "", "pending_op_at": nil, "settle_after": nil}
		if endReason != "" {
			set["end_reason"] = endReason
		}
		pl := map[string]any{h.kind.IDKey: h.id, "from": from, "state": final}
		if out != nil {
			set["last_readback_at"] = now
			if out.Drift != "" {
				set["drift"] = out.Drift
			}
			pl["readback"], pl["ops"], pl["drift"] = out.Readback, out.Ops, out.Drift
		}
		if err := h.moveTx(tx, from, final, set); err != nil {
			return err
		}
		name := h.kind.EvEnded
		if h.kind.Name == r2AccessKind.Name && final == models.R2StateExpired {
			name = GovEventAccessExpired
		}
		pl["end_reason"] = h.endReason
		if err := h.event(tx, h.ws, name, pl); err != nil {
			return err
		}
		return r2NotifyTx(tx, h.ws, h.kind.Notice, h.id, h.users)
	})
	return h.settled(err)
}

// check is the active row's read-only drift check (DECISION R2-18).
func (h r2Handler) check(ctx context.Context, prior string, due time.Time) error {
	drift, read, err := h.row.verifyPresent(ctx, h.run)
	if err != nil {
		return err
	}
	if h.kind.Reapply && drift != "" && drift != R2ReasonAttachedElsewhere {
		return h.reapply(ctx, drift, read, due)
	}
	now := time.Now().UTC()
	err = h.run.InTx(ctx, func(tx *gorm.DB) error {
		if err := tx.Table(h.kind.Table).Where("workspace_id = ? AND id = ? AND state = ?", h.ws, h.id, models.R2StateActive).
			Updates(map[string]any{"last_readback_at": now, "drift": drift, "updated_at": now}).Error; err != nil {
			return err
		}
		if drift == "" || drift == prior {
			return nil
		}
		note := "AuthSec does not re-apply or revert; revoke or let the row expire."
		if h.kind.Reapply {
			note = "Attached to another entity as well; AuthSec leaves that entity unchanged."
		}
		if err := h.event(tx, h.ws, h.kind.EvDrifted, map[string]any{h.kind.IDKey: h.id, "classification": drift, "read": read,
			"note": note}); err != nil {
			return err
		}
		return r2NotifyTx(tx, h.ws, h.kind.Notice, h.id, h.users)
	})
	if err != nil {
		return err
	}
	return PolicyJobRetryLater(r2Wait(due), "active; drift checked every 10 minutes")
}

// reapply puts an access policy back when it was detached or deleted outside
// AuthSec (a removed block would silently restore access): a drifted event,
// then the present convergence; done -> a reapplied event; anything it
// cannot fix (the document was edited, the role was recreated) -> failed.
func (h r2Handler) reapply(ctx context.Context, drift string, read map[string]any, due time.Time) error {
	now := time.Now().UTC()
	if err := h.run.InTx(ctx, func(tx *gorm.DB) error {
		if err := tx.Table(h.kind.Table).Where("workspace_id = ? AND id = ? AND state = ?", h.ws, h.id, models.R2StateActive).
			Updates(map[string]any{"last_readback_at": now, "drift": drift, "updated_at": now}).Error; err != nil {
			return err
		}
		if err := h.event(tx, h.ws, h.kind.EvDrifted, map[string]any{h.kind.IDKey: h.id, "classification": drift, "read": read,
			"note": "AuthSec re-applies the policy."}); err != nil {
			return err
		}
		return r2NotifyTx(tx, h.ws, h.kind.Notice, h.id, h.users)
	}); err != nil {
		return err
	}
	if drift != R2ReasonDetached && drift != R2ReasonDeleted {
		return h.fail(ctx, models.R2StateActive, drift, "AuthSec cannot re-apply: the policy or the role changed outside AuthSec")
	}
	out, err := h.row.converge(ctx, h.run, true)
	if err != nil {
		return err
	}
	switch {
	case out.Fail != "":
		return h.fail(ctx, models.R2StateActive, out.Fail, out.FailDetail)
	case out.Unknown:
		return h.unknown(ctx, models.R2StateActive, out)
	case !out.Done:
		return PolicyJobRetryLater(out.RetryAfter, "re-apply not complete: "+out.FailDetail)
	}
	if err := h.run.InTx(ctx, func(tx *gorm.DB) error {
		if err := tx.Table(h.kind.Table).Where("workspace_id = ? AND id = ? AND state = ?", h.ws, h.id, models.R2StateActive).
			Updates(map[string]any{"drift": "", "verified_at": now, "last_readback_at": now, "pending_op": "", "pending_op_at": nil,
				"settle_after": nil, "updated_at": now}).Error; err != nil {
			return err
		}
		return h.event(tx, h.ws, GovEventAccessReapplied, map[string]any{h.kind.IDKey: h.id, "was": drift, "ops": out.Ops, "readback": out.Readback})
	}); err != nil {
		return err
	}
	return PolicyJobRetryLater(r2Wait(due), "re-applied; drift checked every 10 minutes")
}

func r2Wait(due time.Time) time.Duration {
	w := time.Until(due)
	if w > r2ActiveCheckEvery {
		w = r2ActiveCheckEvery
	}
	if w < time.Second {
		w = time.Second
	}
	return w
}

/* ---------------------------------------------------------------------------- */
/*                            Jobs and schedules                                */
/* ---------------------------------------------------------------------------- */

// RegisterR2Jobs installs the R2 handlers and their schedules on w. The
// schedules re-enqueue every non-terminal row every 10 minutes (dedupe
// <kind>:<id>, so an open job is never doubled): a lost job never leaves a
// grant attached past its expiry beyond the next tick (E-09 "missed
// housekeeping"; the grant's own DateLessThan already makes it inert).
func RegisterR2Jobs(w *PolicyJobWorker, db *gorm.DB) {
	s := NewGovR2(db)
	w.Register(PolicyJobKind{Kind: repositories.GovJobTempGrant, Handler: s.TempGrantHandler})
	w.Register(PolicyJobKind{Kind: repositories.GovJobSessionRevoke, Handler: s.SessionRevokeHandler})
	w.Register(PolicyJobKind{Kind: repositories.GovJobTimeBound, Handler: NewGovDeployments(db, nil).TimeBoundHandler})
	RegisterAzureAccessJobs(w, db)
	for _, k := range []r2Kind{r2GrantKind, r2RevokeKind} {
		k := k
		w.Scheduler().Add(PolicyJobSchedule{Name: k.Job, Kind: k.Job, Every: r2ActiveCheckEvery,
			Due: func(ctx context.Context, db *gorm.DB, now time.Time) ([]ScheduledPolicyJob, error) {
				if !PolicyR2On() {
					return nil, nil
				}
				var rows []struct {
					WorkspaceID uuid.UUID
					ID          uuid.UUID
				}
				// TENANT-EXEMPT: the scheduler's due scan spans every workspace (rows
				// carry workspace_id); each job runs under RLS for its row's workspace.
				if err := db.Table(k.Table).Select("workspace_id, id").
					Where("state IN ?", []string{models.R2StateApproved, models.R2StateDeploying, models.R2StateActive,
						models.R2StateExpiring, models.R2StateRemoving, models.R2StateOutcomeUnknown}).
					Scan(&rows).Error; err != nil {
					return nil, err
				}
				out := make([]ScheduledPolicyJob, 0, len(rows))
				for _, r := range rows {
					id := r.ID
					out = append(out, ScheduledPolicyJob{WorkspaceID: r.WorkspaceID, SubjectID: &id, DedupeKey: k.Name + ":" + id.String()})
				}
				return out, nil
			}})
	}
	w.Scheduler().Add(PolicyJobSchedule{Name: repositories.GovJobTimeBound, Kind: repositories.GovJobTimeBound, Every: 15 * time.Minute,
		Due: dueTimeBound})
}
