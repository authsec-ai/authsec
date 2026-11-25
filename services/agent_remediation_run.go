package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsremediate"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// Applying a remediation (tier 4), the executor, the deferred steps and the
// worker. See agent_remediation.go for the model.

// RemediationApplyResult is POST /remediations/:id/apply's answer.
type RemediationApplyResult struct {
	Remediation   *RemediationView   `json:"remediation"`
	PendingChange *PendingChangeView `json:"pending_change,omitempty"`
	BreakGlass    bool               `json:"break_glass"`
}

type remediationApplyPayload struct {
	RemediationID uuid.UUID `json:"remediation_id"`
	PlanHash      string    `json:"plan_hash"`
}

var remediationRun = struct {
	sync.RWMutex
	kick func(ws, id uuid.UUID)
}{}

// SetRemediationKick replaces what runs a remediation after its write was
// approved (tests: synchronously, or not at all); nil restores the default
// (a background run on the process database; the worker resumes a run the
// process did not finish). It returns the undo.
func SetRemediationKick(f func(ws, id uuid.UUID)) (restore func()) {
	remediationRun.Lock()
	prev := remediationRun.kick
	remediationRun.kick = f
	remediationRun.Unlock()
	return func() { SetRemediationKick(prev) }
}

func kickRemediation(ws, id uuid.UUID) {
	remediationRun.RLock()
	f := remediationRun.kick
	remediationRun.RUnlock()
	if f != nil {
		f(ws, id)
		return
	}
	db := remediationDB()
	if db == nil {
		return
	}
	go func() {
		if err := NewRemediationService(db).Execute(context.Background(), ws, id); err != nil {
			log.Printf("[remediation] workspace %s remediation %s: run: %v", ws, id, err)
		}
	}()
}

func holdsRemediate(tx *gorm.DB, ws, user uuid.UUID) (bool, error) {
	return WorkspaceUserHoldsPermission(tx, ws, user, "governance", "remediate")
}

// Apply is POST /remediations/:id/apply. The caller must hold
// governance:remediate now. A write waits for a second person holding
// governance:approve (pending change remediation.apply) unless nobody else
// holds it (break-glass: it runs now, a review due in 24 h). A pull request
// is opened at once (its review is the second person). A prepared
// remediation cannot be applied by AuthSec.
func (s *RemediationService) Apply(ctx context.Context, ws, id, actor uuid.UUID, note string) (*RemediationApplyResult, error) {
	if err := RequireRemediation(s.db); err != nil {
		return nil, err
	}
	note = strings.TrimSpace(note)
	if len(note) > MaxPendingChangeReason {
		return nil, GovBadParam("reason", "reason is too long.")
	}
	now := s.now().UTC()
	res := &RemediationApplyResult{}
	var openPR *remediationRow
	run := false
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		r, err := readRemediation(tx, ws, id, true)
		if err != nil {
			return err
		}
		ok, err := holdsRemediate(tx, ws, actor)
		if err != nil {
			return err
		}
		if !ok {
			return govErr(http.StatusForbidden, RemCodeRemediateRequired, "Applying a remediation needs governance:remediate (tier 4).", nil)
		}
		switch r.Mode {
		case RemediationModePrepared:
			return govConflict(RemCodePrepared, "AuthSec cannot write this remediation ("+r.ModeReason+"): run its prepared change, then read its proof.",
				map[string]any{"mode_reason": r.ModeReason})
		case RemediationModeIaCPR:
			if r.State != RemediationDraft && r.State != RemediationPRClosed {
				return govConflict(RemCodeState, "Only a draft remediation, or one whose pull request was closed, can be applied.", map[string]any{"state": r.State})
			}
			openPR = r
			return nil
		}
		if r.State != RemediationDraft && r.State != RemediationFailed {
			return govConflict(RemCodeState, "Only a draft (or failed) remediation can be applied.", map[string]any{"state": r.State})
		}
		if r.State == RemediationFailed {
			if err := tx.Exec(`UPDATE agent_remediation_step SET state = 'pending', error = '', updated_at = now()
			    WHERE workspace_id = ? AND remediation_id = ? AND state = 'failed'`, ws, id).Error; err != nil {
				return err
			}
		}
		approvers, err := WorkspaceUsersHoldingPermission(tx, ws, "governance", "approve")
		if err != nil {
			return err
		}
		second := false
		for _, a := range approvers {
			if a != actor && a != r.RequestedBy {
				second = true
				break
			}
		}
		reason := note
		if reason == "" {
			reason = r.Reason
		}
		payload := remediationApplyPayload{RemediationID: id, PlanHash: r.PlanHash}
		target := "agent_remediation:" + id.String()
		if second {
			pc, err := insertPendingChangeTx(tx, ws, PendingChangeKindRemediation, target, payload, reason, actor, now)
			if err != nil {
				return err
			}
			v := pc.view()
			res.PendingChange = &v
			if err := tx.Exec(`UPDATE agent_remediation SET state = 'awaiting_approval', state_reason = '', error = '', pending_change_id = ?,
			        apply_requested_at = ?, updated_at = now() WHERE workspace_id = ? AND id = ?`, pc.ID, now, ws, id).Error; err != nil {
				return err
			}
			return appendGovEvent(tx, ws, GovEventRemediationApplyRequested, models.GovActorUser, actor.String(), govEventRefs{},
				map[string]any{"remediation_id": id, "pending_change_id": pc.ID, "kind": r.Kind, "target_ref": r.TargetRef})
		}
		// Nobody else can approve: break-glass, recorded for review.
		pc, err := insertBreakGlassChangeTx(tx, ws, PendingChangeKindRemediation, target, payload, reason, actor, now)
		if err != nil {
			return err
		}
		v := pc.view()
		res.PendingChange, res.BreakGlass, run = &v, true, true
		if err := tx.Exec(`UPDATE agent_remediation SET state = 'applying', state_reason = 'break-glass: no second approver', error = '',
		        pending_change_id = ?, break_glass = true, apply_requested_at = ?, lease_until = NULL, updated_at = now()
		    WHERE workspace_id = ? AND id = ?`, pc.ID, now, ws, id).Error; err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventRemediationBreakGlass, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"remediation_id": id, "pending_change_id": pc.ID, "review_due_at": pc.ReviewDueAt, "kind": r.Kind, "target_ref": r.TargetRef})
	})
	if err != nil {
		return nil, err
	}
	if openPR != nil {
		v, err := s.openRemediationPR(ctx, ws, actor, openPR)
		if err != nil {
			return nil, err
		}
		res.Remediation = v
		return res, nil
	}
	if run {
		kickRemediation(ws, id)
	}
	if res.Remediation, err = s.Get(ctx, ws, id); err != nil {
		return nil, err
	}
	return res, nil
}

// applyRemediationChange is the pending change applier: a second person
// approved the write. The remediation must still wait for this change with
// the same plan; its own requester may not approve it (a CHECK too).
func applyRemediationChange(tx *gorm.DB, ws uuid.UUID, pc *pendingChangeRow) (func(), error) {
	var p remediationApplyPayload
	if err := json.Unmarshal([]byte(pc.Payload), &p); err != nil {
		return nil, fmt.Errorf("pending change %s: payload: %w", pc.ID, err)
	}
	r, err := readRemediation(tx, ws, p.RemediationID, true)
	if err != nil {
		return nil, err
	}
	if r.State != RemediationAwaitingApproval || r.PendingChangeID == nil || *r.PendingChangeID != pc.ID {
		return nil, govConflict("change_stale", "The remediation no longer waits for this approval; reject it.", map[string]any{"state": r.State})
	}
	if r.PlanHash != p.PlanHash {
		return nil, govConflict("change_stale", "The remediation's plan changed since this was requested; reject it.", nil)
	}
	if pc.ApprovedBy == nil {
		return nil, govConflict("change_stale", "No approver.", nil)
	}
	if *pc.ApprovedBy == r.RequestedBy {
		return nil, govErr(http.StatusForbidden, GovCodeSelfApproval, "You requested this remediation; another approver must decide.", nil)
	}
	if err := tx.Exec(`UPDATE agent_remediation SET state = 'applying', approved_by = ?, lease_until = NULL, updated_at = now()
	    WHERE workspace_id = ? AND id = ?`, *pc.ApprovedBy, ws, r.ID).Error; err != nil {
		return nil, err
	}
	if err := appendGovEvent(tx, ws, GovEventRemediationApproved, models.GovActorUser, pc.ApprovedBy.String(), govEventRefs{},
		map[string]any{"remediation_id": r.ID, "pending_change_id": pc.ID, "requested_by": pc.RequestedBy}); err != nil {
		return nil, err
	}
	id := r.ID
	return func() { kickRemediation(ws, id) }, nil
}

func init() { registerPendingChangeKind(PendingChangeKindRemediation, applyRemediationChange) }

/* --------------------------------- executor -------------------------------- */

const remediationLease = 10 * time.Minute

// Execute runs a remediation in state applying (or the due deferred steps of
// an applied one): every pending step in order -- check the before-state,
// write, read back -- stopping at the first refusal or failure (the steps
// before it stay applied, their before-state kept). It ends applied (with
// its proof evaluated) or failed. One run at a time (a lease).
func (s *RemediationService) Execute(ctx context.Context, ws, id uuid.UUID) error {
	if err := RequireRemediation(s.db); err != nil {
		return err
	}
	now := s.now().UTC()
	var r *remediationRow
	var steps []remediationStepRow
	claimed := false
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var ids []uuid.UUID
		if err := tx.Raw(`UPDATE agent_remediation SET lease_until = ?
		    WHERE workspace_id = ? AND id = ? AND (lease_until IS NULL OR lease_until < ?)
		      AND (state = 'applying' OR (state = 'applied' AND EXISTS (SELECT 1 FROM agent_remediation_step st
		            WHERE st.workspace_id = agent_remediation.workspace_id AND st.remediation_id = agent_remediation.id
		              AND st.state = 'waiting' AND st.due_at <= ?)))
		    RETURNING id`, now.Add(remediationLease), ws, id, now, now).Scan(&ids).Error; err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		claimed = true
		var err error
		if r, err = readRemediation(tx, ws, id, false); err != nil {
			return err
		}
		steps, err = readRemediationSteps(tx, ws, id)
		return err
	})
	if err != nil || !claimed {
		return err
	}
	defer func() {
		_ = tenancy.InWorkspace(context.Background(), s.db, ws, func(tx *gorm.DB) error {
			return tx.Exec(`UPDATE agent_remediation SET lease_until = NULL WHERE workspace_id = ? AND id = ?`, ws, id).Error
		})
	}()
	deferredOnly := r.State == RemediationApplied

	// Open the account only when an AWS step will run.
	var acct awsremediate.Account
	needAWS := false
	for _, st := range steps {
		if awsremediate.IsAWSOp(st.Op) && (st.State == "pending" || (st.State == "waiting" && st.DueAt != nil && !st.DueAt.After(now))) {
			needAWS = true
		}
	}
	if needAWS {
		acc := remediationAccess()
		if acc == nil || r.ConnectorID == nil {
			return s.fail(ctx, ws, id, 0, "remediation_unavailable", "AWS access for remediation is not configured.")
		}
		a, err := acc.Open(ctx, ws, *r.ConnectorID, id)
		if err != nil {
			code, msg := "remediation_role_unavailable", "The remediation role could not be used."
			if ge, ok := err.(*GovError); ok {
				code, msg = ge.Code, ge.Message
			}
			return s.fail(ctx, ws, id, 0, code, msg)
		}
		acct = a
	}
	eng := &awsremediate.Engine{A: acct}
	actor := r.RequestedBy
	if r.ApprovedBy != nil {
		actor = *r.ApprovedBy
	}
	var rotatedAt *time.Time
	grace := remediationDefaultGraceHours
	ranDeferred := 0
	for _, row := range steps {
		st := row.step()
		switch row.State {
		case "applied", "skipped", "asked":
			if row.Op == awsremediate.OpRotateAccessKey && row.State == "applied" {
				rotatedAt = row.AppliedAt
				if g, ok := detailInt(st.Before, "grace_hours", grace); ok {
					grace = g
				}
			}
			continue
		case "waiting":
			if row.DueAt != nil && row.DueAt.After(now) {
				continue
			}
		case "pending":
			if deferredOnly {
				continue
			}
		default:
			continue
		}
		// The old key is deactivated only after its grace: the first run
		// schedules it.
		if r.Kind == RemediationRotateIAMKey && row.Op == awsremediate.OpDeactivateAccessKey && row.State == "pending" {
			if rotatedAt == nil {
				return s.fail(ctx, ws, id, row.Seq, "out_of_order", "The new key was not handed over; the old key stays active.")
			}
			due := rotatedAt.Add(time.Duration(grace) * time.Hour)
			if err := s.updateStep(ctx, ws, id, row.Seq, "waiting", nil, nil, "", &due, nil); err != nil {
				return err
			}
			continue
		}
		if awsremediate.IsAWSOp(row.Op) {
			if err := eng.Check(ctx, &st); err != nil {
				return s.fail(ctx, ws, id, row.Seq, awsremediate.CodeOf(err), err.Error())
			}
			out, aerr := eng.Apply(ctx, &st)
			for k, v := range out {
				st.After[k] = v
			}
			if aerr != nil {
				_ = s.updateStep(ctx, ws, id, row.Seq, "failed", st.After, nil, aerr.Error(), nil, nil)
				return s.fail(ctx, ws, id, row.Seq, awsremediate.CodeOf(aerr), aerr.Error())
			}
			ok, obs, rerr := awsremediate.Readback(ctx, acct, &st)
			rb := map[string]any{"ok": ok, "observed": obs}
			if rerr != nil {
				rb["error"] = "the readback could not be made"
			}
			at := s.now().UTC()
			if err := s.updateStep(ctx, ws, id, row.Seq, "applied", st.After, rb, "", nil, &at); err != nil {
				return err
			}
			if row.Op == awsremediate.OpRotateAccessKey {
				rotatedAt = &at
				if g, ok := detailInt(st.Before, "grace_hours", grace); ok {
					grace = g
				}
			}
			if row.State == "waiting" {
				ranDeferred++
			}
			continue
		}
		if err := s.runAuthSecStep(ctx, ws, r, row, st, actor); err != nil {
			return s.fail(ctx, ws, id, row.Seq, "step_failed", err.Error())
		}
	}
	// Applied: every step applied, skipped, asked or waiting.
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if deferredOnly {
			if ranDeferred == 0 {
				return nil
			}
			return appendGovEvent(tx, ws, GovEventRemediationStepApplied, models.GovActorSystem, "remediation", govEventRefs{},
				map[string]any{"remediation_id": id, "steps": ranDeferred})
		}
		if err := tx.Exec(`UPDATE agent_remediation SET state = 'applied', state_reason = '', error = '', applied_at = COALESCE(applied_at, ?),
		        updated_at = now() WHERE workspace_id = ? AND id = ? AND state = 'applying'`, s.now().UTC(), ws, id).Error; err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventRemediationApplied, models.GovActorSystem, "remediation", govEventRefs{},
			map[string]any{"remediation_id": id, "kind": r.Kind, "target_ref": r.TargetRef, "approved_by": r.ApprovedBy, "break_glass": r.BreakGlass})
	})
	if err != nil {
		return err
	}
	_, perr := s.Proof(ctx, ws, id)
	return perr
}

// runAuthSecStep runs a step AuthSec makes on its own side.
func (s *RemediationService) runAuthSecStep(ctx context.Context, ws uuid.UUID, r *remediationRow, row remediationStepRow, st awsremediate.Step, actor uuid.UUID) error {
	at := s.now().UTC()
	switch row.Op {
	case RemOpGatewayRulesRemove:
		aid, _ := uuid.Parse(row.Target)
		var removed int
		var supported bool
		err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
			var err error
			removed, supported, err = remediationGateway().RemoveAgentRules(tx, ws, aid)
			return err
		})
		if err != nil {
			return err
		}
		if !supported {
			return s.updateStep(ctx, ws, r.ID, row.Seq, "skipped", map[string]any{"removed": 0, "supported": false}, nil,
				"no gateway rule component on this server (W6): nothing removed", nil, &at)
		}
		return s.updateStep(ctx, ws, r.ID, row.Seq, "applied", map[string]any{"removed": removed, "supported": true},
			map[string]any{"ok": true}, "", nil, &at)
	case RemOpAgentRetire:
		aid, _ := uuid.Parse(row.Target)
		_, err := NewAgentIdentityService(s.db).EndAgent(ctx, ws, aid, actor, AgentEndRequest{Action: AgentEndRetire,
			Reason: "Retired by remediation " + r.ID.String() + ": " + r.Reason})
		if ge, ok := err.(*GovError); ok && ge.Code == "agent_ended" {
			return s.updateStep(ctx, ws, r.ID, row.Seq, "skipped", nil, nil, "the agent had already ended", nil, &at)
		}
		if err != nil {
			return err
		}
		return s.updateStep(ctx, ws, r.ID, row.Seq, "applied", map[string]any{"state": AgentStateRetired}, map[string]any{"ok": true}, "", nil, &at)
	case RemOpProviderKeyRotate:
		cid, _ := uuid.Parse(row.Target)
		rot := providerKeyRotator(fmt.Sprint(st.Before["provider"]))
		if rot == nil {
			return fmt.Errorf("no central rotator for %v", st.Before["provider"])
		}
		fp, err := rot.RotateAdminKey(ctx, ws, cid)
		if err != nil {
			return err
		}
		return s.updateStep(ctx, ws, r.ID, row.Seq, "applied", map[string]any{"fingerprint": fp, "fingerprint_changed": true}, nil, "", nil, &at)
	}
	return fmt.Errorf("unknown step %s", row.Op)
}

func (s *RemediationService) updateStep(ctx context.Context, ws, id uuid.UUID, seq int, state string, after, readback map[string]any,
	errMsg string, due, applied *time.Time) error {
	return tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		set := `state = ?, error = ?, updated_at = now()`
		args := []any{state, truncate(errMsg, 2000)}
		if after != nil {
			set += `, after = ?::jsonb`
			args = append(args, remJSON(after))
		}
		if readback != nil {
			set += `, readback = ?::jsonb`
			args = append(args, remJSON(readback))
		}
		if due != nil {
			set += `, due_at = ?`
			args = append(args, *due)
		}
		if applied != nil {
			set += `, applied_at = ?`
			args = append(args, *applied)
		}
		args = append(args, ws, id, seq)
		return tx.Exec(`UPDATE agent_remediation_step SET `+set+` WHERE workspace_id = ? AND remediation_id = ? AND seq = ?`, args...).Error
	})
}

// fail ends a run failed at step seq (0: before any step).
func (s *RemediationService) fail(ctx context.Context, ws, id uuid.UUID, seq int, code, msg string) error {
	return tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if seq > 0 {
			if err := tx.Exec(`UPDATE agent_remediation_step SET state = 'failed', error = ?, updated_at = now()
			    WHERE workspace_id = ? AND remediation_id = ? AND seq = ? AND state IN ('pending','waiting')`,
				truncate(code+": "+msg, 2000), ws, id, seq).Error; err != nil {
				return err
			}
		}
		if err := tx.Exec(`UPDATE agent_remediation SET state = 'failed', error = ?, state_reason = ?, updated_at = now()
		    WHERE workspace_id = ? AND id = ? AND state IN ('applying','applied')`, truncate(code+": "+msg, 2000), code, ws, id).Error; err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventRemediationFailed, models.GovActorSystem, "remediation", govEventRefs{},
			map[string]any{"remediation_id": id, "step": seq, "code": code, "message": truncate(msg, 500)})
	})
}

/* ---------------------------------- cancel --------------------------------- */

// Cancel is POST /remediations/:id/cancel: the requester, or a holder of
// governance:remediate, ends a remediation that changed nothing (a pending
// approval is rejected with it; an open pull request is closed).
func (s *RemediationService) Cancel(ctx context.Context, ws, id, actor uuid.UUID, reason string) (*RemediationView, error) {
	if err := RequireRemediation(s.db); err != nil {
		return nil, err
	}
	reason = strings.TrimSpace(reason)
	if len(reason) > maxRemediationReason {
		return nil, GovBadParam("reason", "reason is too long.")
	}
	now := s.now().UTC()
	var closePR *remediationRow
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		r, err := readRemediation(tx, ws, id, true)
		if err != nil {
			return err
		}
		ok, err := holdsRemediate(tx, ws, actor)
		if err != nil {
			return err
		}
		if !ok && r.RequestedBy != actor {
			return govErr(http.StatusForbidden, RemCodeRemediateRequired, "Cancelling needs governance:remediate (or to be the requester).", nil)
		}
		switch r.State {
		case RemediationDraft, RemediationPrepared, RemediationAwaitingApproval, RemediationPROpen, RemediationPRClosed:
		case RemediationFailed:
			var n int64
			if err := tx.Raw(`SELECT count(*) FROM agent_remediation_step WHERE workspace_id = ? AND remediation_id = ? AND state = 'applied'`,
				ws, id).Scan(&n).Error; err != nil {
				return err
			}
			if n > 0 {
				return govConflict(RemCodeState, "Steps of this remediation were applied; it cannot be cancelled (revert with a new remediation).", nil)
			}
		default:
			return govConflict(RemCodeState, "This remediation can no longer be cancelled.", map[string]any{"state": r.State})
		}
		if r.State == RemediationAwaitingApproval && r.PendingChangeID != nil {
			if err := tx.Exec(`UPDATE pending_change SET state = 'rejected', rejected_by = ?, rejected_at = ?, decision_reason = ?, updated_at = now()
			    WHERE workspace_id = ? AND id = ? AND state = 'pending'`, actor, now, "remediation cancelled", ws, *r.PendingChangeID).Error; err != nil {
				return err
			}
		}
		if r.State == RemediationPROpen {
			closePR = r
		}
		if err := tx.Exec(`UPDATE agent_remediation SET state = 'cancelled', cancelled_at = ?, cancelled_by = ?, state_reason = ?,
		        updated_at = now() WHERE workspace_id = ? AND id = ?`, now, actor, reason, ws, id).Error; err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventRemediationCancelled, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"remediation_id": id, "previous_state": r.State, "reason": reason})
	})
	if err != nil {
		return nil, err
	}
	if closePR != nil && closePR.ConnectorID != nil && closePR.PRNumber != nil {
		var iac RemediationIaC
		_ = json.Unmarshal([]byte(closePR.IaC), &iac)
		if tgt, err := resolveRemediationIaC(ctx, s.db, ws, *closePR.ConnectorID, iac.Tool); err == nil && tgt != nil {
			if gh := DefaultGovIaCGitHub(); gh != nil {
				if err := gh.ClosePullRequest(ctx, tgt.Repo, *closePR.PRNumber, "AuthSec: the remediation was cancelled."); err != nil {
					log.Printf("[remediation] workspace %s remediation %s: closing the pull request failed: %v", ws, id, err)
				}
			}
		}
	}
	return s.Get(ctx, ws, id)
}

/* ---------------------------------- worker --------------------------------- */

// RemediationSweep runs one workspace's due work: runs not finished (a
// lapsed lease), deferred steps due, pull requests to sync, and the proof of
// recent applied remediations (the change event arrives after the write).
func (s *RemediationService) RemediationSweep(ctx context.Context, ws uuid.UUID) error {
	now := s.now().UTC()
	type due struct {
		ID    uuid.UUID
		State string
	}
	var rows []due
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT id, state FROM agent_remediation r WHERE workspace_id = ?
		    AND (state IN ('applying', 'pr_open')
		      OR (state IN ('applied', 'pr_merged', 'prepared') AND updated_at > ?)
		      OR (state = 'applied' AND EXISTS (SELECT 1 FROM agent_remediation_step st WHERE st.workspace_id = r.workspace_id
		            AND st.remediation_id = r.id AND st.state = 'waiting' AND st.due_at <= ?)))
		    ORDER BY updated_at LIMIT 100`, ws, now.Add(-7*24*time.Hour), now).Scan(&rows).Error
	}); err != nil {
		return err
	}
	for _, r := range rows {
		var err error
		switch r.State {
		case RemediationApplying:
			err = s.Execute(ctx, ws, r.ID)
		case RemediationPROpen:
			err = s.SyncPR(ctx, ws, r.ID)
		case RemediationApplied:
			if err = s.Execute(ctx, ws, r.ID); err == nil {
				_, err = s.Proof(ctx, ws, r.ID)
			}
		default:
			_, err = s.Proof(ctx, ws, r.ID)
		}
		if err != nil {
			log.Printf("[remediation] workspace %s remediation %s: %v", ws, r.ID, err)
		}
	}
	return nil
}

// RunRemediationWorker sweeps every workspace each minute
// (AUTHSEC_DISABLE_REMEDIATION_WORKER=true turns it off).
func RunRemediationWorker(ctx context.Context, db *gorm.DB) {
	if os.Getenv("AUTHSEC_DISABLE_REMEDIATION_WORKER") == "true" {
		log.Printf("[remediation] worker not started: AUTHSEC_DISABLE_REMEDIATION_WORKER=true")
		return
	}
	for {
		if ok, _ := RemediationStatus(db); ok {
			var wss []uuid.UUID
			// TENANT-EXEMPT: the worker runs across workspaces and lists workspace ids only; each is swept in its own workspace-bound transaction (tenancy.InWorkspace).
			if err := db.WithContext(ctx).Raw(`SELECT id FROM workspaces ORDER BY id`).Scan(&wss).Error; err != nil && ctx.Err() == nil {
				log.Printf("[remediation] list workspaces: %v", err)
			}
			svc := NewRemediationService(db)
			for _, ws := range wss {
				if ctx.Err() != nil {
					return
				}
				if err := svc.RemediationSweep(ctx, ws); err != nil {
					log.Printf("[remediation] sweep workspace %s: %v", ws, err)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}
