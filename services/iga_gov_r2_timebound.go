package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
)

// Time-conditioned retention after deployment (R2 piece 1; DECISION R2-2,
// R2-7, R2-19): AWS narrows the boundary on its own at each <until>; AuthSec
// tells people before and after, and makes posture reflect it.
//
// DECISION R2-19: the "finding/notice before and after expiry" is a notice,
// not a new finding kind: TimeBoundNoticeLead (7 days) before each <until>
// the time_bound job writes time_bound.expiring and notifies the policy's
// owner and the version's author (and the workspace webhook); at <until> it
// runs an enforcement observation of the role (§8.7, the same compare-and-
// swap writer the drift check uses) so the posture of a time-bound service
// becomes `applied` -- and its unused_service finding follows the posture --
// then writes time_bound.expired and notifies. A new finding kind would need
// its own evaluation rule and fingerprint in the R1a evaluator, which R2
// leaves untouched. Action-level time-bound items are notified the same way;
// their posture is not tracked (posture is per service in R1a).

// Event names.
const (
	GovEventTimeBoundExpiring = "time_bound.expiring"
	GovEventTimeBoundExpired  = "time_bound.expired"
)

func dueTimeBound(ctx context.Context, db *gorm.DB, now time.Time) ([]ScheduledPolicyJob, error) {
	if !PolicyR2On() {
		return nil, nil
	}
	var rows []struct {
		WorkspaceID uuid.UUID
		ID          uuid.UUID
	}
	// TENANT-EXEMPT: the policy job scheduler runs across workspaces (no request tenant); each job it enqueues carries its row's workspace_id
	if err := db.Raw(`SELECT d.workspace_id, d.id FROM iga_gov_deployment d
		JOIN iga_gov_plan p ON p.workspace_id = d.workspace_id AND p.id = d.plan_id
		WHERE d.state = 'verified' AND p.diff -> 'time_bound' IS NOT NULL`).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]ScheduledPolicyJob, 0, len(rows))
	for _, r := range rows {
		id := r.ID
		out = append(out, ScheduledPolicyJob{WorkspaceID: r.WorkspaceID, SubjectID: &id, DedupeKey: "time_bound:" + id.String()})
	}
	return out, nil
}

// TimeBoundHandler is the time_bound job (subject: a verified deployment
// whose plan keeps something until a date).
func (s *GovDeployments) TimeBoundHandler(ctx context.Context, run *PolicyJobRun) error {
	if run.Job.SubjectID == nil {
		return PolicyJobAbandon("time_bound needs a deployment subject")
	}
	if !PolicyR2On() {
		return nil
	}
	ws := run.Job.WorkspaceID
	db := run.DB().WithContext(ctx)
	d, err := s.loadDeployment(db, ws, *run.Job.SubjectID)
	if err != nil {
		var ge *GovError
		if errors.As(err, &ge) {
			return PolicyJobAbandon("deployment not found")
		}
		return err
	}
	if d.State != models.GovDeployVerified {
		return nil
	}
	plan, err := loadGovPlan(run.DB(), ws, d.PlanID)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	observed := false
	for _, it := range plan.Diff.TimeBound {
		until, err := igagov.ParseUntil(it.Until)
		if err != nil {
			continue
		}
		if now.Before(until.Add(-igagov.TimeBoundNoticeLead)) {
			continue
		}
		name := GovEventTimeBoundExpiring
		if !now.Before(until) {
			name = GovEventTimeBoundExpired
		}
		var seen int64
		// TENANT-EXEMPT: fenced time_bound job; bound to workspace_id = ? (the job's workspace) and the deployment
		if err := db.Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND deployment_id = ? AND event = ?
			AND payload->>'key' = ? AND payload->>'until' = ?`, ws, d.ID, name, it.Key, it.Until).Scan(&seen).Error; err != nil {
			return err
		}
		if seen > 0 {
			continue
		}
		if name == GovEventTimeBoundExpired && it.Kind == igagov.TimeBoundKindService && !observed {
			// Posture follows the expiry (DECISION R2-7, R2-19).
			ctl, err := s.loadControl(db, ws, d.ControlID)
			if err != nil {
				return err
			}
			if err := s.observeTimeBound(ctx, run, *d, plan, *ctl); err != nil {
				return err
			}
			observed = true
		}
		if err := run.InTx(ctx, func(tx *gorm.DB) error {
			if err := s.event(tx, *d, name, map[string]any{"kind": it.Kind, "key": it.Key, "until": it.Until,
				"control_id": d.ControlID}); err != nil {
				return err
			}
			return s.timeBoundNotifyTx(tx, *d)
		}); err != nil {
			return err
		}
	}
	return nil
}

// observeTimeBound is one enforcement observation of the deployment's role
// (§8.7): the posture of every service is recomputed from the boundary in
// force, time-aware (excludes, DECISION R2-7), under the control's
// compare-and-swap. A read that is not the deployment's after-state is left
// to the drift check.
func (s *GovDeployments) observeTimeBound(ctx context.Context, run *PolicyJobRun, d models.IGAGovDeployment, p igagov.Plan, ctl models.IGAGovControl) error {
	_, err := s.observe(ctx, run, func(ctx context.Context) (*govObservation, error) {
		db := run.DB().WithContext(ctx)
		seen, cstate, err := controlSeen(db, d.WorkspaceID, d.ControlID)
		if err != nil || cstate == "removed" {
			return nil, err
		}
		live, cl, err := s.readPlan(ctx, run, d, p, ctl)
		if err != nil {
			return nil, err
		}
		if cl.Class != igagov.ClassAfter {
			return nil, nil
		}
		return &govObservation{Dep: d, ControlID: d.ControlID, Seen: seen, InForce: inForce(live), Writer: "time_bound"}, nil
	})
	return err
}

func (s *GovDeployments) timeBoundNotifyTx(tx *gorm.DB, d models.IGAGovDeployment) error {
	var v models.IGAGovPolicyVersion
	if err := tx.Where("workspace_id = ? AND id = ?", d.WorkspaceID, d.VersionID).Take(&v).Error; err != nil {
		return err
	}
	var p models.IGAGovPolicy
	if err := tx.Where("workspace_id = ? AND id = ?", d.WorkspaceID, v.PolicyID).Take(&p).Error; err != nil {
		return err
	}
	users := []uuid.UUID{v.CreatedBy}
	if p.OwnerUserID != nil {
		users = append(users, *p.OwnerUserID)
	}
	return r2NotifyTx(tx, d.WorkspaceID, GovNoticeTimeBound, d.ID, users)
}

/* ---------------------------------- notices -------------------------------- */

func init() {
	RegisterGovNoticeSubject(GovNoticeTemporaryGrant, GovNoticeSubject{Render: renderGrantNotice})
	RegisterGovNoticeSubject(GovNoticeSessionRevocation, GovNoticeSubject{Render: renderRevocationNotice})
	RegisterGovNoticeSubject(GovNoticeTimeBound, GovNoticeSubject{Render: renderTimeBoundNotice})
}

func r2Notice(kind string, n *models.IGAGovNotification, user *uuid.UUID, title string, doc map[string]any, lines []string) *GovNotice {
	link := govConsoleLink("/iga/policy/" + kind)
	doc["type"], doc["version"], doc["workspace_id"] = "iga.policy."+strings.ReplaceAll(kind, "-", "_"), 1, n.WorkspaceID.String()
	if link != "" {
		doc["link"] = link
	}
	if user == nil {
		return &GovNotice{Webhook: doc, Title: title, Link: link}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", title)
	for _, l := range lines {
		fmt.Fprintf(&b, "%s\n", l)
	}
	if link != "" {
		fmt.Fprintf(&b, "\nOpen AuthSec:\n  %s\n", link)
	}
	fmt.Fprintf(&b, "\nRegards,\nAuthSec Team\n")
	return &GovNotice{Subject: title, Text: b.String(), Title: title, Lines: lines, Link: link}
}

func renderGrantNotice(db *gorm.DB, n *models.IGAGovNotification, user *uuid.UUID) (*GovNotice, error) {
	var rows []models.IGAGovTempGrant
	if err := db.Where("workspace_id = ? AND id = ?", n.WorkspaceID, n.SubjectID).Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotifyPermanent(errors.New("the temporary grant no longer exists"))
	}
	g := rows[0]
	var acts []string
	_ = json.Unmarshal(g.Actions, &acts)
	title := fmt.Sprintf("Temporary grant on %s: %s", g.RoleARN, g.State)
	lines := []string{"Actions: " + strings.Join(acts, ", "), "Expires: " + igagov.AWSTime(g.ExpiresAt)}
	if g.StateReason != "" {
		lines = append(lines, "Reason: "+g.StateReason)
	}
	if g.Drift != "" {
		lines = append(lines, "Drift: "+g.Drift)
	}
	return r2Notice("temporary-grants", n, user, title, map[string]any{"grant_id": g.ID.String(), "state": g.State,
		"role_arn": g.RoleARN, "actions": acts, "expires_at": g.ExpiresAt, "drift": g.Drift}, lines), nil
}

func renderRevocationNotice(db *gorm.DB, n *models.IGAGovNotification, user *uuid.UUID) (*GovNotice, error) {
	var rows []models.IGAGovSessionRevocation
	if err := db.Where("workspace_id = ? AND id = ?", n.WorkspaceID, n.SubjectID).Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotifyPermanent(errors.New("the session revocation no longer exists"))
	}
	r := rows[0]
	title := fmt.Sprintf("Session revocation on %s: %s", r.RoleARN, r.State)
	if r.Emergency {
		title = "EMERGENCY " + title
	}
	lines := []string{"Reason: " + r.Reason}
	if r.IssuedBefore != nil {
		lines = append(lines, "Sessions issued before "+igagov.AWSTime(*r.IssuedBefore)+" are denied.")
	}
	if r.RemoveAfter != nil {
		lines = append(lines, "The deny is removed after "+igagov.AWSTime(*r.RemoveAfter)+".")
	}
	return r2Notice("session-revocations", n, user, title, map[string]any{"revocation_id": r.ID.String(), "state": r.State,
		"role_arn": r.RoleARN, "emergency": r.Emergency, "issued_before": r.IssuedBefore, "remove_after": r.RemoveAfter}, lines), nil
}

func renderTimeBoundNotice(db *gorm.DB, n *models.IGAGovNotification, user *uuid.UUID) (*GovNotice, error) {
	var deps []models.IGAGovDeployment
	if err := db.Where("workspace_id = ? AND id = ?", n.WorkspaceID, n.SubjectID).Limit(1).Find(&deps).Error; err != nil {
		return nil, err
	}
	if len(deps) == 0 {
		return nil, GovNotifyPermanent(errors.New("the deployment no longer exists"))
	}
	p, err := loadGovPlan(db, n.WorkspaceID, deps[0].PlanID)
	if err != nil {
		return nil, err
	}
	var c models.IGAGovControl
	if err := db.Where("workspace_id = ? AND id = ?", n.WorkspaceID, deps[0].ControlID).Take(&c).Error; err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var lines []string
	for _, it := range p.Diff.TimeBound {
		state := "kept until"
		if t, err := igagov.ParseUntil(it.Until); err == nil && !now.Before(t) {
			state = "expired at"
		}
		lines = append(lines, fmt.Sprintf("%s %s: %s %s", it.Kind, it.Key, state, it.Until))
	}
	title := "Time-bound access on " + c.RoleARN
	return r2Notice("policies", n, user, title, map[string]any{"deployment_id": deps[0].ID.String(), "role_arn": c.RoleARN,
		"time_bound": p.Diff.TimeBound}, lines), nil
}
