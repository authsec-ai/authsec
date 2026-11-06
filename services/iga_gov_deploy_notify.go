package services

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"context"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// Deployment notices (§8.1 step 3, §8.8, §8.9, §9.7). One `deployment`
// notice per (deployment, channel, recipient); its text follows the
// deployment's state when it is rendered, so a reminder or a retry never
// describes a state the deployment has left:
//
//   - outcome_unresolved: assigned to the policy owner and every holder of
//     governance:enforce, notified at once and reminded hourly;
//   - drifted (not accepted): the policy owner and every enforcer, once;
//   - an emergency undo or removal: the policy owner and every approver, once.
//
// The sweeper is the producer, not each state change: it is the same safety
// net that moves stuck deployments, it runs on every worker replica, and the
// unique notice row means replicas cannot double-send. A notice therefore
// leaves within one sweep of the state change (GovDeploymentNoticeEvery).

const (
	// GovDeploymentNoticeEvery is how often the sweeper looks for deployments
	// that need a notice.
	GovDeploymentNoticeEvery = 2 * time.Minute
	// GovUnresolvedReminder is the reminder interval of an unresolved outcome.
	GovUnresolvedReminder = time.Hour
)

func init() {
	RegisterGovNoticeSubject(GovNoticeDeployment, GovNoticeSubject{Render: renderDeploymentNotice})
}

// deploymentNoticeUsers is who a deployment notice goes to: the policy owner
// (the version's author when no owner is set) and the holders of the
// permission that can act on it.
func deploymentNoticeUsers(tx *gorm.DB, ws uuid.UUID, d models.IGAGovDeployment, action string) ([]uuid.UUID, error) {
	var row struct {
		OwnerUserID *uuid.UUID
		CreatedBy   uuid.UUID
	}
	if err := tenancy.GormRaw(inWorkspace(tx.Statement.Context, ws), tx, `SELECT p.owner_user_id, v.created_by FROM iga_gov_policy_version v
		JOIN iga_gov_policy p ON p.workspace_id = v.workspace_id AND p.id = v.policy_id
		WHERE v.workspace_id = $1 AND v.id = $2`, d.VersionID).Scan(&row).Error; err != nil {
		return nil, err
	}
	seen := map[uuid.UUID]bool{}
	var out []uuid.UUID
	add := func(u uuid.UUID) {
		if u != uuid.Nil && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	if row.OwnerUserID != nil {
		add(*row.OwnerUserID)
	} else {
		add(row.CreatedBy)
	}
	holders, err := WorkspaceUsersHoldingPermission(tx, ws, "governance", action)
	if err != nil {
		return nil, err
	}
	for _, u := range holders {
		add(u)
	}
	return out, nil
}

// notifyDeploymentTx queues the deployment's notice on every channel that
// reaches the users, and the workspace webhook.
func notifyDeploymentTx(tx *gorm.DB, ws uuid.UUID, d models.IGAGovDeployment, users []uuid.UUID, resend bool) error {
	if t, err := GovWorkspaceWebhookTarget(tx, ws); err != nil {
		return err
	} else if t != nil {
		if _, err := EnqueueGovNotificationTx(tx, ws, GovNoticeDeployment, d.ID, GovChannelWebhook, GovRecipientWorkspaceWebhook, resend); err != nil {
			return err
		}
	}
	email := govChannels(tx, ws).EmailEnabled
	for _, u := range users {
		if email {
			if _, err := EnqueueGovNotificationTx(tx, ws, GovNoticeDeployment, d.ID, GovChannelEmail, GovUserRecipient(u), resend); err != nil {
				return err
			}
		}
		for _, ch := range govExtraChannels() {
			ok, err := ch.Reaches(tx, ws, u)
			if err != nil {
				return err
			}
			if ok {
				if _, err := EnqueueGovNotificationTx(tx, ws, GovNoticeDeployment, d.ID, ch.Channel(), GovUserRecipient(u), resend); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// SweepDeploymentNotices queues the notices described in the file comment.
// It returns how many deployments it queued a notice for.
func (s *GovDeployments) SweepDeploymentNotices(ctx context.Context) (int, error) {
	var rows []models.IGAGovDeployment
	// TENANT-EXEMPT: cross-workspace scheduler enumerates deployments; noticeIfDue scopes every read/write to the persisted deployment workspace.
	if err := s.db.WithContext(ctx).Raw(`
		SELECT d.* FROM iga_gov_deployment d
		 WHERE (d.state = 'outcome_unresolved')
		    OR (d.state = 'drifted' AND d.drift_accepted_at IS NULL)
		    OR (d.emergency_by IS NOT NULL AND d.kind IN ('undo','remove_control','split_revert') AND d.created_at > ?)
		 ORDER BY d.created_at`, s.now().Add(-7*24*time.Hour)).Scan(&rows).Error; err != nil {
		return 0, err
	}
	n := 0
	var first error
	for _, d := range rows {
		queued, err := s.noticeIfDue(ctx, d)
		if err != nil {
			if first == nil {
				first = fmt.Errorf("deployment %s: %w", d.ID, err)
			}
			continue
		}
		if queued {
			n++
		}
	}
	return n, first
}

func (s *GovDeployments) noticeIfDue(ctx context.Context, d models.IGAGovDeployment) (bool, error) {
	ws := d.WorkspaceID
	queued := false
	err := s.write(ctx, ws, func(tx *gorm.DB) error {
		// At is the newest moment any notice row was created, sent or reset to
		// pending (a resend moves available_at), so a channel that keeps failing
		// is not reset again at every sweep.
		var last struct {
			Rows int
			At   *time.Time
		}
		if err := tenancy.GormRaw(inWorkspace(ctx, ws), tx, `SELECT count(*) AS rows, max(GREATEST(created_at, available_at, sent_at)) AS at
			FROM iga_gov_notification
			WHERE workspace_id = $1 AND subject_kind = 'deployment' AND subject_id = $2`, d.ID).Scan(&last).Error; err != nil {
			return err
		}
		resend := false
		switch {
		case d.State == models.GovDeployOutcomeUnresolved:
			if last.Rows > 0 && last.At != nil && s.now().Sub(*last.At) < GovUnresolvedReminder {
				return nil
			}
			resend = last.Rows > 0
		case d.State == models.GovDeployDrifted:
			// Once per drift. Include the delivery/reset time because the same
			// notice row is reused; its original created_at never advances.
			if last.Rows > 0 && last.At != nil && !last.At.Before(d.UpdatedAt) {
				return nil
			}
			resend = last.Rows > 0
		case last.Rows > 0:
			return nil // an emergency change is announced once
		}
		action := "enforce"
		if d.EmergencyBy != nil {
			action = "approve"
		}
		users, err := deploymentNoticeUsers(tx, ws, d, action)
		if err != nil {
			return err
		}
		if err := notifyDeploymentTx(tx, ws, d, users, resend); err != nil {
			return err
		}
		queued = true
		return nil
	})
	return queued, err
}

// renderDeploymentNotice renders a deployment notice from the deployment's
// state now.
func renderDeploymentNotice(db *gorm.DB, n *models.IGAGovNotification, user *uuid.UUID) (*GovNotice, error) {
	var ds []models.IGAGovDeployment
	if err := db.Where("workspace_id = ? AND id = ?", n.WorkspaceID, n.SubjectID).Limit(1).Find(&ds).Error; err != nil {
		return nil, err
	}
	if len(ds) == 0 {
		return nil, GovNotifyPermanent(errors.New("the deployment no longer exists"))
	}
	d := ds[0]
	var ctx struct {
		PolicyID   uuid.UUID
		PolicyName string
		VersionNo  int
		RoleARN    string
	}
	if err := tenancy.GormRaw(inWorkspace(db.Statement.Context, d.WorkspaceID), db, `SELECT p.id AS policy_id, p.name AS policy_name, v.version_no, c.role_arn
		FROM iga_gov_policy_version v
		JOIN iga_gov_policy p ON p.workspace_id = v.workspace_id AND p.id = v.policy_id
		JOIN iga_gov_control c ON c.workspace_id = $1 AND c.id = $2
		WHERE v.workspace_id = $1 AND v.id = $3`, d.ControlID, d.VersionID).Scan(&ctx).Error; err != nil {
		return nil, err
	}
	role := roleName(ctx.RoleARN)
	link := govConsoleLink("/iga/policy/deployments/" + d.ID.String())
	var kind, title string
	var lines []string
	switch {
	case d.State == models.GovDeployOutcomeUnresolved:
		var at *time.Time
		if err := tenancy.GormRaw(inWorkspace(db.Statement.Context, d.WorkspaceID), db, `SELECT max(dispatched_at) FROM iga_gov_attempt WHERE workspace_id = $1 AND deployment_id = $2`, d.ID).Scan(&at).Error; err != nil {
			return nil, err
		}
		when := "earlier"
		if at != nil {
			when = at.UTC().Format("15:04 MST")
		}
		kind, title = "outcome_unresolved", "Action needed: "+role+" is locked"
		lines = []string{
			fmt.Sprintf("AuthSec could not confirm whether its %s change to %s reached AWS.", when, role),
			"Choose: Re-read, Accept what AWS shows (needs approval), or Emergency undo.",
			"This role stays locked until you choose.",
		}
		if d.StateReason != "" {
			lines = append(lines, "Detail: "+d.StateReason)
		}
	case d.State == models.GovDeployDrifted && d.DriftAcceptedAt == nil:
		kind, title = "drifted", "Drift: "+role+" no longer matches AuthSec's change"
		lines = []string{
			fmt.Sprintf("The boundary AuthSec applied to %s was changed outside AuthSec (%s).", role, d.StateReason),
			"AuthSec never reconciles on its own. Re-apply (a new plan and approval) or Accept drift.",
		}
	case d.EmergencyBy != nil:
		kind, title = "emergency", "Emergency "+strings.ReplaceAll(d.Kind, "_", " ")+": "+role
		lines = []string{
			fmt.Sprintf("%s of %s was started without an approval.", strings.ReplaceAll(d.Kind, "_", " "), role),
			"Reason: " + d.EmergencyReason,
		}
	default:
		return nil, GovNotifyPermanent(fmt.Errorf("deployment %s is %s; nothing to report", d.ID, d.State))
	}
	if user == nil {
		doc := map[string]any{"type": "iga.policy.deployment", "version": 1, "workspace_id": n.WorkspaceID.String(), "kind": kind,
			"deployment_id": d.ID.String(), "deployment_kind": d.Kind, "state": d.State, "policy_id": ctx.PolicyID.String(),
			"policy_name": ctx.PolicyName, "version_no": ctx.VersionNo, "role_arn": ctx.RoleARN, "detail": d.StateReason}
		if link != "" {
			doc["link"] = link
		}
		return &GovNotice{Webhook: doc, Title: title, Lines: lines, Link: link}, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Policy %q (version %d)\n\n", ctx.PolicyName, ctx.VersionNo)
	for _, l := range lines {
		fmt.Fprintf(&b, "%s\n", l)
	}
	if link != "" {
		fmt.Fprintf(&b, "\nOpen the deployment:\n  %s\n", link)
	}
	fmt.Fprintf(&b, "\nDeployment ID: %s\n\nRegards,\nAuthSec Team\n", d.ID)
	return &GovNotice{Subject: title, Text: b.String(), Title: title, Lines: lines, Link: link}, nil
}
