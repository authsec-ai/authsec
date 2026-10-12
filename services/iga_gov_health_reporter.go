package services

import (
	"context"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// The production health reporter for Slack's "Report a problem" / "It's
// working" buttons (SPEC-iga-phase3-policy.md §7.6, §7.11; review fix R1a P2:
// SetGovHealthReporter had no production caller, so every Slack health
// report answered 503 health_reports_unavailable). It is T3.16's
// POST /deployments/:id/health-reports path -- GovDeployments.CreateHealthReport,
// the same authorization (an owner of a consumer of the role, or a holder of
// governance:author, checked against the database) and the same write
// (iga_gov_health_report + its iga_gov_event) -- with channel "slack".
// InstallGovPolicyRuntime installs it at startup.
//
// The notice's subject names the deployment:
//   - deployment: the subject IS the deployment;
//   - canary_gate: the subject is the rollout (iga_gov_rollout_jobs.go
//     notifyTx); the report is about its canary, so it is recorded on the
//     newest deployment of the rollout's canary target (DECISION).

type govDeploymentsHealthReporter struct{ db *gorm.DB }

// InstallGovHealthReporter installs the production reporter over db for the
// process (InstallGovPolicyRuntime, at startup); it returns a restore func.
func InstallGovHealthReporter(db *gorm.DB) (restore func()) {
	return SetGovHealthReporter(NewGovHealthReporter(db))
}

// NewGovHealthReporter is the production GovHealthReporter over db.
func NewGovHealthReporter(db *gorm.DB) GovHealthReporter {
	return &govDeploymentsHealthReporter{db: db}
}

// resolve is the deployment the report is about, the request GovDeployments
// takes, and whether the actor holds governance:author (the same permission
// lookup the console route makes).
func (h *govDeploymentsHealthReporter) resolve(ctx context.Context, r GovHealthReport) (dep uuid.UUID, req GovHealthReportRequest, author bool, err error) {
	db := h.db.WithContext(ctx)
	dep = r.SubjectID
	switch r.SubjectKind {
	case GovNoticeDeployment:
	case GovNoticeCanaryGate:
		var ids []uuid.UUID
		if err = db.Raw(`SELECT d.id FROM iga_gov_rollout ro
			JOIN iga_gov_target t ON t.workspace_id = ro.workspace_id AND t.version_id = ro.version_id AND t.is_canary
			JOIN iga_gov_plan p ON p.workspace_id = t.workspace_id AND p.target_id = t.id
			JOIN iga_gov_deployment d ON d.workspace_id = p.workspace_id AND d.plan_id = p.id
			WHERE ro.workspace_id = ? AND ro.id = ?
			ORDER BY d.created_at DESC, d.id DESC LIMIT 1`, r.WorkspaceID, r.SubjectID).Scan(&ids).Error; err != nil {
			return
		}
		if len(ids) == 0 {
			err = GovNotFound()
			return
		}
		dep = ids[0]
	default:
		err = GovBadParam("subject_kind", "Health reports are taken on deployment and canary notices.")
		return
	}
	if author, err = WorkspaceUserHoldsPermission(db, r.WorkspaceID, r.ActorID, "governance", "author"); err != nil {
		return
	}
	ch := r.Channel
	if ch == "" {
		ch = "slack"
	}
	req = GovHealthReportRequest{Kind: r.Kind, Detail: r.Detail, Channel: ch}
	return
}

// AuthorizeHealthReport is the console route's validation and authorization
// (an owner of a consumer of the role, or governance:author) without the
// write, so a Slack click is authorized before anything is recorded.
func (h *govDeploymentsHealthReporter) AuthorizeHealthReport(ctx context.Context, r GovHealthReport) error {
	dep, req, author, err := h.resolve(ctx, r)
	if err != nil {
		return err
	}
	_, err = NewGovDeployments(h.db, nil).AuthorizeHealthReport(ctx, r.WorkspaceID, r.ActorID, dep, req, author)
	return err
}

func (h *govDeploymentsHealthReporter) ReportHealth(ctx context.Context, r GovHealthReport) (any, error) {
	dep, req, author, err := h.resolve(ctx, r)
	if err != nil {
		return nil, err
	}
	return NewGovDeployments(h.db, nil).CreateHealthReport(ctx, r.WorkspaceID, r.ActorID, dep, req, author)
}
