package services

import (
	"context"

	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
)

// govIaCDeliveryHandler connects T3.17's IaC and export delivery to T3.16's
// deploy and verify jobs (GovDeliveryHandler, registered for "iac_pr" and
// "export"):
//
//   - Start: the deploy job has checked authority and left the deployment
//     queued; Deliver moves it out of queued (awaiting_merge, awaiting_apply
//     or blocked). A retry-later answer (e.g. the GitHub App still lacks write
//     permission) is returned as is, so the deployment stays queued.
//   - Verify: in awaiting_apply, ObserveApply classifies the live state with
//     igagov.Classify and moves the deployment to applied_unverified (queuing
//     verify), keeps it awaiting (overdue after the deadline, never failed),
//     or fails it as unexpected_state with the diff.
//
// PR polling in awaiting_merge stays in T3.17's iac_sync handler. The GitHub
// adapter and live reader are the process-wide ones, read per call.
type govIaCDeliveryHandler struct{ db *gorm.DB }

func (h govIaCDeliveryHandler) delivery() *GovIaCDelivery {
	return NewGovIaCDelivery(h.db, nil, ProcessGovLiveReader())
}

// Start implements GovDeliveryHandler.
func (h govIaCDeliveryHandler) Start(ctx context.Context, run *PolicyJobRun, dep models.IGAGovDeployment, _ igagov.Plan) error {
	_, err := h.delivery().Deliver(ctx, run, dep.WorkspaceID, dep.ID)
	return err
}

// Verify implements GovDeliveryHandler.
func (h govIaCDeliveryHandler) Verify(ctx context.Context, run *PolicyJobRun, dep models.IGAGovDeployment, _ igagov.Plan) error {
	_, err := h.delivery().ObserveApply(ctx, run, dep.WorkspaceID, dep.ID)
	return err
}

// InstallGovIaCDeliveryHandlers registers IaC and export delivery with the
// deploy and verify jobs. InstallGovPolicyRuntime calls it; without it those
// deployments are blocked as delivery_not_available.
func InstallGovIaCDeliveryHandlers(db *gorm.DB) {
	h := govIaCDeliveryHandler{db: db}
	RegisterGovDeliveryHandler(igagov.DeliveryIaCPR, h)
	RegisterGovDeliveryHandler(igagov.DeliveryExport, h)
}
