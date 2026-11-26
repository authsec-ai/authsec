package services

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// What an operator can do about a drifted deployment (§8.8). R1a never
// auto-reconciles: Re-apply is a new proposal that needs its own approval,
// and Accept drift closes the deployment as it is. Neither writes AWS.

// Route error codes (§7.12).
const (
	GovCodeNotDrifted           = "not_drifted"
	GovCodeDriftAlreadyAccepted = "drift_already_accepted"
	GovCodeControlRemoved       = "control_removed"
)

// Event names (vocabulary: iga_gov_event_vocabulary.go).
const (
	GovEventDriftAccepted    = "deployment.drift_accepted"
	GovEventReapplyRequested = "deployment.reapply_requested"
)

// GovDriftActionRequest is POST /deployments/:id/accept-drift and /reapply.
type GovDriftActionRequest struct {
	Reason string `json:"reason"`
}

// GovDriftAccepted is what Accept drift did.
type GovDriftAccepted struct {
	Deployment models.IGAGovDeployment `json:"deployment"`
	// ControlRemoved is true when AuthSec's boundary was no longer attached
	// and the control moved to removed (reason drift_accepted).
	ControlRemoved bool `json:"control_removed"`
}

func (s *GovDeployments) driftedDeployment(db *gorm.DB, ws, id uuid.UUID, reason string) (*models.IGAGovDeployment, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, GovBadParam("reason", "A reason is required.")
	}
	d, err := s.loadDeployment(db, ws, id)
	if err != nil {
		return nil, err
	}
	if d.State != models.GovDeployDrifted {
		return nil, govConflict(GovCodeNotDrifted, "Only a drifted deployment can be re-applied or accepted.", map[string]any{"state": d.State})
	}
	if d.DriftAcceptedAt != nil {
		return nil, govConflict(GovCodeDriftAlreadyAccepted, "This drift was already accepted.", map[string]any{"accepted_at": d.DriftAcceptedAt})
	}
	return d, nil
}

// AcceptDrift closes a drifted deployment: it stays `drifted`, marked
// accepted with who, when and why. The role is read again first (the
// discovery role, as an enforcement observer: the control's sequence before
// the readback, the write by compare-and-swap) so the posture follows what
// is attached now; when AuthSec's boundary is no longer attached the control
// moves to `removed` (reason drift_accepted). A lost swap is 409: the role
// changed while it was being read; ask again.
func (s *GovDeployments) AcceptDrift(ctx context.Context, ws, actor, depID uuid.UUID, req GovDriftActionRequest) (*GovDriftAccepted, error) {
	var d *models.IGAGovDeployment
	var ctl *models.IGAGovControl
	var plan igagov.Plan
	var pol uuid.UUID
	var seen int64
	err := s.read(ctx, ws, func(tx *gorm.DB) error {
		var e error
		d, e = s.driftedDeployment(tx, ws, depID, req.Reason)
		if e != nil {
			return e
		}
		if d.Kind != igagov.PlanApply && d.Kind != igagov.PlanSplit {
			return govConflict(GovCodeNotDrifted, "Only a drifted apply deployment is accepted.", map[string]any{"kind": d.Kind})
		}
		ctl, e = s.loadControl(tx, ws, d.ControlID)
		if e != nil {
			return e
		}
		if e = inFlightCheck(tx, ws, d.ControlID); e != nil {
			return e
		}
		row, e := s.loadPlanRow(tx, ws, d.PlanID)
		if e != nil {
			return e
		}
		plan, e = fullPlanFromRow(*row)
		if e != nil {
			return e
		}
		pol, _, e = s.policyOfVersion(tx, ws, d.VersionID)
		if e != nil {
			return e
		}
		seen, _, e = controlSeen(tx, ws, d.ControlID)
		return e
	})
	if err != nil {
		return nil, err
	}
	k, a := userActor(actor)
	reason := strings.TrimSpace(req.Reason)
	out := &GovDriftAccepted{}

	if ctl.State == "removed" {
		// Nothing to observe: the control is already retired (the role is gone).
		err = s.write(ctx, ws, func(tx *gorm.DB) error {
			if err := acceptDriftRowTx(tx, *d, actor, reason); err != nil {
				return err
			}
			return appendGovEvent(tx, ws, GovEventDriftAccepted, k, a, depRefs(*d, pol), map[string]any{"reason": reason, "control_removed": false,
				"note": "the control was already retired"})
		})
	} else {
		live, _, lerr := s.liveClassify(ctx, *ctl, plan)
		if lerr != nil {
			return nil, lerr
		}
		retire := live.Role == nil || plan.DesiredBoundaryARN == nil || live.Role.BoundaryARN != *plan.DesiredBoundaryARN
		o := &govObservation{Dep: *d, ControlID: d.ControlID, Seen: seen, InForce: inForce(live), Writer: "accept_drift", Retire: retire}
		o.Step2 = func(tx *gorm.DB, newSeq int64) error {
			// The control row is locked by the compare-and-swap; a change that
			// started since the check above is seen here.
			if err := inFlightCheck(tx, ws, d.ControlID); err != nil {
				return err
			}
			if err := acceptDriftRowTx(tx, *d, actor, reason); err != nil {
				return err
			}
			if err := appendGovEvent(tx, ws, GovEventDriftAccepted, k, a, depRefs(*d, pol), map[string]any{"reason": reason,
				"control_removed": retire, "enforcement_seq": newSeq, "boundary": inForce(live)}); err != nil {
				return err
			}
			if retire {
				pid := pol
				return appendGovEvent(tx, ws, GovEventControlRemoved, k, a, govEventRefs{PolicyID: &pid, DeploymentID: &d.ID}, map[string]any{
					"control_id": d.ControlID, "reason": "drift_accepted", "request_reason": reason, "enforcement_seq": newSeq})
			}
			return nil
		}
		out.ControlRemoved = retire
		err = s.write(ctx, ws, func(tx *gorm.DB) error {
			_, e := s.observeTx(tx, o)
			return e
		})
	}
	switch {
	case errors.Is(err, errGovCASLost):
		return nil, govConflict(GovCodeDeploymentInFlight, "The role changed while AuthSec was reading it; try again.", nil)
	case errors.Is(err, errStateMoved):
		return nil, govConflict(GovCodeNotDrifted, "The deployment moved meanwhile.", nil)
	case err != nil:
		return nil, err
	}
	if err := s.read(ctx, ws, func(tx *gorm.DB) error {
		nd, e := s.loadDeployment(tx, ws, depID)
		if e == nil {
			out.Deployment = *nd
		}
		return e
	}); err != nil {
		return nil, err
	}
	return out, nil
}

func acceptDriftRowTx(tx *gorm.DB, d models.IGAGovDeployment, actor uuid.UUID, reason string) error {
	res := tenancy.GormExec(inWorkspace(tx.Statement.Context, d.WorkspaceID), tx, `UPDATE iga_gov_deployment SET drift_accepted_at = now(), drift_accepted_by = $2, drift_accepted_reason = $3, updated_at = now()
		WHERE workspace_id = $1 AND id = $4 AND state = 'drifted' AND drift_accepted_at IS NULL`, actor, reason, d.ID)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		return errStateMoved
	}
	return nil
}

// Reapply opens a new proposal with the drifted deployment's intent: the
// plans are compiled from what is in AWS now and the version goes to review
// like any other (a new approval; the old one covered a world that changed).
// The control stays as it is until that version is approved and deployed.
func (s *GovDeployments) Reapply(ctx context.Context, ws, actor, depID uuid.UUID, req GovDriftActionRequest) (any, error) {
	var d *models.IGAGovDeployment
	var pol uuid.UUID
	var v models.IGAGovPolicyVersion
	var maxNo int
	err := s.read(ctx, ws, func(tx *gorm.DB) error {
		var e error
		d, e = s.driftedDeployment(tx, ws, depID, req.Reason)
		if e != nil {
			return e
		}
		if d.Kind != igagov.PlanApply {
			return govConflict(GovCodeNotUndoable, "Only an apply deployment is re-applied.", map[string]any{"kind": d.Kind})
		}
		ctl, e := s.loadControl(tx, ws, d.ControlID)
		if e != nil {
			return e
		}
		if ctl.State == "removed" {
			return govConflict(GovCodeControlRemoved, "AuthSec no longer controls this role; create a new policy for it.", nil)
		}
		pol, _, e = s.policyOfVersion(tx, ws, d.VersionID)
		if e != nil {
			return e
		}
		if e = tx.Where("workspace_id = ? AND id = ?", ws, d.VersionID).Take(&v).Error; e != nil {
			return e
		}
		return tenancy.GormRaw(inWorkspace(ctx, ws), tx, `SELECT max(version_no) FROM iga_gov_policy_version WHERE workspace_id = $1 AND policy_id = $2`, pol).Scan(&maxNo).Error
	})
	if err != nil {
		return nil, err
	}
	nv, err := s.authoring.CreateVersion(ctx, ws, actor, pol, maxNo, v.Intent)
	if err != nil {
		return nil, err
	}
	res, err := s.authoring.Propose(ctx, ws, actor, pol, nv.No)
	if err != nil {
		return nil, err
	}
	k, a := userActor(actor)
	if err := s.write(ctx, ws, func(tx *gorm.DB) error {
		return appendGovEvent(tx, ws, GovEventReapplyRequested, k, a, depRefs(*d, pol), map[string]any{"version_no": nv.No,
			"reason": strings.TrimSpace(req.Reason), "note": "A new plan needs its own approval; nothing changes in AWS until it is approved and deployed."})
	}); err != nil {
		return nil, err
	}
	return res, nil
}
