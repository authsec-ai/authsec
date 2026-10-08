package platform

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/services"
)

// §7.6 deployments, validations and health reports, and §7.7 removing
// AuthSec control (T3.16). Deployments run over the process-wide deployment
// environment (services.SetGovDeployEnv). Every mutation writes its
// iga_gov_event in the service transaction and auditAdminMutation here.

func (ctl *IGAGovPolicyController) deployments() *services.GovDeployments {
	return services.NewGovDeployments(ctl.db(), nil).WithAuthoring(ctl.authoring())
}

// ListDeployments handles GET /deployments.
func (ctl *IGAGovPolicyController) ListDeployments(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		limit, err := limitParam(c)
		if err != nil {
			return nil, nil, err
		}
		f := services.GovDeploymentFilter{State: c.Query("state"), Account: c.Query("account"), Kind: c.Query("kind"),
			Cursor: c.Query("cursor"), Limit: limit}
		if p := c.Query("policy_id"); p != "" {
			id, err := uuid.Parse(p)
			if err != nil {
				return nil, nil, services.GovBadParam("policy_id", "policy_id must be a uuid.")
			}
			f.PolicyID = &id
		}
		list, next, err := ctl.deployments().ListDeployments(c.Request.Context(), ws, f)
		if err != nil {
			return nil, nil, err
		}
		return list, gin.H{"next_cursor": next}, nil
	})
}

// GetDeployment handles GET /deployments/:id.
func (ctl *IGAGovPolicyController) GetDeployment(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		d, err := ctl.deployments().GetDeployment(c.Request.Context(), ws, id)
		return d, nil, err
	})
}

// ResolveDeployment handles POST /deployments/:id/resolve (governance:enforce;
// governance:emergency for emergency_undo).
func (ctl *IGAGovPolicyController) ResolveDeployment(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var req services.GovResolveRequest
		if err := bindBody(c, &req, "{action, reason, version_no?}"); err != nil {
			return nil, nil, err
		}
		if req.Action == "emergency_undo" {
			ok, err := services.WorkspaceUserHoldsPermission(ctl.db(), ws, actor, "governance", "emergency")
			if err != nil {
				return nil, nil, err
			}
			if !ok {
				return nil, nil, services.GovForbidden("governance:emergency is required for an emergency undo.")
			}
		}
		out, err := ctl.deployments().Resolve(c.Request.Context(), ws, actor, id, req)
		if err != nil {
			return nil, nil, err
		}
		return out, &audited{"resolve", "iga_gov_deployment", id.String(), nil, gin.H{"action": req.Action, "reason": req.Reason}}, nil
	})
}

func (ctl *IGAGovPolicyController) undo(c *gin.Context, emergency bool) {
	ctl.govMutation(c, http.StatusCreated, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var req services.GovUndoRequest
		if c.Request.ContentLength != 0 {
			if err := bindBody(c, &req, "{plan_id?, reason?}"); err != nil {
				return nil, nil, err
			}
		}
		d, err := ctl.deployments().Undo(c.Request.Context(), ws, actor, id, req, emergency)
		if err != nil {
			return nil, nil, err
		}
		action := "undo"
		if emergency {
			action = "emergency_undo"
		}
		return d, &audited{action, "iga_gov_deployment", id.String(), nil, gin.H{"undo_deployment_id": d.ID, "plan_id": d.PlanID,
			"reason": req.Reason}}, nil
	})
}

// UndoDeployment handles POST /deployments/:id/undo.
func (ctl *IGAGovPolicyController) UndoDeployment(c *gin.Context) { ctl.undo(c, false) }

// EmergencyUndoDeployment handles POST /deployments/:id/emergency-undo.
func (ctl *IGAGovPolicyController) EmergencyUndoDeployment(c *gin.Context) { ctl.undo(c, true) }

// DeclareValidation handles POST /deployments/:id/validations.
func (ctl *IGAGovPolicyController) DeclareValidation(c *gin.Context) {
	ctl.govMutation(c, http.StatusCreated, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var req services.GovValidationRequest
		if err := bindBody(c, &req, "{items, correlation, dedicated_workload_id?, window_start, window_end, note?}"); err != nil {
			return nil, nil, err
		}
		v, err := ctl.deployments().DeclareValidation(c.Request.Context(), ws, actor, id, req)
		if err != nil {
			return nil, nil, err
		}
		return v, &audited{"declare_validation", "iga_gov_validation", v.ID.String(), nil, gin.H{"deployment_id": id,
			"session_name": v.SessionName, "items": len(v.Items)}}, nil
	})
}

// ListValidations handles GET /deployments/:id/validations.
func (ctl *IGAGovPolicyController) ListValidations(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		v, err := ctl.deployments().ListValidations(c.Request.Context(), ws, id)
		return v, nil, err
	})
}

// CreateHealthReport handles POST /deployments/:id/health-reports (an owner
// of a consumer, or governance:author).
func (ctl *IGAGovPolicyController) CreateHealthReport(c *gin.Context) {
	ctl.govMutation(c, http.StatusCreated, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var req services.GovHealthReportRequest
		if err := bindBody(c, &req, "{kind, service?, detail}"); err != nil {
			return nil, nil, err
		}
		author, err := services.WorkspaceUserHoldsPermission(ctl.db(), ws, actor, "governance", "author")
		if err != nil {
			return nil, nil, err
		}
		hr, err := ctl.deployments().CreateHealthReport(c.Request.Context(), ws, actor, id, req, author)
		if err != nil {
			return nil, nil, err
		}
		return hr, &audited{"health_report", "iga_gov_health_report", hr.ID.String(), nil, gin.H{"deployment_id": id, "kind": hr.Kind}}, nil
	})
}

// ListHealthReports handles GET /deployments/:id/health-reports.
func (ctl *IGAGovPolicyController) ListHealthReports(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		r, err := ctl.deployments().ListHealthReports(c.Request.Context(), ws, id)
		return r, nil, err
	})
}

func (ctl *IGAGovPolicyController) removeControl(c *gin.Context, emergency bool) {
	ctl.govMutation(c, http.StatusCreated, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var req services.GovRemoveControlRequest
		if err := bindBody(c, &req, "{control_ids, reason, delivery?}"); err != nil {
			return nil, nil, err
		}
		out, err := ctl.deployments().RemoveControl(c.Request.Context(), ws, actor, id, req, emergency)
		if err != nil {
			return nil, nil, err
		}
		action := "remove_control"
		if emergency {
			action = "emergency_remove_control"
		}
		return out, &audited{action, "iga_gov_policy", id.String(), nil, gin.H{"control_ids": req.ControlIDs, "reason": req.Reason,
			"version_no": out.VersionNo, "deployments": len(out.Deployments)}}, nil
	})
}

// RemoveControl handles POST /policies/:id/remove-control.
func (ctl *IGAGovPolicyController) RemoveControl(c *gin.Context) { ctl.removeControl(c, false) }

// EmergencyRemoveControl handles POST /policies/:id/emergency-remove-control.
func (ctl *IGAGovPolicyController) EmergencyRemoveControl(c *gin.Context) { ctl.removeControl(c, true) }
