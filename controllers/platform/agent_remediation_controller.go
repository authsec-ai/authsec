package platform

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/services"
)

// Remediation (SPEC-secops-backend-upgrade.md W8). On /api/iga/v1, behind
// auth, with the §5.2 envelope:
//
//	GET    /remediations?state=&kind=&case_id=&limit=  governance:read
//	POST   /remediations {kind, target, case_id, reason} governance:author (plans: steps, collateral, mode; writes nothing)
//	GET    /remediations/readiness                       governance:read (remediation role per account)
//	GET    /remediations/:id                             governance:read
//	POST   /remediations/:id/apply {reason}              governance:read + governance:remediate held now (tier 4);
//	                                                    a write then waits for a second person (pending change)
//	GET    /remediations/:id/proof                       governance:read (evaluates and records the proof)
//	POST   /remediations/:id/cancel {reason}             governance:read + (governance:remediate or the requester)
//	POST   /remediations/bindings {connector_id}         iga:admin (remediation role setup: ExternalId, template)
//	POST   /remediations/bindings/:id/verify {role_arn}  iga:admin
//	DELETE /remediations/bindings/:id                    iga:admin
//
// The workspace is the token's only; another workspace's id is 404. Every
// write's actor is the verified human (humanActor) and is audited.

// RemediationController serves the routes above.
type RemediationController struct{ db func() *gorm.DB }

// NewRemediationController reads the process database on every request.
func NewRemediationController() *RemediationController {
	// TENANT-EXEMPT: not a statement: the handle every service below opens its workspace transaction on.
	return &RemediationController{db: func() *gorm.DB { return config.DB }}
}

// NewRemediationControllerFor uses the graph controller's database.
func NewRemediationControllerFor(g *IGAGraphReadController) *RemediationController {
	return &RemediationController{db: g.db}
}

// NewRemediationControllerWith builds the controller over db (tests).
func NewRemediationControllerWith(db *gorm.DB) *RemediationController {
	return &RemediationController{db: func() *gorm.DB { return db }}
}

// MountRemediationRoutes mounts the routes on /api/iga/v1 behind auth.
func MountRemediationRoutes(r gin.IRouter, ctl *RemediationController, auth gin.HandlerFunc, require func(resource, action string) gin.HandlerFunc) {
	g := r.Group("/api/iga/v1")
	g.Use(GraphEnvelope(auth), TierGuard())
	RegisterRemediationRoutes(g, ctl, GraphRequire(require))
}

// RegisterRemediationRoutes is the route table (tests mount the same one).
func RegisterRemediationRoutes(g gin.IRoutes, ctl *RemediationController, require func(resource, action string) gin.HandlerFunc) {
	read := require("governance", "read")
	author := require("governance", "author")
	admin := require("iga", "admin")
	g.GET("/remediations", read, ctl.List)
	g.POST("/remediations", author, ctl.Create)
	g.GET("/remediations/readiness", read, ctl.Readiness)
	g.POST("/remediations/bindings", admin, ctl.SetupBinding)
	g.POST("/remediations/bindings/:id/verify", admin, ctl.VerifyBinding)
	g.DELETE("/remediations/bindings/:id", admin, ctl.RevokeBinding)
	g.GET("/remediations/:id", read, ctl.Get)
	g.POST("/remediations/:id/apply", read, ctl.Apply)
	g.GET("/remediations/:id/proof", read, ctl.Proof)
	g.POST("/remediations/:id/cancel", read, ctl.Cancel)
}

func (ctl *RemediationController) svc() *services.RemediationService {
	// TENANT-EXEMPT: not a statement: the service runs every statement in a transaction under row-level security for the token's workspace.
	return services.NewRemediationService(ctl.db())
}

func (ctl *RemediationController) actor(c *gin.Context, ws uuid.UUID) (uuid.UUID, error) {
	// TENANT-EXEMPT: humanActor runs its one statement through tenancy.QueryRowContext.
	uid, err := humanActor(c, ctl.db(), ws)
	if err != nil {
		if errors.Is(err, errNotWorkspaceHuman) {
			return uuid.Nil, services.GovForbidden("A remediation decision requires a verified workspace member session.")
		}
		return uuid.Nil, err
	}
	return uuid.Parse(uid)
}

// List handles GET /remediations.
func (ctl *RemediationController) List(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		if err := arOnlyParams(c, "state", "kind", "case_id", "limit"); err != nil {
			return nil, nil, err
		}
		limit, err := limitParam(c)
		if err != nil {
			return nil, nil, err
		}
		f := services.RemediationFilter{State: c.Query("state"), Kind: c.Query("kind"), Limit: limit}
		if v := c.Query("case_id"); v != "" {
			id, err := uuid.Parse(v)
			if err != nil {
				return nil, nil, services.GovBadParam("case_id", "case_id must be a case id.")
			}
			f.CaseID = &id
		}
		rows, err := ctl.svc().List(c.Request.Context(), ws, f)
		return rows, nil, err
	})
}

type remediationBody struct {
	Kind   *string                     `json:"kind"`
	Target *services.RemediationTarget `json:"target"`
	CaseID *string                     `json:"case_id"`
	Reason *string                     `json:"reason"`
}

// Create handles POST /remediations.
func (ctl *RemediationController) Create(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		actor, err := ctl.actor(c, ws)
		if err != nil {
			return nil, nil, err
		}
		var b remediationBody
		if err := decodeARBody(c, &b, "kind", "target", "case_id", "reason"); err != nil {
			return nil, nil, err
		}
		if b.Kind == nil || b.Target == nil {
			return nil, nil, services.GovBadParam("kind", "kind and target are required.")
		}
		req := services.RemediationRequest{Kind: *b.Kind, Target: *b.Target}
		if b.Reason != nil {
			req.Reason = *b.Reason
		}
		if b.CaseID != nil && *b.CaseID != "" {
			id, err := uuid.Parse(*b.CaseID)
			if err != nil {
				return nil, nil, services.GovBadParam("case_id", "case_id must be a case id.")
			}
			req.CaseID = &id
		}
		v, err := ctl.svc().Create(c.Request.Context(), ws, actor, req)
		if err != nil {
			return nil, nil, err
		}
		auditAdminMutation(c, ws.String(), "remediation.create", "agent_remediation", v.ID.String(), http.StatusCreated, nil, remediationAudit(v))
		return v, nil, nil
	})
}

// remediationAudit is what the audit row keeps: never documents.
func remediationAudit(v *services.RemediationView) map[string]any {
	if v == nil {
		return nil
	}
	return map[string]any{"id": v.ID, "kind": v.Kind, "target_ref": v.Target.Ref, "state": v.State, "mode": v.Mode, "mode_reason": v.ModeReason}
}

// Get handles GET /remediations/:id.
func (ctl *RemediationController) Get(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := aidPathID(c, "id")
		if err != nil {
			return nil, nil, err
		}
		v, err := ctl.svc().Get(c.Request.Context(), ws, id)
		return v, nil, err
	})
}

type remediationReasonBody struct {
	Reason *string `json:"reason"`
}

func (ctl *RemediationController) reasonBody(c *gin.Context) (string, error) {
	if c.Request.ContentLength == 0 {
		return "", nil
	}
	var b remediationReasonBody
	if err := decodeARBody(c, &b, "reason"); err != nil {
		return "", err
	}
	if b.Reason == nil {
		return "", nil
	}
	return *b.Reason, nil
}

// Apply handles POST /remediations/:id/apply.
func (ctl *RemediationController) Apply(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := aidPathID(c, "id")
		if err != nil {
			return nil, nil, err
		}
		before, err := ctl.svc().Get(c.Request.Context(), ws, id)
		if err != nil {
			return nil, nil, err
		}
		actor, err := ctl.actor(c, ws)
		if err != nil {
			return nil, nil, err
		}
		note, err := ctl.reasonBody(c)
		if err != nil {
			return nil, nil, err
		}
		res, err := ctl.svc().Apply(c.Request.Context(), ws, id, actor, note)
		if err != nil {
			return nil, nil, err
		}
		auditAdminMutation(c, ws.String(), "remediation.apply", "agent_remediation", id.String(), http.StatusOK,
			remediationAudit(before), remediationAudit(res.Remediation))
		return res, nil, nil
	})
}

// Proof handles GET /remediations/:id/proof.
func (ctl *RemediationController) Proof(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := aidPathID(c, "id")
		if err != nil {
			return nil, nil, err
		}
		p, err := ctl.svc().Proof(c.Request.Context(), ws, id)
		return p, nil, err
	})
}

// Cancel handles POST /remediations/:id/cancel.
func (ctl *RemediationController) Cancel(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := aidPathID(c, "id")
		if err != nil {
			return nil, nil, err
		}
		before, err := ctl.svc().Get(c.Request.Context(), ws, id)
		if err != nil {
			return nil, nil, err
		}
		actor, err := ctl.actor(c, ws)
		if err != nil {
			return nil, nil, err
		}
		reason, err := ctl.reasonBody(c)
		if err != nil {
			return nil, nil, err
		}
		v, err := ctl.svc().Cancel(c.Request.Context(), ws, id, actor, reason)
		if err != nil {
			return nil, nil, err
		}
		auditAdminMutation(c, ws.String(), "remediation.cancel", "agent_remediation", id.String(), http.StatusOK, remediationAudit(before), remediationAudit(v))
		return v, nil, nil
	})
}

// Readiness handles GET /remediations/readiness.
func (ctl *RemediationController) Readiness(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		// TENANT-EXEMPT: not a statement: the readiness runs its statements in a workspace transaction under row-level security.
		r, err := services.GetRemediationReadiness(c.Request.Context(), ctl.db(), ws)
		return r, nil, err
	})
}

// SetupBinding handles POST /remediations/bindings.
func (ctl *RemediationController) SetupBinding(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		actor, err := ctl.actor(c, ws)
		if err != nil {
			return nil, nil, err
		}
		var b struct {
			ConnectorID *string `json:"connector_id"`
		}
		if err := decodeARBody(c, &b, "connector_id"); err != nil {
			return nil, nil, err
		}
		if b.ConnectorID == nil {
			return nil, nil, services.GovBadParam("connector_id", "connector_id is required.")
		}
		cid, err := uuid.Parse(*b.ConnectorID)
		if err != nil {
			return nil, nil, services.GovNotFound()
		}
		// TENANT-EXEMPT: not a statement: the binding service runs its statements in workspace transactions under row-level security.
		s, err := services.SetupRemediationBinding(c.Request.Context(), ctl.db(), ws, cid, actor)
		if err != nil {
			return nil, nil, err
		}
		auditAdminMutation(c, ws.String(), "remediation_binding.create", "cloud_remediation_binding", s.Binding.ID.String(), http.StatusCreated, nil, s.Binding)
		return s, nil, nil
	})
}

// VerifyBinding handles POST /remediations/bindings/:id/verify.
func (ctl *RemediationController) VerifyBinding(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := aidPathID(c, "id")
		if err != nil {
			return nil, nil, err
		}
		actor, err := ctl.actor(c, ws)
		if err != nil {
			return nil, nil, err
		}
		var b struct {
			RoleARN *string `json:"role_arn"`
		}
		if err := decodeARBody(c, &b, "role_arn"); err != nil {
			return nil, nil, err
		}
		if b.RoleARN == nil {
			return nil, nil, services.GovBadParam("role_arn", "role_arn is required.")
		}
		// TENANT-EXEMPT: not a statement: the binding service runs its statements in workspace transactions under row-level security.
		out, err := services.VerifyRemediationBinding(c.Request.Context(), ctl.db(), ws, id, actor, *b.RoleARN)
		if out != nil {
			auditAdminMutation(c, ws.String(), "remediation_binding.verify", "cloud_remediation_binding", id.String(), http.StatusOK, nil, out)
		}
		if err != nil {
			return nil, nil, err
		}
		return out, nil, nil
	})
}

// RevokeBinding handles DELETE /remediations/bindings/:id.
func (ctl *RemediationController) RevokeBinding(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := aidPathID(c, "id")
		if err != nil {
			return nil, nil, err
		}
		actor, err := ctl.actor(c, ws)
		if err != nil {
			return nil, nil, err
		}
		// TENANT-EXEMPT: not a statement: the binding service runs its statements in workspace transactions under row-level security.
		out, err := services.RevokeRemediationBinding(c.Request.Context(), ctl.db(), ws, id, actor)
		if err != nil {
			return nil, nil, err
		}
		auditAdminMutation(c, ws.String(), "remediation_binding.revoke", "cloud_remediation_binding", id.String(), http.StatusOK, nil, out)
		return out, nil, nil
	})
}
