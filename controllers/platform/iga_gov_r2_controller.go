package platform

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/services"
)

// R2 routes (SPEC-iga-phase3-policy.md §12.3; IGA_POLICY_R2): temporary
// grants and session revocations under the gated /api/iga/v1/policy group.
// The workspace is the token's; another workspace's row is 404. Every
// mutation writes its iga_gov_event in the service transaction and an
// audit_events row here (govMutation).
//
// DECISION R2-21: the routes are MOUNTED only while IGA_POLICY_R2 is switched
// on at startup (the route table is then exactly R1a's with it off, so the
// R1a audit walker and route tests see no change), and each answers 422
// policy_r2_unavailable while the R2 gate is not on (schema 061 unverified,
// or IGA_POLICY unavailable). Permissions: requesting a grant
// governance:author; approving / rejecting it governance:grant (the new
// permission, 061); revoking it early governance:enforce; requesting a
// session revocation governance:enforce (governance:emergency in addition for
// emergency: true); approving / rejecting it governance:approve; lifting it
// governance:enforce. Separation of duties (requester <> approver) is
// enforced in the service and by 061's CHECKs.

// RegisterIGAPolicyR2Routes adds the R2 routes to the policy group.
func RegisterIGAPolicyR2Routes(g gin.IRoutes, ctl *IGAGovPolicyController, require func(resource, action string) gin.HandlerFunc) {
	r2 := R2Gate()
	g.GET("/temporary-grants", r2, require("governance", "read"), ctl.ListTemporaryGrants)
	g.POST("/temporary-grants", r2, require("governance", "author"), ctl.CreateTemporaryGrant)
	g.GET("/temporary-grants/:id", r2, require("governance", "read"), ctl.GetTemporaryGrant)
	g.POST("/temporary-grants/:id/approve", r2, require("governance", "grant"), ctl.ApproveTemporaryGrant)
	g.POST("/temporary-grants/:id/reject", r2, require("governance", "grant"), ctl.RejectTemporaryGrant)
	g.POST("/temporary-grants/:id/revoke", r2, require("governance", "enforce"), ctl.RevokeTemporaryGrant)
	g.GET("/session-revocations", r2, require("governance", "read"), ctl.ListSessionRevocations)
	g.POST("/session-revocations", r2, require("governance", "enforce"), ctl.CreateSessionRevocation)
	g.GET("/session-revocations/:id", r2, require("governance", "read"), ctl.GetSessionRevocation)
	g.POST("/session-revocations/:id/approve", r2, require("governance", "approve"), ctl.ApproveSessionRevocation)
	g.POST("/session-revocations/:id/reject", r2, require("governance", "approve"), ctl.RejectSessionRevocation)
	g.POST("/session-revocations/:id/revoke", r2, require("governance", "enforce"), ctl.LiftSessionRevocation)
}

// R2Gate answers 422 policy_r2_unavailable while the R2 gate is not on.
func R2Gate() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := services.RequirePolicyR2(); err != nil {
			govError(c, err)
			return
		}
		c.Next()
	}
}

func (ctl *IGAGovPolicyController) r2() *services.GovR2 { return services.NewGovR2(ctl.db()) }

// ListTemporaryGrants handles GET /temporary-grants (?state, ?role_id, ?limit).
func (ctl *IGAGovPolicyController) ListTemporaryGrants(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		limit, err := limitParam(c)
		if err != nil {
			return nil, nil, err
		}
		out, err := ctl.r2().ListGrants(c.Request.Context(), ws, c.Query("state"), c.Query("role_id"), limit)
		return out, nil, err
	})
}

// GetTemporaryGrant handles GET /temporary-grants/:id.
func (ctl *IGAGovPolicyController) GetTemporaryGrant(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		out, err := ctl.r2().GetGrant(c.Request.Context(), ws, id)
		return out, nil, err
	})
}

// CreateTemporaryGrant handles POST /temporary-grants.
func (ctl *IGAGovPolicyController) CreateTemporaryGrant(c *gin.Context) {
	ctl.govMutation(c, http.StatusCreated, func(ws, actor uuid.UUID) (any, *audited, error) {
		var req services.GovGrantRequest
		if err := bindBody(c, &req, "{identity_account_id | role_arn+account_id, actions, resources?, expires_at | duration_minutes, reason, escalation_acknowledgement?}"); err != nil {
			return nil, nil, err
		}
		g, err := ctl.r2().CreateGrant(c.Request.Context(), ws, actor, req)
		if err != nil {
			return nil, nil, err
		}
		return g, &audited{"temporary_grant_request", "iga_gov_temp_grant", g.ID.String(), nil,
			gin.H{"role_id": g.RoleID, "expires_at": g.ExpiresAt, "policy_arn": g.PolicyARN}}, nil
	})
}

func (ctl *IGAGovPolicyController) grantDecision(c *gin.Context, action string,
	call func(s *services.GovR2, ws, actor, id uuid.UUID, req services.GovDecisionRequest) (any, error)) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var req services.GovDecisionRequest
		if c.Request.ContentLength != 0 {
			if err := bindBody(c, &req, "{reason?}"); err != nil {
				return nil, nil, err
			}
		}
		out, err := call(ctl.r2(), ws, actor, id, req)
		if err != nil {
			return nil, nil, err
		}
		return out, &audited{action, "iga_gov_r2", id.String(), nil, gin.H{"reason": req.Reason}}, nil
	})
}

// ApproveTemporaryGrant handles POST /temporary-grants/:id/approve.
func (ctl *IGAGovPolicyController) ApproveTemporaryGrant(c *gin.Context) {
	ctl.grantDecision(c, "temporary_grant_approve", func(s *services.GovR2, ws, actor, id uuid.UUID, req services.GovDecisionRequest) (any, error) {
		return s.ApproveGrant(c.Request.Context(), ws, actor, id, req)
	})
}

// RejectTemporaryGrant handles POST /temporary-grants/:id/reject.
func (ctl *IGAGovPolicyController) RejectTemporaryGrant(c *gin.Context) {
	ctl.grantDecision(c, "temporary_grant_reject", func(s *services.GovR2, ws, actor, id uuid.UUID, req services.GovDecisionRequest) (any, error) {
		return s.RejectGrant(c.Request.Context(), ws, actor, id, req)
	})
}

// RevokeTemporaryGrant handles POST /temporary-grants/:id/revoke.
func (ctl *IGAGovPolicyController) RevokeTemporaryGrant(c *gin.Context) {
	ctl.grantDecision(c, "temporary_grant_revoke", func(s *services.GovR2, ws, actor, id uuid.UUID, req services.GovDecisionRequest) (any, error) {
		return s.RevokeGrant(c.Request.Context(), ws, actor, id, req)
	})
}

// ListSessionRevocations handles GET /session-revocations.
func (ctl *IGAGovPolicyController) ListSessionRevocations(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		limit, err := limitParam(c)
		if err != nil {
			return nil, nil, err
		}
		out, err := ctl.r2().ListRevocations(c.Request.Context(), ws, c.Query("state"), c.Query("role_id"), limit)
		return out, nil, err
	})
}

// GetSessionRevocation handles GET /session-revocations/:id.
func (ctl *IGAGovPolicyController) GetSessionRevocation(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		out, err := ctl.r2().GetRevocation(c.Request.Context(), ws, id)
		return out, nil, err
	})
}

// CreateSessionRevocation handles POST /session-revocations; emergency: true
// needs governance:emergency as well.
func (ctl *IGAGovPolicyController) CreateSessionRevocation(c *gin.Context) {
	ctl.govMutation(c, http.StatusCreated, func(ws, actor uuid.UUID) (any, *audited, error) {
		var req services.GovRevocationRequest
		if err := bindBody(c, &req, "{identity_account_id | role_arn+account_id, reason, keep_hours?, emergency?}"); err != nil {
			return nil, nil, err
		}
		if req.Emergency {
			ok, err := services.WorkspaceUserHoldsPermission(ctl.db(), ws, actor, "governance", "emergency")
			if err != nil {
				return nil, nil, err
			}
			if !ok {
				return nil, nil, services.GovForbidden("governance:emergency is required for an emergency session revocation.")
			}
		}
		r, err := ctl.r2().CreateRevocation(c.Request.Context(), ws, actor, req)
		if err != nil {
			return nil, nil, err
		}
		action := "session_revocation_request"
		if req.Emergency {
			action = "session_revocation_emergency"
		}
		return r, &audited{action, "iga_gov_session_revocation", r.ID.String(), nil,
			gin.H{"role_id": r.RoleID, "emergency": r.Emergency, "reason": r.Reason}}, nil
	})
}

// ApproveSessionRevocation handles POST /session-revocations/:id/approve.
func (ctl *IGAGovPolicyController) ApproveSessionRevocation(c *gin.Context) {
	ctl.grantDecision(c, "session_revocation_approve", func(s *services.GovR2, ws, actor, id uuid.UUID, req services.GovDecisionRequest) (any, error) {
		return s.DecideRevocation(c.Request.Context(), ws, actor, id, true, req)
	})
}

// RejectSessionRevocation handles POST /session-revocations/:id/reject.
func (ctl *IGAGovPolicyController) RejectSessionRevocation(c *gin.Context) {
	ctl.grantDecision(c, "session_revocation_reject", func(s *services.GovR2, ws, actor, id uuid.UUID, req services.GovDecisionRequest) (any, error) {
		return s.DecideRevocation(c.Request.Context(), ws, actor, id, false, req)
	})
}

// LiftSessionRevocation handles POST /session-revocations/:id/revoke.
func (ctl *IGAGovPolicyController) LiftSessionRevocation(c *gin.Context) {
	ctl.grantDecision(c, "session_revocation_lift", func(s *services.GovR2, ws, actor, id uuid.UUID, req services.GovDecisionRequest) (any, error) {
		return s.LiftRevocation(c.Request.Context(), ws, actor, id, req)
	})
}
