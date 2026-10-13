package platform

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/services"
)

// Access-policy routes (decision 2026-10-13; iga_gov_access_policy.go):
// under /api/iga/v1/policy/access-policies, mounted with the R2 routes
// (IGA_POLICY_R2, no new flag). The workspace is the token's only; reads
// need governance:read, writes governance:enforce. Every write is audited.

// RegisterAccessPolicyRoutes adds the routes to the policy group.
func RegisterAccessPolicyRoutes(g gin.IRoutes, ctl *IGAGovPolicyController, require func(resource, action string) gin.HandlerFunc) {
	gate := ctl.accessGate()
	g.GET("/access-policies", gate, require("governance", "read"), ctl.ListAccessPolicies)
	g.GET("/access-policies/readiness", require("governance", "read"), ctl.AccessPolicyReadiness)
	g.POST("/access-policies/preview", gate, require("governance", "read"), ctl.PreviewAccessPolicy)
	g.POST("/access-policies", gate, require("governance", "enforce"), ctl.CreateAccessPolicy)
	g.GET("/access-policies/:id", gate, require("governance", "read"), ctl.GetAccessPolicy)
	g.GET("/access-policies/:id/events", gate, require("governance", "read"), ctl.AccessPolicyEvents)
	g.POST("/access-policies/:id/versions", gate, require("governance", "enforce"), ctl.EditAccessPolicy)
	g.POST("/access-policies/:id/pause", gate, require("governance", "enforce"), ctl.PauseAccessPolicy)
	g.POST("/access-policies/:id/resume", gate, require("governance", "enforce"), ctl.ResumeAccessPolicy)
	g.POST("/access-policies/:id/end", gate, require("governance", "enforce"), ctl.EndAccessPolicy)
}

// accessGate answers 503 access_policies_unavailable while the R2 gate or
// the 137 schema is not in place (readiness stays readable: it says why).
func (ctl *IGAGovPolicyController) accessGate() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TENANT-EXEMPT: the 137 schema check reads the Postgres catalog only.
		if ok, reason := services.AccessPoliciesStatus(ctl.db()); !ok {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": gin.H{"code": services.GovCodeAccessUnavailable,
				"message": "Access policies are not available on this server.", "detail": gin.H{"reason": reason}}})
			return
		}
		c.Next()
	}
}

// TENANT-EXEMPT: not a statement here: GovAccess runs every statement in a
// transaction under row-level security for the token's workspace.
func (ctl *IGAGovPolicyController) access() *services.GovAccess {
	return services.NewGovAccess(ctl.db())
}

const accessBodyShape = "{effect, resource{resource_id, prefix?}, roles[{identity_account_id}], access[], starts_at?, ends_at?, name, reason, base_version_no?}"

// ListAccessPolicies handles GET /access-policies.
func (ctl *IGAGovPolicyController) ListAccessPolicies(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		limit := 0
		if l := c.Query("limit"); l != "" {
			n, err := strconv.Atoi(l)
			if err != nil || n < 1 || n > services.MaxGovPage {
				return nil, nil, services.GovBadParam("limit", "limit is 1 to 200.")
			}
			limit = n
		}
		out, next, err := ctl.access().List(c.Request.Context(), ws, services.AccessListQuery{Status: c.Query("status"),
			Effect: c.Query("effect"), Q: c.Query("q"), ResourceID: c.Query("resource_id"),
			IdentityAccountID: c.Query("identity_account_id"), Cursor: c.Query("cursor"), Limit: limit})
		if err != nil {
			return nil, nil, err
		}
		var cur any
		if next != "" {
			cur = next
		}
		return out, gin.H{"next_cursor": cur}, nil
	})
}

// AccessPolicyReadiness handles GET /access-policies/readiness.
func (ctl *IGAGovPolicyController) AccessPolicyReadiness(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		// TENANT-EXEMPT: AccessPolicyReadiness reads under RLS for ws.
		out, err := services.AccessPolicyReadiness(c.Request.Context(), ctl.db(), ws)
		return out, nil, err
	})
}

// PreviewAccessPolicy handles POST /access-policies/preview (nothing stored).
func (ctl *IGAGovPolicyController) PreviewAccessPolicy(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		var in igagov.AccessIntent
		if err := bindBody(c, &in, accessBodyShape); err != nil {
			return nil, nil, err
		}
		out, err := ctl.access().Preview(c.Request.Context(), ws, in)
		return out, nil, err
	})
}

// CreateAccessPolicy handles POST /access-policies: create and apply.
func (ctl *IGAGovPolicyController) CreateAccessPolicy(c *gin.Context) {
	ctl.govMutation(c, http.StatusCreated, func(ws, actor uuid.UUID) (any, *audited, error) {
		var req services.AccessPolicyRequest
		if err := bindBody(c, &req, accessBodyShape); err != nil {
			return nil, nil, err
		}
		v, err := ctl.access().Create(c.Request.Context(), ws, actor, req)
		if err != nil {
			return nil, nil, err
		}
		return v, &audited{"access_policy_create", "iga_gov_policy", v.ID.String(), nil,
			gin.H{"name": v.Name, "effect": v.Effect, "access": v.Access, "resource": v.Resource.ARN, "ends_at": v.EndsAt}}, nil
	})
}

// GetAccessPolicy handles GET /access-policies/:id.
func (ctl *IGAGovPolicyController) GetAccessPolicy(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		out, err := ctl.access().Get(c.Request.Context(), ws, id)
		return out, nil, err
	})
}

// AccessPolicyEvents handles GET /access-policies/:id/events.
func (ctl *IGAGovPolicyController) AccessPolicyEvents(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		out, err := ctl.access().Events(c.Request.Context(), ws, id)
		return out, nil, err
	})
}

// EditAccessPolicy handles POST /access-policies/:id/versions.
func (ctl *IGAGovPolicyController) EditAccessPolicy(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var req services.AccessPolicyRequest
		if err := bindBody(c, &req, accessBodyShape); err != nil {
			return nil, nil, err
		}
		v, err := ctl.access().Edit(c.Request.Context(), ws, actor, id, req)
		if err != nil {
			return nil, nil, err
		}
		return v, &audited{"access_policy_edit", "iga_gov_policy", id.String(), gin.H{"base_version_no": req.BaseVersionNo},
			gin.H{"version_no": v.VersionNo, "effect": v.Effect, "access": v.Access, "ends_at": v.EndsAt}}, nil
	})
}

func (ctl *IGAGovPolicyController) accessStep(c *gin.Context, action string,
	call func(s *services.GovAccess, ws, actor, id uuid.UUID, req services.AccessReasonRequest) (*services.AccessPolicyView, error)) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var req services.AccessReasonRequest
		if err := bindBody(c, &req, "{reason}"); err != nil {
			return nil, nil, err
		}
		v, err := call(ctl.access(), ws, actor, id, req)
		if err != nil {
			return nil, nil, err
		}
		return v, &audited{action, "iga_gov_policy", id.String(), nil, gin.H{"reason": req.Reason, "status": v.Status}}, nil
	})
}

// PauseAccessPolicy handles POST /access-policies/:id/pause.
func (ctl *IGAGovPolicyController) PauseAccessPolicy(c *gin.Context) {
	ctl.accessStep(c, "access_policy_pause", func(s *services.GovAccess, ws, actor, id uuid.UUID, req services.AccessReasonRequest) (*services.AccessPolicyView, error) {
		return s.Pause(c.Request.Context(), ws, actor, id, req)
	})
}

// ResumeAccessPolicy handles POST /access-policies/:id/resume.
func (ctl *IGAGovPolicyController) ResumeAccessPolicy(c *gin.Context) {
	ctl.accessStep(c, "access_policy_resume", func(s *services.GovAccess, ws, actor, id uuid.UUID, req services.AccessReasonRequest) (*services.AccessPolicyView, error) {
		return s.Resume(c.Request.Context(), ws, actor, id, req)
	})
}

// EndAccessPolicy handles POST /access-policies/:id/end.
func (ctl *IGAGovPolicyController) EndAccessPolicy(c *gin.Context) {
	ctl.accessStep(c, "access_policy_end", func(s *services.GovAccess, ws, actor, id uuid.UUID, req services.AccessReasonRequest) (*services.AccessPolicyView, error) {
		return s.End(c.Request.Context(), ws, actor, id, req)
	})
}
