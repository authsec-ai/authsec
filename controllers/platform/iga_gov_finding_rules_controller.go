package platform

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/services"
)

// The §7.1 finding-rule and finding-exception routes (review fix R1a P2),
// under the gated /api/iga/v1/policy group, all governance:author:
//
//	GET    /finding-rules?cursor&limit
//	POST   /finding-rules                {kind, scope?, params?, enabled?}
//	PATCH  /finding-rules/:id            {scope?, params?, enabled?}
//	DELETE /finding-rules/:id
//	POST   /findings/:id/exception       {until, reason}
//	DELETE /findings/:id/exception       {reason?}
//
// The workspace is the token's only; another workspace's rule or finding is
// 404. Every mutation requires a verified human member, writes iga_gov_event
// in its transaction (services/iga_gov_finding_rules.go) and audit_events
// through auditAdminMutation (govMutation).

func (ctl *IGAGovPolicyController) findingRules() *services.GovFindingRules {
	return services.NewGovFindingRules(ctl.db())
}

// ListFindingRules handles GET /finding-rules?cursor&limit (cursor: the last
// id of the previous page; limit 1-200, default 200).
func (ctl *IGAGovPolicyController) ListFindingRules(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		limit := services.MaxGovPage
		if l := c.Query("limit"); l != "" {
			n, err := strconv.Atoi(l)
			if err != nil || n < 1 || n > services.MaxGovPage {
				return nil, nil, services.GovBadParam("limit", "limit must be 1-200.")
			}
			limit = n
		}
		after := uuid.Nil
		if cur := c.Query("cursor"); cur != "" {
			id, err := uuid.Parse(cur)
			if err != nil {
				return nil, nil, &services.GovError{Status: http.StatusBadRequest, Code: "cursor_invalid",
					Message: "The cursor is not valid.", Detail: map[string]any{"parameter": "cursor"}}
			}
			after = id
		}
		rules, next, err := ctl.findingRules().ListRules(c.Request.Context(), ws, after, limit)
		if err != nil {
			return nil, nil, err
		}
		return rules, gin.H{"next_cursor": next}, nil
	})
}

// CreateFindingRule handles POST /finding-rules.
func (ctl *IGAGovPolicyController) CreateFindingRule(c *gin.Context) {
	ctl.govMutation(c, http.StatusCreated, func(ws, actor uuid.UUID) (any, *audited, error) {
		var req services.GovFindingRuleRequest
		if err := bindBody(c, &req, "{kind, scope?, params?, enabled?}"); err != nil {
			return nil, nil, err
		}
		r, err := ctl.findingRules().CreateRule(c.Request.Context(), ws, actor, req)
		if err != nil {
			return nil, nil, err
		}
		return r, &audited{"create", "iga_gov_finding_rule", r.ID.String(), nil, r}, nil
	})
}

// UpdateFindingRule handles PATCH /finding-rules/:id.
func (ctl *IGAGovPolicyController) UpdateFindingRule(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var req services.GovFindingRuleRequest
		if err := bindBody(c, &req, "{scope?, params?, enabled?}"); err != nil {
			return nil, nil, err
		}
		before, after, err := ctl.findingRules().UpdateRule(c.Request.Context(), ws, actor, id, req)
		if err != nil {
			return nil, nil, err
		}
		return after, &audited{"update", "iga_gov_finding_rule", id.String(), before, after}, nil
	})
}

// DeleteFindingRule handles DELETE /finding-rules/:id.
func (ctl *IGAGovPolicyController) DeleteFindingRule(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		r, err := ctl.findingRules().DeleteRule(c.Request.Context(), ws, actor, id)
		if err != nil {
			return nil, nil, err
		}
		return gin.H{"id": id, "deleted": true}, &audited{"delete", "iga_gov_finding_rule", id.String(), r, nil}, nil
	})
}

// ExceptFinding handles POST /findings/:id/exception {until, reason}.
func (ctl *IGAGovPolicyController) ExceptFinding(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var req services.GovFindingExceptionRequest
		if err := bindBody(c, &req, "{until, reason}"); err != nil {
			return nil, nil, err
		}
		before, after, err := ctl.findingRules().RecordException(c.Request.Context(), ws, actor, id, req)
		if err != nil {
			return nil, nil, err
		}
		return after, &audited{"except_finding", "iga_gov_finding", id.String(), before, after}, nil
	})
}

// ClearFindingException handles DELETE /findings/:id/exception {reason?}.
func (ctl *IGAGovPolicyController) ClearFindingException(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var req struct {
			Reason string `json:"reason"`
		}
		if c.Request.ContentLength != 0 {
			if err := bindBody(c, &req, "{reason?}"); err != nil {
				return nil, nil, err
			}
		}
		before, after, err := ctl.findingRules().ClearException(c.Request.Context(), ws, actor, id, req.Reason)
		if err != nil {
			return nil, nil, err
		}
		return after, &audited{"clear_finding_exception", "iga_gov_finding", id.String(), before, after}, nil
	})
}
