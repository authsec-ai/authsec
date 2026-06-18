package platform

import (
	"fmt"
	"net/http"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/database"
	"github.com/authsec-ai/authsec/internal/policy"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// PolicyCheckRequest represents PDP input.
type PolicyCheckRequest struct {
	PrincipalID    string `json:"principal_id" binding:"required"`
	Resource       string `json:"resource" binding:"required"`
	Action         string `json:"action" binding:"required"`
	ScopeID        string `json:"scope_id,omitempty"`
	ScopeType      string `json:"scope_type,omitempty"`
	ApplicationID  string `json:"application_id,omitempty"`
	OAuthScopeName string `json:"oauth_scope,omitempty"`
}

// PolicyCheckResponse represents PDP output.
type PolicyCheckResponse struct {
	Allowed bool   `json:"allowed"`
	Trace   string `json:"trace"`
}

// AuthorizationController exposes PDP checks for admin and end-user contexts.
type AuthorizationController struct {
	riskEngine *services.RiskEngineService
	actionRepo *database.AgentActionRepository
	pdp        policy.PDP // nil when POLICY_ENGINE_MODE=off
}

func NewAuthorizationController() *AuthorizationController {
	ctrl := &AuthorizationController{}
	if config.DB != nil {
		repo := database.NewAgentActionRepository(config.GetDatabase())
		ctrl.actionRepo = repo
		ctrl.riskEngine = services.NewRiskEngineService(repo)
	}
	if config.AppConfig != nil && config.DB != nil {
		mode := config.AppConfig.PolicyEngineMode
		if mode == "shadow" || mode == "enforce" {
			ctrl.pdp = policy.NewSimplePDP(config.DB)
		}
	}
	return ctrl
}

// DecisionRequest is the body for POST /authz/decision.
type DecisionRequest struct {
	Tool     string                 `json:"tool"`
	Resource string                 `json:"resource"`
	Action   string                 `json:"action"`
	Context  map[string]interface{} `json:"context,omitempty"`
}

// DecisionResponse is the response for POST /authz/decision.
type DecisionResponse struct {
	Effect      string   `json:"effect"`      // "permit" or "deny"
	Obligations []string `json:"obligations"` // e.g. ["require_approval"]
	RiskScore   int      `json:"risk_score"`
	RiskLevel   string   `json:"risk_level"`
	Reason      string   `json:"reason,omitempty"`
}

// Decision is the per-tool PEP endpoint used by SDK/AgentCore to check
// whether a tool call is permitted before executing it. The bearer token
// identifies the subject (user or SA) and workspace; the body carries the
// tool details. Requires POLICY_OBLIGATIONS flag to enforce approval obligations.
//
// POST /authz/decision
func (ac *AuthorizationController) Decision(c *gin.Context) {
	var req DecisionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	userIDStr, err := middlewares.ResolveUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}
	userID, _ := uuid.Parse(userIDStr)

	workspaceIDStr, _ := c.Get("workspace_id")
	workspaceID, _ := uuid.Parse(fmt.Sprintf("%v", workspaceIDStr))

	// action defaults to tool name when not specified separately
	action := req.Action
	if action == "" {
		action = req.Tool
	}
	resource := req.Resource
	if resource == "" {
		resource = req.Tool
	}

	obligations := []string{}
	riskScore := 0
	riskLevel := "low"
	reason := ""

	// ── Risk evaluation ──
	if ac.riskEngine != nil && ac.actionRepo != nil {
		settings, settErr := ac.actionRepo.GetOrCreateSettings(workspaceID)
		if settErr == nil {
			clientID, _ := c.Get("client_id")
			agentID := fmt.Sprintf("%v", clientID)

			eval, evalErr := ac.riskEngine.Evaluate(
				workspaceID, agentID, action, resource,
				req.Context, settings,
			)
			if evalErr == nil {
				riskScore = eval.Score
				riskLevel = eval.Level
				if eval.ApprovalType == "single" || eval.ApprovalType == "multi" {
					obligations = append(obligations, "require_approval")
				}
			}
		}
	}

	// ── PDP gate ──
	effect := "permit"
	if ac.pdp != nil {
		pdpReq := policy.PolicyRequest{
			WorkspaceID: workspaceID,
			SubjectType: "user",
			SubjectID:   userID,
			TokenFamily: "xaa", // per-tool decisions are in the agent (xaa/m2m) context
		}
		clientIDVal, _ := c.Get("client_id")
		pdpReq.ClientID = fmt.Sprintf("%v", clientIDVal)

		decision, _ := ac.pdp.Decide(c.Request.Context(), pdpReq)
		mode := ""
		if config.AppConfig != nil {
			mode = config.AppConfig.PolicyEngineMode
		}
		if mode == "enforce" && decision.Effect == policy.EffectDeny {
			effect = "deny"
			reason = decision.Reason
		}
	}

	c.JSON(http.StatusOK, DecisionResponse{
		Effect:      effect,
		Obligations: obligations,
		RiskScore:   riskScore,
		RiskLevel:   riskLevel,
		Reason:      reason,
	})
}

// buildPDPRequest parses the inbound payload + token into a typed PDPRequest.
// The PrincipalType is supplied by the caller (operator vs end-user routes
// surface different audiences).
func buildPDPRequest(c *gin.Context, req PolicyCheckRequest, principalType services.PrincipalType) (services.PDPRequest, error) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		return services.PDPRequest{}, err
	}

	principalID, err := uuid.Parse(req.PrincipalID)
	if err != nil {
		return services.PDPRequest{}, err
	}

	pdpReq := services.PDPRequest{
		WorkspaceID:   workspaceID,
		PrincipalType: principalType,
		PrincipalID:   principalID,
		Resource:      req.Resource,
		Action:        req.Action,
	}

	if req.ScopeID != "" {
		sid, err := uuid.Parse(req.ScopeID)
		if err != nil {
			return services.PDPRequest{}, err
		}
		pdpReq.ScopeID = &sid
	}
	if req.ScopeType != "" {
		st := req.ScopeType
		pdpReq.ScopeType = &st
	}
	if req.ApplicationID != "" {
		aid, err := uuid.Parse(req.ApplicationID)
		if err != nil {
			return services.PDPRequest{}, err
		}
		pdpReq.ApplicationID = &aid
	}
	if req.OAuthScopeName != "" {
		s := req.OAuthScopeName
		pdpReq.OAuthScopeName = &s
	}

	return pdpReq, nil
}

// PolicyDecisionPointCheckAdmin godoc
// @Summary Admin Authorization - Policy Check
// @Description Workspace-scoped PDP for operator/admin principals. Reads role_bindings -> roles -> role_permissions -> permissions filtered by workspace_id extracted from the JWT.
// @Tags Admin Authorization
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param input body PolicyCheckRequest true "Policy check payload"
// @Success 200 {object} PolicyCheckResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/admin/policy/check [post]
func (ac *AuthorizationController) PolicyDecisionPointCheckAdmin(c *gin.Context) {
	var req PolicyCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}

	pdpReq, err := buildPDPRequest(c, req, services.PrincipalOperator)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := services.NewRBACService(config.DB).Check(c.Request.Context(), pdpReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Policy check failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, PolicyCheckResponse{
		Allowed: result.Allowed,
		Trace:   result.Trace,
	})
}

// PolicyDecisionPointCheckUser godoc
// @Summary Enduser Authorization - Policy Check
// @Description Workspace-scoped PDP for end-user principals. workspace_id is sourced from the JWT — never inferred from URL or headers.
// @Tags Enduser Authorization
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param input body PolicyCheckRequest true "Policy check payload"
// @Success 200 {object} PolicyCheckResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/user/rbac/policy/check [post]
func (ac *AuthorizationController) PolicyDecisionPointCheckUser(c *gin.Context) {
	var req PolicyCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}

	pdpReq, err := buildPDPRequest(c, req, services.PrincipalEndUser)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := services.NewRBACService(config.DB).Check(c.Request.Context(), pdpReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Policy check failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, PolicyCheckResponse{
		Allowed: result.Allowed,
		Trace:   result.Trace,
	})
}
