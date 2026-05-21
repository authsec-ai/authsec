package platform

import (
	"net/http"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
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
type AuthorizationController struct{}

func NewAuthorizationController() *AuthorizationController {
	return &AuthorizationController{}
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
