package controllers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/spire/middleware"
	"github.com/authsec-ai/authsec/internal/spire/services"
	"github.com/authsec-ai/authsec/internal/spire/utils"
)

// defaultMaxDelegatedTTL is the default maximum TTL for delegated JWT-SVIDs (24 hours).
const defaultMaxDelegatedTTL = 86400

// restrictedCustomClaims are claim keys that cannot be injected via custom_claims in delegated tokens.
var restrictedCustomClaims = map[string]bool{
	"role": true, "roles": true, "perms": true,
	"scopes": true, "scope": true, "admin": true, "is_admin": true,
	"workspace_id": true, "tenant_id": true,
}

// JWTSVIDController handles JWT-SVID operations
type JWTSVIDController struct {
	service          *services.JWTSVIDService
	entries          *services.WorkloadEntryService
	logger           *logrus.Entry
	defaultAudience  []string
	allowedAudiences map[string]bool
}

// JWTControllerOption configures optional JWTSVIDController behaviour.
type JWTControllerOption func(*JWTSVIDController)

// WithDefaultAudience sets the audience applied when a delegated issuance omits it.
func WithDefaultAudience(aud []string) JWTControllerOption {
	return func(c *JWTSVIDController) { c.defaultAudience = aud }
}

// WithAllowedAudiences restricts delegated issuance to the listed audiences.
func WithAllowedAudiences(aud []string) JWTControllerOption {
	return func(c *JWTSVIDController) {
		c.allowedAudiences = make(map[string]bool, len(aud))
		for _, a := range aud {
			c.allowedAudiences[a] = true
		}
	}
}

// WithEntryService lets agents request JWT-SVIDs for the workloads they
// serve (entries whose parent is the agent).
func WithEntryService(entries *services.WorkloadEntryService) JWTControllerOption {
	return func(c *JWTSVIDController) { c.entries = entries }
}

// NewJWTSVIDController creates a new JWT-SVID controller
func NewJWTSVIDController(service *services.JWTSVIDService, logger *logrus.Entry, opts ...JWTControllerOption) *JWTSVIDController {
	ctrl := &JWTSVIDController{service: service, logger: logger}
	for _, o := range opts {
		o(ctrl)
	}
	return ctrl
}

type issueBody struct {
	WorkspaceID  string                 `json:"workspace_id"`
	SpiffeID     string                 `json:"spiffe_id"`
	Audience     []string               `json:"audience"`
	TTL          int                    `json:"ttl"`
	CustomClaims map[string]interface{} `json:"custom_claims,omitempty"`
}

func stripRestricted(claims map[string]interface{}) {
	for k := range claims {
		if restrictedCustomClaims[strings.ToLower(k)] {
			delete(claims, k)
		}
	}
}

// IssueJWTSVID handles POST /spiresvc/v1/jwt/issue (mTLS). The workspace is
// the client certificate's. The SVID is for the caller's own SPIFFE ID, or,
// for an agent, for a workload entry of the workspace that the agent serves.
func (ctrl *JWTSVIDController) IssueJWTSVID(c *gin.Context) {
	var req issueBody
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, ctrl.logger, errors.NewBadRequestError("Invalid request body", err))
		return
	}
	if err := sameWorkspace(c, req.WorkspaceID); err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	ws, err := requestWorkspace(c)
	if err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	caller, _ := middleware.GetSpireSpiffeID(c)
	if req.SpiffeID == "" {
		req.SpiffeID = caller
	}
	if req.SpiffeID != caller {
		isAgent, _ := middleware.GetSpireIsAgent(c)
		if !isAgent || ctrl.entries == nil {
			sendError(c, ctrl.logger, errors.NewForbiddenError("spiffe_id must be the authenticated identity", nil))
			return
		}
		entry, err := ctrl.entries.GetBySpiffeID(c.Request.Context(), req.SpiffeID)
		if err != nil || entry == nil || (entry.ParentID != "" && entry.ParentID != caller) {
			sendError(c, ctrl.logger, errors.NewNotFoundError("No workload entry of this agent has that spiffe_id", nil))
			return
		}
	}
	stripRestricted(req.CustomClaims)
	resp, err := ctrl.service.IssueJWTSVID(c.Request.Context(), &services.IssueJWTSVIDRequest{
		WorkspaceID:  ws,
		SpiffeID:     req.SpiffeID,
		Audience:     req.Audience,
		TTL:          req.TTL,
		CustomClaims: req.CustomClaims,
	})
	if err != nil {
		sendError(c, ctrl.logger, errors.NewInternalError(err.Error(), err))
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"spiffe_id":  resp.SpiffeID,
		"token":      resp.Token,
		"expires_at": resp.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
	})
}

// ValidateJWTSVID handles POST /spiresvc/v1/jwt/validate (public). The
// workspace is the token's own issuer, verified by its signature; a body
// workspace_id may only repeat it.
func (ctrl *JWTSVIDController) ValidateJWTSVID(c *gin.Context) {
	var req struct {
		WorkspaceID string `json:"workspace_id"`
		Token       string `json:"token"`
		Audience    string `json:"audience"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, ctrl.logger, errors.NewBadRequestError("Invalid request body", err))
		return
	}
	v, err := ctrl.service.ValidateJWTSVID(c.Request.Context(), &services.ValidateJWTSVIDRequest{
		WorkspaceID: req.WorkspaceID,
		Token:       req.Token,
		Audience:    req.Audience,
	})
	if err != nil {
		sendError(c, ctrl.logger, errors.NewInternalError("Failed to validate token", err))
		return
	}
	resp := gin.H{"spiffe_id": v.SpiffeID, "valid": v.Valid}
	if v.Valid && v.Claims != nil {
		resp["claims"] = v.Claims
		if sub, ok := v.Claims["sub"].(string); ok {
			resp["sub"] = sub
		}
		if iss, ok := v.Claims["iss"].(string); ok {
			resp["workspace_id"] = strings.TrimPrefix(iss, "spiffe://")
		}
		if perms, ok := v.Claims["permissions"]; ok {
			resp["permissions"] = perms
		}
		if aud, ok := v.Claims["aud"]; ok {
			resp["audience"] = aud
		}
		if exp, ok := v.Claims["exp"]; ok {
			resp["expires_at"] = exp
		}
		if iat, ok := v.Claims["iat"]; ok {
			resp["issued_at"] = iat
		}
	}
	c.JSON(http.StatusOK, resp)
}

// GetJWTBundle handles GET /spiresvc/v1/jwt/bundle?workspace_id= (public).
// The id must name an active workspace; no key is created for any other.
func (ctrl *JWTSVIDController) GetJWTBundle(c *gin.Context) {
	ws := c.Query("workspace_id")
	if err := utils.ValidateUUID(ws, "workspace_id"); err != nil {
		sendError(c, ctrl.logger, errors.NewBadRequestError(err.Error(), err))
		return
	}
	bundle, err := ctrl.service.GetJWTBundle(c.Request.Context(), ws)
	if err != nil {
		if services.ErrUnknownWorkspace(err) {
			sendError(c, ctrl.logger, errors.NewNotFoundError("Workspace not found", nil))
			return
		}
		sendError(c, ctrl.logger, errors.NewInternalError("Failed to load the JWT bundle", err))
		return
	}
	c.Data(http.StatusOK, "application/json", []byte(bundle))
}

// IssueDelegatedJWTSVID handles POST /spiresvc/v1/jwt/issue-delegated
// (AuthMiddleware + owner/admin). The workspace is the caller's; the SPIFFE
// ID must be in its trust domain; custom claims cannot carry roles,
// permissions or a workspace; the TTL is capped.
func (ctrl *JWTSVIDController) IssueDelegatedJWTSVID(c *gin.Context) {
	var req issueBody
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, ctrl.logger, errors.NewBadRequestError("Invalid request body", err))
		return
	}
	if err := sameWorkspace(c, req.WorkspaceID); err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	ws, err := requestWorkspace(c)
	if err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	if !strings.HasPrefix(req.SpiffeID, "spiffe://"+ws+"/") {
		sendError(c, ctrl.logger, errors.NewForbiddenError(fmt.Sprintf("spiffe_id must be in the workspace trust domain spiffe://%s/", ws), nil))
		return
	}
	if len(req.Audience) == 0 {
		if len(ctrl.defaultAudience) == 0 {
			sendError(c, ctrl.logger, errors.NewBadRequestError("audience is required", nil))
			return
		}
		req.Audience = ctrl.defaultAudience
	}
	if len(ctrl.allowedAudiences) > 0 {
		for _, aud := range req.Audience {
			if !ctrl.allowedAudiences[aud] {
				sendError(c, ctrl.logger, errors.NewForbiddenError(fmt.Sprintf("audience %q is not allowed", aud), nil))
				return
			}
		}
	}
	if req.TTL <= 0 || req.TTL > defaultMaxDelegatedTTL {
		req.TTL = defaultMaxDelegatedTTL
	}
	stripRestricted(req.CustomClaims)
	resp, err := ctrl.service.IssueJWTSVID(c.Request.Context(), &services.IssueJWTSVIDRequest{
		WorkspaceID:  ws,
		SpiffeID:     req.SpiffeID,
		Audience:     req.Audience,
		TTL:          req.TTL,
		CustomClaims: req.CustomClaims,
	})
	if err != nil {
		sendError(c, ctrl.logger, errors.NewInternalError(err.Error(), err))
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"spiffe_id":  resp.SpiffeID,
		"token":      resp.Token,
		"expires_at": resp.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
	})
}

// RenewJWTSVID handles POST /spiresvc/v1/jwt/renew (public): a valid token
// is re-issued with the same claims and a fresh TTL, by and for the
// workspace that issued it (its verified iss). A body workspace_id may only
// repeat it.
func (ctrl *JWTSVIDController) RenewJWTSVID(c *gin.Context) {
	var req struct {
		WorkspaceID string `json:"workspace_id"`
		Token       string `json:"token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, ctrl.logger, errors.NewBadRequestError("Invalid request body", err))
		return
	}
	if req.Token == "" {
		sendError(c, ctrl.logger, errors.NewBadRequestError("token is required", nil))
		return
	}
	v, err := ctrl.service.ValidateJWTSVID(c.Request.Context(), &services.ValidateJWTSVIDRequest{
		WorkspaceID: req.WorkspaceID,
		Token:       req.Token,
	})
	if err != nil {
		sendError(c, ctrl.logger, errors.NewInternalError("Failed to validate token", err))
		return
	}
	if !v.Valid {
		sendError(c, ctrl.logger, errors.NewUnauthorizedError("Token is invalid or expired - cannot renew", nil))
		return
	}
	iss, _ := v.Claims["iss"].(string)
	ws := strings.TrimPrefix(iss, "spiffe://")
	spiffeID, _ := v.Claims["sub"].(string)

	var audience []string
	switch aud := v.Claims["aud"].(type) {
	case []interface{}:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				audience = append(audience, s)
			}
		}
	case string:
		audience = []string{aud}
	}
	custom := make(map[string]interface{})
	for k, val := range v.Claims {
		switch k {
		case "iss", "sub", "aud", "exp", "nbf", "iat", "jti":
		default:
			custom[k] = val
		}
	}
	resp, err := ctrl.service.IssueJWTSVID(c.Request.Context(), &services.IssueJWTSVIDRequest{
		WorkspaceID:  ws,
		SpiffeID:     spiffeID,
		Audience:     audience,
		TTL:          defaultMaxDelegatedTTL,
		CustomClaims: custom,
	})
	if err != nil {
		sendError(c, ctrl.logger, errors.NewInternalError(err.Error(), err))
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"spiffe_id":  resp.SpiffeID,
		"token":      resp.Token,
		"expires_at": resp.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
	})
}
