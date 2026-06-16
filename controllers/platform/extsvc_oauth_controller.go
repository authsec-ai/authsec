package platform

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/vault"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

// ExternalServiceOAuthController handles HTTP requests for the OAuth connect/token endpoints.
type ExternalServiceOAuthController struct {
	globalDB    *gorm.DB
	vaultOnce   sync.Once
	vaultClient vault.VaultClient
	vaultErr    error
}

// NewExternalServiceOAuthController constructs an ExternalServiceOAuthController.
func NewExternalServiceOAuthController(db *gorm.DB) *ExternalServiceOAuthController {
	return &ExternalServiceOAuthController{globalDB: db}
}

func (ctl *ExternalServiceOAuthController) getVaultClient() (vault.VaultClient, error) {
	ctl.vaultOnce.Do(func() {
		addr := os.Getenv("VAULT_ADDR")
		token := os.Getenv("VAULT_TOKEN")
		if addr == "" || token == "" {
			ctl.vaultErr = fmt.Errorf("VAULT_ADDR or VAULT_TOKEN not set")
			return
		}
		ctl.vaultClient, ctl.vaultErr = vault.NewClient(addr, token)
	})
	return ctl.vaultClient, ctl.vaultErr
}

func (ctl *ExternalServiceOAuthController) resolveClaims(c *gin.Context) (map[string]interface{}, error) {
	claimsInterface, exists := c.Get("claims")
	if !exists {
		return nil, fmt.Errorf("claims not found in context")
	}
	switch v := claimsInterface.(type) {
	case map[string]interface{}:
		return v, nil
	case jwt.MapClaims:
		return map[string]interface{}(v), nil
	default:
		return nil, fmt.Errorf("invalid claims format: %T", claimsInterface)
	}
}

func (ctl *ExternalServiceOAuthController) newOAuthService(vaultClient vault.VaultClient) *services.OAuthConnectService {
	return services.NewOAuthConnectService(
		repositories.NewExternalServiceRepository(config.DB),
		repositories.NewServiceUserTokenRepository(config.DB),
		vaultClient,
	)
}

// ConnectOAuthService handles POST /authsec/exsvc/services/:id/connect
func (ctl *ExternalServiceOAuthController) ConnectOAuthService(c *gin.Context) {
	claims, err := ctl.resolveClaims(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	workspaceID, _ := claims["workspace_id"].(string)
	if workspaceID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id not found in claims"})
		return
	}
	userID, _ := claims["user_id"].(string)
	if userID == "" {
		userID, _ = claims["sub"].(string)
	}
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user_id not found in claims"})
		return
	}

	var body struct {
		RedirectAfter string `json:"redirect_after"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.RedirectAfter == "" && config.AppConfig != nil {
		body.RedirectAfter = config.AppConfig.UIBaseURL()
	}
	// Validate redirect_after is same-origin as the UI to prevent open redirect.
	if body.RedirectAfter != "" && config.AppConfig != nil {
		uiBase := config.AppConfig.UIBaseURL()
		if !strings.HasPrefix(body.RedirectAfter, uiBase) && !strings.HasPrefix(body.RedirectAfter, "/") {
			body.RedirectAfter = uiBase
		}
	}

	vaultClient, err := ctl.getVaultClient()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	svc := ctl.newOAuthService(vaultClient)
	urls, err := svc.InitiateConnect(c.Param("id"), userID, workspaceID, body.RedirectAfter)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, urls)
}

// OAuthCallback handles GET /authsec/exsvc/oauth/callback/:workspace_id
// No auth middleware — the OAuth provider hits this directly.
func (ctl *ExternalServiceOAuthController) OAuthCallback(c *gin.Context) {
	workspaceID := c.Param("workspace_id")
	code := c.Query("code")
	state := c.Query("state")

	// Handle provider-side denial (e.g. user clicked "Deny").
	if providerError := c.Query("error"); providerError != "" {
		// Try to recover redirect_after from the state JWT so we can redirect gracefully.
		if state != "" {
			if svc := ctl.newOAuthService(nil); svc != nil {
				if redirectAfter, _ := svc.ParseStateRedirect(state); redirectAfter != "" {
					sep := "?"
					if strings.Contains(redirectAfter, "?") {
						sep = "&"
					}
					c.Redirect(http.StatusFound, redirectAfter+sep+"error="+url.QueryEscape(providerError))
					return
				}
			}
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": providerError})
		return
	}

	vaultClient, err := ctl.getVaultClient()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	svc := ctl.newOAuthService(vaultClient)
	redirectAfter, err := svc.HandleCallback(workspaceID, code, state)
	if err != nil {
		if redirectAfter != "" {
			sep := "?"
			if strings.Contains(redirectAfter, "?") {
				sep = "&"
			}
			c.Redirect(http.StatusFound, redirectAfter+sep+"error="+url.QueryEscape(err.Error()))
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.Redirect(http.StatusFound, redirectAfter)
}

// GetServiceToken handles GET /authsec/exsvc/services/:id/token
func (ctl *ExternalServiceOAuthController) GetServiceToken(c *gin.Context) {
	claims, err := ctl.resolveClaims(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	workspaceID, _ := claims["workspace_id"].(string)
	if workspaceID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id not found in claims"})
		return
	}
	userID, _ := claims["user_id"].(string)
	if userID == "" {
		userID, _ = claims["sub"].(string)
	}

	serviceID := c.Param("id")

	// SPIFFE agents may pass ?user_id= if the service is agent_accessible
	if authMethod, _ := c.Get("auth_method"); authMethod == "spiffe-jwt-svid" {
		if qUserID := c.Query("user_id"); qUserID != "" {
			repo := repositories.NewExternalServiceRepository(config.DB)
			if extSvc, repoErr := repo.GetByID(serviceID); repoErr == nil && extSvc.AgentAccessible {
				userID = qUserID
			}
		}
	}

	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user_id not found in claims"})
		return
	}

	vaultClient, err := ctl.getVaultClient()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	oauthSvc := ctl.newOAuthService(vaultClient)
	tokenResp, connectURL, err := oauthSvc.GetToken(serviceID, userID, workspaceID)
	if errors.Is(err, services.ErrNotConnected) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_connected", "connect_url": connectURL})
		return
	}
	if errors.Is(err, services.ErrTokenRefreshFailed) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token_refresh_failed", "connect_url": connectURL})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, tokenResp)
}

// DisconnectService handles DELETE /authsec/exsvc/services/:id/token
func (ctl *ExternalServiceOAuthController) DisconnectService(c *gin.Context) {
	claims, err := ctl.resolveClaims(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	workspaceID, _ := claims["workspace_id"].(string)
	userID, _ := claims["user_id"].(string)
	if userID == "" {
		userID, _ = claims["sub"].(string)
	}
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user_id not found in claims"})
		return
	}

	vaultClient, err := ctl.getVaultClient()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	oauthSvc := ctl.newOAuthService(vaultClient)
	if err := oauthSvc.DisconnectUser(c.Param("id"), userID, workspaceID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// ListServiceConnections handles GET /authsec/exsvc/services/:id/connections (admin only)
func (ctl *ExternalServiceOAuthController) ListServiceConnections(c *gin.Context) {
	claims, err := ctl.resolveClaims(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	if !extsvcHasAdminRole(jwt.MapClaims(claims)) {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin role required"})
		return
	}

	// ListConnections does not need vault
	oauthSvc := ctl.newOAuthService(nil)
	connections, err := oauthSvc.ListConnections(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"connections": connections})
}
