package platform

import (
	"fmt"
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// TrustedIssuersController handles workspace-scoped CRUD for external issuers
// that may present ID-JAGs for XAA redemption.
//
// Routes (all require workspace admin JWT):
//   GET    /authsec/trusted-issuers         list workspace issuers
//   POST   /authsec/trusted-issuers         create issuer
//   POST   /authsec/trusted-issuers/test    validate an assertion against stored config
//   DELETE /authsec/trusted-issuers/:id     revoke issuer + bulk-revoke live XAA tokens
type TrustedIssuersController struct {
	xaaService *services.XAAService
}

func NewTrustedIssuersController() *TrustedIssuersController {
	return &TrustedIssuersController{
		xaaService: services.NewXAAService(config.DB),
	}
}

// listTrustedIssuersResponse is the list envelope.
type listTrustedIssuersResponse struct {
	Items []models.TrustedIssuer `json:"items"`
}

// createTrustedIssuerBody is the inbound payload for POST /trusted-issuers.
type createTrustedIssuerBody struct {
	Iss                   string   `json:"iss"`
	JWKSUri               string   `json:"jwks_uri"`
	ProviderName          string   `json:"provider_name"`
	AllowedAlgs           []string `json:"allowed_algs,omitempty"`
	AllowedAuds           []string `json:"allowed_auds,omitempty"`
	ClockSkewSecs         int      `json:"clock_skew_secs,omitempty"`
	WorkspaceClaimMapping string   `json:"workspace_claim_mapping,omitempty"`
	SubjectMapping        string   `json:"subject_mapping,omitempty"`
	JITProvisioning       bool     `json:"jit_provisioning,omitempty"`
}

// testTrustedIssuerBody is the inbound payload for POST /trusted-issuers/test.
type testTrustedIssuerBody struct {
	Assertion string `json:"assertion"`
	ClientID  string `json:"client_id,omitempty"`
}

// List handles GET /authsec/trusted-issuers — returns all trusted issuers for
// this AuthSec instance. Requires workspace admin JWT (auth is workspace-scoped
// even though the issuers table is instance-wide).
func (ctrl *TrustedIssuersController) List(c *gin.Context) {
	if _, err := shared.ResolveWorkspaceIDFromToken(c); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	var issuers []models.TrustedIssuer
	if err := config.DB.WithContext(c.Request.Context()).
		Order("created_at DESC").
		Find(&issuers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "message": "couldn't list trusted issuers"})
		return
	}

	if issuers == nil {
		issuers = []models.TrustedIssuer{}
	}
	c.JSON(http.StatusOK, listTrustedIssuersResponse{Items: issuers})
}

// Create handles POST /authsec/trusted-issuers — registers a new external issuer.
func (ctrl *TrustedIssuersController) Create(c *gin.Context) {
	if _, err := shared.ResolveWorkspaceIDFromToken(c); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	var body createTrustedIssuerBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": err.Error()})
		return
	}
	if body.Iss == "" || body.JWKSUri == "" || body.ProviderName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "iss, jwks_uri, and provider_name are required"})
		return
	}

	algs := pq.StringArray(body.AllowedAlgs)
	if len(algs) == 0 {
		algs = pq.StringArray{"RS256"}
	}
	auds := pq.StringArray(body.AllowedAuds)
	if auds == nil {
		auds = pq.StringArray{}
	}
	skew := body.ClockSkewSecs
	if skew == 0 {
		skew = 30
	}

	now := time.Now().UTC()
	issuer := models.TrustedIssuer{
		ID:              uuid.New(),
		Iss:             body.Iss,
		JWKSUri:         body.JWKSUri,
		ProviderName:    body.ProviderName,
		AllowedAlgs:     algs,
		AllowedAuds:     auds,
		ClockSkewSecs:   skew,
		JITProvisioning: body.JITProvisioning,
		Status:          "active",
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if body.WorkspaceClaimMapping != "" {
		issuer.WorkspaceClaimMapping = &body.WorkspaceClaimMapping
	}
	if body.SubjectMapping != "" {
		issuer.SubjectMapping = &body.SubjectMapping
	}

	if err := config.DB.WithContext(c.Request.Context()).Create(&issuer).Error; err != nil {
		if isDuplicateKeyError(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "conflict", "message": fmt.Sprintf("issuer %q is already registered", body.Iss)})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "message": "couldn't create trusted issuer"})
		return
	}

	c.JSON(http.StatusCreated, issuer)
}

// Test handles POST /authsec/trusted-issuers/test — validates an ID-JAG assertion
// against stored issuer config without creating any tokens.
func (ctrl *TrustedIssuersController) Test(c *gin.Context) {
	if _, err := shared.ResolveWorkspaceIDFromToken(c); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	var body testTrustedIssuerBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": err.Error()})
		return
	}
	if body.Assertion == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "assertion is required"})
		return
	}
	clientID := body.ClientID
	if clientID == "" {
		clientID = "test-client"
	}

	selfIssuer := config.AppConfig.OAuthBaseURL()
	claims, _, err := ctrl.xaaService.ValidateIDJAG(
		c.Request.Context(), body.Assertion, clientID, selfIssuer,
	)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"pass":   false,
			"reason": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"pass":       true,
		"iss":        claims.Issuer,
		"sub":        claims.Subject,
		"client_id":  claims.ClientID,
		"jti":        claims.JTI,
		"issued_at":  claims.IssuedAt,
		"expires_at": claims.ExpiresAt,
	})
}

// Revoke handles DELETE /authsec/trusted-issuers/:id — marks the issuer as
// revoked and bulk-inserts its still-live XAA native tokens into revoked_tokens.
func (ctrl *TrustedIssuersController) Revoke(c *gin.Context) {
	if _, err := shared.ResolveWorkspaceIDFromToken(c); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	issuerID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "invalid issuer id"})
		return
	}

	ctx := c.Request.Context()
	db := config.DB.WithContext(ctx)

	var issuer models.TrustedIssuer
	if err := db.Where("id = ?", issuerID).First(&issuer).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "message": "trusted issuer not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	if issuer.Status == "revoked" {
		c.JSON(http.StatusOK, gin.H{"status": "revoked"})
		return
	}

	// Bulk-revoke active XAA native tokens from this issuer in a transaction.
	now := time.Now().UTC()
	txErr := db.Transaction(func(tx *gorm.DB) error {
		// Mark issuer revoked.
		if err := tx.Exec(
			`UPDATE trusted_issuers SET status = 'revoked', revoked_at = ? WHERE id = ?`,
			now, issuerID,
		).Error; err != nil {
			return err
		}

		// Bulk-insert live XAA tokens from this issuer into revoked_tokens.
		return tx.Exec(`
			INSERT INTO revoked_tokens (iss, kind, jti, revoked_at, reason, expires_at)
			SELECT iss, 'access_token', jti::text, ?, 'issuer_revoked', expires_at
			FROM native_tokens
			WHERE token_family = 'xaa'
			  AND source_grant_iss = ?
			  AND revoked_at IS NULL
			  AND expires_at > NOW()
			ON CONFLICT (iss, kind, jti) DO NOTHING`,
			now, issuer.Iss,
		).Error
	})
	if txErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "message": "revocation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}
