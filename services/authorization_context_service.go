package services

import (
	"fmt"
	"log"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type AuthorizationContextService struct {
	db *gorm.DB
}

func NewAuthorizationContextService(db *gorm.DB) *AuthorizationContextService {
	return &AuthorizationContextService{db: db}
}

// StoreAuthRequestContext saves the auth request context keyed by state.
func (s *AuthorizationContextService) StoreAuthRequestContext(ctx *models.AuthRequestContext) error {
	if ctx == nil {
		return fmt.Errorf("nil auth request context")
	}

	// Keep unbound login challenges as SQL NULL. Some existing local rows may contain
	// the empty string, so BindByContextID also treats "" as unbound for compatibility.
	if loginChallengeBlank(ctx.LoginChallenge) {
		return s.db.Omit("LoginChallenge").Create(ctx).Error
	}

	return s.db.Create(ctx).Error
}

// BindByContextID binds a login_challenge to an auth context using the server-generated context_id.
// IDEMPOTENT: If already bound to this login_challenge, returns the existing context.
// FAIL CLOSED: Returns error if context_id not found, expired, consumed, or bound to a DIFFERENT challenge.
func (s *AuthorizationContextService) BindByContextID(contextID, loginChallenge string) (*models.AuthRequestContext, error) {
	if contextID == "" {
		return nil, fmt.Errorf("empty context_id")
	}

	var ctx models.AuthRequestContext
	err := s.db.Where("context_id = ? AND consumed = false AND expires_at > ?", contextID, time.Now()).First(&ctx).Error
	if err != nil {
		log.Printf("[MCP_AUTH] BindByContextID: context_id=%s not found or expired: %v", contextID, err)
		return nil, fmt.Errorf("no valid auth context for context_id %s", contextID)
	}

	// Already bound to this login_challenge (page refresh / retry) → idempotent return
	if !loginChallengeBlank(ctx.LoginChallenge) && *ctx.LoginChallenge == loginChallenge {
		return &ctx, nil
	}

	// Unbound (first visit) → bind now
	if loginChallengeBlank(ctx.LoginChallenge) {
		result := s.db.Model(&models.AuthRequestContext{}).
			Where("context_id = ? AND (login_challenge IS NULL OR login_challenge = '') AND consumed = false AND expires_at > ?", contextID, time.Now()).
			Update("login_challenge", loginChallenge)
		if result.Error != nil {
			log.Printf("[MCP_AUTH] BindByContextID: update failed for context_id=%s: %v", contextID, result.Error)
			return nil, fmt.Errorf("failed to bind auth context")
		}
		if result.RowsAffected == 0 {
			// Race: someone else bound it between our SELECT and UPDATE.
			// Re-read and check if it's the same login_challenge.
			s.db.Where("context_id = ?", contextID).First(&ctx)
			if !loginChallengeBlank(ctx.LoginChallenge) && *ctx.LoginChallenge == loginChallenge {
				return &ctx, nil
			}
			log.Printf("[MCP_AUTH] BindByContextID: race on context_id=%s, already bound to different challenge", contextID)
			return nil, fmt.Errorf("auth context already bound to a different login challenge")
		}
		ctx.LoginChallenge = &loginChallenge
		return &ctx, nil
	}

	// Bound to a DIFFERENT login_challenge → error (should not happen in normal flow)
	log.Printf("[MCP_AUTH] BindByContextID: context_id=%s bound to challenge=%s but received challenge=%s",
		contextID, *ctx.LoginChallenge, loginChallenge)
	return nil, fmt.Errorf("auth context already bound to a different login challenge")
}

func loginChallengeBlank(challenge *string) bool {
	return challenge == nil || *challenge == ""
}

// GetAuthRequestContextByLoginChallenge retrieves context by login_challenge.
// Used by ConsentHandler — does NOT require consent_completed (consent hasn't happened yet).
func (s *AuthorizationContextService) GetAuthRequestContextByLoginChallenge(loginChallenge string) (*models.AuthRequestContext, error) {
	var ctx models.AuthRequestContext
	err := s.db.Where("login_challenge = ? AND consumed = false AND expires_at > ?", loginChallenge, time.Now()).First(&ctx).Error
	if err != nil {
		return nil, err
	}
	return &ctx, nil
}

// GetAuthRequestContextByContextID retrieves context by server-generated context_id.
// REQUIRES consent_completed = true AND consumed = false.
// Used by Token handler after introspecting the access token to extract context_id.
func (s *AuthorizationContextService) GetAuthRequestContextByContextID(contextID string) (*models.AuthRequestContext, error) {
	if contextID == "" {
		return nil, fmt.Errorf("empty context_id")
	}
	var ctx models.AuthRequestContext
	err := s.db.Where(
		"context_id = ? AND consent_completed = true AND consumed = false AND expires_at > ?",
		contextID, time.Now(),
	).First(&ctx).Error
	if err != nil {
		log.Printf("[MCP_AUTH] GetAuthRequestContextByContextID: context_id=%s not found (consent_completed+unconsumed): %v", contextID, err)
		return nil, err
	}
	return &ctx, nil
}

// GetActiveAuthRequestContextByContextID retrieves a live auth context by context_id
// before token consumption. Used during the login/consent flow.
func (s *AuthorizationContextService) GetActiveAuthRequestContextByContextID(contextID string) (*models.AuthRequestContext, error) {
	if contextID == "" {
		return nil, fmt.Errorf("empty context_id")
	}
	var ctx models.AuthRequestContext
	err := s.db.Where(
		"context_id = ? AND consumed = false AND expires_at > ?",
		contextID, time.Now(),
	).First(&ctx).Error
	if err != nil {
		log.Printf("[MCP_AUTH] GetActiveAuthRequestContextByContextID: context_id=%s not found: %v", contextID, err)
		return nil, err
	}
	return &ctx, nil
}

// MarkConsentCompleted marks consent as done. No authorization code stored.
// The Token handler uses introspection to recover context_id from Hydra session claims.
func (s *AuthorizationContextService) MarkConsentCompleted(state string) error {
	return s.db.Model(&models.AuthRequestContext{}).
		Where("state = ?", state).
		Update("consent_completed", true).Error
}

// ConsumeAuthRequestContext atomically marks a context as consumed after token exchange.
// Returns error if already consumed (prevents double token issuance from concurrent requests).
func (s *AuthorizationContextService) ConsumeAuthRequestContext(state string) error {
	result := s.db.Model(&models.AuthRequestContext{}).
		Where("state = ? AND consumed = false", state).
		Update("consumed", true)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("auth context already consumed or not found")
	}
	return nil
}

// GetUnboundContextByRequestParams finds an unbound auth context by matching multiple fields
// from the original authorize request.
// Deprecated: PAR/request_uri is the canonical correlation path. This helper remains only as
// transition debt and should not be used by new runtime paths.
func (s *AuthorizationContextService) GetUnboundContextByRequestParams(
	hydraClientID, redirectURI, resourceURI, requestedScopes string,
) (*models.AuthRequestContext, error) {
	q := s.db.Where(
		"hydra_client_id = ? AND (login_challenge IS NULL OR login_challenge = '') AND consumed = false AND expires_at > ?",
		hydraClientID, time.Now(),
	)
	if redirectURI != "" {
		q = q.Where("redirect_uri = ?", redirectURI)
	}
	if resourceURI != "" {
		q = q.Where("resource_uri = ?", resourceURI)
	}
	if requestedScopes != "" {
		q = q.Where("requested_scopes = ?", requestedScopes)
	}

	var ctx models.AuthRequestContext
	err := q.Order("created_at DESC").First(&ctx).Error
	if err != nil {
		return nil, err
	}
	return &ctx, nil
}

// UpdateAuthRequestContextPAR sets the Hydra request_uri and aligned expiry after PAR succeeds.
// Compare-and-set: only updates if hydra_request_uri is not already set (race-safe, idempotent).
// Returns error if no row was updated (already set, or state not found).
func (s *AuthorizationContextService) UpdateAuthRequestContextPAR(state, requestURI string, expiresAt time.Time) error {
	if requestURI == "" {
		return fmt.Errorf("empty request_uri")
	}
	result := s.db.Model(&models.AuthRequestContext{}).
		Where("state = ? AND (hydra_request_uri IS NULL OR hydra_request_uri = '')", state).
		Updates(map[string]interface{}{
			"hydra_request_uri": requestURI,
			"expires_at":        expiresAt,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("auth context state=%s already has hydra_request_uri or not found", state)
	}
	return nil
}

// BindByHydraRequestURI deterministically binds a login_challenge to the auth context
// identified by the Hydra-issued request_uri. Each PAR call produces a unique request_uri,
// so this is collision-proof under concurrency.
// IDEMPOTENT: re-reads on page refresh, binds on first visit.
func (s *AuthorizationContextService) BindByHydraRequestURI(requestURI, loginChallenge string) (*models.AuthRequestContext, error) {
	if requestURI == "" {
		return nil, fmt.Errorf("empty request_uri")
	}

	var ctx models.AuthRequestContext
	err := s.db.Where(
		"hydra_request_uri = ? AND consumed = false AND expires_at > ?",
		requestURI, time.Now(),
	).First(&ctx).Error
	if err != nil {
		return nil, fmt.Errorf("no auth context for request_uri %s: %w", requestURI, err)
	}

	// Already bound to this login_challenge (page refresh)
	if !loginChallengeBlank(ctx.LoginChallenge) && *ctx.LoginChallenge == loginChallenge {
		return &ctx, nil
	}

	// Unbound → atomic bind
	if loginChallengeBlank(ctx.LoginChallenge) {
		result := s.db.Model(&models.AuthRequestContext{}).
			Where("hydra_request_uri = ? AND (login_challenge IS NULL OR login_challenge = '') AND consumed = false AND expires_at > ?",
				requestURI, time.Now()).
			Update("login_challenge", loginChallenge)
		if result.Error != nil {
			return nil, fmt.Errorf("bind failed: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			// Race: someone else bound it between our SELECT and UPDATE.
			s.db.Where("hydra_request_uri = ?", requestURI).First(&ctx)
			if !loginChallengeBlank(ctx.LoginChallenge) && *ctx.LoginChallenge == loginChallenge {
				return &ctx, nil
			}
			return nil, fmt.Errorf("auth context already bound to a different login challenge")
		}
		ctx.LoginChallenge = &loginChallenge
		return &ctx, nil
	}

	return nil, fmt.Errorf("auth context already bound to a different login challenge")
}

// CleanupExpired removes expired auth request contexts.
func (s *AuthorizationContextService) CleanupExpired() error {
	return s.db.Where("expires_at < ?", time.Now()).Delete(&models.AuthRequestContext{}).Error
}

// --- Client registration methods ---

// GetClientRegistration checks the join table for a client→RS registration.
func (s *AuthorizationContextService) GetClientRegistration(resourceServerID, oauthClientID uuid.UUID) (*models.ResourceServerClientRegistration, error) {
	var reg models.ResourceServerClientRegistration
	err := s.db.Where("resource_server_id = ? AND oauth_client_id = ?", resourceServerID, oauthClientID).First(&reg).Error
	if err != nil {
		return nil, err
	}
	return &reg, nil
}

// EnsureClientRegistration upserts a client registration for an RS.
func (s *AuthorizationContextService) EnsureClientRegistration(resourceServerID, oauthClientID uuid.UUID, regType string) (*models.ResourceServerClientRegistration, error) {
	reg := models.ResourceServerClientRegistration{
		ResourceServerID: resourceServerID,
		OAuthClientID:    oauthClientID,
		Status:           "approved",
		RegistrationType: regType,
	}
	err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "resource_server_id"}, {Name: "oauth_client_id"}},
		DoNothing: true,
	}).Create(&reg).Error
	if err != nil {
		return nil, err
	}

	var result models.ResourceServerClientRegistration
	err = s.db.Where("resource_server_id = ? AND oauth_client_id = ?", resourceServerID, oauthClientID).First(&result).Error
	return &result, err
}

// --- MCP OAuth client methods ---

func (s *AuthorizationContextService) GetMCPOAuthClientByHydraID(hydraClientID string) (*models.MCPOAuthClient, error) {
	var client models.MCPOAuthClient
	err := s.db.Where("hydra_client_id = ?", hydraClientID).First(&client).Error
	if err != nil {
		return nil, err
	}
	return &client, nil
}

func (s *AuthorizationContextService) GetMCPOAuthClientByClientID(clientID string) (*models.MCPOAuthClient, error) {
	var client models.MCPOAuthClient
	err := s.db.Where("client_id = ?", clientID).First(&client).Error
	if err != nil {
		return nil, err
	}
	return &client, nil
}

func (s *AuthorizationContextService) CreateMCPOAuthClient(client *models.MCPOAuthClient) error {
	return s.db.Create(client).Error
}

func (s *AuthorizationContextService) UpdateMCPOAuthClient(client *models.MCPOAuthClient) error {
	return s.db.Save(client).Error
}
