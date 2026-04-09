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
	if ctx.LoginChallenge == loginChallenge {
		return &ctx, nil
	}

	// Unbound (first visit) → bind now
	if ctx.LoginChallenge == "" {
		result := s.db.Model(&models.AuthRequestContext{}).
			Where("context_id = ? AND login_challenge IS NULL AND consumed = false AND expires_at > ?", contextID, time.Now()).
			Update("login_challenge", loginChallenge)
		if result.RowsAffected == 0 {
			// Race: someone else bound it between our SELECT and UPDATE.
			// Re-read and check if it's the same login_challenge.
			s.db.Where("context_id = ?", contextID).First(&ctx)
			if ctx.LoginChallenge == loginChallenge {
				return &ctx, nil
			}
			log.Printf("[MCP_AUTH] BindByContextID: race on context_id=%s, already bound to different challenge", contextID)
			return nil, fmt.Errorf("auth context already bound to a different login challenge")
		}
		ctx.LoginChallenge = loginChallenge
		return &ctx, nil
	}

	// Bound to a DIFFERENT login_challenge → error (should not happen in normal flow)
	log.Printf("[MCP_AUTH] BindByContextID: context_id=%s bound to challenge=%s but received challenge=%s",
		contextID, ctx.LoginChallenge, loginChallenge)
	return nil, fmt.Errorf("auth context already bound to a different login challenge")
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

// MarkConsentCompleted marks consent as done. No authorization code stored.
// The Token handler uses introspection to recover context_id from Hydra session claims.
func (s *AuthorizationContextService) MarkConsentCompleted(state string) error {
	return s.db.Model(&models.AuthRequestContext{}).
		Where("state = ?", state).
		Update("consent_completed", true).Error
}

// ConsumeAuthRequestContext marks a context as consumed after token exchange.
func (s *AuthorizationContextService) ConsumeAuthRequestContext(state string) error {
	return s.db.Model(&models.AuthRequestContext{}).Where("state = ?", state).Update("consumed", true).Error
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

// --- MCPGrantBinding methods ---

// StoreGrantBinding stores a per-grant RS binding keyed by hash(refresh_token).
func (s *AuthorizationContextService) StoreGrantBinding(binding *models.MCPGrantBinding) error {
	return s.db.Create(binding).Error
}

// GetGrantBindingByRefreshHash looks up grant binding by refresh token hash.
func (s *AuthorizationContextService) GetGrantBindingByRefreshHash(hash string) (*models.MCPGrantBinding, error) {
	var binding models.MCPGrantBinding
	err := s.db.Where("refresh_token_hash = ? AND expires_at > ?", hash, time.Now()).First(&binding).Error
	if err != nil {
		return nil, err
	}
	return &binding, nil
}

// UpdateGrantBindingRefreshHash updates the refresh token hash when Hydra rotates tokens.
func (s *AuthorizationContextService) UpdateGrantBindingRefreshHash(oldHash, newHash string) error {
	return s.db.Model(&models.MCPGrantBinding{}).
		Where("refresh_token_hash = ?", oldHash).
		Update("refresh_token_hash", newHash).Error
}

// CleanupExpiredBindings removes expired grant bindings.
func (s *AuthorizationContextService) CleanupExpiredBindings() error {
	return s.db.Where("expires_at < ?", time.Now()).Delete(&models.MCPGrantBinding{}).Error
}
