package services

import (
	"errors"
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// ServiceAccountService owns the lifecycle of service accounts and their
// confidential M2M credentials. The credential-provisioning logic lived inline
// in the admin ServiceAccountsController; it is extracted here so both the admin
// endpoint and the application-scoped machine-access wrapper share one code path
// (no duplicate secret-generation / client-linking logic to drift).
type ServiceAccountService struct {
	db *gorm.DB
}

func NewServiceAccountService(db *gorm.DB) *ServiceAccountService {
	return &ServiceAccountService{db: db}
}

// Sentinel errors so HTTP callers can map to the right status without string
// matching. Behaviour preserved from the original admin controller.
var (
	ErrCredentialTypeMissing       = errors.New("provide jwks_uri, jwks, or use_client_secret=true")
	ErrCredentialTypeAmbiguous     = errors.New("provide exactly one of jwks/jwks_uri or use_client_secret")
	ErrServiceAccountNotFound      = errors.New("service account not found")
	ErrServiceAccountHasCredential = errors.New("service account already has a credential client")
)

// CredentialOptions selects exactly one credential type for a service account.
type CredentialOptions struct {
	JWKSUri         *string
	JWKS            *string
	UseClientSecret bool
}

// ProvisionedCredential is the result of credential provisioning. ClientSecret
// is non-nil only for client_secret_basic and is the plaintext shown once.
type ProvisionedCredential struct {
	ClientID   string
	AuthMethod string
	// Secret is the plaintext client secret, returned once for
	// client_secret_basic and never persisted in plaintext.
	Secret *string
}

// CreateServiceAccount creates a disabled service account. It becomes usable
// only once a credential is provisioned (status flips to active there).
func (s *ServiceAccountService) CreateServiceAccount(workspaceID uuid.UUID, name, description, ownerEmail, ownerTeam string) (*models.ServiceAccount, error) {
	if ownerEmail == "" {
		return nil, fmt.Errorf("owner_email is required: every agent must have an accountable owner")
	}
	sa := models.ServiceAccount{
		ID:          uuid.New(),
		WorkspaceID: workspaceID,
		Name:        name,
		Description: description,
		Status:      "disabled",
		OwnerEmail:  &ownerEmail,
	}
	if ownerTeam != "" {
		sa.OwnerTeam = &ownerTeam
	}
	if err := s.db.Session(&gorm.Session{NewDB: true}).Create(&sa).Error; err != nil {
		return nil, fmt.Errorf("failed to create service account: %w", err)
	}
	return &sa, nil
}

// GetServiceAccount loads a service account scoped to its workspace.
func (s *ServiceAccountService) GetServiceAccount(workspaceID, saID uuid.UUID) (*models.ServiceAccount, error) {
	var sa models.ServiceAccount
	if err := s.db.Session(&gorm.Session{NewDB: true}).
		Where("workspace_id = ? AND id = ?", workspaceID, saID).
		First(&sa).Error; err != nil {
		return nil, ErrServiceAccountNotFound
	}
	return &sa, nil
}

// ProvisionCredential creates a confidential M2M OAuth client for the service
// account, links it, flips the account to active, and returns the credential
// (with the plaintext secret for client_secret_basic). Idempotency: a service
// account that already has a credential client is rejected with
// ErrServiceAccountHasCredential.
func (s *ServiceAccountService) ProvisionCredential(workspaceID, saID uuid.UUID, opts CredentialOptions) (*ProvisionedCredential, error) {
	var result *ProvisionedCredential
	err := s.db.Session(&gorm.Session{NewDB: true}).Transaction(func(tx *gorm.DB) error {
		r, e := s.ProvisionCredentialTx(tx, workspaceID, saID, opts)
		if e != nil {
			return e
		}
		result = r
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ProvisionCredentialTx is ProvisionCredential bound to a caller-supplied
// transaction handle. It performs all of its writes (client + secret/jwks + the
// SA active-flip) on tx, so the credential provisioning can be committed
// atomically with sibling steps — e.g. the application machine-access wrapper
// commits the role binding, this provisioning, and the client registration in
// ONE transaction, so a later registration failure rolls back the credential
// instead of stranding an active SA whose one-time secret the caller never saw.
// Sentinel errors (ErrCredentialType*, ErrServiceAccountNotFound,
// ErrServiceAccountHasCredential) are returned unwrapped so callers can errors.Is
// them through the surrounding transaction.
func (s *ServiceAccountService) ProvisionCredentialTx(tx *gorm.DB, workspaceID, saID uuid.UUID, opts CredentialOptions) (*ProvisionedCredential, error) {
	hasJWKS := (opts.JWKSUri != nil && *opts.JWKSUri != "") || (opts.JWKS != nil && *opts.JWKS != "")
	if !hasJWKS && !opts.UseClientSecret {
		return nil, ErrCredentialTypeMissing
	}
	if hasJWKS && opts.UseClientSecret {
		return nil, ErrCredentialTypeAmbiguous
	}

	var sa models.ServiceAccount
	if err := tx.Where("workspace_id = ? AND id = ?", workspaceID, saID).First(&sa).Error; err != nil {
		return nil, ErrServiceAccountNotFound
	}
	if sa.OAuthClientID != nil {
		return nil, ErrServiceAccountHasCredential
	}

	authMethod := "private_key_jwt"
	if opts.UseClientSecret {
		authMethod = "client_secret_basic"
	}

	newClientID := uuid.New()
	newClientIDStr := newClientID.String()
	now := time.Now().UTC()
	mcpClient := models.MCPOAuthClient{
		ID:                              newClientID,
		ClientID:                        newClientIDStr,
		HydraClientID:                   newClientIDStr, // never synced to Hydra
		ClientName:                      sa.Name + " (m2m)",
		RedirectURIs:                    pq.StringArray{},
		GrantTypes:                      pq.StringArray{"client_credentials"},
		ResponseTypes:                   pq.StringArray{},
		RegistrationType:                "admin",
		ClientKind:                      "m2m",
		SyncStatus:                      "active",
		HomeWorkspaceID:                 &workspaceID,
		AllowedTokenEndpointAuthMethods: pq.StringArray{authMethod},
		CreatedAt:                       now,
		UpdatedAt:                       now,
	}

	if err := tx.Create(&mcpClient).Error; err != nil {
		return nil, fmt.Errorf("failed to provision credentials: %w", err)
	}

	var plainSecret *string
	if hasJWKS {
		jwksRow := models.OAuthClientJWKS{
			ID:       uuid.New(),
			ClientID: mcpClient.ID,
			JWKSUri:  opts.JWKSUri,
			JWKS:     opts.JWKS,
		}
		if err := tx.Create(&jwksRow).Error; err != nil {
			return nil, fmt.Errorf("failed to provision credentials: %w", err)
		}
	} else {
		secret, genErr := GenerateClientSecret()
		if genErr != nil {
			return nil, genErr
		}
		hash, hashErr := HashClientSecret(secret)
		if hashErr != nil {
			return nil, hashErr
		}
		secretRow := models.OAuthClientSecret{
			ID:         uuid.New(),
			ClientID:   mcpClient.ID,
			SecretHash: hash,
		}
		if err := tx.Create(&secretRow).Error; err != nil {
			return nil, fmt.Errorf("failed to provision credentials: %w", err)
		}
		plainSecret = &secret
	}

	if err := tx.Model(&models.ServiceAccount{}).
		Where("workspace_id = ? AND id = ?", workspaceID, saID).
		Updates(map[string]interface{}{
			"oauth_client_id": mcpClient.ID,
			"status":          "active",
			"updated_at":      now,
		}).Error; err != nil {
		return nil, fmt.Errorf("failed to provision credentials: %w", err)
	}

	return &ProvisionedCredential{
		ClientID:   newClientIDStr,
		AuthMethod: authMethod,
		Secret:     plainSecret,
	}, nil
}
