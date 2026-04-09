package services

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type ResourceServerService struct {
	db *gorm.DB
}

func NewResourceServerService(db *gorm.DB) *ResourceServerService {
	return &ResourceServerService{db: db}
}

type CreateResourceServerRequest struct {
	TenantID          uuid.UUID `json:"tenant_id"`
	Name              string    `json:"name"`
	PublicBaseURL      string    `json:"public_base_url"`
	ProtectedBasePath string    `json:"protected_base_path"`
	ScopesSupported   []string  `json:"scopes_supported"`
	RegistrationModes []string  `json:"registration_modes"`
}

type ResourceServerResponse struct {
	ID                    string   `json:"id"`
	IssuerURL             string   `json:"issuer_url"`
	ResourceURL           string   `json:"resource_url"`
	JWKSURI               string   `json:"jwks_uri"`
	IntrospectionEndpoint string   `json:"introspection_endpoint"`
	IntrospectionSecret   string   `json:"introspection_secret,omitempty"`
	ValidationMode        string   `json:"validation_mode"`
	ScopesSupported       []string `json:"scopes_supported"`
}

func (s *ResourceServerService) Create(req CreateResourceServerRequest, baseURL string) (*models.ResourceServer, *ResourceServerResponse, error) {
	// Bug 11: HTTPS validation
	parsed, err := url.Parse(req.PublicBaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public_base_url: %w", err)
	}
	isLocal := parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1"
	if parsed.Scheme != "https" && !isLocal {
		return nil, nil, fmt.Errorf("public_base_url must use HTTPS (http allowed only for localhost)")
	}

	publicURL := strings.TrimRight(req.PublicBaseURL, "/")
	basePath := req.ProtectedBasePath
	if basePath == "" {
		basePath = "/mcp"
	}
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	resourceURI := publicURL + basePath

	secret, err := generateIntrospectionSecret()
	if err != nil {
		return nil, nil, fmt.Errorf("generate introspection secret: %w", err)
	}

	modes := req.RegistrationModes
	if len(modes) == 0 {
		modes = []string{"dcr", "cimd", "prereg"}
	}

	// Bug 12: Store bcrypt hash, not plaintext
	hashedSecret, hashErr := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if hashErr != nil {
		return nil, nil, fmt.Errorf("hash introspection secret: %w", hashErr)
	}

	rs := &models.ResourceServer{
		TenantID:                req.TenantID,
		Name:                    req.Name,
		PublicBaseURL:           publicURL,
		ProtectedBasePath:      basePath,
		ResourceURI:            resourceURI,
		ScopesSupported:        req.ScopesSupported,
		RegistrationModes:      modes,
		IntrospectionSecret:    "",                  // Not stored in plaintext for new rows
		IntrospectionSecretHash: string(hashedSecret),
		Active:                 true,
	}

	if err := s.db.Create(rs).Error; err != nil {
		return nil, nil, fmt.Errorf("create resource server: %w", err)
	}

	resp := &ResourceServerResponse{
		ID:                    rs.ID.String(),
		IssuerURL:             baseURL,
		ResourceURL:           rs.ResourceURI,
		JWKSURI:               baseURL + "/oauth/jwks",
		IntrospectionEndpoint: baseURL + "/oauth/introspect",
		IntrospectionSecret:   secret,
		ValidationMode:        "auto",
		ScopesSupported:       rs.ScopesSupported,
	}

	return rs, resp, nil
}

func (s *ResourceServerService) GetByID(id string) (*models.ResourceServer, error) {
	var rs models.ResourceServer
	if err := s.db.Where("id = ? AND active = true", id).First(&rs).Error; err != nil {
		return nil, err
	}
	return &rs, nil
}

func (s *ResourceServerService) GetByResourceURI(uri string) (*models.ResourceServer, error) {
	var rs models.ResourceServer
	if err := s.db.Where("resource_uri = ? AND active = true", uri).First(&rs).Error; err != nil {
		return nil, err
	}
	return &rs, nil
}

func (s *ResourceServerService) ListByTenant(tenantID string) ([]models.ResourceServer, error) {
	var servers []models.ResourceServer
	if err := s.db.Where("tenant_id = ? AND active = true", tenantID).Find(&servers).Error; err != nil {
		return nil, err
	}
	return servers, nil
}

func (s *ResourceServerService) Update(id string, updates map[string]interface{}) (*models.ResourceServer, error) {
	var rs models.ResourceServer
	if err := s.db.Where("id = ?", id).First(&rs).Error; err != nil {
		return nil, err
	}
	if err := s.db.Model(&rs).Updates(updates).Error; err != nil {
		return nil, err
	}
	return &rs, nil
}

func (s *ResourceServerService) Delete(id string) error {
	return s.db.Where("id = ?", id).Delete(&models.ResourceServer{}).Error
}

// GetByIDAndTenant fetches a resource server by ID with tenant ownership check.
func (s *ResourceServerService) GetByIDAndTenant(id, tenantID string) (*models.ResourceServer, error) {
	var rs models.ResourceServer
	if err := s.db.Where("id = ? AND tenant_id = ? AND active = true", id, tenantID).First(&rs).Error; err != nil {
		return nil, err
	}
	return &rs, nil
}

// UpdateByTenant updates a resource server with tenant ownership check.
func (s *ResourceServerService) UpdateByTenant(id, tenantID string, updates map[string]interface{}) (*models.ResourceServer, error) {
	var rs models.ResourceServer
	if err := s.db.Where("id = ? AND tenant_id = ?", id, tenantID).First(&rs).Error; err != nil {
		return nil, err
	}
	if err := s.db.Model(&rs).Updates(updates).Error; err != nil {
		return nil, err
	}
	return &rs, nil
}

// DeleteByTenant deletes a resource server with tenant ownership check.
func (s *ResourceServerService) DeleteByTenant(id, tenantID string) error {
	result := s.db.Where("id = ? AND tenant_id = ?", id, tenantID).Delete(&models.ResourceServer{})
	if result.RowsAffected == 0 {
		return fmt.Errorf("resource server not found")
	}
	return result.Error
}

// RotateIntrospectionSecret generates a new secret, stores its bcrypt hash, returns plaintext once.
func (s *ResourceServerService) RotateIntrospectionSecret(id, tenantID string) (string, error) {
	var rs models.ResourceServer
	if err := s.db.Where("id = ? AND tenant_id = ?", id, tenantID).First(&rs).Error; err != nil {
		return "", fmt.Errorf("resource server not found")
	}

	secret, err := generateIntrospectionSecret()
	if err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash secret: %w", err)
	}

	if err := s.db.Model(&rs).Updates(map[string]interface{}{
		"introspection_secret_hash": string(hashed),
		"introspection_secret":      "", // clear plaintext
	}).Error; err != nil {
		return "", err
	}

	return secret, nil
}

func generateIntrospectionSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sec_" + hex.EncodeToString(b), nil
}
