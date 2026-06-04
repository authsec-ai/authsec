package services

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// OAuthASService implements the standards-compliant MCP OAuth server flow on
// the authsec-prod branch. It is the prod analogue of the workspace-scoped
// services/oauth_as_service.go on authsec-dev, rebound to prod's tenant
// model: mcp_oauth_clients lives in master, resource_servers and the
// client-registration join live in tenant DBs.
//
// This file covers what Phase 2 needs: DCR (Dynamic Client Registration) and
// helpers for looking up clients. Phases 3-5 extend it with authorize/token
// state, consent, and the Hydra reconciler.
type OAuthASService struct {
	rs *ResourceServerService
}

func NewOAuthASService(rs *ResourceServerService) *OAuthASService {
	if rs == nil {
		rs = NewResourceServerService()
	}
	return &OAuthASService{rs: rs}
}

// DCRRequest is the RFC 7591 Dynamic Client Registration request body. The
// optional `resource` field is RFC 8707 — when present, the new client is
// bound to that Application via resource_server_client_registrations.
type DCRRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Resource                string   `json:"resource"`
	Scope                   string   `json:"scope"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`
}

// DCRResponse is the RFC 7591 response.
type DCRResponse struct {
	ClientID                string    `json:"client_id"`
	ClientName              string    `json:"client_name,omitempty"`
	RedirectURIs            []string  `json:"redirect_uris"`
	GrantTypes              []string  `json:"grant_types"`
	ResponseTypes           []string  `json:"response_types"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method"`
	Scope                   string    `json:"scope,omitempty"`
	PostLogoutRedirectURIs  []string  `json:"post_logout_redirect_uris,omitempty"`
	ClientIDIssuedAt        int64     `json:"client_id_issued_at"`
	RegistrationType        string    `json:"registration_type"`
	IssuedAt                time.Time `json:"-"`
}

// ErrRegistrationModeNotAllowed is returned when a resource server is
// configured not to accept DCR. The handler turns this into HTTP 400.
var ErrRegistrationModeNotAllowed = errors.New("registration mode not allowed by resource server")

// RegisterDCRClient is the workhorse of POST /oauth/v2/register.
//
// Flow:
//  1. Optionally resolve the resource_uri to a resource_servers row (tenant DB)
//     plus the owning tenant_id from the master index.
//  2. Reject if that resource server doesn't allow DCR.
//  3. Mint a new client_id + hydra_client_id (both UUIDs).
//  4. Create the corresponding client in Hydra via hydraAdminCreateClient.
//  5. Insert the mcp_oauth_clients row in master.
//  6. If bound to a resource server, insert the resource_server_client_registrations
//     row in the tenant DB.
//  7. On any failure after step 4, mark the master row sync_status=pending_delete
//     so the reconciler (Phase 3) can clean up Hydra.
func (s *OAuthASService) RegisterDCRClient(req DCRRequest) (*DCRResponse, error) {
	if len(req.RedirectURIs) == 0 {
		return nil, fmt.Errorf("redirect_uris required")
	}
	for _, u := range req.RedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			return nil, fmt.Errorf("invalid redirect_uri %q: %w", u, err)
		}
	}
	for _, u := range req.PostLogoutRedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			return nil, fmt.Errorf("invalid post_logout_redirect_uri %q: %w", u, err)
		}
	}

	var (
		rs           *models.ResourceServer
		tenantID     string
		tenantDB     *gorm.DB
		bindToRS     bool
	)
	if req.Resource != "" {
		var err error
		rs, tenantID, err = s.rs.GetByResourceURI(req.Resource)
		if err != nil {
			return nil, fmt.Errorf("resolve resource: %w", err)
		}
		if !AllowsRegistrationMode(rs, "dcr") {
			return nil, ErrRegistrationModeNotAllowed
		}
		tenantDB, err = config.GetTenantGORMDB(tenantID)
		if err != nil {
			return nil, fmt.Errorf("get tenant db: %w", err)
		}
		bindToRS = true
	}

	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "none"
	}

	clientID := uuid.New().String()
	hydraClientID := uuid.New().String()

	// Create the Hydra client first. If this fails we never insert anything
	// in our own tables, so there's no cleanup to do.
	hc := hydraClient{
		ClientID:      hydraClientID,
		ClientName:    req.ClientName,
		GrantTypes:    req.GrantTypes,
		RedirectURIs:  req.RedirectURIs,
		ResponseTypes: req.ResponseTypes,
		TokenEndpoint: req.TokenEndpointAuthMethod,
		Scope:         req.Scope,
	}
	if rs != nil {
		hc.Audience = []string{rs.ResourceURI}
	}
	if err := hydraV2AdminCreateClient(hc); err != nil {
		return nil, fmt.Errorf("hydra create client: %w", err)
	}

	supportsRefresh := false
	for _, g := range req.GrantTypes {
		if g == "refresh_token" {
			supportsRefresh = true
			break
		}
	}

	row := models.MCPOAuthClient{
		ClientID:                clientID,
		HydraClientID:           hydraClientID,
		ClientName:              req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		Scope:                   req.Scope,
		RegistrationType:        "dcr",
		PostLogoutRedirectURIs:  req.PostLogoutRedirectURIs,
		SupportsRefreshToken:    supportsRefresh,
		SyncStatus:              "active",
	}
	if err := config.DB.Create(&row).Error; err != nil {
		// Best-effort Hydra rollback; the reconciler (Phase 3) catches what
		// we can't.
		_ = hydraAdminDeleteClient(hydraClientID)
		return nil, fmt.Errorf("insert mcp_oauth_clients: %w", err)
	}

	if bindToRS {
		reg := models.ResourceServerClientRegistration{
			ResourceServerID: rs.ID,
			ClientID:         clientID,
			Status:           models.RegistrationStatusApproved,
			RegistrationType: "dcr",
		}
		if err := tenantDB.Create(&reg).Error; err != nil {
			// Mark the master row pending_delete so the reconciler converges.
			now := time.Now()
			_ = config.DB.Model(&row).Updates(map[string]interface{}{
				"sync_status":         "pending_delete",
				"sync_last_error":     err.Error(),
				"sync_last_error_at":  now,
				"updated_at":          now,
			}).Error
			return nil, fmt.Errorf("insert resource_server_client_registrations: %w", err)
		}
	}

	return &DCRResponse{
		ClientID:                clientID,
		ClientName:              req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		Scope:                   req.Scope,
		PostLogoutRedirectURIs:  req.PostLogoutRedirectURIs,
		ClientIDIssuedAt:        time.Now().Unix(),
		RegistrationType:        "dcr",
		IssuedAt:                time.Now(),
	}, nil
}

// GetClient loads an MCPOAuthClient by its public client_id.
func (s *OAuthASService) GetClient(clientID string) (*models.MCPOAuthClient, error) {
	var row models.MCPOAuthClient
	if err := config.DB.Where("client_id = ?", clientID).First(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

// validateRedirectURI enforces the prod policy that redirect_uris must be
// https:// or localhost. Same rule as the dev branch.
func validateRedirectURI(raw string) error {
	if raw == "" {
		return fmt.Errorf("empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		host := strings.ToLower(u.Hostname())
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
	}
	return fmt.Errorf("must be https:// (or http://localhost for dev)")
}
