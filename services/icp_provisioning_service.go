package services

import (
	"context"
	"fmt"
	"log"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/clients/icp"
	spireservices "github.com/authsec-ai/authsec/internal/spire/services"
	_ "github.com/lib/pq"
)

// ICPProvisioningService handles PKI provisioning tasks.
// Uses the in-process PKIProvisioningService (merged from authsec-spire) when available,
// falls back to HTTP ICP client for backward compatibility.
type ICPProvisioningService struct {
	icpClient  *icp.Client
	pkiService *spireservices.PKIProvisioningService
}

// NewICPProvisioningService creates a new ICP provisioning service using HTTP client.
func NewICPProvisioningService(icpClient *icp.Client) *ICPProvisioningService {
	return &ICPProvisioningService{
		icpClient: icpClient,
	}
}

// NewICPProvisioningServiceInProcess creates a provisioning service using the merged in-process PKI service.
func NewICPProvisioningServiceInProcess(pkiService *spireservices.PKIProvisioningService) *ICPProvisioningService {
	return &ICPProvisioningService{
		pkiService: pkiService,
	}
}

// SetPKIService injects the in-process PKI service (replaces HTTP calls).
func (s *ICPProvisioningService) SetPKIService(pkiService *spireservices.PKIProvisioningService) {
	s.pkiService = pkiService
}

// ProvisionPKI provisions PKI for a tenant. Uses in-process service if available,
// otherwise falls back to HTTP ICP client.
func (s *ICPProvisioningService) ProvisionPKI(ctx context.Context, req *icp.ProvisionPKIRequest) (*icp.ProvisionPKIResponse, error) {
	// Prefer in-process merged service (no HTTP round-trip)
	if s.pkiService != nil {
		log.Printf("Provisioning PKI in-process for tenant: %s", req.WorkspaceID)
		spireResp, err := s.pkiService.ProvisionPKI(ctx, &spireservices.ProvisionPKIRequest{
			WorkspaceID:       req.WorkspaceID,
			CommonName:     req.CommonName,
			AllowedDomains: req.Domain,
			TTL:            req.TTL,
			MaxTTL:         req.MaxTTL,
		})
		if err != nil {
			return nil, fmt.Errorf("in-process PKI provisioning failed: %w", err)
		}
		log.Printf("In-process PKI provisioning successful - PKI Mount: %s", spireResp.PKIMount)
		return &icp.ProvisionPKIResponse{
			WorkspaceID:    spireResp.WorkspaceID,
			PKIMount:    spireResp.PKIMount,
			CACert:      spireResp.CACert,
			RoleCreated: spireResp.RoleCreated,
			Message:     spireResp.Message,
		}, nil
	}

	// Fallback: HTTP call to standalone ICP service
	if s.icpClient == nil {
		return nil, fmt.Errorf("no PKI service available (neither in-process nor HTTP client configured)")
	}

	log.Printf("Provisioning PKI via HTTP for tenant: %s", req.WorkspaceID)
	resp, err := s.icpClient.ProvisionPKI(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("ICP provisioning failed: %w", err)
	}

	log.Printf("HTTP PKI provisioning successful - PKI Mount: %s", resp.PKIMount)
	return resp, nil
}

// RetryPKIProvisioning retries PKI provisioning for a failed tenant
func (s *ICPProvisioningService) RetryPKIProvisioning(ctx context.Context, workspaceID, commonName, domain string) (*icp.ProvisionPKIResponse, error) {
	log.Printf("Retrying PKI provisioning for tenant: %s", workspaceID)

	req := &icp.ProvisionPKIRequest{
		WorkspaceID:   workspaceID,
		CommonName: commonName,
		Domain:     domain,
		TTL:        "87600h", // 10 years
		MaxTTL:     "24h",
	}

	return s.ProvisionPKI(ctx, req)
}

// UpdateTenantStatusInICP updates tenant status in ICP service.
// No-op when using in-process service (tenant status is managed directly).
func (s *ICPProvisioningService) UpdateTenantStatusInICP(ctx context.Context, workspaceID, status string) error {
	if s.pkiService != nil {
		// In-process mode: tenant status is updated directly by PKIProvisioningService
		return nil
	}
	if s.icpClient == nil {
		return nil
	}

	log.Printf("Updating tenant status in ICP: %s -> %s", workspaceID, status)
	if err := s.icpClient.UpdateTenantStatus(ctx, workspaceID, status); err != nil {
		log.Printf("Warning: Failed to update tenant status in ICP: %v", err)
		return nil
	}
	return nil
}

// HealthCheck checks if PKI service is available.
func (s *ICPProvisioningService) HealthCheck(ctx context.Context) error {
	if s.pkiService != nil {
		// In-process: always healthy
		return nil
	}
	if s.icpClient == nil {
		return fmt.Errorf("no PKI service available")
	}
	return s.icpClient.HealthCheck(ctx)
}

// GenerateTenantDatabaseURL generates a database URL for a tenant database
func GenerateTenantDatabaseURL(tenantDBName string) string {
	cfg := config.GetConfig()
	return fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
		cfg.DBHost,
		cfg.DBUser,
		cfg.DBPassword,
		tenantDBName,
		cfg.DBPort,
	)
}
