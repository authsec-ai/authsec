package services

import (
	"context"

	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/spire/infrastructure/vault"
)

// RevocationService revokes certificates of attested workloads of the
// workspace carried by ctx.
type RevocationService struct {
	workspaceRepo repositories.WorkspaceRepository
	certRepo      repositories.CertificateRepository
	auditRepo     repositories.AuditRepository
	vaultClient   *vault.Client
	logger        *logrus.Entry
}

// NewRevocationService creates the revocation service.
func NewRevocationService(
	workspaceRepo repositories.WorkspaceRepository,
	certRepo repositories.CertificateRepository,
	auditRepo repositories.AuditRepository,
	vaultClient *vault.Client,
	logger *logrus.Entry,
) *RevocationService {
	return &RevocationService{
		workspaceRepo: workspaceRepo,
		certRepo:      certRepo,
		auditRepo:     auditRepo,
		vaultClient:   vaultClient,
		logger:        logger,
	}
}

// RevokeRequest is a certificate revocation.
type RevokeRequest struct {
	SerialNumber string
	Reason       string
	IPAddress    string
	UserAgent    string
}

// Revoke revokes a certificate of ctx's workspace; another workspace's
// serial is not found.
func (s *RevocationService) Revoke(ctx context.Context, req *RevokeRequest) error {
	workspaceID, err := workspaceFromContext(ctx)
	if err != nil {
		return err
	}
	tenant, err := s.workspaceRepo.GetByID(ctx, workspaceID)
	if err != nil {
		return errors.NewNotFoundError("Workspace not found", err)
	}
	cert, err := s.certRepo.GetBySerialNumber(ctx, req.SerialNumber)
	if err != nil {
		s.audit(ctx, req, false, "certificate not found")
		return errors.NewNotFoundError("Certificate not found", err)
	}
	if cert.RevokedAt != nil {
		s.audit(ctx, req, false, "certificate already revoked")
		return errors.NewConflictError("Certificate already revoked", nil)
	}
	if !s.vaultClient.Available() {
		return vault.ErrUnavailable
	}
	if err := s.vaultClient.RevokeCertificate(ctx, tenant.VaultMount, req.SerialNumber); err != nil {
		s.audit(ctx, req, false, "vault revocation failed")
		return err
	}
	if err := s.certRepo.Revoke(ctx, cert.ID); err != nil {
		s.logger.WithField("serial_number", req.SerialNumber).WithError(err).Error("Failed to update certificate status")
	}
	s.audit(ctx, req, true, "")
	return nil
}

func (s *RevocationService) audit(ctx context.Context, req *RevokeRequest, success bool, errorMsg string) {
	if err := s.auditRepo.Create(ctx, &models.AuditLog{
		EventType:    models.EventRevoke,
		Success:      success,
		ErrorMessage: errorMsg,
		Metadata: map[string]interface{}{
			"serial_number": req.SerialNumber,
			"reason":        req.Reason,
		},
		IPAddress: req.IPAddress,
		UserAgent: req.UserAgent,
	}); err != nil {
		s.logger.WithError(err).Error("Failed to create audit log")
	}
}
