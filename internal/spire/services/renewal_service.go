package services

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/spire/infrastructure/vault"
)

// RenewalService renews certificates of attested workloads of the workspace
// carried by ctx.
type RenewalService struct {
	workspaceRepo repositories.WorkspaceRepository
	workloadRepo  repositories.WorkloadRepository
	certRepo      repositories.CertificateRepository
	auditRepo     repositories.AuditRepository
	vaultClient   *vault.Client
	logger        *logrus.Entry
}

// NewRenewalService creates the renewal service.
func NewRenewalService(
	workspaceRepo repositories.WorkspaceRepository,
	workloadRepo repositories.WorkloadRepository,
	certRepo repositories.CertificateRepository,
	auditRepo repositories.AuditRepository,
	vaultClient *vault.Client,
	logger *logrus.Entry,
) *RenewalService {
	return &RenewalService{
		workspaceRepo: workspaceRepo,
		workloadRepo:  workloadRepo,
		certRepo:      certRepo,
		auditRepo:     auditRepo,
		vaultClient:   vaultClient,
		logger:        logger,
	}
}

// RenewRequest is a certificate renewal.
type RenewRequest struct {
	WorkloadID     string
	CSR            string
	OldCertificate string
	IPAddress      string
	UserAgent      string
}

// RenewResponse is the renewed certificate.
type RenewResponse struct {
	Certificate  string
	CAChain      []string
	ExpiresAt    time.Time
	SerialNumber string
}

// Renew issues a new certificate for a workload of ctx's workspace; another
// workspace's workload is not found.
func (s *RenewalService) Renew(ctx context.Context, req *RenewRequest) (*RenewResponse, error) {
	workspaceID, err := workspaceFromContext(ctx)
	if err != nil {
		return nil, err
	}
	tenant, err := s.workspaceRepo.GetByID(ctx, workspaceID)
	if err != nil {
		return nil, errors.NewNotFoundError("Workspace not found", err)
	}
	workload, err := s.workloadRepo.GetByID(ctx, req.WorkloadID)
	if err != nil {
		s.audit(ctx, req, false, "workload not found")
		return nil, errors.NewNotFoundError("Workload not found", err)
	}
	if workload.Status != "active" {
		s.audit(ctx, req, false, "workload not active")
		return nil, errors.NewForbiddenError("Workload is not active", nil)
	}
	if req.OldCertificate != "" {
		if err := s.validateOldCertificate(ctx, req.WorkloadID, req.OldCertificate); err != nil {
			s.audit(ctx, req, false, "old certificate validation failed")
			return nil, err
		}
	}

	csrBlock, _ := pem.Decode([]byte(req.CSR))
	if csrBlock == nil {
		s.audit(ctx, req, false, "invalid CSR format")
		return nil, errors.NewBadRequestError("Invalid CSR format", nil)
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		s.audit(ctx, req, false, "failed to parse CSR")
		return nil, errors.NewBadRequestError("Failed to parse CSR", err)
	}
	if err := csr.CheckSignature(); err != nil {
		s.audit(ctx, req, false, "invalid CSR signature")
		return nil, errors.NewBadRequestError("Invalid CSR signature", err)
	}

	if !s.vaultClient.Available() {
		return nil, vault.ErrUnavailable
	}
	vaultResp, err := s.vaultClient.IssueCertificate(ctx, strings.TrimPrefix(tenant.VaultMount, "pki/"), workload.VaultRole, &vault.CertificateRequest{
		CSR:        req.CSR,
		CommonName: workload.SpiffeID,
		TTL:        "24h",
		URISANs:    []string{workload.SpiffeID},
	})
	if err != nil {
		s.audit(ctx, req, false, "vault issuance failed")
		return nil, err
	}

	if err := s.certRepo.Create(ctx, &models.Certificate{
		WorkloadID:        workload.ID,
		SerialNumber:      vaultResp.SerialNumber,
		SHA256Fingerprint: vaultResp.SHA256Fingerprint,
		SpiffeID:          workload.SpiffeID,
		CertPEM:           vaultResp.Certificate,
		CAChain:           vaultResp.CAChain,
		IssuedAt:          time.Now(),
		ExpiresAt:         vaultResp.ExpirationTime,
		Status:            "active",
		IssueType:         "renew",
	}); err != nil {
		s.logger.WithField("serial_number", vaultResp.SerialNumber).WithError(err).Error("Failed to store certificate")
	}
	s.audit(ctx, req, true, "")

	return &RenewResponse{
		Certificate:  vaultResp.Certificate,
		CAChain:      vaultResp.CAChain,
		ExpiresAt:    vaultResp.ExpirationTime,
		SerialNumber: vaultResp.SerialNumber,
	}, nil
}

func (s *RenewalService) validateOldCertificate(ctx context.Context, workloadID, certPEM string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return errors.NewBadRequestError("Invalid certificate format", nil)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.NewBadRequestError("Failed to parse certificate", err)
	}
	active, err := s.certRepo.GetActiveByWorkload(ctx, workloadID)
	if err != nil {
		return errors.NewForbiddenError("No active certificate found for workload", err)
	}
	if cert.SerialNumber.String() != active.SerialNumber {
		return errors.NewForbiddenError("Certificate serial number mismatch", nil)
	}
	return nil
}

func (s *RenewalService) audit(ctx context.Context, req *RenewRequest, success bool, errorMsg string) {
	if err := s.auditRepo.Create(ctx, &models.AuditLog{
		EventType:    models.EventRenew,
		WorkloadID:   req.WorkloadID,
		Success:      success,
		ErrorMessage: errorMsg,
		Metadata:     map[string]interface{}{"workload_id": req.WorkloadID},
		IPAddress:    req.IPAddress,
		UserAgent:    req.UserAgent,
	}); err != nil {
		s.logger.WithError(err).Error("Failed to create audit log")
	}
}
