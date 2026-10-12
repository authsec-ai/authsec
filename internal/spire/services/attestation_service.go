package services

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/spire/infrastructure/vault"
)

// AttestationService attests workloads directly (mTLS /v1/attest) and
// issues their certificates, in the workspace carried by ctx.
type AttestationService struct {
	workspaceRepo repositories.WorkspaceRepository
	workloadRepo  repositories.WorkloadRepository
	certRepo      repositories.CertificateRepository
	policyRepo    repositories.PolicyRepository
	auditRepo     repositories.AuditRepository
	vaultClient   *vault.Client
	logger        *logrus.Entry
}

// NewAttestationService creates the attestation service.
func NewAttestationService(
	workspaceRepo repositories.WorkspaceRepository,
	workloadRepo repositories.WorkloadRepository,
	certRepo repositories.CertificateRepository,
	policyRepo repositories.PolicyRepository,
	auditRepo repositories.AuditRepository,
	vaultClient *vault.Client,
	logger *logrus.Entry,
) *AttestationService {
	return &AttestationService{
		workspaceRepo: workspaceRepo,
		workloadRepo:  workloadRepo,
		certRepo:      certRepo,
		policyRepo:    policyRepo,
		auditRepo:     auditRepo,
		vaultClient:   vaultClient,
		logger:        logger,
	}
}

// AttestRequest represents an attestation request
type AttestRequest struct {
	CSR             string
	AttestationType string
	Selectors       map[string]string
	IPAddress       string
	UserAgent       string
}

// AttestResponse represents an attestation response
type AttestResponse struct {
	Certificate  string
	CAChain      []string
	SpiffeID     string
	ExpiresAt    time.Time
	WorkloadID   string
	SerialNumber string
}

// Attest issues a certificate for a workload of ctx's workspace. The PKI
// mount is always the workspace's own.
func (s *AttestationService) Attest(ctx context.Context, req *AttestRequest) (*AttestResponse, error) {
	workspaceID, err := workspaceFromContext(ctx)
	if err != nil {
		return nil, err
	}
	tenant, err := s.workspaceRepo.GetByID(ctx, workspaceID)
	if err != nil {
		return nil, errors.NewNotFoundError("Workspace not found", err)
	}

	csrBlock, _ := pem.Decode([]byte(req.CSR))
	if csrBlock == nil {
		s.audit(ctx, req, "", false, "invalid CSR format")
		return nil, errors.NewBadRequestError("Invalid CSR format", nil)
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		s.audit(ctx, req, "", false, "failed to parse CSR")
		return nil, errors.NewBadRequestError("Failed to parse CSR", err)
	}
	if err := csr.CheckSignature(); err != nil {
		s.audit(ctx, req, "", false, "invalid CSR signature")
		return nil, errors.NewBadRequestError("Invalid CSR signature", err)
	}

	vaultRole, ttl := "workload", 86400
	if policy, err := s.policyRepo.FindMatchingPolicy(ctx, req.AttestationType, req.Selectors); err == nil {
		vaultRole, ttl = policy.VaultRole, policy.TTL
	}

	spiffeID := generateSpiffeID(workspaceID, req.Selectors)
	workload, err := s.workloadRepo.GetBySpiffeID(ctx, spiffeID)
	if err != nil {
		workload = &models.Workload{
			ID:              uuid.New().String(),
			SpiffeID:        spiffeID,
			Selectors:       req.Selectors,
			VaultRole:       vaultRole,
			Status:          "active",
			AttestationType: req.AttestationType,
		}
		if err := s.workloadRepo.Create(ctx, workload); err != nil {
			s.audit(ctx, req, spiffeID, false, "failed to create workload")
			return nil, err
		}
	}

	if !s.vaultClient.Available() {
		return nil, vault.ErrUnavailable
	}
	vaultResp, err := s.vaultClient.IssueCertificate(ctx, strings.TrimPrefix(tenant.VaultMount, "pki/"), vaultRole, &vault.CertificateRequest{
		CSR:        req.CSR,
		CommonName: spiffeID,
		TTL:        fmt.Sprintf("%ds", ttl),
		URISANs:    []string{spiffeID},
	})
	if err != nil {
		s.audit(ctx, req, spiffeID, false, "vault issuance failed")
		return nil, err
	}

	cert := &models.Certificate{
		WorkloadID:        workload.ID,
		SerialNumber:      vaultResp.SerialNumber,
		SHA256Fingerprint: vaultResp.SHA256Fingerprint,
		SpiffeID:          spiffeID,
		CertPEM:           vaultResp.Certificate,
		CAChain:           vaultResp.CAChain,
		IssuedAt:          time.Now(),
		ExpiresAt:         vaultResp.ExpirationTime,
		Status:            "active",
		IssueType:         "attest",
	}
	if err := s.certRepo.Create(ctx, cert); err != nil {
		s.logger.WithField("serial_number", vaultResp.SerialNumber).WithError(err).Error("Failed to store certificate")
	}
	s.audit(ctx, req, spiffeID, true, "")

	return &AttestResponse{
		Certificate:  vaultResp.Certificate,
		CAChain:      vaultResp.CAChain,
		SpiffeID:     spiffeID,
		ExpiresAt:    vaultResp.ExpirationTime,
		WorkloadID:   workload.ID,
		SerialNumber: vaultResp.SerialNumber,
	}, nil
}

// generateSpiffeID derives a workload SPIFFE ID in the workspace's trust
// domain from its selectors.
func generateSpiffeID(workspaceID string, selectors map[string]string) string {
	base := fmt.Sprintf("spiffe://%s", workspaceID)
	if ns, ok := selectors["k8s:namespace"]; ok {
		base += "/ns/" + ns
	}
	if sa, ok := selectors["k8s:service-account"]; ok {
		base += "/sa/" + sa
	}
	return base
}

func (s *AttestationService) audit(ctx context.Context, req *AttestRequest, spiffeID string, success bool, errorMsg string) {
	if err := s.auditRepo.Create(ctx, &models.AuditLog{
		EventType:    models.EventAttest,
		SpiffeID:     spiffeID,
		Success:      success,
		ErrorMessage: errorMsg,
		Metadata: map[string]interface{}{
			"attestation_type": req.AttestationType,
			"selectors":        req.Selectors,
		},
		IPAddress: req.IPAddress,
		UserAgent: req.UserAgent,
	}); err != nil {
		s.logger.WithError(err).Error("Failed to create audit log")
	}
}
