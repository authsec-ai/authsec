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

// AgentRenewalService renews agent SVIDs. The caller is an agent
// authenticated by its current certificate; the workspace is ctx's.
type AgentRenewalService struct {
	workspaceRepo repositories.WorkspaceRepository
	agentRepo     repositories.AgentRepository
	vaultClient   *vault.Client
	logger        *logrus.Entry
}

// AgentRenewRequest represents an agent renewal request
type AgentRenewRequest struct {
	// AgentID is the authenticated agent (from its certificate).
	AgentID string
	CSR     string
}

// AgentRenewResponse represents an agent renewal response
type AgentRenewResponse struct {
	SpiffeID    string
	Certificate string
	CABundle    string
	TTL         int
	CAChain     []string
	ExpiresAt   time.Time
}

// NewAgentRenewalService creates a new agent renewal service
func NewAgentRenewalService(
	workspaceRepo repositories.WorkspaceRepository,
	agentRepo repositories.AgentRepository,
	vaultClient *vault.Client,
	logger *logrus.Entry,
) *AgentRenewalService {
	return &AgentRenewalService{
		workspaceRepo: workspaceRepo,
		agentRepo:     agentRepo,
		vaultClient:   vaultClient,
		logger:        logger,
	}
}

// Renew issues a new SVID for the authenticated agent of ctx's workspace.
func (s *AgentRenewalService) Renew(ctx context.Context, req *AgentRenewRequest) (*AgentRenewResponse, error) {
	workspaceID, err := workspaceFromContext(ctx)
	if err != nil {
		return nil, err
	}
	tenant, err := s.workspaceRepo.GetByID(ctx, workspaceID)
	if err != nil {
		return nil, errors.NewNotFoundError("Workspace not found", err)
	}
	agent, err := s.agentRepo.GetByID(ctx, req.AgentID)
	if err != nil {
		return nil, errors.NewNotFoundError("Agent not found", err)
	}
	if agent.Status != models.AgentStatusActive {
		return nil, errors.NewForbiddenError("Agent is not active", nil)
	}

	csrBlock, _ := pem.Decode([]byte(req.CSR))
	if csrBlock == nil {
		return nil, errors.NewBadRequestError("Invalid CSR format", nil)
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, errors.NewBadRequestError("Failed to parse CSR", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.NewBadRequestError("Invalid CSR signature", err)
	}

	if !s.vaultClient.Available() {
		return nil, vault.ErrUnavailable
	}
	certResp, err := s.vaultClient.IssueCertificate(ctx, tenant.VaultMount, "agent", &vault.CertificateRequest{
		CSR:        req.CSR,
		CommonName: agent.SpiffeID,
		TTL:        "1h",
		URISANs:    []string{agent.SpiffeID},
	})
	if err != nil {
		return nil, errors.NewInternalError("Failed to issue certificate", err)
	}

	agent.CertificateSerial = certResp.SerialNumber
	agent.LastSeen = time.Now()
	if err := s.agentRepo.Update(ctx, agent); err != nil {
		return nil, errors.NewInternalError("Failed to update agent", err)
	}
	s.logger.WithFields(logrus.Fields{"agent_id": agent.ID, "serial_number": certResp.SerialNumber}).Info("Agent SVID renewed")

	return &AgentRenewResponse{
		SpiffeID:    agent.SpiffeID,
		Certificate: certResp.Certificate,
		CABundle:    strings.Join(certResp.CAChain, "\n"),
		TTL:         3600,
		CAChain:     certResp.CAChain,
		ExpiresAt:   certResp.ExpirationTime,
	}, nil
}
