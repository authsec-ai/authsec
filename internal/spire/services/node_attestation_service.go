package services

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/spire/infrastructure/vault"
	"github.com/authsec-ai/authsec/internal/spire/utils"
)

// AttestationTypeJoinToken attests a node by its join token alone.
const AttestationTypeJoinToken = "join_token"

// NodeAttestationService attests nodes and issues agent SVIDs. A node proves
// it may join a workspace with a single-use join token minted by that
// workspace's admin; the token, never the request, decides the workspace.
// Attestation evidence (Kubernetes PSAT, ...) is still validated for the
// node's selectors.
type NodeAttestationService struct {
	workspaceRepo repositories.WorkspaceRepository
	agentRepo     repositories.AgentRepository
	joinTokens    repositories.JoinTokenRepository
	vaultClient   *vault.Client
	k8sValidator  *KubernetesValidator
	logger        *logrus.Entry
}

// NodeAttestRequest represents a node attestation request
type NodeAttestRequest struct {
	// JoinToken is the secret an admin minted for this node.
	JoinToken string
	// AssertedWorkspaceID is the workspace the caller says it joins; when
	// set it must be the token's.
	AssertedWorkspaceID string
	NodeID              string
	AttestationType     string
	Evidence            map[string]interface{}
	CSR                 string
}

// NodeAttestResponse represents a node attestation response
type NodeAttestResponse struct {
	Certificate string
	CAChain     []string
	SpiffeID    string
	ExpiresAt   time.Time
	AgentID     string
	WorkspaceID string
}

// NewNodeAttestationService creates a new node attestation service
func NewNodeAttestationService(
	workspaceRepo repositories.WorkspaceRepository,
	agentRepo repositories.AgentRepository,
	joinTokens repositories.JoinTokenRepository,
	vaultClient *vault.Client,
	logger *logrus.Entry,
) *NodeAttestationService {
	// PSAT tokens are verified with the TokenReview API (AS-076); the ICP
	// server's service account needs tokenreviews create.
	k8sValidator, err := NewKubernetesValidator(logger, &KubernetesValidatorConfig{})
	if err != nil {
		logger.WithError(err).Error("Failed to initialize Kubernetes validator; kubernetes attestation unavailable")
		k8sValidator = nil
	}
	return &NodeAttestationService{
		workspaceRepo: workspaceRepo,
		agentRepo:     agentRepo,
		joinTokens:    joinTokens,
		vaultClient:   vaultClient,
		k8sValidator:  k8sValidator,
		logger:        logger,
	}
}

// Attest performs node attestation and issues an agent SVID.
func (s *NodeAttestationService) Attest(ctx context.Context, req *NodeAttestRequest) (*NodeAttestResponse, error) {
	if req.JoinToken == "" {
		return nil, errors.NewUnauthorizedError("join_token is required", nil)
	}
	if err := utils.ValidateSpiffeComponent(req.NodeID, "node_id"); err != nil {
		return nil, errors.NewBadRequestError(err.Error(), err)
	}

	// 1. Evidence and CSR first, so a request that fails them does not burn
	//    the token.
	nodeSelectors, err := s.validateEvidence(ctx, req.AttestationType, req.Evidence)
	if err != nil {
		s.logger.WithField("attestation_type", req.AttestationType).WithError(err).Warn("Attestation evidence refused")
		return nil, errors.NewUnauthorizedError("Attestation failed", err)
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

	// 2. The join token decides the workspace. It is consumed atomically; a
	//    used, expired, revoked or unknown token, or one for another
	//    workspace than the asserted one, is refused.
	token, err := s.joinTokens.Consume(ctx, HashJoinToken(req.JoinToken), req.NodeID, req.AssertedWorkspaceID)
	if err != nil {
		return nil, err
	}
	ctx, err = withWorkspace(ctx, token.WorkspaceID, "spire_node")
	if err != nil {
		return nil, err
	}
	tenant, err := s.workspaceRepo.GetByID(ctx, token.WorkspaceID)
	if err != nil {
		return nil, errors.NewUnauthorizedError("The join token's workspace is not active", err)
	}
	s.logger.WithFields(logrus.Fields{
		"workspace_id": tenant.ID, "node_id": req.NodeID, "join_token_id": token.ID,
	}).Info("Node attestation: join token accepted")

	if !s.vaultClient.Available() {
		return nil, vault.ErrUnavailable
	}
	if tenant.VaultMount == "" {
		return nil, errors.NewServiceUnavailableError("Workspace PKI is not provisioned", nil)
	}

	// 3. Issue the agent SVID.
	spiffeID := s.generateAgentSpiffeID(tenant.ID, req.NodeID)
	if err := s.ensureVaultRoleConfigured(ctx, tenant.VaultMount, tenant.ID); err != nil {
		return nil, errors.NewInternalError("Failed to configure Vault PKI role", err)
	}
	certResp, err := s.vaultClient.IssueCertificate(ctx, tenant.VaultMount, "agent", &vault.CertificateRequest{
		CSR:        req.CSR,
		CommonName: spiffeID,
		TTL:        "1h", // short-lived: agents renew often
		URISANs:    []string{spiffeID},
	})
	if err != nil {
		return nil, errors.NewInternalError("Failed to issue certificate", err)
	}

	// 4. Create or update this workspace's agent for the node.
	agent, err := s.agentRepo.GetByNode(ctx, req.NodeID)
	if err == nil {
		agent.SpiffeID = spiffeID
		agent.AttestationType = req.AttestationType
		agent.NodeSelectors = nodeSelectors
		agent.CertificateSerial = certResp.SerialNumber
		agent.Status = models.AgentStatusActive
		agent.LastSeen = time.Now()
		if err := s.agentRepo.Update(ctx, agent); err != nil {
			return nil, errors.NewInternalError("Failed to update agent", err)
		}
	} else {
		agent = &models.Agent{
			ID:                uuid.New().String(),
			NodeID:            req.NodeID,
			SpiffeID:          spiffeID,
			AttestationType:   req.AttestationType,
			NodeSelectors:     nodeSelectors,
			CertificateSerial: certResp.SerialNumber,
			Status:            models.AgentStatusActive,
			LastSeen:          time.Now(),
		}
		if err := s.agentRepo.Create(ctx, agent); err != nil {
			return nil, errors.NewInternalError("Failed to store agent", err)
		}
	}

	return &NodeAttestResponse{
		Certificate: certResp.Certificate,
		CAChain:     certResp.CAChain,
		SpiffeID:    spiffeID,
		ExpiresAt:   certResp.ExpirationTime,
		AgentID:     agent.ID,
		WorkspaceID: tenant.ID,
	}, nil
}

// validateEvidence validates attestation evidence based on type
func (s *NodeAttestationService) validateEvidence(ctx context.Context, attestationType string, evidence map[string]interface{}) (map[string]string, error) {
	switch attestationType {
	case AttestationTypeJoinToken:
		// The join token alone attests the node; no selectors.
		return map[string]string{}, nil

	case models.AttestationTypeKubernetes:
		if s.k8sValidator == nil {
			return nil, fmt.Errorf("kubernetes attestation is not available")
		}
		return s.k8sValidator.Validate(ctx, evidence)

	case models.AttestationTypeUnix:
		// Unix attestation: self-reported selectors; the join token is the
		// proof of authorization.
		nodeSelectors := make(map[string]string)
		if pid, ok := evidence["pid"].(float64); ok {
			nodeSelectors["unix:pid"] = fmt.Sprintf("%d", int(pid))
		}
		if username, ok := evidence["username"].(string); ok {
			nodeSelectors["unix:username"] = username
		}
		if hostname, ok := evidence["hostname"].(string); ok {
			nodeSelectors["unix:hostname"] = hostname
		}
		return nodeSelectors, nil

	case models.AttestationTypeDocker:
		// Docker attestation: self-reported selectors; the join token is the
		// proof of authorization.
		nodeSelectors := make(map[string]string)
		if containerID, ok := evidence["container_id"].(string); ok {
			nodeSelectors["docker:container_id"] = containerID
		}
		if imageName, ok := evidence["image_name"].(string); ok {
			nodeSelectors["docker:image_name"] = imageName
		}
		return nodeSelectors, nil

	case models.AttestationTypeTPM:
		return nil, fmt.Errorf("TPM attestation not yet implemented")

	case models.AttestationTypeAWS:
		return nil, fmt.Errorf("AWS attestation not yet implemented")

	default:
		return nil, fmt.Errorf("unsupported attestation type: %s", attestationType)
	}
}

// generateAgentSpiffeID generates a SPIFFE ID for an agent
// Format: spiffe://{workspace-id}/agent/{node-id}
func (s *NodeAttestationService) generateAgentSpiffeID(workspaceID, nodeID string) string {
	return fmt.Sprintf("spiffe://%s/agent/%s", workspaceID, nodeID)
}

// ensureVaultRoleConfigured ensures the Vault PKI role allows URI SANs for
// this workspace's agent SPIFFE IDs.
func (s *NodeAttestationService) ensureVaultRoleConfigured(ctx context.Context, vaultMount, workspaceID string) error {
	roleConfig := &vault.PKIRoleConfig{
		AllowedDomains:  []string{},
		AllowedURISANs:  []string{fmt.Sprintf("spiffe://%s/*", workspaceID)},
		AllowSubdomains: false,
		AllowAnyName:    false,
		AllowURISANs:    true,
		AllowIPSANs:     false,
		MaxTTL:          "2h",
		TTL:             "1h",
		KeyType:         "rsa",
		KeyBits:         2048,
		RequireCN:       false,
	}
	// Idempotent: creates or updates the agent role. vaultMount already
	// includes the full path (e.g. "pki/spire.app.authsec.dev").
	if err := s.vaultClient.CreatePKIRole(ctx, vaultMount, "agent", roleConfig); err != nil {
		s.logger.WithField("vault_mount", vaultMount).WithError(err).Error("Failed to create/update PKI role")
		return err
	}
	return nil
}
