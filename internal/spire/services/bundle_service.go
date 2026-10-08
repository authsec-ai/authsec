package services

import (
	"context"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/spire/infrastructure/vault"
	"github.com/authsec-ai/authsec/internal/spire/utils"
)

// BundleService serves a workspace's public X.509 trust bundle.
type BundleService struct {
	workspaceRepo repositories.WorkspaceRepository
	vaultClient   *vault.Client
	logger        *logrus.Entry
}

// NewBundleService creates the bundle service.
func NewBundleService(workspaceRepo repositories.WorkspaceRepository, vaultClient *vault.Client, logger *logrus.Entry) *BundleService {
	return &BundleService{workspaceRepo: workspaceRepo, vaultClient: vaultClient, logger: logger}
}

// GetBundle returns the CA bundle of the active workspace named by its id
// or domain (a trust domain). The bundle is public; the identifier is
// validated and must name an existing workspace with provisioned PKI.
func (s *BundleService) GetBundle(ctx context.Context, trustDomain string) (string, error) {
	if err := utils.ValidateSpiffeComponent(trustDomain, "trust domain"); err != nil {
		return "", errors.NewBadRequestError(err.Error(), err)
	}
	tenant, err := s.workspaceRepo.GetByTrustDomain(ctx, trustDomain)
	if err != nil {
		return "", errors.NewNotFoundError("Workspace not found", nil)
	}
	if tenant.VaultMount == "" {
		return "", errors.NewNotFoundError("Workspace PKI is not provisioned", nil)
	}
	if !s.vaultClient.Available() {
		return "", vault.ErrUnavailable
	}
	return s.vaultClient.GetCABundle(ctx, strings.TrimPrefix(tenant.VaultMount, "pki/"))
}
