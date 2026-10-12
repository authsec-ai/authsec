package spire

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/controllers"
	infrarepos "github.com/authsec-ai/authsec/internal/spire/infrastructure/repositories"
	"github.com/authsec-ai/authsec/internal/spire/infrastructure/vault"
	"github.com/authsec-ai/authsec/internal/spire/middleware"
	"github.com/authsec-ai/authsec/internal/spire/services"
)

// BootstrapConfig holds configuration for initializing the SPIRE sub-module.
type BootstrapConfig struct {
	// MasterDB is the shared database. Every SPIRE table is workspace-owned
	// (migration 120) and every statement is scoped through internal/tenancy.
	MasterDB *sql.DB

	// VaultClient is an existing Vault API client (optional). Without it PKI
	// operations answer 503 and no client certificate can be verified.
	VaultClient *api.Client

	// Vault PKI config
	VaultPKIBasePath string
	VaultCARole      string

	// CABundles overrides where client certificates' workspace CAs come from
	// (default: Vault). Tests inject one.
	CABundles middleware.CABundleSource
}

// Bootstrap initializes all SPIRE sub-module dependencies and returns
// a Dependencies struct ready for route registration.
func Bootstrap(cfg *BootstrapConfig) (*Dependencies, error) {
	logger := logrus.WithField("module", "spire")
	fillDefaults(cfg)
	if cfg.MasterDB == nil {
		return nil, fmt.Errorf("spire bootstrap: MasterDB is required")
	}

	var vaultPKI *vault.Client
	if cfg.VaultClient != nil {
		vaultPKI = vault.NewClientFromExisting(cfg.VaultClient, logger.WithField("component", "vault_pki"), cfg.VaultPKIBasePath, cfg.VaultCARole)
	} else {
		logger.Warn("No Vault client provided — PKI operations will fail until Vault is configured")
	}

	// ── Repositories (shared DB, workspace-scoped) ──
	db := cfg.MasterDB
	workspaceRepo := infrarepos.NewPostgresWorkspaceRepository(db)
	agentRepo := infrarepos.NewPostgresAgentRepository(db, logger.WithField("repo", "agent"))
	joinTokenRepo := infrarepos.NewPostgresJoinTokenRepository(db)
	entryRepo := infrarepos.NewPostgresWorkloadEntryRepository(db, logger.WithField("repo", "workload_entry"))
	workloadRepo := infrarepos.NewPostgresWorkloadRepository(db)
	certRepo := infrarepos.NewPostgresCertificateRepository(db)
	policyRepo := infrarepos.NewPostgresPolicyRepository(db)
	auditRepo := infrarepos.NewPostgresAuditRepository(db)

	// ── Services ──
	entrySvc := services.NewWorkloadEntryService(entryRepo, workspaceRepo, logger.WithField("service", "workload_entry"))
	workloadAttestSvc := services.NewWorkloadAttestationService(workspaceRepo, entryRepo, vaultPKI, logger.WithField("service", "workload_attest"))
	nodeAttestSvc := services.NewNodeAttestationService(workspaceRepo, agentRepo, joinTokenRepo, vaultPKI, logger.WithField("service", "node_attest"))
	joinTokenSvc := services.NewJoinTokenService(joinTokenRepo, logger.WithField("service", "join_token"))
	agentRenewalSvc := services.NewAgentRenewalService(workspaceRepo, agentRepo, vaultPKI, logger.WithField("service", "agent_renewal"))
	agentSvc := services.NewAgentService(agentRepo, logger.WithField("service", "agent"))
	attestSvc := services.NewAttestationService(workspaceRepo, workloadRepo, certRepo, policyRepo, auditRepo, vaultPKI, logger.WithField("service", "attestation"))
	renewalSvc := services.NewRenewalService(workspaceRepo, workloadRepo, certRepo, auditRepo, vaultPKI, logger.WithField("service", "renewal"))
	revocationSvc := services.NewRevocationService(workspaceRepo, certRepo, auditRepo, vaultPKI, logger.WithField("service", "revocation"))
	bundleSvc := services.NewBundleService(workspaceRepo, vaultPKI, logger.WithField("service", "bundle"))
	jwtSvidSvc := services.NewJWTSVIDService(vaultPKI, logger.WithField("service", "jwt_svid"))
	jwtSvidSvc.SetDelegationStore(db)
	jwtSvidSvc.SetWorkspaceRepository(workspaceRepo)
	pkiProvSvc := services.NewPKIProvisioningService(workspaceRepo, vaultPKI, logger.WithField("service", "pki_prov"))

	// ── Certificate authentication ──
	caSource := cfg.CABundles
	if caSource == nil && vaultPKI.Available() {
		caSource = vaultPKI
	}
	certAuth := middleware.NewCertAuthenticator(middleware.CertAuthConfig{
		Workspaces:               workspaceRepo,
		Agents:                   agentRepo,
		CA:                       caSource,
		TrustForwardedCertHeader: os.Getenv("SPIRE_TRUST_CLIENT_CERT_HEADER") == "true",
		DevBypass:                middleware.DevBypassFromEnv(),
		Logger:                   logger.WithField("component", "cert_auth"),
	})

	logger.Info("SPIRE sub-module bootstrapped")
	return &Dependencies{
		Health:             controllers.NewHealthController(logger.WithField("ctrl", "health")),
		NodeAttestation:    controllers.NewNodeAttestationController(nodeAttestSvc, logger.WithField("ctrl", "node_attest")),
		JoinTokens:         controllers.NewJoinTokenController(joinTokenSvc, logger.WithField("ctrl", "join_tokens")),
		Agent:              controllers.NewAgentController(agentSvc, agentRenewalSvc, logger.WithField("ctrl", "agent")),
		Attestation:        controllers.NewAttestationController(attestSvc, logger.WithField("ctrl", "attestation")),
		Workload:           controllers.NewWorkloadController(workloadAttestSvc, entrySvc, logger.WithField("ctrl", "workload")),
		Certificate:        controllers.NewCertificateController(renewalSvc, revocationSvc, logger.WithField("ctrl", "certificate")),
		JWTSVID:            controllers.NewJWTSVIDController(jwtSvidSvc, logger.WithField("ctrl", "jwt_svid"), controllers.WithEntryService(entrySvc)),
		Bundle:             controllers.NewBundleController(bundleSvc, logger.WithField("ctrl", "bundle")),
		PKIAdmin:           controllers.NewPKIAdminController(pkiProvSvc, workspaceRepo, logger.WithField("ctrl", "pki_admin")),
		PKIProvisioningSvc: pkiProvSvc,
		WorkloadEntrySvc:   entrySvc,
		JWTSVIDSvc:         jwtSvidSvc,
		AgentSvc:           agentSvc,
		AgentCert:          certAuth.RequireAgent(),
		MTLSAuth:           certAuth.RequireSVID(),
		Logger:             logger,
	}, nil
}

func fillDefaults(cfg *BootstrapConfig) {
	if cfg.VaultPKIBasePath == "" {
		cfg.VaultPKIBasePath = os.Getenv("VAULT_PKI_BASE_PATH")
	}
	if cfg.VaultCARole == "" {
		cfg.VaultCARole = os.Getenv("VAULT_CA_ROLE")
	}
}
