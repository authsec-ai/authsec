package spire

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/controllers"
	"github.com/authsec-ai/authsec/internal/spire/infrastructure/database"
	infrarepos "github.com/authsec-ai/authsec/internal/spire/infrastructure/repositories"
	"github.com/authsec-ai/authsec/internal/spire/infrastructure/vault"
	"github.com/authsec-ai/authsec/internal/spire/middleware"
	"github.com/authsec-ai/authsec/internal/spire/services"
	"github.com/authsec-ai/authsec/internal/spire/utils"
)

// BootstrapConfig holds configuration for initializing the SPIRE sub-module.
type BootstrapConfig struct {
	// MasterDB is the raw *sql.DB for the master (authsec) database.
	MasterDB *sql.DB

	// VaultClient is an existing Vault API client (optional — if nil, creates one from env).
	VaultClient *api.Client

	// WorkspaceDB connection config (reads from env if zero-valued).
	WorkspaceDBHost     string
	WorkspaceDBPort     int
	WorkspaceDBUsername string
	WorkspaceDBPassword string
	WorkspaceDBSSLMode  string

	// Vault PKI config
	VaultPKIBasePath string
	VaultCARole      string

	// JWT validation key (PEM public key or HMAC secret)
	JWTKeyOrSecret string
}

// Bootstrap initializes all SPIRE sub-module dependencies and returns
// a Dependencies struct ready for route registration.
func Bootstrap(cfg *BootstrapConfig) (*Dependencies, error) {
	logger := logrus.WithField("module", "spire")

	// ── Fill defaults from environment ──
	fillDefaults(cfg)

	if cfg.MasterDB == nil {
		return nil, fmt.Errorf("spire bootstrap: MasterDB is required")
	}

	// ── Tenant repository (master DB) ──
	workspaceRepo := infrarepos.NewPostgresWorkspaceRepository(cfg.MasterDB)

	// ── Connection manager (multi-tenant) ──
	connMgr := database.NewConnectionManager(
		cfg.MasterDB,
		logger.WithField("component", "conn_manager"),
		workspaceRepo,
		10, 5, 30*time.Minute,
		cfg.WorkspaceDBHost, cfg.WorkspaceDBPort,
		cfg.WorkspaceDBUsername, cfg.WorkspaceDBPassword, cfg.WorkspaceDBSSLMode,
	)

	// ── Vault PKI client ──
	var vaultPKI *vault.Client
	if cfg.VaultClient != nil {
		vaultPKI = vault.NewClientFromExisting(
			cfg.VaultClient,
			logger.WithField("component", "vault_pki"),
			cfg.VaultPKIBasePath,
			cfg.VaultCARole,
		)
		logger.Info("Vault PKI client initialized from existing client")
	} else {
		logger.Warn("No Vault client provided — PKI operations will fail until Vault is configured")
	}

	// ── Master-DB repositories ──
	auditRepo := infrarepos.NewPostgresAuditRepository(cfg.MasterDB)
	policyRepo := infrarepos.NewPostgresPolicyRepository(cfg.MasterDB)

	// ── Application services ──
	workloadEntrySvc := services.NewWorkloadEntryService(connMgr, logger.WithField("service", "workload_entry"))
	workloadAttestSvc := services.NewWorkloadAttestationService(connMgr, workspaceRepo, workloadEntrySvc, vaultPKI, logger.WithField("service", "workload_attest"))

	nodeAttestSvc := services.NewNodeAttestationService(connMgr, workspaceRepo, vaultPKI, logger.WithField("service", "node_attest"))
	agentRenewalSvc := services.NewAgentRenewalService(connMgr, workspaceRepo, vaultPKI, logger.WithField("service", "agent_renewal"))
	agentSvc := services.NewAgentService(connMgr, workspaceRepo, logger.WithField("service", "agent"))

	attestSvc := services.NewAttestationService(nil, nil, policyRepo, auditRepo, workspaceRepo, vaultPKI, connMgr, logger.WithField("service", "attestation"))
	renewalSvc := services.NewRenewalService(nil, nil, auditRepo, workspaceRepo, vaultPKI, connMgr, logger.WithField("service", "renewal"))
	revocationSvc := services.NewRevocationService(nil, auditRepo, workspaceRepo, vaultPKI, connMgr, logger.WithField("service", "revocation"))

	bundleSvc := services.NewBundleService(workspaceRepo, vaultPKI, logger.WithField("service", "bundle"))
	jwtSvidSvc := services.NewJWTSVIDService(vaultPKI, logger.WithField("service", "jwt_svid"))
	pkiProvSvc := services.NewPKIProvisioningService(workspaceRepo, vaultPKI, logger.WithField("service", "pki_prov"))

	// ── Controllers ──
	healthCtrl := controllers.NewHealthController(logger.WithField("ctrl", "health"))
	nodeAttestCtrl := controllers.NewNodeAttestationController(nodeAttestSvc, logger.WithField("ctrl", "node_attest"))
	agentCtrl := controllers.NewAgentController(agentSvc, agentRenewalSvc, logger.WithField("ctrl", "agent"))
	attestCtrl := controllers.NewAttestationController(attestSvc, logger.WithField("ctrl", "attestation"))
	workloadCtrl := controllers.NewWorkloadController(workloadAttestSvc, workloadEntrySvc, logger.WithField("ctrl", "workload"))
	certCtrl := controllers.NewCertificateController(renewalSvc, revocationSvc, logger.WithField("ctrl", "certificate"))
	jwtSvidCtrl := controllers.NewJWTSVIDController(jwtSvidSvc, logger.WithField("ctrl", "jwt_svid"))
	bundleCtrl := controllers.NewBundleController(bundleSvc, logger.WithField("ctrl", "bundle"))
	pkiAdminCtrl := controllers.NewPKIAdminController(pkiProvSvc, logger.WithField("ctrl", "pki_admin"))

	// ── Middleware ──
	baseLogger := logrus.StandardLogger()
	mtlsMiddleware := middleware.NewMTLSMiddleware(baseLogger)
	mtlsAuth := mtlsMiddleware.Authenticate()

	agentCertMiddleware := middleware.NewAgentCertMiddleware(nil, baseLogger, false) // permissive, no DB lookup initially
	agentCert := agentCertMiddleware.Authenticate()

	var jwtAuth gin.HandlerFunc = func(c *gin.Context) { c.Next() } // noop default
	if cfg.JWTKeyOrSecret != "" {
		validator, err := utils.NewJWTValidator(cfg.JWTKeyOrSecret)
		if err != nil {
			logger.WithError(err).Warn("Failed to create JWT validator for SPIRE routes — JWT-protected endpoints will be unavailable")
		} else {
			jwtMiddleware := middleware.NewJWTAuthMiddleware(validator, baseLogger)
			jwtAuth = jwtMiddleware.Authenticate()
		}
	}

	logger.Info("SPIRE sub-module bootstrapped successfully")

	return &Dependencies{
		Health:             healthCtrl,
		NodeAttestation:    nodeAttestCtrl,
		Agent:              agentCtrl,
		Attestation:        attestCtrl,
		Workload:           workloadCtrl,
		Certificate:        certCtrl,
		JWTSVID:            jwtSvidCtrl,
		Bundle:             bundleCtrl,
		PKIAdmin:           pkiAdminCtrl,
		PKIProvisioningSvc: pkiProvSvc,
		WorkloadEntrySvc:   workloadEntrySvc,
		JWTSVIDSvc:         jwtSvidSvc,
		AgentSvc:           agentSvc,
		JWTAuth:            jwtAuth,
		AgentCert:          agentCert,
		MTLSAuth:           mtlsAuth,
		Logger:             logger,
	}, nil
}

func fillDefaults(cfg *BootstrapConfig) {
	if cfg.WorkspaceDBHost == "" {
		cfg.WorkspaceDBHost = getEnv("TENANT_DB_HOST", getEnv("DB_HOST", "localhost"))
	}
	if cfg.WorkspaceDBPort == 0 {
		port, _ := strconv.Atoi(getEnv("TENANT_DB_PORT", getEnv("DB_PORT", "5432")))
		cfg.WorkspaceDBPort = port
	}
	if cfg.WorkspaceDBUsername == "" {
		cfg.WorkspaceDBUsername = getEnv("TENANT_DB_USERNAME", getEnv("DB_USERNAME", "postgres"))
	}
	if cfg.WorkspaceDBPassword == "" {
		cfg.WorkspaceDBPassword = getEnv("TENANT_DB_PASSWORD", getEnv("DB_PASSWORD", ""))
	}
	if cfg.WorkspaceDBSSLMode == "" {
		cfg.WorkspaceDBSSLMode = getEnv("TENANT_DB_SSLMODE", getEnv("DB_SSLMODE", "disable"))
	}
	if cfg.VaultPKIBasePath == "" {
		cfg.VaultPKIBasePath = getEnv("VAULT_PKI_BASE_PATH", "")
	}
	if cfg.VaultCARole == "" {
		cfg.VaultCARole = getEnv("VAULT_CA_ROLE", "")
	}
	if cfg.JWTKeyOrSecret == "" {
		cfg.JWTKeyOrSecret = getEnv("SPIRE_JWT_KEY", getEnv("JWT_SECRET", ""))
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
