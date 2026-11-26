// Package spire provides the merged authsec-spire service as a sub-module
// within the authsec monolith. It registers all SPIRE identity service routes
// under /authsec/spiresvc.
package spire

import (
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/controllers"
	"github.com/authsec-ai/authsec/internal/spire/middleware"
	"github.com/authsec-ai/authsec/internal/spire/services"
	"github.com/authsec-ai/authsec/middlewares"
)

// Dependencies holds all controller and middleware instances needed for routing.
type Dependencies struct {
	// Controllers
	Health          *controllers.HealthController
	NodeAttestation *controllers.NodeAttestationController
	JoinTokens      *controllers.JoinTokenController
	Agent           *controllers.AgentController
	Attestation     *controllers.AttestationController
	Workload        *controllers.WorkloadController
	Certificate     *controllers.CertificateController
	JWTSVID         *controllers.JWTSVIDController
	Bundle          *controllers.BundleController
	PKIAdmin        *controllers.PKIAdminController

	// Services (exposed for injection into existing monolith controllers)
	PKIProvisioningSvc *services.PKIProvisioningService
	WorkloadEntrySvc   *services.WorkloadEntryService
	JWTSVIDSvc         *services.JWTSVIDService
	AgentSvc           *services.AgentService

	// Middleware. AgentCert admits active agents and MTLSAuth any SVID; both
	// take the workspace only from the verified client certificate.
	AgentCert gin.HandlerFunc
	MTLSAuth  gin.HandlerFunc

	Logger *logrus.Entry
}

// RegisterRoutes registers all SPIRE identity service routes on the given router group.
// The caller is expected to pass a group like router.Group("/authsec/spiresvc").
//
// Every route's workspace comes from a verified credential (AS-081):
//   - platform token (middlewares.AuthMiddleware): agents, entries, delegated
//     JWT-SVIDs, join tokens, PKI provisioning; writes need owner/admin;
//   - agent certificate: agent renewal, entries by parent, workload attest/revoke;
//   - any workload/agent certificate: attest, renew, revoke, JWT-SVID issue;
//   - a single-use join token: node attestation;
//   - the presented JWT-SVID's verified issuer: JWT-SVID validate/renew.
//
// Trust bundles are public; the workspace they name is validated.
func RegisterRoutes(rg *gin.RouterGroup, deps *Dependencies) {
	auth := middlewares.AuthMiddleware()
	admin := middlewares.RequireWorkspaceRole("owner", "admin")

	// ── Public ──
	rg.GET("/health", deps.Health.Health)
	rg.POST("/v1/node/attest", middleware.BootstrapLimiter.Middleware(), deps.NodeAttestation.Attest)
	rg.GET("/bundle/:tenant", deps.Bundle.GetBundle)
	rg.GET("/v1/jwt/bundle", deps.JWTSVID.GetJWTBundle)
	rg.POST("/v1/jwt/validate", middleware.SensitiveLimiter.Middleware(), deps.JWTSVID.ValidateJWTSVID)
	rg.POST("/v1/jwt/renew", middleware.SensitiveLimiter.Middleware(), deps.JWTSVID.RenewJWTSVID)

	// ── Workspace admin (platform token, owner/admin) ──
	rg.POST("/admin/pki/provision", middleware.SensitiveLimiter.Middleware(), auth, admin, deps.PKIAdmin.ProvisionPKI)
	rg.POST("/admin/pki/provision/:workspace_id", middleware.SensitiveLimiter.Middleware(), auth, admin, deps.PKIAdmin.ProvisionPKI)
	joinTokens := rg.Group("/v1/join-tokens", auth, admin)
	{
		joinTokens.POST("", deps.JoinTokens.Create)
		joinTokens.GET("", deps.JoinTokens.List)
		joinTokens.DELETE("/:id", deps.JoinTokens.Revoke)
	}

	// ── Agent certificate ──
	agentGroup := rg.Group("/v1", deps.AgentCert, middleware.StandardLimiter.Middleware())
	{
		agentGroup.POST("/agent/renew", deps.Agent.RenewAgent)
		agentGroup.GET("/entries/by-parent", deps.Workload.ListEntriesByParent)
		agentGroup.POST("/workload/attest", deps.Workload.AttestWorkload)
		agentGroup.POST("/workload/revoke", deps.Workload.RevokeWorkloadSVID)
	}

	// ── Platform token (admin / user-flow UI) ──
	jwtGroup := rg.Group("/v1", auth)
	{
		jwtGroup.GET("/agents", deps.Agent.ListAgents)
		jwtGroup.GET("/entries", deps.Workload.ListEntries)
		jwtGroup.GET("/entries/:id", deps.Workload.GetEntry)

		jwtGroup.POST("/entries", admin, deps.Workload.CreateEntry)
		jwtGroup.PUT("/entries/:id", admin, deps.Workload.UpdateEntry)
		jwtGroup.DELETE("/entries/:id", admin, deps.Workload.DeleteEntry)
		jwtGroup.POST("/entries/agent", admin, deps.Workload.CreateAgentEntry)
		jwtGroup.POST("/jwt/issue-delegated", admin, deps.JWTSVID.IssueDelegatedJWTSVID)
	}

	// ── Workload / agent certificate (service-to-service mTLS) ──
	mtlsGroup := rg.Group("/v1", deps.MTLSAuth)
	{
		mtlsGroup.POST("/attest", deps.Attestation.Attest)
		mtlsGroup.POST("/renew", deps.Certificate.Renew)
		mtlsGroup.POST("/revoke", deps.Certificate.Revoke)
		mtlsGroup.POST("/jwt/issue", deps.JWTSVID.IssueJWTSVID)
	}

	deps.Logger.Info("SPIRE identity service routes registered under /authsec/spiresvc")
}
