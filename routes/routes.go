// Package routes wires together all HTTP routes for the merged authsec monolith.
//
// All API routes are served under the /authsec prefix:
//
//	/authsec/auth/*          – admin and end-user authentication
//	/authsec/webauthn/*      – WebAuthn/FIDO2 passkey flows
//	/authsec/admin/*         – admin management (tenants, users, RBAC, OIDC, …)
//	/authsec/user/*          – end-user self-service
//	/authsec/oidc/*          – OIDC federation
//	/authsec/scim/v2/*       – SCIM 2.0 provisioning
//	/authsec/health          – health checks
//	/authsec/debug/*         – debug helpers (dev only)
//
// The well-known OAuth/OIDC discovery endpoints remain at the root as required by RFC 8414
// and OpenID Connect Discovery. They are advertised from the canonical OAuth issuer host.
//
//	/.well-known/openid-configuration
//	/.well-known/oauth-authorization-server
//	/oauth/jwks
//
// All merged microservice routes are under /authsec:
//
//	/authsec/uflow/*      – user flow (formerly user-flow)
//	/authsec/webauthn/*   – WebAuthn/passkeys (formerly webauthn-service)
//	/authsec/exsvc/*      – external services (formerly mcp-service/external-service)
//	/authsec/hmgr/*       – Hydra manager (formerly hydra-service)
//	/authsec/oocmgr/*     – OIDC config manager (formerly oath_oidc_configuration_manager)
//	/authsec/authz/*      – canonical authorization and RBAC surface
//	/authsec/auth/token/* – token helper endpoints
package routes

import (
	"log"
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/config"
	adminCtrl "github.com/authsec-ai/authsec/controllers/admin"
	userCtrl "github.com/authsec-ai/authsec/controllers/enduser"
	platformCtrl "github.com/authsec-ai/authsec/controllers/platform"
	sharedCtrl "github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/handlers"
	"github.com/authsec-ai/authsec/internal/spire"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// SetupRoutes registers all HTTP routes on the provided Gin engine.
// It accepts the initialised WebAuthn handler structs so the caller
// (main.go) controls their lifecycle.
func SetupRoutes(
	r *gin.Engine,
	webAuthnHandler *handlers.WebAuthnHandler,
	adminWebAuthnHandler *handlers.AdminWebAuthnHandler,
	endUserWebAuthnHandler *handlers.EndUserWebAuthnHandler,
	spireDeps *spire.Dependencies,
) {
	// ────────────────────────────────────────────────────────
	// CORS is already applied by the caller (main.go)
	// ────────────────────────────────────────────────────────

	// ────────────────────────────────────────────────────────
	// Initialise controllers
	// ────────────────────────────────────────────────────────
	userController, err := adminCtrl.NewUserController()
	if err != nil {
		log.Fatalf("Failed to initialize user controller: %v", err)
	}
	adminAuthController, err := adminCtrl.NewAdminAuthController()
	if err != nil {
		log.Fatalf("Failed to initialize admin auth controller: %v", err)
	}
	adminUserController, err := adminCtrl.NewAdminUserController()
	if err != nil {
		log.Fatalf("Failed to initialize admin user controller: %v", err)
	}
	endUserAuthController, err := userCtrl.NewEndUserAuthController()
	if err != nil {
		log.Fatalf("Failed to initialize end-user auth controller: %v", err)
	}
	// Scoped RBAC Controllers
	rolesScopedBindingsController := adminCtrl.NewRolesScopedBindingsController()
	serviceAccountsController := adminCtrl.NewServiceAccountsController()
	authController := platformCtrl.NewAuthorizationController()
	permissionController := adminCtrl.NewPermissionController()

	// AI Agent Delegation controllers
	agentController := adminCtrl.NewAgentController()
	delegationPolicyController := adminCtrl.NewDelegationPolicyController()
	sdkTokenController := adminCtrl.NewSDKTokenController()

	// Phase A: tenant memberships & end-user states
	membershipController := adminCtrl.NewMembershipController()

	// Legacy / existing controllers
	groupController := &adminCtrl.GroupController{}
	endUserController := &userCtrl.EndUserController{}
	adSyncController := &sharedCtrl.ADSyncController{}
	entraIDController := &sharedCtrl.EntraIDController{}
	syncConfigController := &adminCtrl.SyncConfigController{}
	healthController := &sharedCtrl.HealthController{}
	adminInviteController, err := adminCtrl.NewAdminInviteController()
	if err != nil {
		log.Fatalf("Failed to initialize admin invite controller: %v", err)
	}

	domainController := adminCtrl.NewDomainController(config.GetDatabase())
	hubspotController := platformCtrl.NewHubSpotController()

	scimController := &platformCtrl.SCIMController{}
	scimAdminController, err := adminCtrl.NewSCIMAdminController()
	if err != nil {
		log.Fatalf("Failed to initialize SCIM admin controller: %v", err)
	}

	oidcController, err := platformCtrl.NewOIDCController()
	if err != nil {
		log.Fatalf("Failed to initialize OIDC controller: %v", err)
	}
	adminSyncController, err := adminCtrl.NewAdminSyncController()
	if err != nil {
		log.Fatalf("Failed to initialize admin sync controller: %v", err)
	}

	deviceAuthController, err := userCtrl.NewDeviceAuthController()
	if err != nil {
		log.Fatalf("Failed to initialize device auth controller: %v", err)
	}

	voiceAuthController, err := userCtrl.NewVoiceAuthController()
	if err != nil {
		log.Fatalf("Failed to initialize voice auth controller: %v", err)
	}

	totpController, err := userCtrl.NewTOTPController()
	if err != nil {
		log.Fatalf("Failed to initialize TOTP controller: %v", err)
	}

	cibaAuthController, err := userCtrl.NewCIBAAuthController()
	if err != nil {
		log.Fatalf("Failed to initialize CIBA auth controller: %v", err)
	}

	workspaceCIBAController, err := userCtrl.NewTenantCIBAController()
	if err != nil {
		log.Fatalf("Failed to initialize tenant CIBA auth controller: %v", err)
	}

	// Initialize Agent Action Guard controller (human-in-the-loop approvals)
	agentActionController, err := platformCtrl.NewAgentActionController()
	if err != nil {
		log.Fatalf("Failed to initialize agent action controller: %v", err)
	}

	workspaceTOTPController := userCtrl.NewTenantTOTPController()

	spiffeDelegateController, err := platformCtrl.NewSpiffeDelegateController()
	if err != nil {
		log.Fatalf("Failed to initialize SPIFFE delegate controller: %v", err)
	}

	delegationPolicyCtrl := platformCtrl.NewDelegationPolicyController()
	sdkTokenCtrl := platformCtrl.NewSDKTokenController()
	forbiddenLegacyRBACMutation := func(c *gin.Context) {
		c.JSON(http.StatusForbidden, gin.H{
			"error":   "forbidden",
			"message": "RBAC mutations are restricted to operator/admin APIs. Use /authsec/uflow/admin or the Application access APIs.",
		})
	}

	// ── Inject merged SPIRE services into controllers that need them ──
	if spireDeps != nil {
		// Agent controller (admin). The platform agent controller was unrouted
		// dead code (RESIDUAL #40) and has been removed.
		agentController.SetJWTSVIDService(spireDeps.JWTSVIDSvc)

		// Delegation policy controllers (admin + platform)
		delegationPolicyController.SetServices(spireDeps.WorkloadEntrySvc, spireDeps.JWTSVIDSvc, spireDeps.AgentSvc)
		delegationPolicyCtrl.SetServices(spireDeps.WorkloadEntrySvc, spireDeps.JWTSVIDSvc, spireDeps.AgentSvc)

		// PKI provisioning — inject into tenant + OIDC controllers
		if spireDeps.PKIProvisioningSvc != nil {
			userController.SetPKIService(spireDeps.PKIProvisioningSvc)
			oidcController.SetPKIService(spireDeps.PKIProvisioningSvc)
		}
	}

	// Catch-all OPTIONS handler so CORS preflight requests are answered for every
	// path regardless of which method-specific route is registered.
	r.OPTIONS("/*path", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	// ════════════════════════════════════════════════════════
	// MCP OAuth Authorization Server (global endpoints)
	// RFC 8414 AS Metadata + OAuth endpoints at root level
	// ════════════════════════════════════════════════════════
	oauthASController := platformCtrl.NewOAuthASController()
	rsController := platformCtrl.NewResourceServerController()
	scopeMatrixController := platformCtrl.NewScopeMatrixController()
	workspaceController := platformCtrl.NewWorkspaceController()
	applicationsController := platformCtrl.NewApplicationsController()
	trustedIssuersController := platformCtrl.NewTrustedIssuersController()
	a2aBrokeringController := platformCtrl.NewA2ABrokeringController()
	workloadProvidersController := platformCtrl.NewWorkloadIdentityProvidersController()
	scimConnectionsController := adminCtrl.NewSCIMConnectionsController()
	identityProvidersController := adminCtrl.NewIdentityProvidersController()
	applicationIDPPoliciesController := adminCtrl.NewApplicationIDPPoliciesController()

	// RFC 8414 — AS Metadata discovery (must be at root)
	r.GET("/.well-known/oauth-authorization-server", oauthASController.CanonicalIssuerOnly(), oauthASController.ASMetadata)
	// OpenID Connect Discovery 1.0 — same superset metadata
	r.GET("/.well-known/openid-configuration", oauthASController.CanonicalIssuerOnly(), oauthASController.OIDCDiscovery)

	// Global OAuth + OIDC endpoints (unauthenticated — the OAuth flow itself handles authz)
	oauth := r.Group("/oauth")
	oauth.Use(oauthASController.CanonicalIssuerOnly())
	{
		oauth.GET("/authorize", middlewares.StrictAuthRateLimitMiddleware(30, time.Minute), oauthASController.Authorize)
		oauth.POST("/token", middlewares.StrictAuthRateLimitMiddleware(30, time.Minute), oauthASController.Token)
		oauth.POST("/register", middlewares.StrictAuthRateLimitMiddleware(10, time.Minute), oauthASController.Register)
		// RFC 7592 — Client Registration Management endpoints (self-service via registration_access_token)
		oauth.GET("/register/:client_id", oauthASController.RFC7592Get)
		oauth.PUT("/register/:client_id", oauthASController.RFC7592Put)
		oauth.DELETE("/register/:client_id", oauthASController.RFC7592Delete)
		oauth.POST("/introspect", middlewares.StrictAuthRateLimitMiddleware(60, time.Minute), oauthASController.Introspect)
		oauth.GET("/jwks", oauthASController.JWKS)
		oauth.POST("/revoke", oauthASController.Revoke)
		// OIDC endpoints
		oauth.GET("/userinfo", oauthASController.Userinfo)
		oauth.POST("/userinfo", oauthASController.Userinfo)
		oauth.GET("/logout", oauthASController.EndSession)
		// RFC 9126 — Pushed Authorization Request (public)
		oauth.POST("/par", oauthASController.PAR)
		// XAA access-request status poll (Journey B — no auth, capability by ID)
		oauth.GET("/access-requests/:id", oauthASController.AccessRequestStatus)
		// Requester SDK bootstrap (client-authenticated; XAA_ISSUANCE flag gates it).
		// Returns the list of approved RS targets + recommended flow for the SDK.
		// POST is preferred: clients using private_key_jwt put the client_assertion
		// in the request body, never the query string (query-string JWTs leak into
		// access logs, proxies, and browser history). GET remains for clients that
		// authenticate with a header credential (client_secret_basic / Bearer).
		oauth.GET("/requester-bootstrap", oauthASController.RequesterBootstrap)
		oauth.POST("/requester-bootstrap", oauthASController.RequesterBootstrap)
		// OIDC CIBA backchannel authorization (client-authenticated; XAA_CIBA gates it).
		// The ciba grant poll rides /oauth/token (urn:openid:params:grant-type:ciba).
		// Rate-limited like the other client-auth endpoints — each call fans out a
		// push notification, so it must not be cheaply spammable.
		oauth.POST("/bc-authorize", middlewares.StrictAuthRateLimitMiddleware(30, time.Minute), oauthASController.BackchannelAuthorize)
		// Consent grant management (user self-service, authenticated)
		oauthSelfService := oauth.Group("")
		oauthSelfService.Use(middlewares.AuthMiddleware())
		{
			oauthSelfService.GET("/consent-grants", oauthASController.ListUserConsentGrants)
			oauthSelfService.DELETE("/consent-grants/:id", oauthASController.RevokeUserConsentGrant)
		}
	}

	// ════════════════════════════════════════════════════════
	// AGENTIC IGA — /api/iga/v1
	// ════════════════════════════════════════════════════════
	// ADDITIVE. This sits alongside the existing /authsec/discovery/* surface
	// (Kubernetes sightings, claim/quarantine, coverage) and changes none of
	// it. Different prefix, different tables (iga_*), different permissions
	// (iga:*), so nothing in the working discovery path can be affected.
	//
	// The authenticated workspace is established by AuthMiddleware and is never
	// read from a body, query parameter or provider identifier.
	{
		igaController := platformCtrl.NewIGAController(config.DB)

		// Provider ingress. Unauthenticated at the TOKEN layer only — GitHub
		// holds no AuthSec token — but authenticated by HMAC signature over the
		// raw body, with the workspace resolved server-side from the verified
		// binding. Registered outside the authenticated group so it cannot
		// inherit AuthMiddleware.
		r.POST("/api/iga/v1/webhooks/github/:app_registration_id", igaController.ReceiveWebhook)

		iga := r.Group("/api/iga/v1")
		iga.Use(middlewares.AuthMiddleware())
		{
			// Connect and authorize.
			iga.POST("/integrations", middlewares.Require("iga", "admin"), igaController.CreateIntegration)
			iga.GET("/integrations", middlewares.Require("iga", "read"), igaController.ListIntegrations)
			iga.GET("/integrations/:integration_id", middlewares.Require("iga", "read"), igaController.GetIntegration)
			// Verification turns an untrusted installation id into a trusted
			// binding; it is an admin action and it is audited.
			iga.POST("/integrations/:integration_id/verify", middlewares.Require("iga", "admin"), igaController.VerifyIntegration)
			iga.POST("/integrations/:integration_id/disconnect", middlewares.Require("iga", "admin"), igaController.DisconnectIntegration)

			// Enumerate.
			iga.POST("/integrations/:integration_id/scans", middlewares.Require("iga", "admin"), igaController.CreateScan)
			iga.GET("/scan-runs/:scan_id", middlewares.Require("iga", "read"), igaController.GetScanRun)

			// Coverage and source health are separate surfaces on purpose: a
			// scan failure is an operational issue, not an agent-risk finding.
			iga.GET("/integrations/:integration_id/coverage", middlewares.Require("iga", "read"), igaController.GetCoverage)
			iga.GET("/integrations/:integration_id/source-health", middlewares.Require("iga", "read"), igaController.GetSourceHealth)

			// Inventory. Confirmed agents, candidates and identities are
			// DIFFERENT routes with different counts.
			iga.GET("/agents", middlewares.Require("iga", "read"), igaController.ListAgents)
			iga.GET("/agents/:agent_id", middlewares.Require("iga", "read"), igaController.GetAgent)
			iga.GET("/agents/:agent_id/evidence", middlewares.Require("iga", "read"), igaController.GetAgentEvidence)
			iga.GET("/agents/:agent_id/access-paths", middlewares.Require("iga", "read"), igaController.GetAgentAccessPaths)
			iga.GET("/identity-accounts", middlewares.Require("iga", "read"), igaController.ListIdentityAccounts)
			iga.GET("/classification-candidates", middlewares.Require("iga", "review"), igaController.ListCandidates)

			// Governance decisions. Both require an expected version, so a
			// stale decision is rejected rather than last-write-wins.
			iga.POST("/classification-candidates/:candidate_id/decisions", middlewares.Require("iga", "review"), igaController.DecideCandidate)
			iga.POST("/ownership-candidates/:candidate_id/decisions", middlewares.Require("iga", "review"), igaController.DecideOwnership)
		}
	}

	// ════════════════════════════════════════════════════════
	// ALL ROUTES UNDER /authsec
	// ════════════════════════════════════════════════════════
	authsec := r.Group("/authsec")
	{
		workspaces := authsec.Group("/workspaces")
		workspaces.Use(middlewares.AuthMiddleware())
		{
			workspaces.POST("/:workspace_id/switch", workspaceController.SwitchWorkspace)
		}

		// ────────────────────────────────────────────────────────
		// Resource Server admin API (authenticated)
		// ────────────────────────────────────────────────────────
		// Scope preset catalog (read-only, no tenant scoping — same 12 for everyone).
		// Surfaced on the Create Application page.
		scopePresets := authsec.Group("/scope-presets")
		scopePresets.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			scopePresets.GET("", rsController.ScopePresets)
		}

		resourceServers := authsec.Group("/resource-servers")
		resourceServers.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			resourceServers.POST("", rsController.Create)
			resourceServers.GET("", rsController.List)
			resourceServers.GET("/:id", rsController.Get)
			resourceServers.PUT("/:id", rsController.Update)
			resourceServers.DELETE("/:id", rsController.Delete)
			resourceServers.POST("/:id/rotate-introspection-secret", rsController.RotateIntrospectionSecret)
			// Prereg admin (Bug 9)
			resourceServers.POST("/:id/clients", rsController.PreRegisterClient)
			resourceServers.GET("/:id/clients", rsController.ListClients)
			resourceServers.DELETE("/:id/clients/:client_id", rsController.RevokeClient)
			// CIMD redirect approval (Bug 10)
			resourceServers.PUT("/:id/clients/:client_id/approve-redirects", rsController.ApproveRedirects)
			resourceServers.GET("/:id/access-policy", rsController.GetAccessPolicy)
			resourceServers.PUT("/:id/access-policy", rsController.UpdateAccessPolicy)
			resourceServers.POST("/:id/validate", rsController.Validate)

			// Scope matrix, tool discovery, and scope management
			resourceServers.GET("/:id/scope-matrix", scopeMatrixController.GetScopeMatrix)
			resourceServers.POST("/:id/rescan", scopeMatrixController.Rescan)
			resourceServers.GET("/:id/scopes", scopeMatrixController.ListScopes)
			resourceServers.POST("/:id/scopes", scopeMatrixController.CreateScope)
			resourceServers.PUT("/:id/tool-scope-map", scopeMatrixController.UpdateToolScopeMap)
			resourceServers.GET("/:id/scope-resolution-preview", scopeMatrixController.ScopeResolutionPreview)

			// Setup wizard endpoints (JWT auth)
			resourceServers.GET("/:id/setup", scopeMatrixController.SetupChecklist)
			resourceServers.GET("/:id/activation-preview", scopeMatrixController.ActivationPreview)
			resourceServers.POST("/:id/activate", scopeMatrixController.Activate)
			resourceServers.POST("/:id/tools", scopeMatrixController.CreateManualTool)
			resourceServers.POST("/:id/tools/:tool_id/public", scopeMatrixController.MarkToolPublic)
			resourceServers.GET("/:id/sdk-manifest-status", scopeMatrixController.SDKManifestStatus)
			resourceServers.GET("/:id/drift-events", scopeMatrixController.DriftEvents)
			resourceServers.POST("/:id/drift-events/:event_id/dismiss", scopeMatrixController.DismissDriftEvent)
			resourceServers.POST("/:id/test-login", rsController.TestLogin)

			// RS-scoped roles + bindings management
			resourceServers.GET("/:id/roles", scopeMatrixController.ListRSRoles)
			resourceServers.PUT("/:id/roles/:role_id/scope-grants", scopeMatrixController.UpdateRSRoleScopeGrants)
			resourceServers.GET("/:id/bindings", scopeMatrixController.ListRSBindings)
			resourceServers.POST("/:id/bindings", scopeMatrixController.CreateRSBinding)
			resourceServers.DELETE("/:id/bindings/:binding_id", scopeMatrixController.DeleteRSBinding)
			resourceServers.GET("/:id/eligible-users", scopeMatrixController.ListRSEndUsers)
		}

		// SDK endpoints (Basic auth with RS introspection credentials — no JWT middleware)
		authsec.GET("/resource-servers/:id/sdk-policy", scopeMatrixController.SDKPolicy)
		authsec.PUT("/resource-servers/:id/sdk-manifest", scopeMatrixController.PutSDKManifest)

		// ────────────────────────────────────────────────────────
		// Applications facade — preferred read/write surface.
		// /authsec/applications is the new product-level API on top of the
		// resource_servers physical table. The /resource-servers group above
		// remains as a compatibility shim until SDK callers have migrated.
		// Subresources without product-vs-protocol rename (tools, scopes,
		// access-policy, validate, drift events, RS roles/bindings) are mounted
		// at the same paths using the existing controllers — they're agnostic
		// to the URL prefix.
		// ────────────────────────────────────────────────────────
		applications := authsec.Group("/applications")
		applications.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			applications.POST("", applicationsController.Create)
			applications.GET("", applicationsController.List)
			applications.GET("/:id", applicationsController.Get)
			applications.PUT("/:id", applicationsController.Update)
			applications.DELETE("/:id", applicationsController.Delete)
			applications.POST("/:id/rotate-introspection-secret", rsController.RotateIntrospectionSecret)

			// OAuth client registrations — "connections" in product vocabulary.
			applications.POST("/:id/connections", rsController.PreRegisterClient)
			applications.GET("/:id/connections", applicationsController.ListConnections)
			applications.DELETE("/:id/connections/:connection_id", applicationsController.RevokeConnection)
			applications.PUT("/:id/connections/:connection_id/approve", applicationsController.ApproveConnection)
			applications.PUT("/:id/connections/:connection_id/deny", applicationsController.DenyConnection)

			// Access policy + validate + access surface
			applications.GET("/:id/access-policy", rsController.GetAccessPolicy)
			applications.PUT("/:id/access-policy", rsController.UpdateAccessPolicy)
			applications.GET("/:id/access", rsController.GetAccessPolicy) // alias used by the new UI
			applications.POST("/:id/validate", rsController.Validate)
			applications.POST("/:id/prm-override", applicationsController.SetPRMOverride)
			applications.POST("/:id/test", rsController.TestLogin)
			applications.POST("/:id/launch", applicationsController.Launch)

			// Scope matrix + tools (shared with /resource-servers)
			applications.GET("/:id/scope-matrix", scopeMatrixController.GetScopeMatrix)
			applications.POST("/:id/rescan", scopeMatrixController.Rescan)
			applications.GET("/:id/scopes", scopeMatrixController.ListScopes)
			applications.POST("/:id/scopes", scopeMatrixController.CreateScope)
			applications.PUT("/:id/tool-scope-map", scopeMatrixController.UpdateToolScopeMap)
			applications.GET("/:id/scope-resolution-preview", scopeMatrixController.ScopeResolutionPreview)
			applications.GET("/:id/tools", scopeMatrixController.GetScopeMatrix) // tools view; consolidated with matrix for now
			applications.POST("/:id/tools", scopeMatrixController.CreateManualTool)
			applications.POST("/:id/tools/:tool_id/public", scopeMatrixController.MarkToolPublic)

			// Setup wizard, drift, manifest
			applications.GET("/:id/setup", scopeMatrixController.SetupChecklist)
			applications.GET("/:id/activation-preview", scopeMatrixController.ActivationPreview)
			applications.POST("/:id/activate", scopeMatrixController.Activate)
			applications.GET("/:id/sdk-manifest-status", scopeMatrixController.SDKManifestStatus)
			applications.GET("/:id/drift-events", scopeMatrixController.DriftEvents)
			applications.POST("/:id/drift-events/:event_id/dismiss", scopeMatrixController.DismissDriftEvent)

			// RS-scoped roles + bindings management
			applications.GET("/:id/roles", scopeMatrixController.ListRSRoles)
			applications.POST("/:id/roles", scopeMatrixController.CreateApplicationRole)
			applications.PUT("/:id/roles/:role_id/scope-grants", scopeMatrixController.UpdateRSRoleScopeGrants)
			applications.GET("/:id/bindings", scopeMatrixController.ListRSBindings)
			applications.POST("/:id/bindings", scopeMatrixController.CreateRSBinding)
			applications.DELETE("/:id/bindings/:binding_id", scopeMatrixController.DeleteRSBinding)
			applications.GET("/:id/eligible-users", scopeMatrixController.ListRSEndUsers)
			applications.GET("/:id/access/users", scopeMatrixController.ListApplicationAccessUsers)
			applications.GET("/:id/users/:user_id/effective-access", scopeMatrixController.GetApplicationUserEffectiveAccess)

			// Access assignments — union view of user + SA bindings with effective
			// scopes; explicit create/delete paths per identity type.
			applications.GET("/:id/access-assignments", scopeMatrixController.ListAccessAssignments)
			applications.GET("/:id/access-assignments/summary", scopeMatrixController.GetAccessSummary)
			applications.POST("/:id/access-assignments/users", scopeMatrixController.CreateUserAssignment)
			applications.POST("/:id/access-assignments/service-accounts", scopeMatrixController.CreateSAAssignment)
			applications.DELETE("/:id/access-assignments/:assignment_id", scopeMatrixController.DeleteAssignment)

			// Per-app access requests: list pending + approve (binds role to acting
			// user + approves connection atomically) + deny.
			applications.GET("/:id/requests", applicationsController.ListRequests)
			applications.POST("/:id/requests/:rid/approve", applicationsController.ApproveRequest)
			applications.POST("/:id/requests/:rid/deny", applicationsController.DenyRequest)

			// Machine access — create a service account + API credential + role +
			// approved registration in one call; dry-run the resulting mint.
			applications.POST("/:id/machine-access/api-credential", applicationsController.CreateAPICredentialAccess)
			applications.POST("/:id/token-test/simulate", applicationsController.SimulateToken)
			applications.POST("/:id/token-test/simulate-xaa", applicationsController.SimulateXAA)

			// Workload identity (SPIFFE/SVID, K8s-first).
			applications.POST("/:id/machine-access/workload", applicationsController.CreateWorkloadAccess)
			applications.GET("/:id/workloads", applicationsController.ListWorkloads)
			applications.DELETE("/:id/workloads/:wid", applicationsController.RevokeWorkload)
			applications.POST("/:id/workloads/:wid/restore", applicationsController.RestoreWorkload)

			// Grant an EXISTING workload access to this MCP server (role binding +
			// approved registration only — never mints/changes the workload identity).
			applications.POST("/:id/access/workloads", applicationsController.GrantWorkloadAccess)

			// Register a FEDERATED (bring-your-own SPIRE) workload: an external
			// SPIFFE ID from a registered workload_identity_provider, mapped to a
			// confidential spiffe-svid client + rs-scoped role. No identity minting.
			applications.POST("/:id/access/federated-workload", applicationsController.CreateFederatedWorkloadAccess)

			// Application↔IDP policy (optional whitelist; default-allow when empty).
			applications.GET("/:id/identity-providers", applicationIDPPoliciesController.List)
			applications.POST("/:id/identity-providers", applicationIDPPoliciesController.Add)
			applications.DELETE("/:id/identity-providers/:idp_id", applicationIDPPoliciesController.Remove)
		}

		// Workspace-wide OAuth client list (across all applications).
		authsec.GET("/clients",
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
			applicationsController.ListWorkspaceClients,
		)

		// Cross-workspace Connections governance view — admin sees all foreign
		// client registrations + pending access_requests for this workspace.
		authsec.GET("/connections",
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
			applicationsController.ListCrossWorkspaceConnections,
		)

		// Admin native-token revocation by JTI. Workspace-scoped: only tokens
		// that belong to this workspace can be revoked here.
		authsec.DELETE("/tokens/:jti",
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
			applicationsController.RevokeTokenByJTI,
		)

		// Trusted issuers CRUD + test (G7). Issuers are instance-wide but CRUD
		// requires workspace admin JWT.
		trustedIssuers := authsec.Group("/trusted-issuers")
		trustedIssuers.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			trustedIssuers.GET("", trustedIssuersController.List)
			trustedIssuers.POST("", trustedIssuersController.Create)
			trustedIssuers.POST("/test", trustedIssuersController.Test)
			trustedIssuers.DELETE("/:id", trustedIssuersController.Revoke)
		}

		// A2A brokering policies (cross-app permit/deny) — same workspace-admin
		// guard as trusted issuers; the token-endpoint gate already enforces them.
		brokering := authsec.Group("/brokering-policies")
		brokering.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			brokering.GET("", a2aBrokeringController.List)
			brokering.POST("", a2aBrokeringController.Create)
			brokering.DELETE("/:id", a2aBrokeringController.Delete)
		}

		// Workload identity providers (multi-cluster SPIFFE + OIDC/CI federation).
		workloadProviders := authsec.Group("/workload-identity-providers")
		workloadProviders.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			workloadProviders.GET("", workloadProvidersController.List)
			workloadProviders.POST("", workloadProvidersController.Create)
			workloadProviders.DELETE("/:id", workloadProvidersController.Delete)
		}

		// A2A agent registration — mint a confidential authorization_code +
		// token-exchange client in the caller's workspace (self-serve J5).
		agents := authsec.Group("/agents")
		agents.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			agents.POST("", applicationsController.RegisterAgent)
		}

		// v1 IAM cockpit aggregate/read-model aliases. These routes expose the
		// product vocabulary used by the AI/MCP access-control UI while reusing
		// the existing scope matrix, bindings, and runtime resolver backends.
		v1 := authsec.Group("/v1")
		v1.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			v1.GET("/workspaces/:workspace_id/applications/posture-summary", applicationsController.PostureSummary)

			v1Applications := v1.Group("/applications")
			{
				v1Applications.GET("/:id/tool-exposure", scopeMatrixController.GetScopeMatrix)
				v1Applications.GET("/:id/scopes", scopeMatrixController.ListScopes)
				v1Applications.GET("/:id/scopes/:scope_id/impact", scopeMatrixController.ScopeImpact)
				v1Applications.GET("/:id/access-assignments", scopeMatrixController.ListAccessAssignments)
				v1Applications.GET("/:id/end-user-access-summary", scopeMatrixController.ListApplicationAccessUsers)
				v1Applications.GET("/:id/effective-access", scopeMatrixController.GetApplicationUserEffectiveAccessQuery)
				v1Applications.POST("/:id/access-simulations", scopeMatrixController.AccessSimulation)
				v1Applications.POST("/:id/access-change-previews", scopeMatrixController.AccessChangePreview)
				v1Applications.POST("/:id/evidence-exports", scopeMatrixController.EvidenceExport)
			}
		}

		authsec.GET("/application-roles",
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
			scopeMatrixController.ListApplicationRoles,
		)
		authsec.GET("/scope-catalog",
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
			scopeMatrixController.ListScopeCatalog,
		)
		authsec.POST("/scope-catalog",
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
			scopeMatrixController.CreateScopeCatalogEntry,
		)
		authsec.POST("/scope-catalog/:catalog_id/applications/:application_id",
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
			scopeMatrixController.AttachScopeCatalogEntryToApplication,
		)

		// SCIM connection management (mint + revoke). Operators only —
		// returns the plaintext token exactly once on Create. Drives the new
		// /scim/v2/c/:scim_connection_id provisioning route.
		scimConnections := authsec.Group("/scim-connections")
		scimConnections.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			scimConnections.POST("", scimConnectionsController.Create)
			scimConnections.GET("", scimConnectionsController.List)
			scimConnections.DELETE("/:id", scimConnectionsController.Revoke)
			scimConnections.POST("/:id/rotate", scimConnectionsController.Rotate)
			scimConnections.GET("/:id/events", scimConnectionsController.ListEvents)
		}

		// Workspace IDP management. One POST endpoint dispatches on
		// provider_type (oidc | saml) and writes both the underlying provider
		// config and the identity_providers row in one transaction. Workspace
		// owner/admin only.
		idps := authsec.Group("/identity-providers")
		idps.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			idps.POST("", identityProvidersController.Create)
			idps.GET("", identityProvidersController.List)
			idps.GET("/:id", identityProvidersController.Get)
			idps.PUT("/:id", identityProvidersController.Update)
			idps.PUT("/:id/status", identityProvidersController.UpdateStatus)
			idps.DELETE("/:id", identityProvidersController.Delete)
		}

		// Scope management (not RS-scoped)
		scopes := authsec.Group("/scopes")
		scopes.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			scopes.PUT("/:scope_id", scopeMatrixController.UpdateScope)
			scopes.DELETE("/:scope_id", scopeMatrixController.DeleteScope)
		}

		// Admin consent grant management
		consentGrants := authsec.Group("/consent-grants")
		consentGrants.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			consentGrants.GET("", oauthASController.ListConsentGrants)
			consentGrants.DELETE("/:id", oauthASController.RevokeConsentGrant)
		}
		// ────────────────────────────────────────────────────
		// WebAuthn routes  (/authsec/webauthn/*)
		// Served under /authsec/webauthn (formerly webauthn-service).
		// ────────────────────────────────────────────────────
		registerWebAuthnRoutes(authsec.Group("/webauthn"), webAuthnHandler, adminWebAuthnHandler, endUserWebAuthnHandler)

		// ────────────────────────────────────────────────────
		// User Flow (formerly user-flow)
		// Served under /authsec/uflow.
		// ────────────────────────────────────────────────────
		uflow := authsec.Group("/uflow")

		// Device activation page (public)
		uflow.GET("/activate", deviceAuthController.ShowActivationPage)

		// ────────────────────────────────────────────────────
		// API docs
		// ────────────────────────────────────────────────────
		uflow.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
		uflow.GET("/docs", func(c *gin.Context) {
			c.Header("Content-Type", "text/html; charset=utf-8")
			html := `<!DOCTYPE html>
						<html>
						<head>
							<title>AuthSec API Documentation</title>
							<meta charset="utf-8"/>
							<meta name="viewport" content="width=device-width, initial-scale=1">
							<link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
							<style>body { margin: 0; padding: 0; }</style>
						</head>
						<body>
							<redoc spec-url='/authsec/uflow/swagger/doc.json'></redoc>
							<script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
						</body>
						</html>`
			c.String(http.StatusOK, html)
		})
		uflow.GET("/apidocs", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"title":   "AuthSec API",
				"version": "5.0.0",
				"status":  "available",
			})
		})
		uflow.GET("/apidocs/*any", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "API documentation available at /authsec/uflow/docs"})
		})

		// ────────────────────────────────────────────────────
		// Admin RBAC routes
		// ────────────────────────────────────────────────────
		adminRBAC := uflow.Group("/admin")
		adminRBAC.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			adminRBAC.POST("/roles", rolesScopedBindingsController.CreateRoleCompositeAdmin)
			adminRBAC.GET("/roles", rolesScopedBindingsController.ListRolesAdmin)
			adminRBAC.GET("/roles/:role_id", rolesScopedBindingsController.GetRoleAdmin)
			adminRBAC.PUT("/roles/:role_id", rolesScopedBindingsController.UpdateRoleCompositeAdmin)
			adminRBAC.DELETE("/roles/:role_id", rolesScopedBindingsController.DeleteRoleAdmin)
			adminRBAC.POST("/bindings", rolesScopedBindingsController.AssignRoleScopedAdmin)
			adminRBAC.GET("/bindings", rolesScopedBindingsController.ListRoleBindingsAdmin)
			adminRBAC.DELETE("/bindings/:binding_id", rolesScopedBindingsController.DeleteRoleBindingAdmin)
			adminRBAC.POST("/permissions", permissionController.RegisterAtomicPermission)
			adminRBAC.GET("/permissions", permissionController.ListPermissions)
			adminRBAC.DELETE("/permissions/:id", permissionController.DeletePermission)
			adminRBAC.DELETE("/permissions", permissionController.DeletePermissionByBody)
			adminRBAC.GET("/permissions/resources", permissionController.ShowResources)
			adminRBAC.POST("/policy/check", authController.PolicyDecisionPointCheckAdmin)

			// AI Agent Management
			adminRBAC.GET("/agents", agentController.ListAgents)
			adminRBAC.GET("/agents/:id", agentController.GetAgent)
			adminRBAC.GET("/agents/:id/activity", agentController.GetAgentActivity)
			adminRBAC.POST("/agents/:id/provision-identity", agentController.ProvisionIdentity)
			adminRBAC.DELETE("/agents/:id/revoke-identity", agentController.RevokeIdentity)
			adminRBAC.POST("/agents/:id/delegate-token", agentController.DelegateToken)
			adminRBAC.POST("/agents/:id/revoke-token", sdkTokenController.RevokeDelegationToken)

			// Service accounts (Agent Identity Phase 1)
			adminRBAC.POST("/service-accounts", serviceAccountsController.CreateServiceAccount)
			adminRBAC.GET("/service-accounts", serviceAccountsController.ListServiceAccounts)
			adminRBAC.GET("/service-accounts/:sa_id", serviceAccountsController.GetServiceAccount)
			adminRBAC.GET("/service-accounts/:sa_id/access", serviceAccountsController.ListServiceAccountAccess)
			adminRBAC.PUT("/service-accounts/:sa_id", serviceAccountsController.UpdateServiceAccount)
			adminRBAC.DELETE("/service-accounts/:sa_id", serviceAccountsController.DeleteServiceAccount)
			adminRBAC.POST("/service-accounts/:sa_id/credentials", serviceAccountsController.CredentialServiceAccount)
			adminRBAC.POST("/service-accounts/:sa_id/credentials/rotate", serviceAccountsController.RotateCredentialServiceAccount)

			// Admin self-introspection (delegation UI)
			adminRBAC.GET("/me/roles-permissions", delegationPolicyController.GetMyRolesAndPermissions)
		}

		// ────────────────────────────────────────────────────
		// OIDC public endpoints
		// ────────────────────────────────────────────────────
		oidcPublic := uflow.Group("/oidc")
		{
			oidcPublic.GET("/providers", oidcController.GetProviders)
			oidcPublic.POST("/initiate", oidcController.Initiate)
			oidcPublic.POST("/register/initiate", oidcController.InitiateRegistration)
			oidcPublic.POST("/login/initiate", oidcController.InitiateLogin)
			oidcPublic.GET("/callback", oidcController.Callback)
			oidcPublic.POST("/exchange-code", oidcController.ExchangeCode)
			oidcPublic.POST("/complete-registration", oidcController.CompleteRegistration)
			oidcPublic.GET("/check-tenant", oidcController.CheckTenantExists)
			oidcPublic.POST("/auth-url", oidcController.GetAuthURL)
		}

		// Authenticated OIDC endpoints
		oidcAuth := uflow.Group("/oidc")
		oidcAuth.Use(middlewares.AuthMiddleware(), middlewares.ValidateWorkspaceFromToken())
		{
			oidcAuth.POST("/link", oidcController.LinkIdentity)
			oidcAuth.GET("/identities", oidcController.GetLinkedIdentities)
			oidcAuth.DELETE("/unlink/:provider", oidcController.UnlinkIdentity)
		}

		// ────────────────────────────────────────────────────
		// Authentication routes
		// ────────────────────────────────────────────────────
		auth := uflow.Group("/auth")
		{
			notify := auth.Group("/notify")
			notify.Use(middlewares.AuthMiddleware(), middlewares.ValidateWorkspaceFromToken())
			{
				notify.POST("/new-user-registration", endUserController.NotifyOwnerNewRegistration)
			}

			// Admin authentication (strict rate limit: 5 req/min)
			adminAuth := auth.Group("/admin")
			adminAuth.Use(middlewares.StrictAuthRateLimitMiddleware(5, time.Minute))
			{
				adminAuth.GET("/challenge", adminAuthController.GetAuthChallenge)
				adminAuth.POST("/login/precheck", adminAuthController.AdminLoginPrecheck)
				adminAuth.POST("/login/bootstrap", adminAuthController.AdminBootstrap)
				adminAuth.POST("/login/resend-otp", adminAuthController.AdminResendOTP)
				adminAuth.POST("/login", adminAuthController.AdminLogin)
				adminAuth.POST("/register", adminAuthController.AdminRegister)
				adminAuth.POST("/complete-registration", adminAuthController.AdminCompleteRegistration)
				adminAuth.POST("/forgot-password", adminAuthController.AdminForgotPassword)
				adminAuth.POST("/forgot-password/verify-otp", adminAuthController.AdminVerifyOTP)
				adminAuth.POST("/forgot-password/reset", adminAuthController.AdminResetPassword)
			}

			// End-user authentication (strict rate limit: 10 req/min)
			enduserAuth := auth.Group("/enduser")
			enduserAuth.Use(middlewares.StrictAuthRateLimitMiddleware(10, time.Minute))
			{
				enduserAuth.GET("/challenge", endUserAuthController.GetAuthChallenge)
				enduserAuth.POST("/webauthn-callback", endUserAuthController.WebAuthnCallback)
				// /delegate-svid is deprecated: plane C bespoke SVID issuance is
				// being retired in favour of NativeSealer XAA/M2M. Use
				// POST /oauth/token (grant_type=client_credentials or jwt-bearer)
				// with a SPIFFE JWT-SVID client assertion instead.
				enduserAuth.POST("/delegate-svid", func(c *gin.Context) {
					sunset := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
					c.Header("Deprecation", "true")
					c.Header("Sunset", sunset.Format(time.RFC1123))
					c.Header("Link", `</oauth/token>; rel="successor-version"`)
					c.Next()
				}, spiffeDelegateController.DelegateSVID)
			}

			// Device Authorization Grant (RFC 8628)
			deviceAuth := auth.Group("/device")
			{
				deviceAuth.POST("/code", deviceAuthController.RequestDeviceCode)
				deviceAuth.POST("/token", deviceAuthController.PollDeviceToken)
				deviceAuth.GET("/activate/info", deviceAuthController.GetActivationInfo)
				// /verify: public — activation page checks user_code before login
				deviceAuth.POST("/verify", deviceAuthController.VerifyUserCode)
				// /authorize: requires auth — browser posts approval/denial after login
				deviceAuth.POST("/authorize", middlewares.AuthMiddleware(), deviceAuthController.AuthorizeDevice)
				// /authorize-oidc: public — for end-user shield login via OIDC
				// Takes {user_code, oidc_code, state} → exchanges OIDC code for identity → authorizes device
				deviceAuth.POST("/authorize-oidc", deviceAuthController.AuthorizeDeviceWithOIDC)
				// /verify-legacy: old authenticated verify endpoint (backwards compat)
				deviceAuth.POST("/verify-legacy", middlewares.AuthMiddleware(), deviceAuthController.VerifyDeviceCode)
			}

			// Voice Authentication
			voiceAuth := auth.Group("/voice")
			{
				voiceAuth.POST("/initiate", voiceAuthController.InitiateVoiceAuth)
				voiceAuth.POST("/verify", voiceAuthController.VerifyVoiceOTP)
				voiceAuth.POST("/token", voiceAuthController.GetTokenWithCredentials)
				voiceAuth.POST("/link", middlewares.AuthMiddleware(), voiceAuthController.LinkVoiceAssistant)
				voiceAuth.POST("/unlink", middlewares.AuthMiddleware(), voiceAuthController.UnlinkVoiceAssistant)
				voiceAuth.GET("/links", middlewares.AuthMiddleware(), voiceAuthController.ListVoiceLinks)
				voiceAuth.GET("/device-pending", middlewares.AuthMiddleware(), voiceAuthController.GetPendingDeviceCodes)
				voiceAuth.POST("/device-approve", middlewares.AuthMiddleware(), voiceAuthController.ApproveDeviceCode)
			}

			// TOTP
			totp := auth.Group("/totp")
			{
				totp.POST("/login", totpController.LoginWithTOTP)
				totp.POST("/device-approve", totpController.ApproveDeviceCodeWithTOTP)
				totp.POST("/register", middlewares.AuthMiddleware(), totpController.RegisterDevice)
				totp.POST("/confirm", middlewares.AuthMiddleware(), totpController.ConfirmRegistration)
				totp.POST("/verify", middlewares.AuthMiddleware(), totpController.VerifyTOTP)
				totp.GET("/devices", middlewares.AuthMiddleware(), totpController.GetUserDevices)
				totp.POST("/device/delete", middlewares.AuthMiddleware(), totpController.DeleteDevice)
				totp.POST("/device/primary", middlewares.AuthMiddleware(), totpController.SetPrimaryDevice)
				totp.POST("/backup/regenerate", middlewares.AuthMiddleware(), totpController.RegenerateBackupCodes)
			}

			// CIBA (user-plane — deprecated; migrate to /auth/workspace/ciba)
			// Emits Deprecation + Sunset headers per RFC 8594 and the Phase 4d plan.
			// The HMAC token path stays intact for middlewares/auth.go consumers.
			ciba := auth.Group("/ciba")
			ciba.Use(func(c *gin.Context) {
				sunset := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
				c.Header("Deprecation", "true")
				c.Header("Sunset", sunset.Format(time.RFC1123))
				c.Header("Link", `</authsec/uflow/auth/workspace/ciba>; rel="successor-version"`)
				c.Next()
			})
			{
				ciba.POST("/initiate", cibaAuthController.InitiateCIBAAuth)
				ciba.POST("/token", cibaAuthController.PollCIBAToken)
				ciba.POST("/respond", middlewares.AuthMiddleware(), cibaAuthController.RespondToCIBA)
				ciba.POST("/register-device", middlewares.AuthMiddleware(), cibaAuthController.RegisterDevice)
				ciba.GET("/devices", middlewares.AuthMiddleware(), cibaAuthController.GetDevices)
				ciba.DELETE("/devices/:device_id", middlewares.AuthMiddleware(), cibaAuthController.DeleteDevice)
			}
		}

		// ────────────────────────────────────────────────────
		// Workspace auth routes (Phase 5/6: renamed from /auth/tenant)
		// ────────────────────────────────────────────────────
		workspaceAuth := uflow.Group("/auth/workspace")
		{
			workspaceCIBA := workspaceAuth.Group("/ciba")
			{
				workspaceCIBA.POST("/initiate", workspaceCIBAController.InitiateTenantCIBA)
				workspaceCIBA.POST("/token", workspaceCIBAController.PollTenantCIBAToken)
				workspaceCIBA.POST("/respond", middlewares.AuthMiddleware(), middlewares.ValidateWorkspaceFromToken(), workspaceCIBAController.RespondToTenantCIBA)
				workspaceCIBA.POST("/register-device", middlewares.AuthMiddleware(), middlewares.ValidateWorkspaceFromToken(), workspaceCIBAController.RegisterTenantDevice)
				workspaceCIBA.GET("/requests", middlewares.AuthMiddleware(), middlewares.ValidateWorkspaceFromToken(), workspaceCIBAController.GetTenantCIBARequests)
				workspaceCIBA.GET("/devices", middlewares.AuthMiddleware(), middlewares.ValidateWorkspaceFromToken(), workspaceCIBAController.ListTenantDevices)
				workspaceCIBA.DELETE("/devices/:device_id", middlewares.AuthMiddleware(), middlewares.ValidateWorkspaceFromToken(), workspaceCIBAController.DeleteTenantDevice)
			}

			workspaceTOTP := workspaceAuth.Group("/totp")
			{
				workspaceTOTP.POST("/login", workspaceTOTPController.LoginWithTenantTOTP)
				workspaceTOTP.POST("/register", middlewares.AuthMiddleware(), middlewares.ValidateWorkspaceFromToken(), workspaceTOTPController.RegisterTenantTOTPDevice)
				workspaceTOTP.POST("/confirm", middlewares.AuthMiddleware(), middlewares.ValidateWorkspaceFromToken(), workspaceTOTPController.ConfirmTenantTOTPDevice)
				workspaceTOTP.GET("/devices", middlewares.AuthMiddleware(), middlewares.ValidateWorkspaceFromToken(), workspaceTOTPController.GetTenantTOTPDevices)
				workspaceTOTP.POST("/devices/delete", middlewares.AuthMiddleware(), middlewares.ValidateWorkspaceFromToken(), workspaceTOTPController.DeleteTenantTOTPDevice)
				workspaceTOTP.POST("/devices/primary", middlewares.AuthMiddleware(), middlewares.ValidateWorkspaceFromToken(), workspaceTOTPController.SetTenantPrimaryTOTPDevice)
			}
		}

		// ────────────────────────────────────────────────────
		// Admin management routes
		// ────────────────────────────────────────────────────
		admin := uflow.Group("/admin")
		admin.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			admin.GET("/tenants", adminUserController.ListTenants)
			admin.POST("/tenants", adminUserController.CreateTenant)
			admin.PUT("/tenants/:workspace_id", adminUserController.UpdateTenant)
			admin.DELETE("/tenants/:workspace_id", middlewares.Require("tenants", "delete"), adminUserController.DeleteTenant)
			admin.GET("/tenants/:workspace_id/users", adminUserController.GetTenantUsers)
			admin.GET("/users/list", adminUserController.ListAdminUsers)
			admin.POST("/users/list", adminUserController.ListAdminUsers)
			admin.DELETE("/users/:user_id", middlewares.Require("users", "delete"), adminUserController.DeleteAdminUser)
			admin.DELETE("/users/delete_all/:user_id", middlewares.Require("users", "delete"), adminUserController.DeleteAdminUserAll)
			admin.POST("/enduser/list", adminUserController.ListEndUsersByTenant)
			admin.POST("/invite", adminInviteController.InviteAdmin)
			admin.POST("/invite/cancel", adminInviteController.CancelInvite)
			admin.POST("/invite/resend", adminInviteController.ResendInvite)
			admin.GET("/invite/pending", adminInviteController.ListPendingInvites)

			adminDomains := admin.Group("/tenants/:workspace_id/domains")
			adminDomains.Use(middlewares.ExtractTenantFromPath())
			{
				adminDomains.POST("", domainController.CreateDomain)
				adminDomains.GET("", domainController.ListDomains)
				adminDomains.POST("/:domain_id/verify", domainController.VerifyDomain)
				adminDomains.POST("/:domain_id/set-primary", domainController.SetPrimaryDomain)
				adminDomains.GET("/:domain_id", domainController.GetDomainByID)
				adminDomains.DELETE("/:domain_id", domainController.DeleteDomain)
			}
		}

		// Platform admin routes
		adminPlatform := uflow.Group("/admin")
		adminPlatform.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			adminPlatform.GET("/oidc/providers", oidcController.GetAllProviders)
			adminPlatform.PUT("/oidc/providers/:provider", oidcController.UpdateProvider)
			adminPlatform.POST("/users/active", adminUserController.ToggleAdminUserActive)
			adminPlatform.POST("/groups", groupController.AddUserDefinedGroups)
			adminPlatform.POST("/groups/map", groupController.MapGroupsToClient)
			adminPlatform.POST("/groups/list", groupController.ListTenantGroupsForAdmin)
			adminPlatform.DELETE("/groups/map", groupController.RemoveGroupsFromClient)
			adminPlatform.GET("/groups/:workspace_id", groupController.GetUserDefinedGroups)
			adminPlatform.PUT("/groups/:id", groupController.UpdateUserDefinedGroup)
			adminPlatform.DELETE("/groups", groupController.DeleteUserDefinedGroups)
			adminPlatform.POST("/groups/:workspace_id/users/bulk", groupController.AddUsersToGroup)
			adminPlatform.DELETE("/groups/:workspace_id/users/bulk", groupController.RemoveUsersFromGroup)
			adminPlatform.POST("/enduser/active", adminUserController.ToggleEndUserActive)
			adminPlatform.POST("/ad/sync", adSyncController.SyncADUsers)
			adminPlatform.POST("/ad/test-connection", adSyncController.TestADConnection)
			adminPlatform.POST("/ad/test-network", adSyncController.TestNetworkConnection)
			adminPlatform.POST("/ad/agent-sync", adSyncController.AgentSyncUsers)
			adminPlatform.POST("/entra/sync", entraIDController.SyncEntraIDUsers)
			adminPlatform.POST("/entra/test-connection", entraIDController.TestEntraIDConnection)
			adminPlatform.POST("/entra/check-permissions", entraIDController.GetEntraIDPermissions)
			adminPlatform.POST("/sync-configs/create", syncConfigController.CreateSyncConfig)
			adminPlatform.POST("/sync-configs/list", syncConfigController.ListSyncConfigs)
			adminPlatform.POST("/sync-configs/update", syncConfigController.UpdateSyncConfig)
			adminPlatform.POST("/sync-configs/delete", syncConfigController.DeleteSyncConfig)
			adminPlatform.GET("/sync-configs/:id/runs", syncConfigController.ListSyncRuns)
			adminPlatform.POST("/admin-users/ad/sync", adminSyncController.SyncADAdminUsers)
			adminPlatform.POST("/admin-users/entra/sync", adminSyncController.SyncEntraAdminUsers)
		}

		// SCIM token
		scimToken := uflow.Group("/admin/scim")
		scimToken.Use(middlewares.AuthMiddleware(), middlewares.ValidateWorkspaceFromToken())
		{
			scimToken.POST("/generate-token", scimController.GenerateSCIMToken)
		}

		// ────────────────────────────────────────────────────
		// Phase A v2: Tenant Memberships, End-User States, Effective Access
		// New, object-first endpoints. The legacy /admin/* endpoints stay in
		// place for backward compatibility; the UI rewrite layer points new
		// pages at /v2/* and gradually drains the old ones.
		// ────────────────────────────────────────────────────
		v2 := uflow.Group("/v2")
		v2.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			// Tenant memberships (operators)
			v2.GET("/tenants/:workspace_id/memberships", membershipController.ListMembers)
			v2.POST("/tenants/:workspace_id/memberships", membershipController.CreateMembership)
			v2.GET("/tenants/:workspace_id/memberships/:user_id", membershipController.GetMembership)
			v2.PATCH("/tenants/:workspace_id/memberships/:user_id", membershipController.UpdateMembership)
			v2.DELETE("/tenants/:workspace_id/memberships/:user_id", membershipController.DeleteMembership)

			// Tenant end-user states (consumers)
			v2.GET("/tenants/:workspace_id/end-users", membershipController.ListEndUsers)
			v2.GET("/tenants/:workspace_id/end-users/:user_id", membershipController.GetEndUser)
			v2.PATCH("/tenants/:workspace_id/end-users/:user_id", membershipController.UpdateEndUser)
			v2.POST("/tenants/:workspace_id/end-users/:user_id/suspend", membershipController.SuspendEndUser)
			v2.POST("/tenants/:workspace_id/end-users/:user_id/reactivate", membershipController.ReactivateEndUser)

			// Group-subject role bindings
			v2.POST("/groups/:group_id/role-bindings", membershipController.BindGroupToRole)

			// Effective access explorer
			v2.GET("/users/:user_id/effective-access", membershipController.EffectiveAccess)
		}

		// ────────────────────────────────────────────────────
		// Delegation policies
		// ────────────────────────────────────────────────────
		delegationPolicies := uflow.Group("/delegation-policies")
		delegationPolicies.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			delegationPolicies.POST("", delegationPolicyCtrl.CreateDelegationPolicy)
			delegationPolicies.GET("", delegationPolicyCtrl.ListDelegationPolicies)
			delegationPolicies.GET("/:id", delegationPolicyCtrl.GetDelegationPolicy)
			delegationPolicies.PUT("/:id", delegationPolicyCtrl.UpdateDelegationPolicy)
			delegationPolicies.DELETE("/:id", delegationPolicyCtrl.DeleteDelegationPolicy)
		}

		// SDK delegation-token retrieval requires an authenticated caller.
		// Bare client_id is not authentication.
		sdk := uflow.Group("/sdk")
		sdk.Use(middlewares.AuthMiddleware())
		{
			sdk.GET("/delegation-token", sdkTokenCtrl.GetDelegationToken)
		}

		// ────────────────────────────────────────────────────
		// End-user admin scopes
		// ────────────────────────────────────────────────────
		enduserAdmin := uflow.Group("/enduser")
		enduserAdmin.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
		}

		// ────────────────────────────────────────────────────
		// End-user self-service routes
		// ────────────────────────────────────────────────────
		user := uflow.Group("/user")
		{
			user.POST("/login", endUserController.CustomLogin)
			user.POST("/login/status", endUserController.CustomLoginStatus)
			user.POST("/saml/login", endUserAuthController.SAMLLogin)
			user.POST("/register/initiate", endUserController.InitiateCustomLoginRegister)
			user.POST("/register/complete", endUserController.CompleteCustomLoginRegister)
			user.POST("/register", endUserController.CustomLoginRegister)
			user.POST("/forgot-password", endUserController.CustomForgotPassword)
			user.POST("/forgot-password/verify-otp", endUserController.CustomVerifyPasswordResetOTP)
			user.POST("/forgot-password/reset", endUserController.CustomResetPassword)
			user.POST("/oidc/login", endUserController.OIDCLogin)
		}

		user.Use(middlewares.AuthMiddleware(), middlewares.ValidateWorkspaceFromToken())
		{
			user.GET("/enduser/:workspace_id/:user_id", endUserController.GetEndUser)
			user.POST("/enduser/list", endUserController.GetEndUsers)
			user.GET("/enduser/list", endUserController.GetEndUsers)
			user.PUT("/enduser/:workspace_id/:user_id", endUserController.UpdateUser)
			user.PUT("/enduser/:workspace_id/:user_id/status", endUserController.UpdateEndUserStatus)
			user.POST("/enduser/active", endUserController.ActiveOrDeactiveEndUser)
			user.POST("/enduser/delete", endUserController.DeleteEndUser)
			user.DELETE("/enduser/:workspace_id/:user_id", middlewares.Require("users", "delete"), endUserController.DeleteEndUser)
			user.DELETE("/enduser/delete_all/:workspace_id/:user_id", middlewares.Require("users", "delete"), endUserController.DeleteUserAll)
			user.POST("/rbac/roles", forbiddenLegacyRBACMutation)
			user.GET("/rbac/roles", rolesScopedBindingsController.ListRolesEndUser)
			user.PUT("/rbac/roles/:role_id", forbiddenLegacyRBACMutation)
			user.DELETE("/rbac/roles/:role_id", forbiddenLegacyRBACMutation)
			user.POST("/rbac/bindings", forbiddenLegacyRBACMutation)
			user.GET("/rbac/bindings", rolesScopedBindingsController.ListRoleBindingsEndUser)
			user.GET("/rbac/permissions", permissionController.ListPermissionsEndUser)
			user.POST("/rbac/permissions", forbiddenLegacyRBACMutation)
			user.DELETE("/rbac/permissions/:id", forbiddenLegacyRBACMutation)
			user.DELETE("/rbac/permissions", forbiddenLegacyRBACMutation)
			user.GET("/rbac/permissions/resources", permissionController.ShowResourcesEndUser)
			user.POST("/rbac/policy/check", authController.PolicyDecisionPointCheckUser)
			user.GET("/permissions", permissionController.GetMyPermissions)
			user.GET("/permissions/effective", permissionController.GetMyEffectivePermissions)
			user.GET("/permissions/check", permissionController.CheckPermission)
			user.POST("/groups/users/add", groupController.AddUserToGroups)
			user.POST("/groups/users/remove", groupController.RemoveUserFromGroups)
			user.GET("/groups/users", groupController.GetMyGroups)
			user.GET("/groups/:workspace_id/:group_id/users", groupController.GetGroupUsers)
			user.POST("/admin/change-password", endUserController.AdminChangeUserPassword)
			user.POST("/admin/reset-password", endUserController.AdminResetUserPassword)
		}

		// ────────────────────────────────────────────────────
		// HubSpot integration
		// ────────────────────────────────────────────────────
		hubspot := uflow.Group("/hubspot")
		hubspot.Use(middlewares.AuthMiddleware(), middlewares.ValidateWorkspaceFromToken())
		{
			hubspot.POST("/contacts/sync", hubspotController.SyncContact)
		}

		// ────────────────────────────────────────────────────
		// SCIM 2.0
		// ────────────────────────────────────────────────────

		// Discovery (public)
		scimDiscovery := uflow.Group("/scim/v2")
		{
			scimDiscovery.GET("/ServiceProviderConfig", scimController.GetServiceProviderConfig)
			scimDiscovery.GET("/Schemas", scimController.GetSchemas)
			scimDiscovery.GET("/ResourceTypes", scimController.GetResourceTypes)
		}

		// Opaque connection-id route. The auth middleware loads
		// scim_connections by the path id, verifies the Bearer token against
		// the stored hash, and sets workspace/tenant context for downstream
		// handlers. No client_id/project_id in URL — those come from the
		// connection's default_client_id / default_project_id columns.
		scimConn := uflow.Group("/scim/v2/c/:scim_connection_id")
		scimConn.Use(middlewares.SCIMConnectionAuth(), middlewares.SCIMEventLogger())
		{
			scimConn.GET("/Users", scimController.ListUsers)
			scimConn.GET("/Users/:id", scimController.GetUser)
			scimConn.POST("/Users", scimController.CreateUser)
			scimConn.PUT("/Users/:id", scimController.ReplaceUser)
			scimConn.PATCH("/Users/:id", scimController.PatchUser)
			scimConn.DELETE("/Users/:id", scimController.DeleteUser)
			scimConn.GET("/Groups", scimController.ListGroups)
			scimConn.GET("/Groups/:id", scimController.GetGroup)
			scimConn.POST("/Groups", scimController.CreateGroup)
			scimConn.PUT("/Groups/:id", scimController.ReplaceGroup)
			scimConn.PATCH("/Groups/:id", scimController.PatchGroup)
			scimConn.DELETE("/Groups/:id", scimController.DeleteGroup)
		}

		// Admin provisioning
		scimAdmin := uflow.Group("/scim/v2/admin")
		scimAdmin.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			scimAdmin.GET("/Users", scimAdminController.ListAdminUsers)
			scimAdmin.GET("/Users/:id", scimAdminController.GetAdminUser)
			scimAdmin.POST("/Users", scimAdminController.CreateAdminUser)
			scimAdmin.PUT("/Users/:id", scimAdminController.ReplaceAdminUser)
			scimAdmin.PATCH("/Users/:id", scimAdminController.PatchAdminUser)
			scimAdmin.DELETE("/Users/:id", scimAdminController.DeleteAdminUser)
		}

		// ========================================
		// Agent Action Guard routes (Human-in-the-Loop approvals for AI agents)
		// ========================================

		// Agent-facing endpoints (JWT auth required)
		agentActions := uflow.Group("/agent/actions")
		agentActions.Use(middlewares.AuthMiddleware())
		{
			agentActions.POST("/evaluate", agentActionController.EvaluateAction)
			agentActions.GET("/status", agentActionController.PollActionStatus)
			agentActions.POST("/respond", agentActionController.RespondToAction)
			agentActions.GET("/pending", agentActionController.GetPendingActions)
		}

		// Risk policy admin endpoints
		agentGuardAdmin := uflow.Group("/admin/risk-policies")
		agentGuardAdmin.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			agentGuardAdmin.GET("", agentActionController.ListRiskPolicies)
			agentGuardAdmin.POST("", agentActionController.CreateRiskPolicy)
			agentGuardAdmin.PUT("/:id", agentActionController.UpdateRiskPolicy)
			agentGuardAdmin.DELETE("/:id", agentActionController.DeleteRiskPolicy)
		}

		// Agent guard settings (admin)
		agentGuardSettings := uflow.Group("/admin/agent-guard")
		agentGuardSettings.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			agentGuardSettings.GET("/settings", agentActionController.GetSettings)
			agentGuardSettings.PUT("/settings", agentActionController.UpdateSettings)
		}

		// Agent audit log (admin)
		agentAudit := uflow.Group("/admin/agent-audit")
		agentAudit.Use(
			middlewares.AuthMiddleware(),
			middlewares.RequireWorkspaceRole("owner", "admin"),
			middlewares.ValidateWorkspaceFromToken(),
		)
		{
			agentAudit.GET("", agentActionController.GetAuditLog)
		}

		// ────────────────────────────────────────────────────
		// Health checks
		// ────────────────────────────────────────────────────
		health := uflow.Group("/health")
		{
			health.GET("", healthController.ComprehensiveHealthCheck)
			health.GET("/tenant/:workspace_id", healthController.CheckTenantDatabase)
			health.GET("/tenants", healthController.CheckAllTenantDatabases)
		}

		// ────────────────────────────────────────────────────
		// Hydra Manager (formerly hydra-service)
		// Served under /authsec/hmgr.
		// ────────────────────────────────────────────────────
		registerHmgrRoutes(authsec)

		// ────────────────────────────────────────────────────
		// OIDC Configuration Manager (formerly oath_oidc_configuration_manager)
		// Served under /authsec/oocmgr.
		// ────────────────────────────────────────────────────
		registerOocmgrRoutes(authsec)

		// ────────────────────────────────────────────────────
		// Authorization and RBAC surface (implemented by the merged auth-manager logic)
		// Served under /authsec/authz and /authsec/auth/token.
		// ────────────────────────────────────────────────────
		registerAuthmgrRoutes(authsec)

		// ────────────────────────────────────────────────────
		// Migration API (formerly authsec-migration microservice)
		// Served under /authsec/migration.
		// ────────────────────────────────────────────────────
		// Migration API — master bootstrap only. Per-tenant DB routes removed
		// (single-DB architecture; per-workspace databases do not exist).
		migCtrl := adminCtrl.NewMigrationController()
		mig := authsec.Group("/migration")
		{
			master := mig.Group("/migrations/master")
			master.Use(middlewares.AuthMiddleware())
			{
				master.POST("/run", migCtrl.RunMasterMigrations)
				master.GET("/status", migCtrl.GetMasterMigrationStatus)
			}
		}

		// ────────────────────────────────────────────────────
		// Logs API — serves the Logs UI from the existing audit tables.
		// Served under /authsec/logs.
		// ────────────────────────────────────────────────────
		registerLogsRoutes(authsec)

		// ────────────────────────────────────────────────────
		// Legacy embedded SPIRE control plane — quarantined behind
		// ENABLE_EMBEDDED_SPIRE (default off). Both mounts back onto
		// internal/spire repositories that query control-plane tables
		// (agents, workloads, certificates, …) absent from the single
		// master bootstrap, so they 500 if mounted. The SPIFFE-SVID M2M
		// path is independent of this flag and stays available.
		//   - /authsec/spire     : SPIRE Headless (spire-headless microservice)
		//   - /authsec/spiresvc  : SPIRE Identity Service (authsec-spire)
		// ────────────────────────────────────────────────────
		embeddedSpireEnabled := config.AppConfig != nil && config.AppConfig.EnableEmbeddedSpire
		if embeddedSpireEnabled {
			registerSpireRoutes(authsec)
			if spireDeps != nil {
				spiresvc := authsec.Group("/spiresvc")
				spire.RegisterRoutes(spiresvc, spireDeps)
			}
		}

		// ────────────────────────────────────────────────────
		// External Service (formerly exsvc / mcp-service)
		// Served under /authsec/exsvc.
		// ────────────────────────────────────────────────────
		extSvcController := platformCtrl.NewExternalServiceController(config.DB)

		exsvc := authsec.Group("/exsvc")
		exsvc.GET("/health", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok", "service": "external-service"})
		})
		exsvc.GET("/debug/auth", middlewares.AuthMiddleware(), platformCtrl.DebugExternalServiceAuth)
		exsvc.GET("/debug/test", middlewares.AuthMiddleware(), func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "authenticated", "path": "/debug/test"})
		})
		exsvc.GET("/debug/token", middlewares.AuthMiddleware(), func(c *gin.Context) {
			contextData := make(map[string]interface{})
			if claims, exists := c.Get("claims"); exists {
				contextData["claims"] = claims
			}
			if perms, exists := c.Get("perms"); exists {
				contextData["perms"] = perms
			}
			if scope, exists := c.Get("scope"); exists {
				contextData["scope"] = scope
			}
			if user, exists := c.Get("user"); exists {
				contextData["user"] = user
			}
			contextData["all_context_keys"] = c.Keys
			c.JSON(200, gin.H{"status": "authenticated", "context_data": contextData})
		})

		// Dual-auth: accepts standard auth-manager JWT or SPIFFE JWT-SVID (for agent access).
		extSvcs := exsvc.Group("/services")
		extSvcs.Use(middlewares.SpiffeAuthMiddleware())
		{
			extSvcs.POST("", middlewares.Require("external-service", "create"), extSvcController.CreateExternalService)
			extSvcs.GET("", middlewares.Require("external-service", "read"), extSvcController.ListExternalServices)
			extSvcs.GET("/:id", middlewares.Require("external-service", "read"), extSvcController.GetExternalService)
			extSvcs.PUT("/:id", middlewares.Require("external-service", "update"), extSvcController.UpdateExternalService)
			extSvcs.DELETE("/:id", middlewares.Require("external-service", "delete"), extSvcController.DeleteExternalService)
			extSvcs.GET("/:id/credentials", middlewares.Require("external-service", "credentials"), extSvcController.GetExternalServiceCredentials)
		}

		// ────────────────────────────────────────────────────
		// Connectors — admin control plane (/authsec/connectors/*).
		// Interactive admin/user session; CRUD + non-secret config only.
		// NO credential-vending route: AuthSec vends actions + results, not
		// secrets. Agents execute actions on the broker data plane
		// (/broker/connectors/*, provisioned in a later P0 step).
		// ────────────────────────────────────────────────────
		connectorController := platformCtrl.NewConnectorController(config.DB)
		connectors := authsec.Group("/connectors")
		connectors.Use(middlewares.AuthMiddleware())
		{
			connectors.GET("/providers", middlewares.Require("connector", "read"), connectorController.ListProviders)
			// Read-only, non-secret: lets the console tell a configured workspace
			// from an unconfigured one. Requires only `read`, since it exposes no
			// secret material.
			connectors.GET("/providers/:provider/app", middlewares.Require("connector", "read"), connectorController.GetProviderApp)
			connectors.POST("/providers/:provider/app", middlewares.Require("connector", "update"), connectorController.SetProviderApp)
			connectors.POST("/providers/github/app-github", middlewares.Require("connector", "update"), connectorController.SetGitHubApp)
			// Self-service reads that let the console stop asking humans for
			// values GitHub already knows. Both are non-secret and read-only.
			connectors.GET("/providers/github/app/describe", middlewares.Require("connector", "read"), connectorController.DescribeGitHubApp)
			connectors.GET("/providers/github/installations", middlewares.Require("connector", "read"), connectorController.ListGitHubInstallations)
			// Completes GitHub's App-manifest flow; writes the App id + key.
			connectors.POST("/providers/github/app-manifest/convert", middlewares.Require("connector", "update"), connectorController.ConvertGitHubAppManifest)
			connectors.POST("/:id/connections/github-app", middlewares.Require("connector", "update"), connectorController.ConnectGitHubApp)
			// R4 — end-user self-service consent (bind to the caller's own identity).
			connectors.POST("/:id/connections/user/oauth/start", middlewares.Require("connector", "read"), connectorController.StartUserConnect)
			connectors.DELETE("/:id/connections/me", middlewares.Require("connector", "read"), connectorController.RevokeMyConnection)
			connectors.GET("/connections/me", middlewares.Require("connector", "read"), connectorController.ListMyConnections)
			connectors.POST("", middlewares.Require("connector", "create"), connectorController.CreateConnector)
			connectors.GET("", middlewares.Require("connector", "read"), connectorController.ListConnectors)
			connectors.GET("/:id", middlewares.Require("connector", "read"), connectorController.GetConnector)
			connectors.PUT("/:id", middlewares.Require("connector", "update"), connectorController.UpdateConnector)
			connectors.DELETE("/:id", middlewares.Require("connector", "delete"), connectorController.DeleteConnector)
			connectors.GET("/:id/config", middlewares.Require("connector", "config"), connectorController.GetConnectorConfig)
			connectors.POST("/:id/connections/oauth/start", middlewares.Require("connector", "update"), connectorController.StartOAuthConnect)
			connectors.POST("/:id/assignments", middlewares.Require("connector", "assign"), connectorController.GrantAssignment)
			connectors.GET("/:id/assignments", middlewares.Require("connector", "assign"), connectorController.ListAssignments)
			connectors.DELETE("/:id/assignments/:aid", middlewares.Require("connector", "assign"), connectorController.RevokeAssignment)
			connectors.GET("/:id/audit", middlewares.Require("connector", "read"), connectorController.GetConnectorAudit)
			connectors.PUT("/:id/subject-groups", middlewares.Require("connector", "assign"), connectorController.SetSubjectGroups)
		}
		// OAuth callback is provider-redirected and state-validated — it must NOT
		// sit behind the admin auth middleware (the browser arrives unauthenticated
		// from the provider). Distinct top-level path to avoid colliding with the
		// /connectors/:id param route in Gin's tree.
		authsec.GET("/connector-oauth/callback", connectorController.OAuthCallback)

		// ────────────────────────────────────────────────────
		// Agent Discovery (IGA) — /authsec/discovery/*.
		// A quarantine-first inventory of every AI agent running in the
		// workspace, including ones nobody registered. A sighting grants
		// NOTHING: rows land unregistered, so discovery is safe to run against
		// production before anything is provisioned. A human then either claims
		// the agent (binding it to a governed identity + an accountable owner)
		// or quarantines it.
		//
		// ────────────────────────────────────────────────────
		discoveryController := platformCtrl.NewDiscoveryController(config.DB)

		// Connector ingress is UNAUTHENTICATED by deliberate choice.
		//
		// A connector runs inside a customer's cluster and is configured with its
		// workspace_id at deploy time (a Helm --set on the discovery agent), which it
		// then asserts in the request body. That removes the token-minting step from
		// the install flow entirely.
		//
		// What this trades away, stated plainly so it is not rediscovered later:
		//   - the workspace is CALLER-ASSERTED, not derived from a verified token, so
		//     any caller who knows a workspace_id can add rows to that workspace's
		//     inventory
		//   - there is no rate limit, so inventory growth from this path is unbounded
		//
		// What keeps the blast radius to noise rather than privilege: a sighting
		// grants nothing. Rows land `unregistered`, and only an authenticated,
		// permission-checked human can claim one into a governed identity. The worst
		// case is a polluted Unregistered Agents report, not access.
		//
		// Registered on its own group so it cannot accidentally inherit
		// AuthMiddleware from the block below. Same pattern as the connector OAuth
		// callback above, which is also necessarily unauthenticated.
		discoveryIngress := authsec.Group("/discovery")
		{
			discoveryIngress.POST("/sightings", discoveryController.ReportSighting)

			// Connector self-registration + heartbeat. One control plane serves agents
			// in many clusters, so each announces itself and gets back a
			// discovery_source_id it stamps on every sighting — which is what makes
			// "which cluster did this agent come from" a foreign key rather than a
			// string buried in metadata, and "has this cluster gone quiet" answerable
			// at all.
			discoveryIngress.POST("/agent-registration", discoveryController.RegisterAgent)

			// Runtime lifecycle. Sightings only ever said "this exists"; these carry
			// the other half — deleted, when, and (on the admission channel, where the
			// API server authenticates the caller) by whom. They write runtime_status
			// only, never the governance status, so a claimed-then-deleted agent stays
			// registered while its runtime state becomes gone.
			discoveryIngress.POST("/lifecycle", discoveryController.ReportLifecycleEvent)

			// Per-sweep manifest of everything a connector observed. The only signal
			// that catches an agent destroyed while nobody was watching — before
			// install, or during an outage — since admission sees deletions live or
			// never. A partial sweep retires nothing.
			discoveryIngress.POST("/resync-manifest", discoveryController.ReportResyncManifest)
		}

		// Everything else stays authenticated and permission-gated: reading the
		// inventory exposes hostnames and workload metadata across the workspace, and
		// claim/quarantine are governance decisions that must be attributable.
		// Declared before the discovery group because the IGA-correlation bridge
		// hangs off /discovery/agents/:id as well as /governance.
		governanceController := platformCtrl.NewGovernanceController(config.DB)

		discovery := authsec.Group("/discovery")
		discovery.Use(middlewares.AuthMiddleware())
		{
			// Connector registry.
			discovery.POST("/sources", middlewares.Require("discovery", "admin"), discoveryController.CreateDiscoverySource)
			discovery.GET("/sources", middlewares.Require("discovery", "read"), discoveryController.ListDiscoverySources)
			discovery.GET("/sources/:id", middlewares.Require("discovery", "read"), discoveryController.GetDiscoverySource)
			discovery.PUT("/sources/:id", middlewares.Require("discovery", "admin"), discoveryController.UpdateDiscoverySource)
			discovery.DELETE("/sources/:id", middlewares.Require("discovery", "admin"), discoveryController.DeleteDiscoverySource)

			// NOTE: POST /sightings, /agent-registration, /lifecycle and
			// /resync-manifest are deliberately NOT here — they are registered
			// unauthenticated on discoveryIngress above. Re-adding any of them here
			// would make Gin panic at startup on the duplicate method+path.

			// Inventory. ?status=unregistered is the Unregistered Agents report;
			// add &live=true to drop agents already observed to be destroyed.
			// ?runtime_status= and ?discovery_source_id= filter by observed state and
			// by reporting cluster.
			// The static /agents/lookup must be registered before /agents/:id.
			discovery.GET("/agents/lookup", middlewares.Require("discovery", "read"), discoveryController.LookupDiscoveredAgent)
			discovery.GET("/agents", middlewares.Require("discovery", "read"), discoveryController.ListDiscoveredAgents)
			discovery.GET("/agents/:id", middlewares.Require("discovery", "read"), discoveryController.GetDiscoveredAgent)
			// The lifecycle trail behind an agent's runtime status: when it was
			// deleted, through which channel, and which principal the API server
			// attributed it to.
			discovery.GET("/agents/:id/events", middlewares.Require("discovery", "read"), discoveryController.ListAgentLifecycle)
			discovery.PUT("/agents/:id", middlewares.Require("discovery", "admin"), discoveryController.UpdateDiscoveredAgent)
			discovery.DELETE("/agents/:id", middlewares.Require("discovery", "admin"), discoveryController.DeleteDiscoveredAgent)

			// The two governance decisions, each with its own permission.
			discovery.POST("/agents/:id/claim", middlewares.Require("discovery", "claim"), discoveryController.ClaimAgent)
			discovery.POST("/agents/:id/quarantine", middlewares.Require("discovery", "quarantine"), discoveryController.QuarantineAgent)
			// Releasing takes the SAME permission as quarantining: whoever can cut an
			// agent off can restore it. Splitting them would leave an operator able to
			// contain an incident but not to undo a mistake — which is how a mis-click
			// becomes an outage nobody on shift can fix.
			discovery.POST("/agents/:id/unquarantine", middlewares.Require("discovery", "quarantine"), discoveryController.UnquarantineAgent)

			// Which canonical agent in the correlated estate is this workload?
			// Read is a discovery read; the decision is a correlation decision.
			discovery.GET("/agents/:id/iga-link",
				middlewares.Require("discovery", "read"), governanceController.GetAgentIGALink)
			discovery.POST("/agents/:id/iga-link/decisions",
				middlewares.Require("iga", "review"), governanceController.DecideAgentIGALink)

			// Headline KPI: registered / total, segmented by origin.
			discovery.GET("/coverage", middlewares.Require("discovery", "read"), discoveryController.GetCoverage)

			// GitHub as a discovery channel, alongside the Kubernetes webhook.
			// ADDITIVE: one new trigger route on a separate controller. The
			// sightings it reports land in the SAME discovered_agents
			// inventory and are governed by the claim/quarantine/coverage
			// endpoints above, unchanged. Gated on discovery:admin because a
			// scan spends the workspace's GitHub API budget.
			// The flow is: register the App once, add an organisation, choose
			// repositories, scan.
			//
			//   github/app*           the ONE GitHub App this workspace owns.
			//                         Workspace-level, because one App serves
			//                         every organisation it is installed on.
			//   github/installations  where that App is installed, read live
			//                         from GitHub and annotated with what has
			//                         already been added here
			//   github/organisations  adds one: creates the verified
			//                         iga_integrations binding AND the
			//                         discovery source, in one call
			//   GET  repositories     what the installation actually exposes
			//   PUT  repositories     the explicit scan plan
			//   POST scan             inspects only the selected repositories
			//
			// These live under discovery, not under /connectors. The GitHub App
			// KEY store is shared with the connector broker on purpose -- one
			// private key, one place -- but the product surface is not: per
			// SPEC-connectors, Agentic IGA must not depend on that framework,
			// and nothing here reads or writes a connector row.
			//
			// Selection is deliberate: a new source selects nothing, so adding
			// an organisation can never trigger an unbounded scan by itself.
			discoveryGitHub := platformCtrl.NewDiscoveryGitHubController(config.DB)
			discovery.GET("/github/app", middlewares.Require("discovery", "read"), discoveryGitHub.GetGitHubApp)
			discovery.GET("/github/app/describe", middlewares.Require("discovery", "read"), discoveryGitHub.DescribeGitHubApp)
			discovery.POST("/github/app", middlewares.Require("discovery", "admin"), discoveryGitHub.SetGitHubApp)
			discovery.DELETE("/github/app", middlewares.Require("discovery", "admin"), discoveryGitHub.DeleteGitHubApp)
			discovery.POST("/github/app/manifest/convert", middlewares.Require("discovery", "admin"), discoveryGitHub.ConvertGitHubAppManifest)
			discovery.GET("/github/installations", middlewares.Require("discovery", "read"), discoveryGitHub.ListGitHubInstallations)
			discovery.POST("/github/organisations", middlewares.Require("discovery", "admin"), discoveryGitHub.AddOrganisation)
			discovery.GET("/sources/:id/repositories", middlewares.Require("discovery", "read"), discoveryGitHub.ListSourceRepositories)
			discovery.PUT("/sources/:id/repositories", middlewares.Require("discovery", "admin"), discoveryGitHub.SetSourceRepositories)
			discovery.POST("/sources/:id/scan", middlewares.Require("discovery", "admin"), discoveryGitHub.ScanGitHubSource)

			// Scan runs. POST .../scan queues and returns 202 with a run id;
			// these are how the console follows it and how anyone answers "what
			// did the last scan actually see?" after the fact. Reading a run is
			// discovery:read — it reports coverage, it does not change anything.
			// Detection patterns. What a scan searches for used to be compiled
			// in; a workspace can now tune the path globs and the token
			// vocabulary without waiting for a release. The PARSERS stay in
			// code and are selected by name — config never introduces one.
			//
			// Reading is discovery:read (it describes coverage). Writing is
			// discovery:admin: widening a glob widens what every later scan
			// downloads, so it is a spending decision as much as a detection one.
			ruleCatalog := platformCtrl.NewDiscoveryRuleCatalogController(config.DB)
			discovery.GET("/rule-catalog", middlewares.Require("discovery", "read"), ruleCatalog.GetRuleCatalog)
			discovery.PUT("/rule-catalog", middlewares.Require("discovery", "admin"), ruleCatalog.SetRuleCatalog)
			discovery.DELETE("/rule-catalog", middlewares.Require("discovery", "admin"), ruleCatalog.ResetRuleCatalog)
			discovery.POST("/rule-catalog/test", middlewares.Require("discovery", "read"), ruleCatalog.TestRuleCatalog)

			discovery.GET("/sources/:id/scan-runs", middlewares.Require("discovery", "read"), discoveryGitHub.ListScanRuns)
			discovery.GET("/scan-runs/:run_id", middlewares.Require("discovery", "read"), discoveryGitHub.GetScanRun)
			discovery.POST("/scan-runs/:run_id/cancel", middlewares.Require("discovery", "admin"), discoveryGitHub.CancelScanRun)

			// AWS as a discovery channel, alongside Kubernetes and GitHub.
			//
			// These endpoints ONBOARD an AWS account: they establish an agentless,
			// read-only cross-account connection and record the cloud_connector row
			// that every later AWS surface — IAM identities, access keys, policies,
			// Bedrock, activity — resolves against. Nothing here discovers anything
			// yet.
			//
			// Under /discovery rather than /connectors, the same boundary the GitHub
			// channel keeps: the connector broker is the action framework, and
			// Agentic IGA must not depend on it.
			//
			// Reading the onboarding package is discovery:read even though it mints
			// an ExternalId — the id is worthless until a role that trusts it exists,
			// and gating it on admin would stop a reader from seeing the permissions
			// AuthSec is asking for, which is exactly the thing a reviewer needs.
			// Everything that CHANGES a connection is discovery:admin: connecting an
			// AWS account decides what a scan may read and what it will cost.
			cloudAWS := platformCtrl.NewCloudAWSController(config.DB)
			discovery.GET("/aws/onboarding", middlewares.Require("discovery", "read"), cloudAWS.GetOnboardingPackage)
			discovery.POST("/aws/connectors", middlewares.Require("discovery", "admin"), cloudAWS.CreateConnector)
			discovery.GET("/aws/connectors", middlewares.Require("discovery", "read"), cloudAWS.ListConnectors)
			discovery.GET("/aws/connectors/:id", middlewares.Require("discovery", "read"), cloudAWS.GetConnector)
			discovery.POST("/aws/connectors/:id/verify", middlewares.Require("discovery", "admin"), cloudAWS.VerifyConnector)
			// DELETE verb, revoke semantics: the connector row and everything it
			// discovered stay for audit, aligned with GCP's planned behaviour. See
			// CloudConnectorRepository.Revoke.
			discovery.DELETE("/aws/connectors/:id", middlewares.Require("discovery", "admin"), cloudAWS.RevokeConnector)

			// IAM identity discovery: the foundation every later AWS surface
			// resolves against. Writes cloud_identity and cloud_secret and
			// nothing else.
			//
			// Starting a scan is discovery:admin because it spends the
			// customer's API quota and can take minutes on a large account.
			// Reading the results is discovery:read — and note that an identity
			// row is a CANDIDATE, not an agent: nothing this endpoint returns
			// asserts that anything is an AI agent.
			discovery.POST("/aws/connectors/:id/scan", middlewares.Require("discovery", "admin"), cloudAWS.ScanIAM)
			discovery.GET("/aws/identities", middlewares.Require("discovery", "read"), cloudAWS.ListIdentities)
			discovery.GET("/aws/secrets", middlewares.Require("discovery", "read"), cloudAWS.ListSecrets)

			// Trust relationships and permission/resource extraction: who may
			// assume each identity, and what each identity may do. No separate
			// trigger route — this runs chained after the scan above, against
			// the same generation, so cloud_assume_edge and cloud_permission are
			// never a scan behind cloud_identity.
			discovery.GET("/aws/assume-edges", middlewares.Require("discovery", "read"), cloudAWS.ListAssumeEdges)
			discovery.GET("/aws/permissions", middlewares.Require("discovery", "read"), cloudAWS.ListPermissions)
			discovery.GET("/aws/resources", middlewares.Require("discovery", "read"), cloudAWS.ListResources)
		}

		// ────────────────────────────────────────────────────
		// Provisioning & Governance — /authsec/provisioning/*, /authsec/governance/*.
		//
		// Where discovery answers "what exists?", these answer "should it exist, with
		// what authority, and is that still true?" — and then make it so.
		//
		// ALL of these are authenticated and permission-gated. The reasoning that made
		// the discovery ingress unauthenticated does NOT transfer: a sighting grants
		// nothing and lands `unregistered`, whereas provisioning grants real authority
		// and de-provisioning takes it away.
		//
		// Provisioning is one transaction (PG-2) and de-provisioning is the single
		// revocation path every mechanism funnels through (PG-6), which is why both
		// live behind one controller rather than being spread across callers.
		// ────────────────────────────────────────────────────

		provisioning := authsec.Group("/provisioning")
		provisioning.Use(middlewares.AuthMiddleware())
		{
			// Claimed sighting -> governed principal. discovery:claim is the permission
			// that already means "may bring an agent under management", so provisioning
			// reuses it rather than inventing a second gate for the same decision.
			provisioning.POST("/agents/:id/provision",
				middlewares.Require("discovery", "claim"), governanceController.ProvisionAgent)
			// Taking authority away is its own permission: an operator who may enrol an
			// agent is not automatically trusted to revoke a production one.
			provisioning.POST("/agents/:id/deprovision",
				middlewares.Require("governance", "revoke"), governanceController.DeprovisionAgent)
		}

		// The in-cluster agent's ACTUATION surface.
		//
		// Deliberately NOT under AuthMiddleware: the caller is a workload in a
		// customer's cluster, not a console user. It authenticates with the
		// per-connector actuation token, which also determines WHICH cluster is calling
		// — so an agent never asserts its own identity.
		//
		// Unlike the discovery ingress this is authenticated, because the reasoning
		// there does not carry over. A sighting grants nothing, but a forged
		// UNQUARANTINE would lift a network deny, which fails OPEN. (A forged quarantine
		// fails safe: it denies.)
		actuation := authsec.Group("/provisioning")
		{
			actuation.GET("/instructions", governanceController.LeaseInstructions)
			actuation.POST("/instructions/:id/result", governanceController.ReportInstruction)
		}

		governance := authsec.Group("/governance")
		governance.Use(middlewares.AuthMiddleware())
		{
			// "Why does this subject have this?" — the question the platform could not
			// answer before provenance existed, and the whole basis of certification.
			governance.GET("/provenance",
				middlewares.Require("governance", "read"), governanceController.ListProvenance)
			governance.GET("/provenance/:id",
				middlewares.Require("governance", "read"), governanceController.GetProvenance)

			// Separation of duties. Reading rules and violations is a read; resolving a
			// violation is a governance decision somebody has to answer for, so it needs
			// governance:certify rather than governance:read.
			governance.GET("/sod/rules",
				middlewares.Require("governance", "read"), governanceController.ListSoDRules)
			governance.GET("/sod/violations",
				middlewares.Require("governance", "read"), governanceController.ListSoDViolations)
			governance.POST("/sod/violations/:id/resolve",
				middlewares.Require("governance", "certify"), governanceController.ResolveSoDViolation)
			// "Would this grant conflict?" — lets a console warn before an operator
			// submits, instead of surfacing the refusal as an error afterwards.
			governance.POST("/sod/simulate",
				middlewares.Require("governance", "read"), governanceController.SimulateSoD)
			// Trigger a detective pass on demand, for after writing a new rule.
			governance.POST("/sod/scan",
				middlewares.Require("governance", "admin"), governanceController.RunSoDScan)

			// Certification. Creating and closing a campaign is administration;
			// DECIDING an item is the reviewer's act and needs governance:certify —
			// which is deliberately NOT governance:admin, so a reviewer can work a
			// campaign without gaining the ability to grant anything (PG-5).
			governance.POST("/campaigns",
				middlewares.Require("governance", "admin"), governanceController.CreateCampaign)
			governance.GET("/campaigns",
				middlewares.Require("governance", "read"), governanceController.ListCampaigns)
			governance.GET("/campaigns/:id",
				middlewares.Require("governance", "read"), governanceController.GetCampaign)
			governance.POST("/campaigns/:id/generate",
				middlewares.Require("governance", "admin"), governanceController.GenerateCampaign)
			governance.GET("/campaigns/:id/items",
				middlewares.Require("governance", "read"), governanceController.ListCampaignItems)
			governance.POST("/campaigns/:id/items/:item/decide",
				middlewares.Require("governance", "certify"), governanceController.DecideItem)
			governance.POST("/campaigns/:id/close",
				middlewares.Require("governance", "admin"), governanceController.CloseCampaign)

			// Actuation. Enabling it mints the cluster's credential, so it is admin-only;
			// the instruction list is a read.
			governance.POST("/connectors/:id/actuation",
				middlewares.Require("governance", "admin"), governanceController.EnableActuation)
			governance.GET("/instructions",
				middlewares.Require("governance", "read"), governanceController.ListInstructions)

			// Human lifecycle. Birthright policy is administration; the reconcile is
			// too, because it grants. The reports are reads.
			governance.POST("/birthrights",
				middlewares.Require("governance", "admin"), governanceController.CreateBirthright)
			governance.GET("/birthrights",
				middlewares.Require("governance", "read"), governanceController.ListBirthrights)
			governance.DELETE("/birthrights/:id",
				middlewares.Require("governance", "admin"), governanceController.DeleteBirthright)
			// The bridge to the correlated IGA estate. Reading a proposal is a
			// discovery read; DECIDING one is a correlation decision, so it takes
			// iga:review — the same permission as the classification and ownership
			// decisions it sits alongside, rather than a governance permission that
			// would let an entitlement reviewer redefine what an agent IS.
			governance.GET("/iga-links",
				middlewares.Require("discovery", "read"), governanceController.ListIGALinkProposals)

			governance.POST("/jml/reconcile",
				middlewares.Require("governance", "admin"), governanceController.ReconcileJML)
			// The mover queue: grants whose policy no longer matches the holder.
			governance.GET("/jml/stale",
				middlewares.Require("governance", "read"), governanceController.ListStaleBirthrights)
			// Agents whose accountable owner has been deactivated.
			governance.GET("/jml/orphans",
				middlewares.Require("governance", "read"), governanceController.ListOrphanedAgents)
		}

		// ────────────────────────────────────────────────────
		// Connector Broker — runtime DATA plane (/broker/connectors/*).
		// Agents/workloads call here with a native AuthSec access token whose
		// audience is the workspace Connector Broker RS (RFC 8707). The broker
		// controller verifies the token itself via the shared
		// ProtectedResourceVerifier and runs the policy chain — so NO standard
		// auth middleware here (HMAC authsec-api tokens are rejected by design).
		// ────────────────────────────────────────────────────
		connectorBroker := platformCtrl.NewConnectorBrokerController(config.DB)
		broker := r.Group("/broker/connectors")
		{
			broker.GET("", connectorBroker.ListConnectors)
			broker.GET("/:id/actions", connectorBroker.ListActions)
			// The client calls .../actions/<actionKey>:execute; the handler trims
			// the ":execute" suffix from the :key param.
			broker.POST("/:id/actions/:key", connectorBroker.ExecuteAction)
		}
		// MCP tools surface — the "automatic" path: agents list + call connector
		// actions as MCP tools. Same broker-audience token + policy chain.
		brokerMCP := r.Group("/broker/mcp")
		{
			brokerMCP.GET("/tools", connectorBroker.MCPListTools)
			brokerMCP.POST("/call", connectorBroker.MCPCallTool)
		}

		// Legacy login/register endpoints
		uflow.POST("/register/verify", userController.VerifyOTPAndCompleteRegistration)
		uflow.POST("/login/webauthn-callback", userController.WebAuthnCallback)
		uflow.POST("/login", userController.Login)

		// Misrouted health-check helpers for monitoring. When the embedded SPIRE
		// control plane is quarantined (default), report it as disabled rather
		// than pointing at a /spiresvc/health endpoint that is not mounted.
		uflow.GET("/spire/health", func(c *gin.Context) {
			if config.AppConfig != nil && config.AppConfig.EnableEmbeddedSpire {
				c.JSON(404, gin.H{"error": "Health check URL misconfigured", "correct_url": "/spiresvc/health"})
				return
			}
			c.JSON(503, gin.H{"status": "disabled", "service": "embedded-spire", "hint": "set ENABLE_EMBEDDED_SPIRE=true to mount /authsec/spire and /authsec/spiresvc"})
		})
		uflow.GET("/clients/clients/api/v1/health", func(c *gin.Context) {
			c.JSON(410, gin.H{"error": "clientms routes have been removed", "correct_url": "/authsec/applications"})
		})
	}
}

// registerWebAuthnRoutes registers WebAuthn routes on the provided router group.
// Previously served by the standalone webauthn-service under /webauthn/*.
// Now served under /authsec/webauthn/*.
func registerWebAuthnRoutes(
	router gin.IRouter,
	webAuthnHandler *handlers.WebAuthnHandler,
	adminHandler *handlers.AdminWebAuthnHandler,
	endUserHandler *handlers.EndUserWebAuthnHandler,
) {
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy", "service": "webauthn-service"})
	})

	// Admin WebAuthn (uses global DB)  →  /authsec/webauthn/admin/*
	admin := router.Group("/admin")
	{
		admin.POST("/mfa/status", adminHandler.GetMFAStatus)
		admin.POST("/mfa/loginStatus", adminHandler.GetMFAStatusForLogin)
		admin.GET("/mfa/loginStatus", adminHandler.GetMFAStatusForLoginGET)
		admin.POST("/beginRegistration", adminHandler.BeginRegistration)
		admin.POST("/finishRegistration", adminHandler.FinishRegistration)
		admin.POST("/beginAuthentication", adminHandler.BeginAuthentication)
		admin.POST("/finishAuthentication", adminHandler.FinishAuthentication)
	}

	// End-user WebAuthn (uses tenant-specific DBs)  →  /authsec/webauthn/enduser/*
	enduser := router.Group("/enduser")
	{
		enduser.POST("/mfa/status", endUserHandler.GetMFAStatus)
		enduser.POST("/mfa/loginStatus", endUserHandler.GetMFAStatusForLogin)
		enduser.GET("/mfa/loginStatus", endUserHandler.GetMFAStatusForLoginGET)
		enduser.POST("/beginRegistration", endUserHandler.BeginRegistration)
		enduser.POST("/finishRegistration", endUserHandler.FinishRegistration)
		enduser.POST("/beginAuthentication", endUserHandler.BeginAuthentication)
		enduser.POST("/finishAuthentication", endUserHandler.FinishAuthentication)
	}

	// Legacy flat routes  →  /authsec/webauthn/*
	router.POST("/mfa/status", webAuthnHandler.GetMFAStatus)
	router.POST("/mfa/loginStatus", webAuthnHandler.GetMFAStatusForLogin)
	router.GET("/mfa/loginStatus", webAuthnHandler.GetMFAStatusForLoginGET)
	router.POST("/beginRegistration", webAuthnHandler.BeginRegistration)
	router.POST("/beginAuthRegistration", webAuthnHandler.BeginWebAuthnRegistration)
	router.POST("/finishRegistration", webAuthnHandler.FinishRegistration)
	router.POST("/beginAuthentication", webAuthnHandler.BeginAuthentication)
	router.POST("/finishAuthentication", webAuthnHandler.FinishAuthentication)

	// Biometric (alias flows)
	router.POST("/biometric/verifyBegin", webAuthnHandler.BeginBiometricVerify)
	router.POST("/biometric/verifyFinish", webAuthnHandler.FinishBiometricVerify)
	router.POST("/biometric/beginSetup", webAuthnHandler.BeginBiometricSetup)
	router.POST("/biometric/confirmSetup", webAuthnHandler.ConfirmBiometricSetup)
	router.POST("/biometric/beginLoginSetup", webAuthnHandler.BeginBiometricLoginSetup)
	router.POST("/biometric/confirmLoginSetup", webAuthnHandler.ConfirmBiometricLoginSetup)
	router.POST("/biometric/verifyLoginBegin", webAuthnHandler.BeginBiometricLoginVerify)
	router.POST("/biometric/verifyLoginFinish", webAuthnHandler.FinishBiometricLoginVerify)

	// TOTP (legacy)
	totpHandler := handlers.NewTOTPHandler()
	router.POST("/totp/beginLoginSetup", totpHandler.BeginSetup)
	router.POST("/totp/beginSetup", totpHandler.BeginTOTPSetup)
	router.POST("/totp/confirmLoginSetup", totpHandler.ConfirmSetup)
	router.POST("/totp/confirmSetup", totpHandler.ConfirmTOTPSetup)
	router.POST("/totp/verifyLogin", totpHandler.VerifyLoginTOTP)
	router.POST("/totp/verify", totpHandler.VerifyTOTP)

	// SMS (legacy)
	smsHandler := handlers.NewSMSHandler()
	router.POST("/sms/beginSetup", smsHandler.BeginSMSSetup)
	router.POST("/sms/confirmSetup", smsHandler.ConfirmSMSSetup)
	router.POST("/sms/requestCode", smsHandler.RequestSMSCode)
	router.POST("/sms/verify", smsHandler.VerifySMS)
}

// registerHmgrRoutes registers all Hydra Manager routes under /hmgr.
// Previously served by the standalone hydra-service.
func registerHmgrRoutes(r gin.IRouter) {
	hmgrController := platformCtrl.NewHmgrController(*config.AppConfig)

	// ── Public routes (no authentication required) ──
	pub := r.Group("/hmgr")
	{
		// OIDC endpoints
		pub.GET("/login/page-data", hmgrController.GetLoginPageDataHandler)
		pub.POST("/login/complete-local", hmgrController.CompleteLocalLoginHandler)
		// OIDC initiate is a thin v4 delegate. The callback lives at
		// /authsec/uflow/oidc/callback (server-side, no SPA round-trip);
		// the legacy /hmgr/auth/callback handler was deleted.
		pub.POST("/auth/initiate/:provider", hmgrController.InitiateAuthHandler)
		pub.POST("/auth/exchange-token", hmgrController.ExchangeTokenHandler)
		pub.POST("/pkce/store", hmgrController.StorePKCEVerifierHandler)

		// SAML protocol endpoints. Provider management is now at
		// /authsec/identity-providers (v4); the CRUD handlers under
		// /hmgr/.../saml-providers have been removed.
		pub.POST("/saml/initiate/:provider", hmgrController.InitiateSAMLAuthHandler)
		pub.POST("/saml/acs", hmgrController.HandleSAMLACSHandler)
		pub.POST("/saml/acs/:workspace_id", hmgrController.HandleSAMLACSClientHandler)
		pub.GET("/saml/metadata/:workspace_id", hmgrController.GetSAMLMetadataHandler)

		// Common endpoints
		pub.GET("/login", hmgrController.LoginRedirectHandler)
		pub.GET("/consent", hmgrController.ConsentHandler)
		pub.POST("/consent", hmgrController.ConsentHandler)
		pub.GET("/health", hmgrController.HealthHandler)
		pub.GET("/challenge", hmgrController.LoginChallengeHandler)
	}

	// ── Protected routes requiring authentication ──
	prot := r.Group("/hmgr/admin")
	prot.Use(middlewares.AuthMiddleware())
	{
		// Admin-only routes
		admin := prot.Group("/")
		admin.Use(middlewares.Require("admin", "manage"))
		{
			// User management
			admin.GET("/users", hmgrController.GetUsersHandler)
			admin.POST("/users", hmgrController.CreateUserHandler)
			admin.PUT("/users/:id", hmgrController.UpdateUserHandler)
			admin.DELETE("/users/:id", hmgrController.DeleteUserHandler)

			// Tenant management
			admin.GET("/tenants", hmgrController.GetTenantsHandler)
			admin.POST("/tenants", hmgrController.CreateTenantHandler)
			admin.PUT("/tenants/:id", hmgrController.UpdateTenantHandler)
			admin.DELETE("/tenants/:id", hmgrController.DeleteTenantHandler)

			// (SAML provider management moved to /authsec/identity-providers)

			// Role and permission management
			admin.GET("/roles", hmgrController.GetRolesHandler)
			admin.POST("/roles", hmgrController.CreateRoleHandler)
			admin.PUT("/roles/:id", hmgrController.UpdateRoleHandler)
			admin.DELETE("/roles/:id", hmgrController.DeleteRoleHandler)
			admin.GET("/permissions", hmgrController.GetPermissionsHandler)
			admin.POST("/permissions", hmgrController.CreatePermissionHandler)

			// User role assignments
			admin.POST("/users/:id/roles", hmgrController.AssignUserRoleHandler)
			admin.DELETE("/users/:id/roles/:role_id", hmgrController.RemoveUserRoleHandler)
		}

		// Authenticated user routes (own profile)
		user := prot.Group("/")
		{
			user.GET("/profile", hmgrController.GetProfileHandler)
			user.PUT("/profile", hmgrController.UpdateProfileHandler)
		}
	}
}

// registerOocmgrRoutes registers all OIDC Configuration Manager routes under /oocmgr.
// Previously served by the standalone oath_oidc_configuration_manager microservice.
func registerOocmgrRoutes(r gin.IRouter) {
	ac := platformCtrl.NewOocmgrController()

	v1 := r.Group("/oocmgr")

	v1.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy", "service": "oidc-config-manager", "version": "2.0.0"})
	})

	secured := v1.Group("/")

	// v4: legacy tenant-CRUD / config-edit / per-tenant Hydra-client lookups
	// have all been removed. The IDP lifecycle moved to /authsec/identity-providers.
	// Workspace lifecycle moved to /authsec/uflow/admin and /authsec/applications.
	//
	// The only surviving operator-facing surfaces under /oocmgr are:
	//   * /oocmgr/oidc/raw-hydra-dump   — raw Hydra-client dump for debugging
	//   * /oocmgr/hydra-clients/sync    — reconcile MCP client rows with Hydra
	oidc := secured.Group("/oidc")
	{
		oidc.POST("/raw-hydra-dump", middlewares.AuthMiddleware(), ac.DumpHydraRawData)
	}

	hydraClients := secured.Group("/hydra-clients")
	{
		hydraClients.POST("/sync", ac.SyncHydraClients)
	}
}

// registerAuthmgrRoutes registers all authorization-related routes.
// /authz/* is the single canonical surface for validation, RBAC checks, and group management.
// Legacy /authmgr/* routes have been removed — all consumers must migrate to /authz/*.
func registerAuthmgrRoutes(r gin.IRouter) {
	ac := platformCtrl.NewAuthmgrController()
	authzCtrl := platformCtrl.NewAuthorizationController()

	// Token endpoints. /verify and /oidc are intentionally public and
	// workspace-agnostic: they validate a presented token and return only claims
	// that token already proves — they must never expand the caller's authority
	// or expose another workspace's data beyond the token itself. /generate mints
	// a token and therefore requires authentication.
	tokenGroup := r.Group("/auth/token")
	{
		tokenGroup.POST("/verify", ac.VerifyToken)
		tokenGroup.POST("/generate", middlewares.AuthMiddleware(), ac.GenerateToken)
		tokenGroup.POST("/oidc", ac.OIDCToken)
	}

	// ── /authz/* — single canonical authorization surface ──
	authz := r.Group("/authz")
	authz.Use(middlewares.AuthMiddleware())
	{
		// Profile & status
		authz.GET("/profile", ac.GetProfile)
		authz.GET("/auth-status", ac.GetAuthStatus)

		// Validation
		authz.GET("/validate/token", ac.ValidateToken)
		authz.GET("/validate/scope", ac.ValidateScope)
		authz.GET("/validate/resource", ac.ValidateResource)
		authz.POST("/validate/permissions", ac.ValidatePermissions)

		// RBAC permission checks
		authz.GET("/check/permission", ac.CheckPermission)
		authz.GET("/check/role", ac.CheckRole)
		authz.GET("/check/role-resource", ac.CheckRoleResource)
		authz.GET("/check/permission-scoped", ac.CheckPermissionScoped)
		authz.GET("/check/oauth-scope", ac.CheckOAuthScopePermission)
		authz.GET("/permissions", ac.ListUserPermissions)

		// Per-tool PEP (Phase 4b) — SDK calls this before executing a tool.
		authz.POST("/decision", authzCtrl.Decision)

		// Group management. Reads are available to any authenticated workspace
		// member; mutations require an admin/owner role. All handlers derive the
		// workspace from the JWT (never from query/body) — see authmgr_controller.
		adminOnly := middlewares.RequireWorkspaceRole("owner", "admin")
		authz.GET("/groups", ac.ListGroups)
		authz.GET("/groups/:id", ac.GetGroup)
		authz.GET("/groups/:id/users", ac.ListGroupUsers)
		authz.POST("/groups", adminOnly, ac.CreateGroup)
		authz.PUT("/groups/:id", adminOnly, ac.UpdateGroup)
		authz.DELETE("/groups/:id", adminOnly, ac.DeleteGroup)
		authz.POST("/groups/:id/users", adminOnly, ac.AddUsersToGroup)
		authz.DELETE("/groups/:id/users", adminOnly, ac.RemoveUsersFromGroup)
	}
}

// registerLogsRoutes registers the Logs API under /logs. All routes are
// admin-only and workspace-scoped; handlers read workspace_id from the JWT
// context set by ValidateWorkspaceFromToken and serve the existing audit tables.
func registerLogsRoutes(r gin.IRouter) {
	lc := platformCtrl.NewLogsController()

	logs := r.Group("/logs")
	logs.Use(
		middlewares.AuthMiddleware(),
		middlewares.RequireWorkspaceRole("owner", "admin"),
		middlewares.ValidateWorkspaceFromToken(),
	)
	{
		logs.GET("/auth/paginated", lc.GetAuthLogs)
		logs.GET("/audit/paginated", lc.GetAuditLogs)
		logs.GET("/m2m/paginated", lc.GetM2MLogs)
		logs.GET("/status", lc.GetStatus)
		logs.POST("/admin/fluent-bit", lc.ConfigureFluentBit)
	}
}

// registerSpireRoutes registers all SPIRE Headless routes under /spire.
// Previously served by the standalone spire-headless microservice.
func registerSpireRoutes(r gin.IRouter) {
	sc := platformCtrl.NewSpireController()
	platformCtrl.SetSharedSpireController(sc)

	spire := r.Group("/spire")

	spire.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy", "service": "spire-headless", "version": "1.0.0"})
	})

	// ── OIDC discovery (no auth required) ──
	spire.GET("/.well-known/openid-configuration", sc.OIDCDiscovery)
	spire.GET("/.well-known/jwks.json", sc.OIDCJWKSHandler)

	// ── Registry (requires authentication) ──
	registry := spire.Group("/registry", middlewares.AuthMiddleware())
	{
		registry.POST("/workloads", sc.RegisterWorkload)
		registry.PUT("/workloads/:id", sc.UpdateWorkload)
		registry.DELETE("/workloads/:id", sc.DeleteWorkload)
		registry.GET("/workloads", sc.ListWorkloads)
	}

	// ── OIDC token operations ──
	oidc := spire.Group("/oidc")
	{
		oidc.POST("/token", sc.OIDCTokenExchange)
		oidc.POST("/introspect", sc.OIDCIntrospect)
		oidc.POST("/revoke", sc.OIDCRevoke)
		oidc.POST("/exchange/spiffe", sc.OIDCExchangeSPIFFE)
		oidc.POST("/issue/jwt-svid", sc.OIDCIssueJWTSVID)
		oidc.POST("/exchange/cloud", sc.OIDCExchangeCloud)
		oidc.POST("/exchange/aws", sc.OIDCExchangeAWS)
		oidc.POST("/exchange/azure", sc.OIDCExchangeAzure)
		oidc.POST("/exchange/gcp", sc.OIDCExchangeGCP)
	}

	// ── Policy engine ──
	policy := spire.Group("/policy")
	{
		policy.POST("", sc.CreatePolicy)
		policy.GET("", sc.ListPolicies)
		policy.GET("/:id", sc.GetPolicy)
		policy.PUT("/:id", sc.UpdatePolicy)
		policy.DELETE("/:id", sc.DeletePolicy)
		policy.POST("/evaluate", sc.EvaluatePolicy)
		policy.POST("/batch-evaluate", sc.BatchEvaluatePolicy)
		policy.POST("/test", sc.TestPolicy)
	}

	// ── Role bindings ──
	roles := spire.Group("/roles")
	{
		roles.POST("/bind", sc.BindRole)
		roles.POST("/unbind", sc.UnbindRole)
		roles.GET("/bindings", sc.ListRoleBindings)
	}

	// ── Audit (admin + workspace-scoped) ──
	audit := spire.Group("/audit")
	audit.Use(
		middlewares.AuthMiddleware(),
		middlewares.RequireWorkspaceRole("owner", "admin"),
		middlewares.ValidateWorkspaceFromToken(),
	)
	{
		audit.GET("/logs", sc.GetAuditLogs)
		audit.GET("/logs/export", sc.ExportAuditLogs)
	}
}
