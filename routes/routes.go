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
		// Consent grant management (user self-service, authenticated)
		oauthSelfService := oauth.Group("")
		oauthSelfService.Use(middlewares.AuthMiddleware())
		{
			oauthSelfService.GET("/consent-grants", oauthASController.ListUserConsentGrants)
			oauthSelfService.DELETE("/consent-grants/:id", oauthASController.RevokeUserConsentGrant)
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

			// Access policy + validate + access surface
			applications.GET("/:id/access-policy", rsController.GetAccessPolicy)
			applications.PUT("/:id/access-policy", rsController.UpdateAccessPolicy)
			applications.GET("/:id/access", rsController.GetAccessPolicy) // alias used by the new UI
			applications.POST("/:id/validate", rsController.Validate)
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
				v1Applications.GET("/:id/access-assignments", scopeMatrixController.ListRSBindings)
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
			adminRBAC.POST("/agents/:id/provision-identity", agentController.ProvisionIdentity)
			adminRBAC.DELETE("/agents/:id/revoke-identity", agentController.RevokeIdentity)
			adminRBAC.POST("/agents/:id/delegate-token", agentController.DelegateToken)
			adminRBAC.POST("/agents/:id/revoke-token", sdkTokenController.RevokeDelegationToken)

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
				enduserAuth.POST("/delegate-svid", spiffeDelegateController.DelegateSVID)
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

			// CIBA
			ciba := auth.Group("/ciba")
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
		// SPIRE Headless (formerly spire-headless microservice)
		// Served under /authsec/spire.
		// ────────────────────────────────────────────────────
		registerSpireRoutes(authsec)

		// ────────────────────────────────────────────────────
		// SPIRE Identity Service (merged from authsec-spire)
		// Served under /authsec/spiresvc.
		// ────────────────────────────────────────────────────
		if spireDeps != nil {
			spiresvc := authsec.Group("/spiresvc")
			spire.RegisterRoutes(spiresvc, spireDeps)
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

		// Legacy login/register endpoints
		uflow.POST("/register/verify", userController.VerifyOTPAndCompleteRegistration)
		uflow.POST("/login/webauthn-callback", userController.WebAuthnCallback)
		uflow.POST("/login", userController.Login)

		// Misrouted health-check helpers for monitoring
		uflow.GET("/spire/health", func(c *gin.Context) {
			c.JSON(404, gin.H{"error": "Health check URL misconfigured", "correct_url": "/spiresvc/health"})
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

	// Token endpoints — /verify is public, /generate and /oidc require auth.
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

		// Group management
		authz.POST("/groups", ac.CreateGroup)
		authz.GET("/groups", ac.ListGroups)
		authz.GET("/groups/:id", ac.GetGroup)
		authz.PUT("/groups/:id", ac.UpdateGroup)
		authz.DELETE("/groups/:id", ac.DeleteGroup)
		authz.POST("/groups/:id/users", ac.AddUsersToGroup)
		authz.DELETE("/groups/:id/users", ac.RemoveUsersFromGroup)
		authz.GET("/groups/:id/users", ac.ListGroupUsers)
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

	// ── Audit ──
	audit := spire.Group("/audit")
	{
		audit.GET("/logs", sc.GetAuditLogs)
		audit.GET("/logs/export", sc.ExportAuditLogs)
	}
}
