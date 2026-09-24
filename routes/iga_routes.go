package routes

import (
	platformCtrl "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/gin-gonic/gin"
)

// SetupIGARoutes mounts the Agentic IGA surface, /api/iga/v1, on r: the
// GitHub provider ingress, the Phase 1 routes behind the shared
// AuthMiddleware and permission middleware, and the Phase 2 graph catalogue
// (SPEC-iga-phase2-graph.md §5.3) on its own group.
//
// It is its own function, and exported, for one reason: SetupRoutes cannot be
// built in a test without the whole platform (every controller it constructs
// needs the platform database, and several log.Fatalf without it), so the
// wiring D-9 depends on -- which middlewares guard the graph routes, and how
// their denials are rendered -- would otherwise be tested only through a
// copy. SetupRoutes calls this, and the frozen-contract test
// (tests/integration/p2_contract_errors_test.go) mounts THIS, with the
// production middlewares, so a graph route's 401 and 403 are proven where
// production defines them (D-100). That test also checks that SetupRoutes
// calls SetupIGARoutes and that the graph catalogue is mounted nowhere else.
//
// The authenticated workspace is established by AuthMiddleware and is never
// read from a body, query parameter or provider identifier. Different prefix,
// different tables (iga_*), different permissions (iga:*) from the
// /authsec/discovery/* surface, so nothing in the working discovery path can
// be affected.
func SetupIGARoutes(r gin.IRouter, igaController *platformCtrl.IGAController, igaGraphRead *platformCtrl.IGAGraphReadController) {
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

		// Phase 2 graph reads (SPEC §5.3) live in iga_graph_read_controller.go.
		// The graph branch's GET /workloads/:id/access-path and
		// POST /estate/:id/classification were removed (§6.1): §5.3 replaces
		// both, with revisions, typed refs and operation ids.
		// The whole §5.3 graph catalogue, with its permissions, is one table
		// in iga_graph_read_routes.go so tests assert the same one.
		//
		// D-9: a graph route's 401 and 403 are the §5.2 envelope, like
		// every other error on it. So the catalogue is mounted on its own
		// group, behind the SAME AuthMiddleware and the SAME permission
		// middleware, each wrapped by GraphEnvelope, which rewrites only
		// the body of a denial -- never the decision. The Phase 1 routes
		// on this group keep the shared middlewares' bodies.
		platformCtrl.MountIGAGraphReadRoutes(r, igaGraphRead, middlewares.AuthMiddleware(), middlewares.Require)
		iga.GET("/classification-candidates", middlewares.Require("iga", "review"), igaController.ListCandidates)

		// Governance decisions. Both require an expected version, so a
		// stale decision is rejected rather than last-write-wins.
		iga.POST("/classification-candidates/:candidate_id/decisions", middlewares.Require("iga", "review"), igaController.DecideCandidate)
		iga.POST("/ownership-candidates/:candidate_id/decisions", middlewares.Require("iga", "review"), igaController.DecideOwnership)
	}
}
