package platform

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/services"
)

// The Phase 3 policy surface, /api/iga/v1/policy (SPEC-iga-phase3-policy.md
// §7, T3.02): a subgroup of the graph route group -- the same AuthMiddleware
// and §5.2 envelope (GraphEnvelope / GraphRequire) -- behind the IGA_POLICY
// gate. With the gate off or unverified, EVERY route under it answers
//
//	503 {"error": {"code": "policy_unavailable", "message": "...", "detail": {"reason": "..."}}}
//
// with the same reason GET /api/iga/v1/capabilities reports in policy.reason,
// before any permission or handler runs. GET /policy/status is mounted
// in this build with the §7.1 owners routes (T3.07), the §7.1 / §7.2
// reads of T3.06b (iga_gov_findings_controller.go), the §7.4 owner review
// (T3.12) and the §7.8 settings and events (T3.20); the other §7 routes are
// added to RegisterIGAPolicyRoutes by the tasks that implement them, and
// inherit the gate by being in the group.

// IGAGovPolicyController serves /api/iga/v1/policy.
type IGAGovPolicyController struct {
	gate func() *services.PolicyGate
	db   func() *gorm.DB
	// key signs list cursors: the graph controller's (IGA_CURSOR_SECRET).
	key []byte
	// live is the compiler's discovery-role live reader (T3.11).
	live func() services.LiveReader
}

// Policy returns the policy controller over this graph controller's database
// and policy gate, so the gate /capabilities reports is the gate the policy
// routes enforce -- one source, never two that can disagree.
func (ctl *IGAGraphReadController) Policy() *IGAGovPolicyController {
	live := func() services.LiveReader { return services.DefaultGovLiveReader() }
	if ctl.govLive != nil {
		r := ctl.govLive
		live = func() services.LiveReader { return r }
	}
	return &IGAGovPolicyController{gate: ctl.policyGateFn(), db: ctl.db, key: ctl.key, live: live}
}

// WithGovLiveReader makes the policy routes compile with r instead of the
// process-wide live reader. Tests use it.
func (ctl *IGAGraphReadController) WithGovLiveReader(r services.LiveReader) *IGAGraphReadController {
	ctl.govLive = r
	return ctl
}

// WithPolicyGate makes this controller (and its Policy() controller) read the
// given gate instead of the process-wide one. Tests use it.
func (ctl *IGAGraphReadController) WithPolicyGate(g *services.PolicyGate) *IGAGraphReadController {
	ctl.policyGate = func() *services.PolicyGate { return g }
	return ctl
}

// policyGateFn is the gate this controller reads: the one a test installed,
// else the process-wide gate, read on every request so a gate verified after
// startup is served as soon as it is.
func (ctl *IGAGraphReadController) policyGateFn() func() *services.PolicyGate {
	if ctl.policyGate != nil {
		return ctl.policyGate
	}
	return services.PolicyGateState
}

// MountIGAPolicyRoutes mounts /api/iga/v1/policy on its own /api/iga/v1 group
// of r: behind auth wrapped by GraphEnvelope (the graph group's contract), then
// the IGA_POLICY gate, then each route's permission built by require wrapped
// by GraphEnvelope. Production calls it from routes.SetupIGARoutes.
func MountIGAPolicyRoutes(r gin.IRouter, ctl *IGAGovPolicyController, auth gin.HandlerFunc, require func(resource, action string) gin.HandlerFunc) {
	g := r.Group("/api/iga/v1")
	g.Use(GraphEnvelope(auth))
	policy := g.Group("/policy")
	policy.Use(ctl.Gate())
	RegisterIGAPolicyRoutes(policy, ctl, GraphRequire(require))
}

// RegisterIGAPolicyRoutes is the Phase 3 route table, on a group that already
// carries auth and the gate. One table, so tests assert the same one.
func RegisterIGAPolicyRoutes(g gin.IRoutes, ctl *IGAGovPolicyController, require func(resource, action string) gin.HandlerFunc) {
	g.GET("/status", require("governance", "read"), ctl.GetStatus)

	// §7.1 owners (T3.07, iga_gov_owners_controller.go).
	g.GET("/owners", require("governance", "read"), ctl.GetOwners)
	g.PUT("/owners", require("iga", "admin"), ctl.PutOwners)
	g.PATCH("/owners/:id", require("iga", "admin"), ctl.PatchOwner)
	g.GET("/owner-rules", require("iga", "admin"), ctl.ListOwnerRules)
	g.POST("/owner-rules", require("iga", "admin"), ctl.CreateOwnerRule)
	g.DELETE("/owner-rules/:id", require("iga", "admin"), ctl.DeleteOwnerRule)

	// §7.1 / §7.2 reads (T3.06b): findings at a revision, readiness, target
	// resolution and evidence bundles.
	g.GET("/findings", require("governance", "read"), ctl.ListFindings)
	g.GET("/findings/summary", require("governance", "read"), ctl.FindingsSummary)
	g.GET("/findings/:id", require("governance", "read"), ctl.GetFinding)
	g.GET("/identities/:id/activity-evidence", require("governance", "read"), ctl.ActivityEvidence)
	g.GET("/readiness", require("governance", "read"), ctl.GetReadiness)
	g.POST("/targets/resolve", require("governance", "read"), ctl.ResolveTargets)
	g.GET("/evidence-bundles/:id", require("governance", "read"), ctl.GetEvidenceBundle)

	// §7.4 owner review (T3.12, iga_gov_reviews_controller.go). The member
	// routes check ownership in the handler, with governance:read as the
	// fallback for a caller who is not an owner.
	g.GET("/reviews", ctl.ListReviews(require("governance", "read")))
	g.GET("/reviews/:id", ctl.GetReview(require("governance", "read")))
	g.POST("/reviews/:id/respond", ctl.RespondReview)
	g.POST("/reviews/:id/exception", require("governance", "approve"), ctl.ExceptReview)
	g.POST("/reviews/:id/remind", require("governance", "author"), ctl.RemindReview)

	// §7.8 settings and events (T3.20, iga_gov_events_controller.go).
	g.GET("/settings", require("governance", "read"), ctl.GetSettings)
	g.PUT("/settings", require("governance", "enforce"), ctl.PutSettings)
	g.GET("/events", require("governance", "read"), ctl.ListEvents)
	g.GET("/events/export", require("governance", "read"), ctl.ExportEvents)
	g.GET("/events/kinds", require("governance", "read"), ctl.EventKinds)

	// §7.3 policies, versions and plans (T3.11, iga_gov_authoring_controller.go).
	g.GET("/policies", require("governance", "read"), ctl.ListPolicies)
	g.POST("/proposals", require("governance", "author"), ctl.CreateProposal)
	g.GET("/policies/:id", require("governance", "read"), ctl.GetPolicy)
	g.PATCH("/policies/:id", require("governance", "author"), ctl.PatchPolicy)
	g.POST("/policies/:id/pause", require("governance", "enforce"), ctl.PausePolicy)
	g.POST("/policies/:id/resume", require("governance", "enforce"), ctl.ResumePolicy)
	g.POST("/policies/:id/archive", require("governance", "author"), ctl.ArchivePolicy)
	g.GET("/policies/:id/versions", require("governance", "read"), ctl.ListVersions)
	g.POST("/policies/:id/versions", require("governance", "author"), ctl.CreateVersion)
	g.GET("/policies/:id/versions/:no", require("governance", "read"), ctl.GetVersion)
	g.POST("/policies/:id/versions/:no/propose", require("governance", "author"), ctl.ProposeVersion)
	g.GET("/policies/:id/versions/:no/plans", require("governance", "read"), ctl.VersionPlans)
	// §7.3 J1 export (T3.17, iga_gov_export_controller.go).
	g.GET("/policies/:id/versions/:no/export", require("governance", "read"), ctl.ExportVersion)
	g.POST("/policies/:id/versions/:no/withdraw", require("governance", "author"), ctl.WithdrawVersion)

	// §7.5 approval (T3.13, iga_gov_approval_controller.go).
	g.GET("/approvals", require("governance", "approve"), ctl.ListApprovals)
	g.POST("/policies/:id/versions/:no/approve", require("governance", "approve"), ctl.ApproveVersion)
	g.POST("/policies/:id/versions/:no/reject", require("governance", "approve"), ctl.RejectVersion)

	// §7.6 deployments, validations, health reports and §7.7 removing
	// AuthSec control (T3.16, iga_gov_deployments_controller.go). Health
	// reports check "owner of a consumer, or governance:author" in the handler.
	g.GET("/deployments", require("governance", "read"), ctl.ListDeployments)
	g.GET("/deployments/:id", require("governance", "read"), ctl.GetDeployment)
	g.POST("/deployments/:id/resolve", require("governance", "enforce"), ctl.ResolveDeployment)
	g.POST("/deployments/:id/undo", require("governance", "enforce"), ctl.UndoDeployment)
	g.POST("/deployments/:id/emergency-undo", require("governance", "emergency"), ctl.EmergencyUndoDeployment)
	g.POST("/deployments/:id/validations", require("governance", "author"), ctl.DeclareValidation)
	g.GET("/deployments/:id/validations", require("governance", "read"), ctl.ListValidations)
	g.POST("/deployments/:id/health-reports", ctl.CreateHealthReport)
	g.GET("/deployments/:id/health-reports", require("governance", "read"), ctl.ListHealthReports)
	g.POST("/policies/:id/remove-control", require("governance", "author"), ctl.RemoveControl)
	g.POST("/policies/:id/emergency-remove-control", require("governance", "emergency"), ctl.EmergencyRemoveControl)
	// §7.5 rollout (T3.15, iga_gov_rollout_controller.go).
	g.GET("/policies/:id/rollout", require("governance", "read"), ctl.GetRollout)
	g.POST("/policies/:id/rollout/start", require("governance", "enforce"), ctl.StartRollout)
	g.POST("/policies/:id/rollout/expand", require("governance", "enforce"), ctl.ExpandRollout)
	g.POST("/policies/:id/rollout/pause", require("governance", "enforce"), ctl.PauseRollout)
	g.POST("/policies/:id/rollout/resume", require("governance", "enforce"), ctl.ResumeRollout)
}

// Gate is the IGA_POLICY middleware: 503 policy_unavailable, with the gate's
// reason, unless the gate is on (switch on, graph on and verified, Phase 3
// schema verified). Fail closed: a nil gate is off.
func (ctl *IGAGovPolicyController) Gate() gin.HandlerFunc {
	return func(c *gin.Context) {
		var gate *services.PolicyGate
		if ctl.gate != nil {
			gate = ctl.gate()
		}
		state, reason, _ := gate.Status()
		if state != services.PolicyOn {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, PolicyUnavailableBody(reason))
			return
		}
		c.Next()
	}
}

// PolicyUnavailableBody is the 503 body every Phase 3 route answers while the
// gate is not on (§7.12 policy_unavailable).
func PolicyUnavailableBody(reason string) gin.H {
	return gin.H{"error": gin.H{
		"code":    "policy_unavailable",
		"message": "The policy product is not available.",
		"detail":  gin.H{"reason": reason},
	}}
}

// GetStatus handles GET /api/iga/v1/policy/status: the gate as the routes see
// it. Reaching the handler means the gate is on; it exists so the gate is
// testable end to end before the §7 routes land.
func (ctl *IGAGovPolicyController) GetStatus(c *gin.Context) {
	if _, ok := tokenWorkspace(c); !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": gin.H{
			"code": "unauthenticated", "message": "No workspace in the token."}})
		return
	}
	state, _, head := ctl.gate().Status()
	c.JSON(http.StatusOK, gin.H{"data": gin.H{
		"state":       state,
		"schema_head": nullIfEmpty(head),
	}})
}

// policyFeature is one flag of the /capabilities policy block (§4.3).
type policyFeature struct {
	name string
	// served is true once this build implements the routes the feature names;
	// notServed is the reason shown while it does not. A flag is true only
	// when served AND the gate is on (D-11's rule for graph features: a
	// feature reported available with no route behind it renders as empty
	// rather than unavailable).
	served    bool
	notServed string
	// available, when set, is a runtime condition on a served feature
	// (Slack: the app is configured on this server), with its reason.
	available func() (bool, string)
}

// policyFeatures are the §4.3 flags in this build. A feature whose routes
// have not landed is false with its own reason even with the gate on; the
// task that mounts a feature's routes flips its served (findings: T3.06b).
var policyFeatures = []policyFeature{
	// T3.06 / T3.06b: evaluation in the projection job and the §7.1 reads.
	{"findings", true, "", nil},
	// T3.11 / T3.13: proposals, versions, plans and approval (§7.3, §7.5).
	{"proposals", true, "", nil},
	// T3.17: J1 export (GET .../export, export deployments) and J2 IaC
	// delivery (IaC sources under /authsec/discovery/aws, the PR adapter,
	// iac_sync).
	{"export", true, "", nil},
	{"iac", true, "", nil},
	// T3.09 ships the enforcement role binding (§7.9, under
	// /authsec/discovery/aws/connectors/:id/enforcement); the flag stays
	// false because direct enforcement also needs the AWS enforcement adapter
	// (T3.10) and deployments (T3.15/T3.16), which are not in this build.
	{"enforcement", false, "Direct enforcement is not available in this build: the AuthSec enforcement role can be bound and self-tested, but the AWS enforcement adapter and deployments have not been released, so every workspace is findings-only.", nil},
	// T3.14: the Slack app's routes (/authsec/integrations/slack) are in this
	// build; the flag is true only while the app is configured on this
	// server (signing secret, Vault credentials) and installed at startup.
	{"slack", true, "", services.SlackAvailable},
}

// policyProviders is §4.3's provider support for R1a, with the reason for the
// unsupported one (§1.2: Kubernetes needs K-1 to K-3 first).
var (
	policyProviders       = gin.H{"aws": "supported", "k8s": "not_supported"}
	policyProviderReasons = gin.H{"k8s": "Kubernetes is not supported for policy in this release: it needs an authenticated, ordered RBAC ingest (K-1), revisioned Kubernetes reads (K-2) and an actuation credential (K-3)."}
)

// policyCapabilities is the "policy" block of GET /api/iga/v1/capabilities
// (§4.3): the gate (state, reason, schema_head), one boolean per feature with
// a reason in "reasons" for every false one, and provider support.
func policyCapabilities(gate *services.PolicyGate) gin.H {
	state, reason, head := gate.Status()
	on := state == services.PolicyOn
	out := gin.H{
		"state":            state,
		"reason":           nil,
		"schema_head":      nullIfEmpty(head),
		"providers":        policyProviders,
		"provider_reasons": policyProviderReasons,
	}
	if !on {
		out["reason"] = reason
	}
	reasons := gin.H{}
	for _, f := range policyFeatures {
		available := on && f.served
		why := f.notServed
		if available && f.available != nil {
			available, why = f.available()
		}
		out[f.name] = available
		switch {
		case available:
		case !on:
			reasons[f.name] = reason
		default:
			reasons[f.name] = why
		}
	}
	out["reasons"] = reasons
	return out
}
