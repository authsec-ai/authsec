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
// in this build with the §7.1 owners routes (T3.07) and the §7.1 / §7.2
// reads of T3.06b (iga_gov_findings_controller.go); the other §7 routes are
// added to RegisterIGAPolicyRoutes by the tasks that implement them, and
// inherit the gate by being in the group.

// IGAGovPolicyController serves /api/iga/v1/policy.
type IGAGovPolicyController struct {
	gate func() *services.PolicyGate
	db   func() *gorm.DB
	// key signs list cursors: the graph controller's (IGA_CURSOR_SECRET).
	key []byte
}

// Policy returns the policy controller over this graph controller's database
// and policy gate, so the gate /capabilities reports is the gate the policy
// routes enforce -- one source, never two that can disagree.
func (ctl *IGAGraphReadController) Policy() *IGAGovPolicyController {
	return &IGAGovPolicyController{gate: ctl.policyGateFn(), db: ctl.db, key: ctl.key}
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
}

// policyFeatures are the §4.3 flags in this build. A feature whose routes
// have not landed is false with its own reason even with the gate on; the
// task that mounts a feature's routes flips its served (findings: T3.06b).
var policyFeatures = []policyFeature{
	// T3.06 / T3.06b: evaluation in the projection job and the §7.1 reads.
	{"findings", true, ""},
	{"proposals", false, "Policy proposals are not available in this build yet: policy authoring and proposal generation have not been released."},
	{"export", false, "Policy export is not available in this build yet."},
	{"iac", false, "Infrastructure-as-code pull requests are not available in this build: IaC sources and the pull-request adapter have not been released."},
	{"enforcement", false, "Direct enforcement is not available in this build: the AuthSec enforcement role binding and the AWS enforcement adapter have not been released, so every workspace is findings-only."},
	{"slack", false, "Slack approvals are not available in this build: the Slack app has not been released."},
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
		out[f.name] = available
		switch {
		case available:
		case !on:
			reasons[f.name] = reason
		default:
			reasons[f.name] = f.notServed
		}
	}
	out["reasons"] = reasons
	return out
}
