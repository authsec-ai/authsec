package routes

import (
	platformCtrl "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// MountRuntimePolicy registers /api/iga/v2/runtime-policies when IGA_V2_POLICY
// is on. When the flag is off the routes are not registered, so a request is
// 404 and nothing is evaluated. auth is the existing user middleware.
func MountRuntimePolicy(r gin.IRouter, db *gorm.DB, auth gin.HandlerFunc) {
	if r == nil || db == nil || auth == nil || !services.V2PolicyEnabled() {
		return
	}
	svc := services.NewRuntimePolicyService(db)
	svc.SetIGAAudit(services.NewIGAAuditService(db))
	MountRuntimePolicyService(r, svc, auth)

	// Per-workload policy bindings (needs db directly).
	wbSvc := services.NewWorkloadBindingService(db)
	wbCtl := platformCtrl.NewWorkloadBindingController(wbSvc)
	wb := r.Group("/api/iga/v2/workloads/:id/runtime-policy-binding", auth)
	wb.GET("", middlewares.Require("runtime_policy", "read"), wbCtl.Get)
	wb.PUT("", middlewares.Require("runtime_policy", "write"), wbCtl.Put)

	// BG05: policy context preparation (needs db directly).
	pcSvc := services.NewPolicyContextService(db)
	pcCtl := platformCtrl.NewPolicyContextController(pcSvc)
	ctxG := r.Group("/api/iga/v2/runtime-policies/contexts", auth)
	ctxG.POST("", middlewares.Require("runtime_policy", "write"), pcCtl.Prepare)
	ctxG.GET("/:id", middlewares.Require("runtime_policy", "read"), pcCtl.Get)
}

// MountRuntimePolicyService registers the runtime-policy routes on an
// existing service. Production uses MountRuntimePolicy, which loads the
// certified profile registry and does not enable test digests.
func MountRuntimePolicyService(r gin.IRouter, svc *services.RuntimePolicyService, auth gin.HandlerFunc) {
	if r == nil || svc == nil || auth == nil || !services.V2PolicyEnabled() {
		return
	}
	ctl := platformCtrl.NewRuntimePolicyController(svc)
	g := r.Group("/api/iga/v2/runtime-policies", auth)

	g.GET("", middlewares.Require("runtime_policy", "read"), ctl.List)
	g.GET("/simulations/:simulation_id", middlewares.Require("runtime_policy", "read"), ctl.GetSimulation)
	g.POST("/candidates", middlewares.Require("runtime_policy", "write"), ctl.CreateCandidate)
	g.POST("", middlewares.Require("runtime_policy", "write"), ctl.Create)

	g.GET("/:id", middlewares.Require("runtime_policy", "read"), ctl.Get)
	g.GET("/:id/rollouts", middlewares.Require("runtime_policy", "read"), ctl.GetRollout)
	g.PUT("/:id/draft", middlewares.Require("runtime_policy", "write"), ctl.PutDraft)
	g.POST("/:id/validate", middlewares.Require("runtime_policy", "write"), ctl.Validate)
	g.POST("/:id/simulations", middlewares.Require("runtime_policy", "write"), ctl.Simulate)
	g.POST("/:id/approvals", middlewares.Require("runtime_policy", "approve"), ctl.Approve)
	g.POST("/:id/publications", middlewares.Require("runtime_policy", "enforce"), ctl.Publish)
	g.POST("/:id/rollback", middlewares.Require("runtime_policy", "enforce"), ctl.Rollback)
	g.POST("/:id/revoke", middlewares.Require("runtime_policy", "enforce"), ctl.Revoke)
	g.GET("/:id/revisions/:revision/artifacts", middlewares.Require("runtime_policy", "read"), ctl.GetRevisionArtifacts)

	g.GET("/candidates/:candidate_id", middlewares.Require("runtime_policy", "read"), ctl.GetCandidate)

	// Batch 11 (S14): per-workload enforcement capabilities.
	capCtl := platformCtrl.NewCapabilityController()
	caps := r.Group("/api/iga/v2/runtime-policy-capabilities", auth)
	caps.GET("", middlewares.Require("runtime_policy", "read"), capCtl.GetCapabilities)
}
