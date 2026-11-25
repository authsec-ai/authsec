package platform

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentcontain"
	"github.com/authsec-ai/authsec/services"
)

// Agent containment routes (SPEC-agent-runtime-visibility.md §5.8, §10;
// services/agent_runtime_contain.go):
//
//	POST /api/iga/v1/agent-runtime/containments/preview      governance:enforce  blast radius; stores nothing
//	POST /api/iga/v1/agent-runtime/containments              governance:enforce  (+ governance:emergency for level identity)
//	GET  /api/iga/v1/agent-runtime/containments?state=&limit= governance:read
//	GET  /api/iga/v1/agent-runtime/containments/:id          governance:read
//	POST /api/iga/v1/agent-runtime/containments/:id/release  governance:enforce  tier 3: a release request (409 held_by_cases while held)
//	POST .../containments/:id/holds                          governance:enforce  {case_id}: another case holds the stop
//	POST .../containments/:id/holds/:case/release            governance:enforce  tier 3: a release request for that case's hold
//	POST .../containments/:id/release-requests/:rid/approve  governance:approve  a DIFFERENT user applies it
//	POST .../containments/:id/release-requests/:rid/reject   governance:enforce  the author withdraws; an approver rejects
//	POST .../containments/:id/release-requests/:rid/review   governance:approve  review of a break-glass release
//	POST .../containments/:id/probe                          governance:enforce  active probe with AuthSec's own credentials
//	POST .../containments/:id/narrow                         governance:enforce  a narrower stop; the wider one ends once it is proven
//
// Mounted on their own /api/iga/v1 group with the policy surface's contract:
// AuthMiddleware wrapped by GraphEnvelope, the policy gate (503
// policy_unavailable), then 503 agent_containment_unavailable until R2,
// AWS access and migration 151 are in place. The workspace is the token's
// only; another workspace's identity, workload or containment is 404. No
// approval (§10 Q6).
//
// DECISION P3-7 (permissions, as R2): containing and releasing need
// governance:enforce. Identity-level containment stops every workload on the
// role at once and revokes its sessions, which R2 lets only an emergency
// actor do without approval: it needs governance:emergency as well
// (spec §5.8 "emergency: governance:emergency, as R2").

// MountAgentRuntimeContainRoutes mounts the containment routes on r.
// Production calls it from routes.SetupIGARoutes.
func MountAgentRuntimeContainRoutes(r gin.IRouter, ctl *IGAGovPolicyController, auth gin.HandlerFunc, require func(resource, action string) gin.HandlerFunc) {
	g := r.Group("/api/iga/v1/agent-runtime")
	g.Use(GraphEnvelope(auth))
	g.Use(ctl.Gate())
	RegisterAgentRuntimeContainRoutes(g, ctl, GraphRequire(require))
}

// RegisterAgentRuntimeContainRoutes is the route table, on a group that
// already carries auth and the policy gate.
func RegisterAgentRuntimeContainRoutes(g gin.IRoutes, ctl *IGAGovPolicyController, require func(resource, action string) gin.HandlerFunc) {
	gate := ctl.containGate()
	g.POST("/containments/preview", gate, require("governance", "enforce"), ctl.PreviewContainment)
	g.POST("/containments", gate, require("governance", "enforce"), ctl.CreateContainment)
	g.GET("/containments", gate, require("governance", "read"), ctl.ListContainments)
	g.GET("/containments/:id", gate, require("governance", "read"), ctl.GetContainment)
	g.POST("/containments/:id/release", gate, require("governance", "enforce"), ctl.ReleaseContainment)
	g.POST("/containments/:id/holds", gate, require("governance", "enforce"), ctl.AddContainmentHold)
	g.POST("/containments/:id/holds/:case/release", gate, require("governance", "enforce"), ctl.ReleaseContainmentHold)
	g.POST("/containments/:id/release-requests/:rid/approve", gate, require("governance", "approve"), ctl.ApproveContainmentRelease)
	g.POST("/containments/:id/release-requests/:rid/reject", gate, require("governance", "enforce"), ctl.RejectContainmentRelease)
	g.POST("/containments/:id/release-requests/:rid/review", gate, require("governance", "approve"), ctl.ReviewContainmentRelease)
	g.POST("/containments/:id/probe", gate, require("governance", "enforce"), ctl.ProbeContainment)
	g.POST("/containments/:id/narrow", gate, require("governance", "enforce"), ctl.NarrowContainment)
}

// wideLevels need governance:emergency besides governance:enforce: they stop
// everything the identity does (identity), every assumer of a role (chain),
// a whole Entra principal (entra) or a ServiceAccount's every binding
// (kubernetes) -- tier 2 (SecOps P3).
var wideLevels = map[string]bool{agentcontain.LevelIdentity: true, agentcontain.LevelChain: true,
	agentcontain.LevelEntra: true, agentcontain.LevelKubernetes: true}

func (ctl *IGAGovPolicyController) requireWide(c *gin.Context, ws, actor uuid.UUID, level string) error {
	if !wideLevels[level] {
		return nil
	}
	ok, err := ctl.contain().HoldsPermission(c.Request.Context(), ws, actor, "governance", "emergency")
	if err != nil {
		return err
	}
	if !ok {
		return services.GovForbidden("governance:emergency is required to contain at the " + level + " level (it stops far more than one agent).")
	}
	return nil
}

// containGate answers 503 agent_containment_unavailable while containment
// cannot run on this server.
func (ctl *IGAGovPolicyController) containGate() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TENANT-EXEMPT: the 151 schema check reads the Postgres catalog only.
		if ok, reason := services.AgentContainStatus(ctl.db()); !ok {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": gin.H{"code": services.GovCodeContainUnavailable,
				"message": "Agent containment is not available on this server.", "detail": gin.H{"reason": reason}}})
			return
		}
		c.Next()
	}
}

// TENANT-EXEMPT: not a statement here: AgentContain runs every statement in
// a transaction under row-level security for the token's workspace.
func (ctl *IGAGovPolicyController) contain() *services.AgentContain {
	return services.NewAgentContain(ctl.db())
}

// PreviewContainment handles POST /containments/preview: a read with a body.
func (ctl *IGAGovPolicyController) PreviewContainment(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		var req services.AgentContainPreviewRequest
		if err := bindBody(c, &req, "{identity_id, workload_ids?}"); err != nil {
			return nil, nil, err
		}
		out, err := ctl.contain().Preview(c.Request.Context(), ws, req)
		return out, nil, err
	})
}

// CreateContainment handles POST /containments.
func (ctl *IGAGovPolicyController) CreateContainment(c *gin.Context) {
	ctl.govMutation(c, http.StatusCreated, func(ws, actor uuid.UUID) (any, *audited, error) {
		var req services.AgentContainRequest
		if err := bindBody(c, &req, "{identity_id, workload_ids?, level, reason, target?, case_id?}"); err != nil {
			return nil, nil, err
		}
		if err := ctl.requireWide(c, ws, actor, req.Level); err != nil {
			return nil, nil, err
		}
		out, err := ctl.contain().Contain(c.Request.Context(), ws, actor, req)
		if err != nil {
			return nil, nil, err
		}
		return out, &audited{"agent_containment_request", "agent_containment", out.ID.String(), nil,
			gin.H{"identity_id": out.IdentityID, "identity_arn": out.IdentityARN, "level": out.Level, "workload_ids": out.WorkloadIDs,
				"reason": out.Reason, "target": out.Target, "case_id": req.CaseID}}, nil
	})
}

// ListContainments handles GET /containments (?state=a,b, ?limit).
func (ctl *IGAGovPolicyController) ListContainments(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		limit := 0
		if s := c.Query("limit"); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < 1 || n > services.MaxGovPage {
				return nil, nil, services.GovBadParam("limit", "limit must be 1..200.")
			}
			limit = n
		}
		out, err := ctl.contain().List(c.Request.Context(), ws, c.Query("state"), limit)
		return out, nil, err
	})
}

// GetContainment handles GET /containments/:id.
func (ctl *IGAGovPolicyController) GetContainment(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		out, err := ctl.contain().Get(c.Request.Context(), ws, id)
		return out, nil, err
	})
}

// ReleaseContainment handles POST /containments/:id/release.
func (ctl *IGAGovPolicyController) ReleaseContainment(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var req services.AgentContainReleaseRequest
		if err := bindBody(c, &req, "{reason}"); err != nil {
			return nil, nil, err
		}
		out, err := ctl.contain().Release(c.Request.Context(), ws, actor, id, req)
		if err != nil {
			return nil, nil, err
		}
		return out, &audited{"agent_containment_release", "agent_containment", id.String(), nil, gin.H{"reason": req.Reason,
			"release_request_id": out.Request.ID, "applied": out.Applied, "break_glass": out.Request.BreakGlass}}, nil
	})
}

// AddContainmentHold handles POST /containments/:id/holds.
func (ctl *IGAGovPolicyController) AddContainmentHold(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var req services.AgentContainHoldRequest
		if err := bindBody(c, &req, "{case_id}"); err != nil {
			return nil, nil, err
		}
		out, err := ctl.contain().AddHold(c.Request.Context(), ws, actor, id, req)
		if err != nil {
			return nil, nil, err
		}
		return out, &audited{"agent_containment_hold", "agent_containment", id.String(), nil, gin.H{"case_id": req.CaseID}}, nil
	})
}

// ReleaseContainmentHold handles POST /containments/:id/holds/:case/release.
func (ctl *IGAGovPolicyController) ReleaseContainmentHold(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		caseID, err := uuidParam(c, "case")
		if err != nil {
			return nil, nil, err
		}
		var req services.AgentContainReleaseRequest
		if err := bindBody(c, &req, "{reason}"); err != nil {
			return nil, nil, err
		}
		out, err := ctl.contain().ReleaseHold(c.Request.Context(), ws, actor, id, caseID, req)
		if err != nil {
			return nil, nil, err
		}
		return out, &audited{"agent_containment_hold_release", "agent_containment", id.String(), nil, gin.H{"case_id": caseID,
			"reason": req.Reason, "release_request_id": out.Request.ID, "applied": out.Applied, "break_glass": out.Request.BreakGlass}}, nil
	})
}

func (ctl *IGAGovPolicyController) releaseDecision(c *gin.Context, action string,
	do func(ws, actor, id, rid uuid.UUID, req services.AgentContainDecisionRequest) (any, error)) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		rid, err := uuidParam(c, "rid")
		if err != nil {
			return nil, nil, err
		}
		var req services.AgentContainDecisionRequest
		if err := bindBody(c, &req, "{reason}"); err != nil {
			return nil, nil, err
		}
		out, err := do(ws, actor, id, rid, req)
		if err != nil {
			return nil, nil, err
		}
		return out, &audited{action, "agent_containment", id.String(), nil, gin.H{"release_request_id": rid, "reason": req.Reason}}, nil
	})
}

// ApproveContainmentRelease handles POST /containments/:id/release-requests/:rid/approve.
func (ctl *IGAGovPolicyController) ApproveContainmentRelease(c *gin.Context) {
	ctl.releaseDecision(c, "agent_containment_release_approve", func(ws, actor, id, rid uuid.UUID, req services.AgentContainDecisionRequest) (any, error) {
		return ctl.contain().ApproveRelease(c.Request.Context(), ws, actor, id, rid, req)
	})
}

// RejectContainmentRelease handles POST /containments/:id/release-requests/:rid/reject.
func (ctl *IGAGovPolicyController) RejectContainmentRelease(c *gin.Context) {
	ctl.releaseDecision(c, "agent_containment_release_reject", func(ws, actor, id, rid uuid.UUID, req services.AgentContainDecisionRequest) (any, error) {
		return ctl.contain().RejectRelease(c.Request.Context(), ws, actor, id, rid, req)
	})
}

// ReviewContainmentRelease handles POST /containments/:id/release-requests/:rid/review.
func (ctl *IGAGovPolicyController) ReviewContainmentRelease(c *gin.Context) {
	ctl.releaseDecision(c, "agent_containment_release_review", func(ws, actor, id, rid uuid.UUID, req services.AgentContainDecisionRequest) (any, error) {
		return ctl.contain().ReviewRelease(c.Request.Context(), ws, actor, id, rid, req)
	})
}

// ProbeContainment handles POST /containments/:id/probe.
func (ctl *IGAGovPolicyController) ProbeContainment(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		out, err := ctl.contain().Probe(c.Request.Context(), ws, actor, id)
		if err != nil {
			return nil, nil, err
		}
		return out, &audited{"agent_containment_probe", "agent_containment", id.String(), nil, gin.H{"result": out.Result}}, nil
	})
}

// NarrowContainment handles POST /containments/:id/narrow.
func (ctl *IGAGovPolicyController) NarrowContainment(c *gin.Context) {
	ctl.govMutation(c, http.StatusCreated, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var req services.AgentContainNarrowRequest
		if err := bindBody(c, &req, "{level, target?, workload_ids?, reason}"); err != nil {
			return nil, nil, err
		}
		if err := ctl.requireWide(c, ws, actor, req.Level); err != nil {
			return nil, nil, err
		}
		out, err := ctl.contain().Narrow(c.Request.Context(), ws, actor, id, req)
		if err != nil {
			return nil, nil, err
		}
		return out, &audited{"agent_containment_narrow", "agent_containment", out.ID.String(), nil, gin.H{"narrowed_from": id,
			"level": out.Level, "target": out.Target, "reason": req.Reason}}, nil
	})
}

// agentContainCapabilities is /capabilities' agent_containment block for
// the token's workspace (services.AgentContainCapabilities): the server's
// state, and per AWS account whether the identity/model levels and the
// workload level (EnableWorkloadContainment) are available, with reasons.
func agentContainCapabilities(c *gin.Context, db *gorm.DB) gin.H {
	if db == nil {
		return gin.H{"available": false, "reason": "no database"}
	}
	ws, _ := tokenWorkspace(c)
	// TENANT-EXEMPT: the 151 schema check reads the Postgres catalog only;
	// the per-account reads run under RLS for the token's workspace.
	return gin.H(services.AgentContainCapabilities(c.Request.Context(), db, ws))
}
