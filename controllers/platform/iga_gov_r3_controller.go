package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/delegation"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/services"
)

// R3 routes (SPEC-iga-phase3-policy.md §12.4; R3).
//
// Management routes live under the gated /api/iga/v1/policy group, with the
// workspace from the member's token (another workspace's row is 404) and
// every mutation audited (iga_gov_event in the service transaction,
// audit_events here). Runtime routes live under /authsec/runtime, behind
// SpiffeAuthMiddleware, and accept ONLY a delegated agent JWT-SVID: the
// workspace is the trust bundle that verified it, the agent its spiffe://
// subject, the human its signed user_id (DECISION R3-3).
//
// DECISION R3-17 (mounting): like R2-21, both route sets are MOUNTED only
// while R3 is available at startup, so without it the route
// table is exactly R2's (the R1a audit walker and route tests see no
// change). Mounted but not available (schema 062 unverified, or policy
// unavailable), management routes answer 422 policy_r3_unavailable and
// runtime routes 503 runtime_unavailable with fail_closed: true.
//
// Permissions: reads governance:read; authoring a runtime policy or version
// governance:author; approving or rejecting a version or a hold
// governance:approve (re-read from the database; the author / initiating
// human never decides); settings, routing proofs, AgentCore push and broker
// roles governance:enforce. Pause / resume / archive of a runtime policy use
// the existing /policies/:id routes.

// RegisterIGAPolicyR3Routes adds the R3 management routes to the policy group.
func RegisterIGAPolicyR3Routes(g gin.IRoutes, ctl *IGAGovPolicyController, require func(resource, action string) gin.HandlerFunc) {
	r3 := R3Gate()
	g.GET("/runtime/policies", r3, require("governance", "read"), ctl.ListRuntimePolicies)
	g.POST("/runtime/policies", r3, require("governance", "author"), ctl.CreateRuntimePolicy)
	g.GET("/runtime/policies/:id", r3, require("governance", "read"), ctl.GetRuntimePolicy)
	g.POST("/runtime/policies/:id/versions", r3, require("governance", "author"), ctl.CreateRuntimeVersion)
	g.POST("/runtime/policies/:id/versions/:no/approve", r3, require("governance", "approve"), ctl.ApproveRuntimeVersion)
	g.POST("/runtime/policies/:id/versions/:no/reject", r3, require("governance", "approve"), ctl.RejectRuntimeVersion)
	g.POST("/runtime/policies/:id/versions/:no/withdraw", r3, require("governance", "author"), ctl.WithdrawRuntimeVersion)
	g.GET("/runtime/policies/:id/versions/:no/cedar", r3, require("governance", "read"), ctl.RuntimeCedar)
	g.POST("/runtime/policies/:id/agentcore/push", r3, require("governance", "enforce"), ctl.PushRuntimeAgentCore)
	g.GET("/runtime/coverage", r3, require("governance", "read"), ctl.RuntimeCoverage)
	g.GET("/runtime/settings", r3, require("governance", "read"), ctl.GetRuntimeSettings)
	g.PUT("/runtime/settings", r3, require("governance", "enforce"), ctl.PutRuntimeSettings)
	g.GET("/runtime/routing-proofs", r3, require("governance", "read"), ctl.ListRoutingProofs)
	g.POST("/runtime/routing-proofs", r3, require("governance", "enforce"), ctl.RecordRoutingProof)
	g.POST("/runtime/routing-proofs/:id/revoke", r3, require("governance", "enforce"), ctl.RevokeRoutingProof)
	g.GET("/runtime/holds", r3, require("governance", "read"), ctl.ListRuntimeHolds)
	g.GET("/runtime/holds/:id", r3, require("governance", "read"), ctl.GetRuntimeHold)
	g.POST("/runtime/holds/:id/approve", r3, require("governance", "approve"), ctl.ApproveRuntimeHold)
	g.POST("/runtime/holds/:id/reject", r3, require("governance", "approve"), ctl.RejectRuntimeHold)
	g.GET("/runtime/decisions", r3, require("governance", "read"), ctl.ListRuntimeDecisions)
	g.GET("/runtime/decisions/:id", r3, require("governance", "read"), ctl.GetRuntimeDecision)
	g.GET("/runtime/budgets", r3, require("governance", "read"), ctl.ListRuntimeBudgets)
	g.GET("/runtime/broker-roles", r3, require("governance", "read"), ctl.ListBrokerRoles)
	g.POST("/runtime/broker-roles", r3, require("governance", "enforce"), ctl.BindBrokerRole)
	g.POST("/runtime/broker-roles/:id/disable", r3, require("governance", "enforce"), ctl.DisableBrokerRole)
}

// R3Gate answers 422 policy_r3_unavailable while the R3 gate is not on.
func R3Gate() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := services.RequirePolicyR3(); err != nil {
			govError(c, err)
			return
		}
		c.Next()
	}
}

// TENANT-EXEMPT: not a statement here: GovR3 runs every statement in a
// transaction under row-level security for the token's workspace.
func (ctl *IGAGovPolicyController) r3() *services.GovR3 { return services.NewGovR3(ctl.db()) }

func (ctl *IGAGovPolicyController) ListRuntimePolicies(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		out, err := ctl.r3().ListRuntimePolicies(c.Request.Context(), ws)
		return out, nil, err
	})
}

func (ctl *IGAGovPolicyController) GetRuntimePolicy(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		out, err := ctl.r3().GetRuntimePolicy(c.Request.Context(), ws, id)
		return out, nil, err
	})
}

func (ctl *IGAGovPolicyController) CreateRuntimePolicy(c *gin.Context) {
	ctl.govMutation(c, http.StatusCreated, func(ws, actor uuid.UUID) (any, *audited, error) {
		var req services.RuntimePolicyRequest
		if err := bindBody(c, &req, "{name, purpose?, intent: {kind: runtime_controls, subjects, tools, budgets?, gateways?}}"); err != nil {
			return nil, nil, err
		}
		out, err := ctl.r3().CreateRuntimePolicy(c.Request.Context(), ws, actor, req)
		if err != nil {
			return nil, nil, err
		}
		return out, &audited{"runtime_policy_create", "iga_gov_policy", out.ID.String(), nil,
			gin.H{"name": out.Name, "family": out.Family, "intent_hash": out.Versions[0].IntentHash}}, nil
	})
}

func (ctl *IGAGovPolicyController) CreateRuntimeVersion(c *gin.Context) {
	ctl.govMutation(c, http.StatusCreated, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var req services.RuntimeVersionRequest
		if err := bindBody(c, &req, "{base_version_no, intent}"); err != nil {
			return nil, nil, err
		}
		v, err := ctl.r3().CreateRuntimeVersion(c.Request.Context(), ws, actor, id, req)
		if err != nil {
			return nil, nil, err
		}
		return v, &audited{"runtime_version_create", "iga_gov_runtime_version", v.ID.String(), nil,
			gin.H{"policy_id": id, "version_no": v.VersionNo, "intent_hash": v.IntentHash}}, nil
	})
}

func (ctl *IGAGovPolicyController) runtimeVersionDecision(c *gin.Context, action string, approve bool) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		no, err := versionNoParam(c)
		if err != nil {
			return nil, nil, err
		}
		var req services.RuntimeDecisionRequest
		if c.Request.ContentLength != 0 {
			if err := bindBody(c, &req, "{intent_hash, reason?}"); err != nil {
				return nil, nil, err
			}
		}
		v, err := ctl.r3().DecideRuntimeVersion(c.Request.Context(), ws, actor, id, no, approve, req)
		if err != nil {
			return nil, nil, err
		}
		return v, &audited{action, "iga_gov_runtime_version", v.ID.String(), nil,
			gin.H{"policy_id": id, "version_no": no, "status": v.Status, "reason": req.Reason}}, nil
	})
}

func (ctl *IGAGovPolicyController) ApproveRuntimeVersion(c *gin.Context) {
	ctl.runtimeVersionDecision(c, "runtime_version_approve", true)
}

func (ctl *IGAGovPolicyController) RejectRuntimeVersion(c *gin.Context) {
	ctl.runtimeVersionDecision(c, "runtime_version_reject", false)
}

func (ctl *IGAGovPolicyController) WithdrawRuntimeVersion(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		no, err := versionNoParam(c)
		if err != nil {
			return nil, nil, err
		}
		var req services.RuntimeDecisionRequest
		if c.Request.ContentLength != 0 {
			if err := bindBody(c, &req, "{reason?}"); err != nil {
				return nil, nil, err
			}
		}
		v, err := ctl.r3().WithdrawRuntimeVersion(c.Request.Context(), ws, actor, id, no, req.Reason)
		if err != nil {
			return nil, nil, err
		}
		return v, &audited{"runtime_version_withdraw", "iga_gov_runtime_version", v.ID.String(), nil,
			gin.H{"policy_id": id, "version_no": no, "reason": req.Reason}}, nil
	})
}

func (ctl *IGAGovPolicyController) RuntimeCedar(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		no, err := versionNoParam(c)
		if err != nil {
			return nil, nil, err
		}
		out, err := ctl.r3().CompileRuntimeCedar(c.Request.Context(), ws, id, no, c.Query("gateway_arn"))
		return out, gin.H{"verified_against_agentcore": false}, err
	})
}

func (ctl *IGAGovPolicyController) PushRuntimeAgentCore(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var req services.AgentCorePushRequest
		if err := bindBody(c, &req, "{gateway_arn}"); err != nil {
			return nil, nil, err
		}
		row, err := ctl.r3().PushAgentCore(c.Request.Context(), ws, actor, id, req)
		if err != nil {
			if row != nil {
				// The failed push is recorded (event in the service); audit it too.
				auditAdminMutation(c, ws.String(), "runtime_agentcore_push", "iga_gov_runtime_agentcore_push", row.ID.String(),
					http.StatusBadGateway, nil, gin.H{"state": row.State, "gateway_arn": row.GatewayARN})
			}
			return nil, nil, err
		}
		return row, &audited{"runtime_agentcore_push", "iga_gov_runtime_agentcore_push", row.ID.String(), nil,
			gin.H{"state": row.State, "gateway_arn": row.GatewayARN, "cedar_hash": row.CedarHash}}, nil
	})
}

func (ctl *IGAGovPolicyController) RuntimeCoverage(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		out, err := ctl.r3().RuntimeCoverage(c.Request.Context(), ws)
		ok, why := services.RuntimeAgentCoreAvailable()
		meta := gin.H{"agentcore_push_available": ok, "verified_against_aws": false}
		if !ok {
			meta["agentcore_push_reason"] = why
		}
		return out, meta, err
	})
}

func (ctl *IGAGovPolicyController) GetRuntimeSettings(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		out, err := ctl.r3().RuntimeSettings(c.Request.Context(), ws)
		return out, nil, err
	})
}

func (ctl *IGAGovPolicyController) PutRuntimeSettings(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		var p services.RuntimeSettingsPatch
		if err := bindBody(c, &p, "{argument_retention?, redact_keys?, retention_days?, decision_ttl_seconds?, hold_timeout_minutes?, approval_valid_minutes?}"); err != nil {
			return nil, nil, err
		}
		before, after, err := ctl.r3().PutRuntimeSettings(c.Request.Context(), ws, actor, p)
		if err != nil {
			return nil, nil, err
		}
		return after, &audited{"runtime_settings_update", "iga_gov_runtime_settings", ws.String(), before, after}, nil
	})
}

func (ctl *IGAGovPolicyController) ListRoutingProofs(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		out, err := ctl.r3().ListRoutingProofs(c.Request.Context(), ws, c.Query("gateway_arn"))
		return out, nil, err
	})
}

func (ctl *IGAGovPolicyController) RecordRoutingProof(c *gin.Context) {
	ctl.govMutation(c, http.StatusCreated, func(ws, actor uuid.UUID) (any, *audited, error) {
		var req services.RoutingProofRequest
		if err := bindBody(c, &req, "{gateway_arn, method, statement, evidence?, valid_days?}"); err != nil {
			return nil, nil, err
		}
		p, err := ctl.r3().RecordRoutingProof(c.Request.Context(), ws, actor, req)
		if err != nil {
			return nil, nil, err
		}
		return p, &audited{"routing_proof_record", "iga_gov_runtime_routing_proof", p.ID.String(), nil,
			gin.H{"gateway_arn": p.GatewayARN, "method": p.Method, "evidence_hash": p.EvidenceHash, "valid_until": p.ValidUntil}}, nil
	})
}

func (ctl *IGAGovPolicyController) RevokeRoutingProof(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var req services.GovDecisionRequest
		if c.Request.ContentLength != 0 {
			if err := bindBody(c, &req, "{reason?}"); err != nil {
				return nil, nil, err
			}
		}
		p, err := ctl.r3().RevokeRoutingProof(c.Request.Context(), ws, actor, id, req.Reason)
		if err != nil {
			return nil, nil, err
		}
		return p, &audited{"routing_proof_revoke", "iga_gov_runtime_routing_proof", id.String(), nil, gin.H{"reason": req.Reason}}, nil
	})
}

func (ctl *IGAGovPolicyController) ListRuntimeHolds(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		limit, err := limitParam(c)
		if err != nil {
			return nil, nil, err
		}
		out, err := ctl.r3().ListHolds(c.Request.Context(), ws, c.Query("state"), limit)
		return out, nil, err
	})
}

func (ctl *IGAGovPolicyController) GetRuntimeHold(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		out, err := ctl.r3().GetHold(c.Request.Context(), ws, id)
		return out, nil, err
	})
}

func (ctl *IGAGovPolicyController) runtimeHoldDecision(c *gin.Context, action string, approve bool) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var req services.GovDecisionRequest
		if c.Request.ContentLength != 0 {
			if err := bindBody(c, &req, "{reason?}"); err != nil {
				return nil, nil, err
			}
		}
		h, err := ctl.r3().DecideHold(c.Request.Context(), ws, actor, id, approve, req.Reason)
		if err != nil {
			return nil, nil, err
		}
		return h, &audited{action, "iga_gov_runtime_hold", id.String(), nil,
			gin.H{"state": h.State, "tool": h.Tool, "agent_ref": h.AgentRef, "reason": req.Reason}}, nil
	})
}

func (ctl *IGAGovPolicyController) ApproveRuntimeHold(c *gin.Context) {
	ctl.runtimeHoldDecision(c, "runtime_hold_approve", true)
}

func (ctl *IGAGovPolicyController) RejectRuntimeHold(c *gin.Context) {
	ctl.runtimeHoldDecision(c, "runtime_hold_reject", false)
}

func (ctl *IGAGovPolicyController) ListRuntimeDecisions(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		limit, err := limitParam(c)
		if err != nil {
			return nil, nil, err
		}
		out, err := ctl.r3().ListDecisions(c.Request.Context(), ws, services.RuntimeDecisionFilter{AgentRef: c.Query("agent_ref"),
			Tool: c.Query("tool"), Decision: c.Query("decision"), Limit: limit})
		return out, nil, err
	})
}

func (ctl *IGAGovPolicyController) GetRuntimeDecision(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		out, err := ctl.r3().GetDecision(c.Request.Context(), ws, id)
		return out, nil, err
	})
}

func (ctl *IGAGovPolicyController) ListRuntimeBudgets(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		limit, err := limitParam(c)
		if err != nil {
			return nil, nil, err
		}
		out, err := ctl.r3().ListBudgets(c.Request.Context(), ws, c.Query("agent_ref"), c.Query("session_id"), limit)
		return out, nil, err
	})
}

func (ctl *IGAGovPolicyController) ListBrokerRoles(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		out, err := ctl.r3().ListBrokerRoles(c.Request.Context(), ws)
		return out, nil, err
	})
}

func (ctl *IGAGovPolicyController) BindBrokerRole(c *gin.Context) {
	ctl.govMutation(c, http.StatusCreated, func(ws, actor uuid.UUID) (any, *audited, error) {
		var req services.BrokerRoleRequest
		if err := bindBody(c, &req, "{connector_id, role_arn, max_session_seconds?}"); err != nil {
			return nil, nil, err
		}
		r, err := ctl.r3().BindBrokerRole(c.Request.Context(), ws, actor, req)
		if err != nil {
			return nil, nil, err
		}
		return r, &audited{"broker_role_bind", "iga_gov_runtime_broker_role", r.ID.String(), nil,
			gin.H{"role_arn": r.RoleARN, "max_session_seconds": r.MaxSessionSeconds}}, nil
	})
}

func (ctl *IGAGovPolicyController) DisableBrokerRole(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var req services.GovDecisionRequest
		if c.Request.ContentLength != 0 {
			if err := bindBody(c, &req, "{reason?}"); err != nil {
				return nil, nil, err
			}
		}
		r, err := ctl.r3().DisableBrokerRole(c.Request.Context(), ws, actor, id, req.Reason)
		if err != nil {
			return nil, nil, err
		}
		return r, &audited{"broker_role_disable", "iga_gov_runtime_broker_role", id.String(), nil, gin.H{"reason": req.Reason}}, nil
	})
}

/* ---------------------------------------------------------------------------- */
/*                          Runtime (agent-credential) routes                    */
/* ---------------------------------------------------------------------------- */

// IGAGovRuntimeController serves /authsec/runtime.
type IGAGovRuntimeController struct {
	db func() *gorm.DB
}

// NewIGAGovRuntimeController builds the runtime controller over config.DB.
func NewIGAGovRuntimeController() *IGAGovRuntimeController {
	return &IGAGovRuntimeController{db: func() *gorm.DB { return config.DB }}
}

// r3 is the runtime service. The workspace every call runs in is the one
// SpiffeAuthMiddleware established from the trust bundle that verified the
// agent's JWT-SVID (runtimeAgent); GovR3 opens its transactions under
// row-level security for it.
//
// TENANT-EXEMPT: not a statement here: the handle is handed to GovR3, which
// runs every runtime statement under tenancy.InWorkspace(that workspace).
func (ctl *IGAGovRuntimeController) r3() *services.GovR3 { return services.NewGovR3(ctl.db()) }

// RegisterRuntimeAgentRoutes mounts the runtime routes on a group that
// already carries SpiffeAuthMiddleware.
func RegisterRuntimeAgentRoutes(g gin.IRoutes, ctl *IGAGovRuntimeController) {
	g.POST("/decide", ctl.Decide)
	g.POST("/decisions/:id/redeem", ctl.Redeem)
	g.POST("/decisions/:id/outcome", ctl.Outcome)
	g.POST("/decisions/:id/aws-session", ctl.AWSSession)
	g.GET("/holds/:id", ctl.Hold)
}

const maxRuntimeBody = 512 * 1024

// runtimeAgent is the verified delegated agent of the request (DECISION
// R3-3), or a 403 written. The workspace is the one SpiffeAuthMiddleware
// established from the verifying trust bundle; the token's workspace claim
// must agree.
func runtimeAgent(c *gin.Context) (uuid.UUID, services.RuntimeAgent, bool) {
	refuse := func() (uuid.UUID, services.RuntimeAgent, bool) {
		policyErr(c, http.StatusForbidden, services.GovCodeDelegatedAgentRequired,
			"Runtime routes accept only a delegated agent JWT-SVID (an agent acting for a human).", nil)
		return uuid.Nil, services.RuntimeAgent{}, false
	}
	if c.GetString("auth_method") != "spiffe-jwt-svid" {
		return refuse()
	}
	raw, ok := c.Get("claims")
	if !ok {
		return refuse()
	}
	claims, ok := raw.(jwt.MapClaims)
	if !ok {
		return refuse()
	}
	wsClaim, clientID, ok := delegation.Delegated(map[string]interface{}(claims))
	if !ok {
		return refuse()
	}
	tc, err := tenancy.From(c)
	if err != nil || !strings.EqualFold(wsClaim, tc.WorkspaceID.String()) {
		return refuse()
	}
	uid, _ := claims["user_id"].(string)
	human, err := uuid.Parse(uid)
	spiffeID := c.GetString("spiffe_id")
	if err != nil || human == uuid.Nil || !strings.HasPrefix(spiffeID, "spiffe://") {
		return refuse()
	}
	return tc.WorkspaceID, services.RuntimeAgent{SpiffeID: spiffeID, ClientID: clientID, HumanUserID: human}, true
}

// runtimeCall runs one runtime route: R3 available (else 503 fail closed),
// the delegated agent, the call, audit_events, {data, meta}.
func (ctl *IGAGovRuntimeController) runtimeCall(c *gin.Context, action string, fn func(ws uuid.UUID, ag services.RuntimeAgent) (any, string, int, error)) {
	if err := services.RequireRuntimeR3(); err != nil {
		govError(c, err)
		return
	}
	ws, ag, ok := runtimeAgent(c)
	if !ok {
		return
	}
	data, resourceID, status, err := fn(ws, ag)
	if err != nil {
		var ge *services.GovError
		if errors.As(err, &ge) {
			auditRuntime(c, ws, ag, action, resourceID, ge.Status, gin.H{"error": ge.Code})
			c.AbortWithStatusJSON(ge.Status, ge.Body())
			return
		}
		policyInternal(c, err)
		return
	}
	auditRuntime(c, ws, ag, action, resourceID, status, nil)
	c.JSON(status, gin.H{"data": data, "meta": gin.H{}})
}

// auditRuntime writes the audit_events row of a runtime call: the user is the
// initiating human, the agent is in the values.
func auditRuntime(c *gin.Context, ws uuid.UUID, ag services.RuntimeAgent, action, resourceID string, status int, extra gin.H) {
	if config.AuditLogger == nil {
		return
	}
	vals := gin.H{"agent_ref": ag.SpiffeID, "agent_client_id": ag.ClientID, "credential": "delegated_jwt_svid"}
	for k, v := range extra {
		vals[k] = v
	}
	config.AuditLogger.LogAdminAction(c.GetString("request_id"), ws.String(), ag.HumanUserID.String(), action,
		"iga_gov_runtime_decision", resourceID, c.Request.Method, c.Request.URL.Path, c.ClientIP(), c.GetHeader("User-Agent"),
		status, time.Duration(0), nil, vals, "")
}

// decodeStrict reads a JSON body refusing unknown members (no prompts, no
// workspace or agent fields: R-11, DECISION R3-3 / R3-4).
func decodeStrict(c *gin.Context, v any, shape string) error {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxRuntimeBody+1))
	if err != nil || len(body) > maxRuntimeBody {
		return services.GovBadParam("body", "The body must be JSON of at most 512 KiB: "+shape+".")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return services.GovBadParam("body", "The body must be JSON with only these members: "+shape+".")
	}
	return nil
}

// Decide handles POST /authsec/runtime/decide.
func (ctl *IGAGovRuntimeController) Decide(c *gin.Context) {
	ctl.runtimeCall(c, "runtime_decide", func(ws uuid.UUID, ag services.RuntimeAgent) (any, string, int, error) {
		var req services.RuntimeDecideRequest
		if err := decodeStrict(c, &req, "{tool, action?, target?, arguments | arguments_digest, session_id?, idempotency_key, context?}"); err != nil {
			return nil, "", 0, err
		}
		out, err := ctl.r3().Decide(c.Request.Context(), ws, ag, req)
		if err != nil {
			return nil, "", 0, err
		}
		return out, out.DecisionID.String(), http.StatusOK, nil
	})
}

// Redeem handles POST /authsec/runtime/decisions/:id/redeem.
func (ctl *IGAGovRuntimeController) Redeem(c *gin.Context) {
	ctl.runtimeCall(c, "runtime_redeem", func(ws uuid.UUID, ag services.RuntimeAgent) (any, string, int, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, c.Param("id"), 0, err
		}
		var req services.RuntimeRedeemRequest
		if err := decodeStrict(c, &req, "{decision_token, arguments_digest, tool, action?, target?}"); err != nil {
			return nil, id.String(), 0, err
		}
		d, err := ctl.r3().Redeem(c.Request.Context(), ws, ag, id, req)
		if err != nil {
			return nil, id.String(), 0, err
		}
		return gin.H{"decision_id": d.ID, "redeemed": true, "binding_hash": d.BindingHash, "consumed_at": d.ConsumedAt,
			"expires_at": d.ExpiresAt}, id.String(), http.StatusOK, nil
	})
}

// Outcome handles POST /authsec/runtime/decisions/:id/outcome.
func (ctl *IGAGovRuntimeController) Outcome(c *gin.Context) {
	ctl.runtimeCall(c, "runtime_outcome", func(ws uuid.UUID, ag services.RuntimeAgent) (any, string, int, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, c.Param("id"), 0, err
		}
		var req services.RuntimeOutcomeRequest
		if err := decodeStrict(c, &req, "{decision_token, tool_outcome, aws_outcome?, actual_cost?}"); err != nil {
			return nil, id.String(), 0, err
		}
		d, err := ctl.r3().ReportOutcome(c.Request.Context(), ws, ag, id, req)
		if err != nil {
			return nil, id.String(), 0, err
		}
		return gin.H{"decision_id": d.ID, "authsec_decision": d.Decision, "tool_outcome": d.ToolOutcome, "aws_outcome": d.AWSOutcome,
			"actual_cost": d.ActualCost, "outcome_source": d.OutcomeSource}, id.String(), http.StatusOK, nil
	})
}

// AWSSession handles POST /authsec/runtime/decisions/:id/aws-session.
func (ctl *IGAGovRuntimeController) AWSSession(c *gin.Context) {
	ctl.runtimeCall(c, "runtime_aws_session", func(ws uuid.UUID, ag services.RuntimeAgent) (any, string, int, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, c.Param("id"), 0, err
		}
		var req services.RuntimeSessionRequest
		if err := decodeStrict(c, &req, "{decision_token}"); err != nil {
			return nil, id.String(), 0, err
		}
		out, err := ctl.r3().BrokerSession(c.Request.Context(), ws, ag, id, req)
		if err != nil {
			return nil, id.String(), 0, err
		}
		c.Header("Cache-Control", "no-store")
		return out, id.String(), http.StatusOK, nil
	})
}

// Hold handles GET /authsec/runtime/holds/:id (the held agent polls).
func (ctl *IGAGovRuntimeController) Hold(c *gin.Context) {
	ctl.runtimeCall(c, "runtime_hold_read", func(ws uuid.UUID, ag services.RuntimeAgent) (any, string, int, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, c.Param("id"), 0, err
		}
		out, err := ctl.r3().AgentHold(c.Request.Context(), ws, ag, id)
		if err != nil {
			return nil, id.String(), 0, err
		}
		return out, id.String(), http.StatusOK, nil
	})
}
