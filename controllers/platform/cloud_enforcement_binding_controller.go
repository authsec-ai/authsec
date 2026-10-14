package platform

import (
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
)

// The enforcement binding routes (SPEC-iga-phase3-policy.md §7.9, T3.09),
// under /authsec/discovery/aws because the binding reuses the connector's
// Quick Create callback:
//
//	GET    /aws/connectors/:id/enforcement                discovery:read      binding state, capabilities, template version, last self-test
//	POST   /aws/connectors/:id/enforcement/sessions       governance:enforce  Quick Create session for the enforcement stack
//	GET    /aws/connectors/:id/enforcement/sessions/:sid  governance:enforce  poll
//	POST   /aws/connectors/:id/enforcement                governance:enforce  manual path: { role_arn, selftest_role_arn }
//	POST   /aws/connectors/:id/enforcement/verify         governance:enforce  run the self-test now
//	DELETE /aws/connectors/:id/enforcement                governance:enforce  revoke; lists artifacts still in AWS
//
// They follow the Phase 3 rules (§7 intro) although they sit outside
// /api/iga/v1/policy: the IGA_POLICY gate (503 policy_unavailable while it is
// off or unverified -- the binding is a Phase 3 table), the workspace from the
// token only, another workspace's connector 404, the {data, meta} /
// {error:{code,message,detail}} envelope, and every mutation writing an
// iga_gov_event in its own transaction (the service) and an audit_events row
// (auditAdminMutation, here).
//
// DECISION (T3.09): the IaC-source routes of the same §7.9 table belong to
// T3.17 and are not mounted here.

// CloudEnforcementBindingController serves the §7.9 binding routes.
type CloudEnforcementBindingController struct {
	db   *gorm.DB
	gate func() *services.PolicyGate

	override *services.EnforcementBindingService
	svcOnce  sync.Once
	svc      *services.EnforcementBindingService
	svcErr   error
}

// NewCloudEnforcementBindingController builds the controller over the
// process-wide policy gate.
func NewCloudEnforcementBindingController(db *gorm.DB) *CloudEnforcementBindingController {
	return &CloudEnforcementBindingController{db: db, gate: services.PolicyGateState}
}

// WithService makes every handler use svc (tests: fake AWS, memory vault).
func (ctl *CloudEnforcementBindingController) WithService(svc *services.EnforcementBindingService) *CloudEnforcementBindingController {
	ctl.override = svc
	return ctl
}

// WithPolicyGate makes the routes read g instead of the process-wide gate.
func (ctl *CloudEnforcementBindingController) WithPolicyGate(g *services.PolicyGate) *CloudEnforcementBindingController {
	ctl.gate = func() *services.PolicyGate { return g }
	return ctl
}

// service builds the binding service once from the environment: Vault (the
// ExternalId store), the Quick Create callback configuration (optional: the
// manual path works without it) and AuthSec's AWS principal.
func (ctl *CloudEnforcementBindingController) service() (*services.EnforcementBindingService, error) {
	if ctl.override != nil {
		return ctl.override, nil
	}
	ctl.svcOnce.Do(func() {
		addr, token := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN")
		if addr == "" || token == "" {
			ctl.svcErr = errors.New("VAULT_ADDR/VAULT_TOKEN not configured; the enforcement ExternalId cannot be stored")
			return
		}
		vc, err := vault.NewClient(addr, token)
		if err != nil {
			ctl.svcErr = err
			return
		}
		cfg, err := services.LoadAWSCallbackConfig()
		if err != nil {
			log.Printf("[aws-enf] ALERT automatic AWS setup misconfigured, enforcement Quick Create disabled: %v", err)
			cfg = awsdiscovery.CallbackConfig{}
		}
		ctl.svc = services.NewEnforcementBindingService(ctl.db, vc, cfg, os.Getenv(authsecPrincipalEnv))
	})
	return ctl.svc, ctl.svcErr
}

// RegisterEnforcementBindingRoutes mounts the §7.9 binding routes on the
// authenticated /authsec/discovery group: the IGA_POLICY gate first, then
// each route's permission (require, wrapped so a 401/403 is the envelope).
func RegisterEnforcementBindingRoutes(discovery gin.IRouter, ctl *CloudEnforcementBindingController, require func(resource, action string) gin.HandlerFunc) {
	req := GraphRequire(require)
	enf := discovery.Group("/aws/connectors/:id/enforcement", ctl.Gate())
	enf.GET("", req("discovery", "read"), ctl.Get)
	enf.POST("", req("governance", "enforce"), ctl.BindManual)
	enf.DELETE("", req("governance", "enforce"), ctl.Revoke)
	enf.POST("/sessions", req("governance", "enforce"), ctl.StartSession)
	enf.GET("/sessions/:sid", req("governance", "enforce"), ctl.GetSession)
	enf.POST("/verify", req("governance", "enforce"), ctl.Verify)
}

// Gate is the IGA_POLICY middleware for these routes (fail closed).
func (ctl *CloudEnforcementBindingController) Gate() gin.HandlerFunc {
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

func enfFail(c *gin.Context, status int, code, msg string, detail map[string]any) {
	body := gin.H{"code": code, "message": msg}
	if detail != nil {
		body["detail"] = detail
	} else {
		body["detail"] = gin.H{}
	}
	c.AbortWithStatusJSON(status, gin.H{"error": body})
}

func enfError(c *gin.Context, err error) {
	var ee *services.EnforcementError
	if errors.As(err, &ee) {
		enfFail(c, ee.Status, ee.Code, ee.Message, ee.Detail)
		return
	}
	log.Printf("[aws-enf] %s %s: %v", c.Request.Method, c.FullPath(), err)
	enfFail(c, http.StatusInternalServerError, "internal_error", "The request could not be completed.", nil)
}

func enfOK(c *gin.Context, status int, data any) {
	c.JSON(status, gin.H{"data": data, "meta": gin.H{"as_of": time.Now().UTC()}})
}

// enfScope resolves the token's workspace and the connector id; a malformed
// id is 404 like an absent one (ids never leak existence).
func (ctl *CloudEnforcementBindingController) enfScope(c *gin.Context) (ws, connectorID uuid.UUID, svc *services.EnforcementBindingService, ok bool) {
	ws, okWS := tokenWorkspace(c)
	if !okWS {
		enfFail(c, http.StatusUnauthorized, "unauthenticated", "No workspace in the token.", nil)
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		enfFail(c, http.StatusNotFound, services.EnfCodeNotFound, "Connector not found.", nil)
		return
	}
	s, err := ctl.service()
	if err != nil {
		enfFail(c, http.StatusServiceUnavailable, services.EnfCodeNotConfigured, err.Error(), nil)
		return
	}
	return ws, id, s, true
}

// enfUser is the signed-in user. A binding records who consented
// (cloud_enforcement_binding.consented_by references users), so a mutation
// needs a user, not only a client.
func enfUser(c *gin.Context) (uuid.UUID, bool) {
	raw, err := middlewares.ResolveUserID(c)
	if err != nil {
		enfFail(c, http.StatusForbidden, "user_required", "Enforcement setup must be done by a signed-in user.", nil)
		return uuid.Nil, false
	}
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil || id == uuid.Nil {
		enfFail(c, http.StatusForbidden, "user_required", "Enforcement setup must be done by a signed-in user.", nil)
		return uuid.Nil, false
	}
	return id, true
}

// Get handles GET .../enforcement.
func (ctl *CloudEnforcementBindingController) Get(c *gin.Context) {
	ws, id, svc, ok := ctl.enfScope(c)
	if !ok {
		return
	}
	v, err := svc.Get(ws, id)
	if err != nil {
		enfError(c, err)
		return
	}
	enfOK(c, http.StatusOK, v)
}

// StartSession handles POST .../enforcement/sessions. Body (optional):
// {"deployment_region": "us-east-1"}.
func (ctl *CloudEnforcementBindingController) StartSession(c *gin.Context) {
	ws, id, svc, ok := ctl.enfScope(c)
	if !ok {
		return
	}
	user, ok := enfUser(c)
	if !ok {
		return
	}
	var in struct {
		DeploymentRegion string `json:"deployment_region"`
	}
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&in); err != nil {
			enfFail(c, http.StatusBadRequest, "invalid_request", "Invalid request body: "+err.Error(), nil)
			return
		}
	}
	sess, err := svc.StartSession(c.Request.Context(), ws, id, user, in.DeploymentRegion)
	if err != nil {
		enfError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "start_enforcement_session", "cloud_enforcement_binding", sess.BindingID.String(),
		http.StatusCreated, nil, gin.H{"connector_id": id, "account_id": sess.AccountID, "automatic": sess.Automatic,
			"deployment_region": sess.DeploymentRegion, "stack_name": sess.StackName})
	enfOK(c, http.StatusCreated, sess)
}

// GetSession handles GET .../enforcement/sessions/:sid.
func (ctl *CloudEnforcementBindingController) GetSession(c *gin.Context) {
	ws, id, svc, ok := ctl.enfScope(c)
	if !ok {
		return
	}
	sid, err := uuid.Parse(c.Param("sid"))
	if err != nil {
		enfFail(c, http.StatusNotFound, services.EnfCodeNotFound, "Session not found.", nil)
		return
	}
	user := uuid.Nil
	if raw, err := middlewares.ResolveUserID(c); err == nil {
		user, _ = uuid.Parse(raw)
	}
	sess, err := svc.GetSession(ws, id, sid, user)
	if err != nil {
		enfError(c, err)
		return
	}
	enfOK(c, http.StatusOK, sess)
}

// BindManual handles POST .../enforcement: {role_arn, selftest_role_arn,
// template_version?}.
func (ctl *CloudEnforcementBindingController) BindManual(c *gin.Context) {
	ws, id, svc, ok := ctl.enfScope(c)
	if !ok {
		return
	}
	user, ok := enfUser(c)
	if !ok {
		return
	}
	var in struct {
		RoleARN         string `json:"role_arn"`
		SelftestRoleARN string `json:"selftest_role_arn"`
		TemplateVersion string `json:"template_version"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		enfFail(c, http.StatusBadRequest, "invalid_request", "Invalid request body: "+err.Error(), nil)
		return
	}
	v, err := svc.BindManual(c.Request.Context(), ws, id, user, in.RoleARN, in.SelftestRoleARN, in.TemplateVersion)
	if err != nil {
		enfError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "bind_enforcement", "cloud_enforcement_binding", v.BindingID.String(),
		http.StatusOK, nil, gin.H{"connector_id": id, "account_id": v.AccountID, "role_arn": v.RoleARN,
			"selftest_role_arn": v.SelftestRoleARN, "state": v.State, "source": "manual"})
	enfOK(c, http.StatusOK, v)
}

// Verify handles POST .../enforcement/verify.
func (ctl *CloudEnforcementBindingController) Verify(c *gin.Context) {
	ws, id, svc, ok := ctl.enfScope(c)
	if !ok {
		return
	}
	user, ok := enfUser(c)
	if !ok {
		return
	}
	v, err := svc.Verify(c.Request.Context(), ws, id, services.EnforcementActor{Kind: "user", ID: user.String()})
	if err != nil {
		enfError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "verify_enforcement", "cloud_enforcement_binding", v.BindingID.String(),
		http.StatusOK, nil, gin.H{"connector_id": id, "state": v.State, "failing": v.Failing})
	enfOK(c, http.StatusOK, v)
}

// Revoke handles DELETE .../enforcement. Body (optional): {"reason": "..."}.
func (ctl *CloudEnforcementBindingController) Revoke(c *gin.Context) {
	ws, id, svc, ok := ctl.enfScope(c)
	if !ok {
		return
	}
	user, ok := enfUser(c)
	if !ok {
		return
	}
	var in struct {
		Reason string `json:"reason"`
	}
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&in); err != nil {
			enfFail(c, http.StatusBadRequest, "invalid_request", "Invalid request body: "+err.Error(), nil)
			return
		}
	}
	res, err := svc.Revoke(c.Request.Context(), ws, id, user, strings.TrimSpace(in.Reason))
	if err != nil {
		enfError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "revoke_enforcement", "cloud_enforcement_binding", res.Binding.BindingID.String(),
		http.StatusOK, nil, gin.H{"connector_id": id, "account_id": res.Binding.AccountID,
			"artifacts_in_aws": len(res.ArtifactsInAWS), "reason": in.Reason})
	enfOK(c, http.StatusOK, res)
}
