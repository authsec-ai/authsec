package platform

import (
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/services"
)

// The Slack app routes, SPEC-iga-phase3-policy.md §7.11 (T3.14), under
// /authsec/integrations/slack, behind the IGA_POLICY gate (§7 intro: every
// Phase 3 route answers 503 policy_unavailable while it is off):
//
//	GET    /install          governance:enforce   Slack OAuth v2: the authorize URL; sets the install cookie
//	GET    /oauth/callback   OAuth state bound to workspace + member + browser session (no bearer token)
//	POST   /interactions     Slack signature only
//	PUT    /settings         governance:enforce   {approvals_channel_id}
//	DELETE /                 governance:enforce   disconnect
//	POST   /link/confirm     member               {token}: confirm a Slack <-> member link
//
// The workspace is the token's (or, for the two Slack-called routes, the
// signed state's / the notification's). Every mutation writes its
// iga_gov_event in the service's transaction and an audit_events row here.

// SlackIntegrationController serves the Slack app routes.
type SlackIntegrationController struct {
	db   *gorm.DB
	svc  *services.SlackIntegrationService
	gate func() *services.PolicyGate
}

// NewSlackIntegrationController is the controller over svc (nil: the app
// is not configured; every route says so).
func NewSlackIntegrationController(db *gorm.DB, svc *services.SlackIntegrationService) *SlackIntegrationController {
	return &SlackIntegrationController{db: db, svc: svc, gate: services.PolicyGateState}
}

// NewDefaultSlackIntegrationController is the controller over the process's
// Slack app (services.DefaultSlackService, set at startup; nil when not
// configured).
func NewDefaultSlackIntegrationController(db *gorm.DB) *SlackIntegrationController {
	return NewSlackIntegrationController(db, services.DefaultSlackService())
}

// WithPolicyGate makes the routes read g instead of the process-wide gate.
func (ctl *SlackIntegrationController) WithPolicyGate(g *services.PolicyGate) *SlackIntegrationController {
	ctl.gate = func() *services.PolicyGate { return g }
	return ctl
}

// MountSlackIntegrationRoutes mounts §7.11 on the /authsec group: the gate
// first; the Slack-called routes without bearer auth; the others behind
// auth and their permission, both rendered as the §7 envelope.
func MountSlackIntegrationRoutes(authsec gin.IRouter, ctl *SlackIntegrationController, auth gin.HandlerFunc, require func(resource, action string) gin.HandlerFunc) {
	g := authsec.Group("/integrations/slack", ctl.Gate())
	g.POST("/interactions", ctl.Interactions)
	g.GET("/oauth/callback", ctl.OAuthCallback)
	req := GraphRequire(require)
	a := g.Group("", GraphEnvelope(auth))
	a.GET("/install", req("governance", "enforce"), ctl.Install)
	a.PUT("/settings", req("governance", "enforce"), ctl.PutSettings)
	a.DELETE("", req("governance", "enforce"), ctl.Disconnect)
	a.POST("/link/confirm", ctl.ConfirmLink)
}

// Gate is the IGA_POLICY middleware (fail closed).
func (ctl *SlackIntegrationController) Gate() gin.HandlerFunc {
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

func (ctl *SlackIntegrationController) configured(c *gin.Context) bool {
	if ok, reason := ctl.svc.Configured(); !ok {
		policyErr(c, http.StatusServiceUnavailable, services.SlackCodeNotConfigured, reason, nil)
		return false
	}
	return true
}

// member is the token workspace and its verified human member.
func (ctl *SlackIntegrationController) member(c *gin.Context) (ws, user uuid.UUID, ok bool) {
	ws, ok = policyWorkspace(c)
	if !ok {
		return
	}
	uid, err := humanActor(c, ctl.db, ws)
	if err != nil {
		if errors.Is(err, errNotWorkspaceHuman) {
			policyErr(c, http.StatusForbidden, "forbidden", "Slack setup requires a verified workspace member session.", nil)
		} else {
			policyInternal(c, err)
		}
		return ws, uuid.Nil, false
	}
	user, err = uuid.Parse(uid)
	if err != nil {
		policyErr(c, http.StatusForbidden, "forbidden", "Slack setup requires a verified workspace member session.", nil)
		return ws, uuid.Nil, false
	}
	return ws, user, true
}

// Install handles GET /install.
func (ctl *SlackIntegrationController) Install(c *gin.Context) {
	if !ctl.configured(c) {
		return
	}
	ws, user, ok := ctl.member(c)
	if !ok {
		return
	}
	membership, err := uuid.Parse(c.GetString("workspace_membership_id"))
	if err != nil {
		policyErr(c, http.StatusForbidden, "forbidden", "Slack setup requires a verified workspace member session.", nil)
		return
	}
	st, err := ctl.svc.StartInstall(c.Request.Context(), ws, user, membership)
	if err != nil {
		govError(c, err)
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: services.SlackInstallCookie, Value: st.Nonce, Path: "/authsec/integrations/slack/oauth",
		MaxAge: 600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	c.JSON(http.StatusOK, gin.H{"data": st, "meta": gin.H{}})
}

// OAuthCallback handles GET /oauth/callback (Slack's browser redirect).
func (ctl *SlackIntegrationController) OAuthCallback(c *gin.Context) {
	// The cookie is single use whatever happens.
	http.SetCookie(c.Writer, &http.Cookie{Name: services.SlackInstallCookie, Value: "", Path: "/authsec/integrations/slack/oauth",
		MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	if !ctl.configured(c) {
		return
	}
	if e := c.Query("error"); e != "" {
		ctl.callbackOut(c, services.GovBadParam("error", "The Slack install was cancelled or refused ("+e+")."), nil)
		return
	}
	nonce, _ := c.Cookie(services.SlackInstallCookie)
	res, err := ctl.svc.CompleteInstall(c.Request.Context(), c.Query("state"), nonce, c.Query("code"))
	if err != nil {
		ctl.callbackOut(c, err, nil)
		return
	}
	c.Set("user_id", res.ActorID.String())
	auditAdminMutation(c, res.WorkspaceID.String(), "install", "workspace_slack_integration", res.WorkspaceID.String(),
		http.StatusOK, res.Before, res.Integration)
	ctl.callbackOut(c, nil, res)
}

// callbackOut answers the browser: back to the console's Setup page when a
// console URL is configured, else the §7 envelope.
func (ctl *SlackIntegrationController) callbackOut(c *gin.Context, err error, res *services.SlackInstallResult) {
	setup := services.SlackConsoleLink("/iga/policy/setup/notifications")
	if setup != "" {
		q := url.Values{}
		if err != nil {
			code := "slack_install_failed"
			var ge *services.GovError
			if errors.As(err, &ge) {
				code = ge.Code
			} else {
				log.Printf("[slack] oauth callback: %v", err)
			}
			q.Set("slack_error", code)
		} else {
			q.Set("slack", "connected")
		}
		c.Redirect(http.StatusFound, setup+"?"+q.Encode())
		return
	}
	if err != nil {
		govError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": res, "meta": gin.H{}})
}

// Interactions handles POST /interactions: Slack signature only.
func (ctl *SlackIntegrationController) Interactions(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
	if err != nil {
		policyErr(c, http.StatusBadRequest, "invalid_parameter", "The body could not be read.", nil)
		return
	}
	if ctl.svc == nil {
		policyErr(c, http.StatusUnauthorized, services.SlackCodeSignatureInvalid, "The request is not a valid, fresh Slack request.",
			gin.H{"reason": "not_configured"})
		return
	}
	res, err := ctl.svc.HandleInteraction(c.Request.Context(), c.Request.Header, body)
	if err != nil {
		govError(c, err)
		return
	}
	if !res.Ignored && res.Resource != "" {
		c.Set("user_id", res.UserID.String())
		auditAdminMutation(c, res.WorkspaceID.String(), res.Action, res.Resource, res.ResourceID, http.StatusOK, res.Before, res.After)
	}
	c.JSON(http.StatusOK, gin.H{"data": res, "meta": gin.H{}})
}

// PutSettings handles PUT /settings {approvals_channel_id}.
func (ctl *SlackIntegrationController) PutSettings(c *gin.Context) {
	if !ctl.configured(c) {
		return
	}
	ws, user, ok := ctl.member(c)
	if !ok {
		return
	}
	var in services.SlackSettingsInput
	if err := strictJSON(c, &in); err != nil {
		policyErr(c, http.StatusBadRequest, "invalid_parameter", "The body must be JSON: {approvals_channel_id}.", gin.H{"parameter": "body"})
		return
	}
	before, after, err := ctl.svc.UpdateSettings(c.Request.Context(), ws, user, in)
	if err != nil {
		govError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "update_settings", "workspace_slack_integration", ws.String(), http.StatusOK, before, after)
	c.JSON(http.StatusOK, gin.H{"data": after, "meta": gin.H{}})
}

// Disconnect handles DELETE /.
func (ctl *SlackIntegrationController) Disconnect(c *gin.Context) {
	if !ctl.configured(c) {
		return
	}
	ws, user, ok := ctl.member(c)
	if !ok {
		return
	}
	before, err := ctl.svc.Disconnect(c.Request.Context(), ws, user)
	if err != nil {
		govError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "disconnect", "workspace_slack_integration", ws.String(), http.StatusOK, before, nil)
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"disconnected": true, "slack_team_id": before.SlackTeamID}, "meta": gin.H{}})
}

// ConfirmLink handles POST /link/confirm {token}.
func (ctl *SlackIntegrationController) ConfirmLink(c *gin.Context) {
	if !ctl.configured(c) {
		return
	}
	ws, user, ok := ctl.member(c)
	if !ok {
		return
	}
	var in struct {
		Token string `json:"token"`
	}
	if err := strictJSON(c, &in); err != nil {
		policyErr(c, http.StatusBadRequest, "invalid_parameter", "The body must be JSON: {token}.", gin.H{"parameter": "body"})
		return
	}
	res, err := ctl.svc.ConfirmLink(c.Request.Context(), ws, user, in.Token)
	if err != nil {
		govError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "link", "slack_user_link", res.Link.SlackUserID, http.StatusOK, nil, res.Link)
	c.JSON(http.StatusOK, gin.H{"data": res, "meta": gin.H{}})
}
