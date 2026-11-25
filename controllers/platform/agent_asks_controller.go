package platform

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/authz"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
)

// Asks and their delivery (SPEC-secops-backend-upgrade.md W4), on
// /api/iga/v1 behind auth:
//
//	GET    /agent-runtime/asks                    governance:read or discovery:read
//	       ?state=&mine=true&overdue=true|false&about_kind=&about_id=&case_id=&cursor=&limit=
//	GET    /agent-runtime/asks/policy             governance:read
//	PUT    /agent-runtime/asks/policy             governance:author (loosening: tier 3, a pending change)
//	GET    /agent-runtime/asks/:id                governance:read or discovery:read
//	POST   /agent-runtime/asks                    governance:enforce (tier 1)
//	POST   /agent-runtime/asks/:id/answer         read + the current decider (never the requester)
//	POST   /agent-runtime/asks/:id/not-mine       read + the current decider
//	POST   /agent-runtime/asks/:id/withdraw       read + the creator or a holder of governance:approve
//	POST   /agent-runtime/asks/:id/confirm        read + the person whose Slack answer waits
//	POST   /agent-runtime/cases/:id/tickets       governance:enforce {provider}
//	GET    /integrations/ticketing|paging         iga:read
//	PUT    /integrations/ticketing|paging/:provider    iga:admin {enabled?, config, secret?}
//	DELETE /integrations/ticketing|paging/:provider    iga:admin
//
// Who decides and when an ask is due are the server's: POST /asks refuses
// any field naming them (unknown field). The workspace is the token's only;
// another workspace's ask, case or integration is 404. Every write's actor
// is the verified human (humanActor) and writes an audit_events row.

// AgentAsksController serves the routes above.
type AgentAsksController struct{ db func() *gorm.DB }

// NewAgentAsksControllerFor uses the graph controller's database.
func NewAgentAsksControllerFor(g *IGAGraphReadController) *AgentAsksController {
	return &AgentAsksController{db: g.db}
}

// NewAgentAsksControllerWith builds the controller over db (tests).
func NewAgentAsksControllerWith(db *gorm.DB) *AgentAsksController {
	return &AgentAsksController{db: func() *gorm.DB { return db }}
}

// NewAgentAsksController reads the process database on every request.
func NewAgentAsksController() *AgentAsksController {
	// TENANT-EXEMPT: not a statement: the handle every service call opens its workspace transaction on.
	return &AgentAsksController{db: func() *gorm.DB { return config.DB }}
}

// AgentAskRouteGuards are the permission middlewares of the route table.
type AgentAskRouteGuards struct {
	Read, GovRead, Author, Enforce, IGARead, IGAAdmin gin.HandlerFunc
}

// MountAgentAskRoutes mounts the routes on g (the authenticated /api/iga/v1
// group).
func MountAgentAskRoutes(g *gin.RouterGroup, ctl *AgentAsksController) {
	RegisterAgentAskRoutes(g, ctl, AgentAskRouteGuards{
		Read:     middlewares.RequireAny(authz.Need{Resource: "governance", Action: "read"}, authz.Need{Resource: "discovery", Action: "read"}),
		GovRead:  middlewares.Require("governance", "read"),
		Author:   middlewares.Require("governance", "author"),
		Enforce:  middlewares.Require("governance", "enforce"),
		IGARead:  middlewares.Require("iga", "read"),
		IGAAdmin: middlewares.Require("iga", "admin"),
	})
}

// RegisterAgentAskRoutes is the route table (tests mount the same one).
func RegisterAgentAskRoutes(g gin.IRoutes, ctl *AgentAsksController, m AgentAskRouteGuards) {
	s := ctl.requireSchema
	g.GET("/agent-runtime/asks", m.Read, s, ctl.ListAsks)
	g.GET("/agent-runtime/asks/policy", m.GovRead, s, ctl.GetPolicy)
	g.PUT("/agent-runtime/asks/policy", m.Author, s, ctl.PutPolicy)
	g.GET("/agent-runtime/asks/:id", m.Read, s, ctl.GetAsk)
	g.POST("/agent-runtime/asks", m.Enforce, s, ctl.CreateAsk)
	g.POST("/agent-runtime/asks/:id/answer", m.Read, s, ctl.Answer)
	g.POST("/agent-runtime/asks/:id/not-mine", m.Read, s, ctl.NotMine)
	g.POST("/agent-runtime/asks/:id/withdraw", m.Read, s, ctl.Withdraw)
	g.POST("/agent-runtime/asks/:id/confirm", m.Read, s, ctl.Confirm)
	g.POST("/agent-runtime/cases/:id/tickets", m.Enforce, s, ctl.CaseTicket)
	for _, cat := range []string{services.AskIntegrationTicketing, services.AskIntegrationPaging} {
		g.GET("/integrations/"+cat, m.IGARead, s, ctl.listIntegrations(cat))
		g.PUT("/integrations/"+cat+"/:provider", m.IGAAdmin, s, ctl.putIntegration(cat))
		g.DELETE("/integrations/"+cat+"/:provider", m.IGAAdmin, s, ctl.deleteIntegration(cat))
	}
}

// requireSchema answers 503 with the reason until migration 220 verifies.
func (ctl *AgentAsksController) requireSchema(c *gin.Context) {
	// TENANT-EXEMPT: the schema check reads the Postgres catalog only.
	if err := services.RequireAgentAsks(ctl.db()); err != nil {
		govErrorOut(c, err)
	}
}

func (ctl *AgentAsksController) svc() *services.AgentAskService {
	// TENANT-EXEMPT: not a statement: the service runs every statement in a workspace transaction.
	return services.NewAgentAskService(ctl.db())
}

func (ctl *AgentAsksController) actor(c *gin.Context, ws uuid.UUID) (uuid.UUID, error) {
	// TENANT-EXEMPT: humanActor runs its one statement through tenancy.QueryRowContext.
	uid, err := humanActor(c, ctl.db(), ws)
	if err != nil {
		if errors.Is(err, errNotWorkspaceHuman) {
			return uuid.Nil, services.GovForbidden("Asks are answered and raised by a verified workspace member session.")
		}
		return uuid.Nil, err
	}
	return uuid.Parse(uid)
}

// optionalActor is the verified human, or uuid.Nil (reads).
func (ctl *AgentAsksController) optionalActor(c *gin.Context, ws uuid.UUID) uuid.UUID {
	id, err := ctl.actor(c, ws)
	if err != nil {
		return uuid.Nil
	}
	return id
}

func (ctl *AgentAsksController) begin(c *gin.Context, ws uuid.UUID) (id, actor uuid.UUID, err error) {
	if id, err = aidPathID(c, "id"); err != nil {
		return
	}
	actor, err = ctl.actor(c, ws)
	return
}

// decodeOptionalBody decodes a body that may be empty.
func decodeOptionalBody(c *gin.Context, dst any, allowed ...string) error {
	if c.Request.ContentLength == 0 {
		return nil
	}
	return decodeARBody(c, dst, allowed...)
}

// ListAsks handles GET /agent-runtime/asks.
func (ctl *AgentAsksController) ListAsks(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		if err := arOnlyParams(c, "state", "mine", "overdue", "about_kind", "about_id", "case_id", "cursor", "limit"); err != nil {
			return nil, nil, err
		}
		limit, err := limitParam(c)
		if err != nil {
			return nil, nil, err
		}
		f := services.AgentAskFilter{State: c.Query("state"), AboutKind: c.Query("about_kind"), AboutID: c.Query("about_id"),
			Cursor: c.Query("cursor"), Limit: limit}
		switch c.Query("mine") {
		case "", "false":
		case "true":
			f.Mine = true
		default:
			return nil, nil, services.GovBadParam("mine", "mine must be true or false.")
		}
		switch v := c.Query("overdue"); v {
		case "":
		case "true", "false":
			b := v == "true"
			f.Overdue = &b
		default:
			return nil, nil, services.GovBadParam("overdue", "overdue must be true or false.")
		}
		if f.CaseID, err = optUUIDParam(c, "case_id"); err != nil {
			return nil, nil, err
		}
		actor := ctl.optionalActor(c, ws)
		if f.Mine && actor == uuid.Nil {
			return nil, nil, services.GovForbidden("mine=true needs a verified workspace member session.")
		}
		items, next, err := ctl.svc().List(c.Request.Context(), ws, actor, f)
		if err != nil {
			return nil, nil, err
		}
		var nc any
		if next != "" {
			nc = next
		}
		return items, gin.H{"next_cursor": nc}, nil
	})
}

// GetAsk handles GET /agent-runtime/asks/:id.
func (ctl *AgentAsksController) GetAsk(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := aidPathID(c, "id")
		if err != nil {
			return nil, nil, err
		}
		out, err := ctl.svc().Get(c.Request.Context(), ws, ctl.optionalActor(c, ws), id)
		return out, nil, err
	})
}

type askCreateBody struct {
	About *struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	} `json:"about"`
	Question         string               `json:"question"`
	Choices          []services.AskChoice `json:"choices"`
	Tier             *int                 `json:"tier"`
	CaseID           *uuid.UUID           `json:"case_id"`
	RequesterUserID  *uuid.UUID           `json:"requester_user_id"`
	ExternalDeadline *askExternalDeadline `json:"external_deadline"`
}

type askExternalDeadline struct {
	At     *time.Time `json:"at"`
	Source string     `json:"source"`
}

// CreateAsk handles POST /agent-runtime/asks.
func (ctl *AgentAsksController) CreateAsk(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		actor, err := ctl.actor(c, ws)
		if err != nil {
			return nil, nil, err
		}
		var b askCreateBody
		if err := decodeARBody(c, &b, "about", "question", "choices", "tier", "case_id", "requester_user_id", "external_deadline"); err != nil {
			return nil, nil, err
		}
		if b.About == nil {
			return nil, nil, services.GovBadParam("about", "about {kind, id} is required.")
		}
		req := services.AskCreateRequest{AboutKind: b.About.Kind, AboutID: b.About.ID, CaseID: b.CaseID, Question: b.Question,
			Choices: b.Choices, RequesterUserID: b.RequesterUserID}
		if b.Tier != nil {
			req.Tier = *b.Tier
		}
		if b.ExternalDeadline != nil {
			if b.ExternalDeadline.At == nil {
				return nil, nil, services.GovBadParam("external_deadline.at", "an external deadline needs its time.")
			}
			req.ExternalDeadline, req.ExternalDeadlineSource = b.ExternalDeadline.At, b.ExternalDeadline.Source
		}
		out, err := ctl.svc().Create(c.Request.Context(), ws, actor, req)
		if err != nil {
			return nil, nil, err
		}
		auditAdminMutation(c, ws.String(), "agent_ask_create", "agent_ask", out.ID.String(), http.StatusOK, nil, out)
		return out, nil, nil
	})
}

// Answer handles POST /agent-runtime/asks/:id/answer.
func (ctl *AgentAsksController) Answer(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, actor, err := ctl.begin(c, ws)
		if err != nil {
			return nil, nil, err
		}
		var b struct {
			Choice *string `json:"choice"`
			Note   string  `json:"note"`
		}
		if err := decodeARBody(c, &b, "choice", "note"); err != nil {
			return nil, nil, err
		}
		if b.Choice == nil {
			return nil, nil, services.GovBadParam("choice", "choice is required.")
		}
		out, err := ctl.svc().Answer(c.Request.Context(), ws, id, actor, *b.Choice, b.Note)
		if err != nil {
			return nil, nil, err
		}
		auditAdminMutation(c, ws.String(), "agent_ask_answer", "agent_ask", id.String(), http.StatusOK, nil, out)
		return out, nil, nil
	})
}

func (ctl *AgentAsksController) reasonCall(c *gin.Context, action string,
	fn func(s *services.AgentAskService, ws, id, actor uuid.UUID, reason string) (*services.AgentAskView, error)) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, actor, err := ctl.begin(c, ws)
		if err != nil {
			return nil, nil, err
		}
		var b struct {
			Reason string `json:"reason"`
		}
		if err := decodeOptionalBody(c, &b, "reason"); err != nil {
			return nil, nil, err
		}
		out, err := fn(ctl.svc(), ws, id, actor, b.Reason)
		if err != nil {
			return nil, nil, err
		}
		auditAdminMutation(c, ws.String(), action, "agent_ask", id.String(), http.StatusOK, nil, out)
		return out, nil, nil
	})
}

// NotMine handles POST /agent-runtime/asks/:id/not-mine.
func (ctl *AgentAsksController) NotMine(c *gin.Context) {
	ctl.reasonCall(c, "agent_ask_not_mine", func(s *services.AgentAskService, ws, id, actor uuid.UUID, r string) (*services.AgentAskView, error) {
		return s.NotMine(c.Request.Context(), ws, id, actor, r)
	})
}

// Withdraw handles POST /agent-runtime/asks/:id/withdraw.
func (ctl *AgentAsksController) Withdraw(c *gin.Context) {
	ctl.reasonCall(c, "agent_ask_withdraw", func(s *services.AgentAskService, ws, id, actor uuid.UUID, r string) (*services.AgentAskView, error) {
		return s.Withdraw(c.Request.Context(), ws, id, actor, r)
	})
}

// Confirm handles POST /agent-runtime/asks/:id/confirm.
func (ctl *AgentAsksController) Confirm(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, actor, err := ctl.begin(c, ws)
		if err != nil {
			return nil, nil, err
		}
		var b struct{}
		if err := decodeOptionalBody(c, &b); err != nil {
			return nil, nil, err
		}
		out, err := ctl.svc().Confirm(c.Request.Context(), ws, id, actor)
		if err != nil {
			return nil, nil, err
		}
		auditAdminMutation(c, ws.String(), "agent_ask_confirm", "agent_ask", id.String(), http.StatusOK, nil, out)
		return out, nil, nil
	})
}

// GetPolicy handles GET /agent-runtime/asks/policy.
func (ctl *AgentAsksController) GetPolicy(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		out, err := ctl.svc().GetPolicy(c.Request.Context(), ws)
		return out, nil, err
	})
}

// PutPolicy handles PUT /agent-runtime/asks/policy.
func (ctl *AgentAsksController) PutPolicy(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		actor, err := ctl.actor(c, ws)
		if err != nil {
			return nil, nil, err
		}
		var b struct {
			Version        *int64 `json:"version"`
			DueHighHours   *int   `json:"due_high_hours"`
			DueMediumHours *int   `json:"due_medium_hours"`
			DueLowHours    *int   `json:"due_low_hours"`
			HoursPerStep   *int   `json:"hours_per_step"`
			ChannelSlack   *bool  `json:"channel_slack"`
			ChannelEmail   *bool  `json:"channel_email"`
			ChannelWebhook *bool  `json:"channel_webhook"`
			Reason         string `json:"reason"`
		}
		if err := decodeARBody(c, &b, "version", "due_high_hours", "due_medium_hours", "due_low_hours", "hours_per_step",
			"channel_slack", "channel_email", "channel_webhook", "reason"); err != nil {
			return nil, nil, err
		}
		out, err := ctl.svc().UpdatePolicy(c.Request.Context(), ws, actor, services.AgentAskPolicyUpdate{Version: b.Version,
			DueHighHours: b.DueHighHours, DueMediumHours: b.DueMediumHours, DueLowHours: b.DueLowHours, HoursPerStep: b.HoursPerStep,
			ChannelSlack: b.ChannelSlack, ChannelEmail: b.ChannelEmail, ChannelWebhook: b.ChannelWebhook, Reason: b.Reason})
		if err != nil {
			return nil, nil, err
		}
		auditAdminMutation(c, ws.String(), "agent_ask_policy_update", "agent_ask_policy", ws.String(), http.StatusOK, nil, out)
		return out, nil, nil
	})
}

// CaseTicket handles POST /agent-runtime/cases/:id/tickets.
func (ctl *AgentAsksController) CaseTicket(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, actor, err := ctl.begin(c, ws)
		if err != nil {
			return nil, nil, err
		}
		var b struct {
			Provider string `json:"provider"`
		}
		if err := decodeARBody(c, &b, "provider"); err != nil {
			return nil, nil, err
		}
		out, err := ctl.svc().RequestCaseTicket(c.Request.Context(), ws, actor, id, b.Provider)
		if err != nil {
			return nil, nil, err
		}
		auditAdminMutation(c, ws.String(), "agent_case_ticket", "agent_case", id.String(), http.StatusOK, nil, out)
		return out, nil, nil
	})
}

func (ctl *AgentAsksController) listIntegrations(cat string) gin.HandlerFunc {
	return func(c *gin.Context) {
		arCall(c, func(ws uuid.UUID) (any, any, error) {
			out, err := ctl.svc().ListIntegrations(c.Request.Context(), ws, cat)
			return out, nil, err
		})
	}
}

func (ctl *AgentAsksController) putIntegration(cat string) gin.HandlerFunc {
	return func(c *gin.Context) {
		arCall(c, func(ws uuid.UUID) (any, any, error) {
			actor, err := ctl.actor(c, ws)
			if err != nil {
				return nil, nil, err
			}
			var b struct {
				Enabled *bool             `json:"enabled"`
				Config  map[string]string `json:"config"`
				Secret  *string           `json:"secret"`
			}
			if err := decodeARBody(c, &b, "enabled", "config", "secret"); err != nil {
				return nil, nil, err
			}
			provider := c.Param("provider")
			out, err := ctl.svc().PutIntegration(c.Request.Context(), ws, actor, cat, provider,
				services.AgentAskIntegrationInput{Enabled: b.Enabled, Config: b.Config, Secret: b.Secret})
			if err != nil {
				return nil, nil, err
			}
			// The audit row holds the stored view: config and fingerprint, never the secret.
			auditAdminMutation(c, ws.String(), "agent_ask_integration_put", "agent_ask_integration", provider, http.StatusOK, nil, out)
			return out, nil, nil
		})
	}
}

func (ctl *AgentAsksController) deleteIntegration(cat string) gin.HandlerFunc {
	return func(c *gin.Context) {
		arCall(c, func(ws uuid.UUID) (any, any, error) {
			actor, err := ctl.actor(c, ws)
			if err != nil {
				return nil, nil, err
			}
			provider := c.Param("provider")
			if err := ctl.svc().DeleteIntegration(c.Request.Context(), ws, actor, cat, provider); err != nil {
				return nil, nil, err
			}
			auditAdminMutation(c, ws.String(), "agent_ask_integration_delete", "agent_ask_integration", provider, http.StatusOK, nil, nil)
			return gin.H{"deleted": true}, nil, nil
		})
	}
}
