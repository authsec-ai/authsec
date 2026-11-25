package platform

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/services"
)

// One agent id, lifecycle, classification, directory, responder groups and
// hygiene (SPEC-secops-backend-upgrade.md W7). On /api/iga/v1, behind auth,
// with the §5.2 envelope (as the agent runtime routes):
//
//	GET    /agent-identities                       discovery:read
//	GET    /agent-identities/:id                   discovery:read
//	GET    /agent-identities/:id/responder         discovery:read
//	POST   /agent-identities/:id/retire            iga:review + verified human (reason)
//	POST   /agent-identities/:id/merge             iga:review + verified human (reason, merge_into)
//	POST   /agent-identities/:id/transfer          iga:review + verified human (reason, transfer_to)
//	POST   /agent-identities/:id/not-an-agent      iga:review + verified human (reason)
//	PUT    /agent-identities/:id/purpose           governance:author (tier 1)
//	PUT    /agent-identities/:id/risk-class        governance:author (raise tier 1; lower tier 3 -> pending change)
//	POST   /agent-identities/:id/deployers         governance:author
//	GET    /agent-changes                          governance:read
//	POST   /agent-changes/:id/approve|reject       governance:approve, never the requester
//	POST   /agent-changes/:id/withdraw             governance:author, the requester only
//	GET    /resources/:id/classification           discovery:read
//	PUT    /resources/:id/classification           iga:review (raise tier 0; lower tier 3)
//	GET    /directory/people                       discovery:read
//	GET    /agent-hygiene/findings                 discovery:read
//	GET    /responder-groups                       governance:read
//	POST   /responder-groups                       governance:author
//	GET    /responder-groups/:id                   governance:read
//	PATCH  /responder-groups/:id                   governance:author
//	DELETE /responder-groups/:id                   governance:author
//	POST   /responder-groups/:id/members           governance:author (assigns a candidate)
//	DELETE /responder-groups/:id/members/:user_id  governance:author
//	POST   /responder-groups/:id/accept            governance:read, the candidate themselves
//	POST   /responder-groups/:id/delegate          governance:read, an accepted member themselves
//	POST   /responder-groups/:id/scopes            governance:author
//	DELETE /responder-groups/:id/scopes/:scope_id  governance:author
//	POST   /responder-groups/:id/handover          governance:author
//
// /agent-identities, not /agents: GET /api/iga/v1/agents is the Phase 1 IGA
// estate's list (iga_agents) and keeps its contract.
//
// The workspace is the token's only; another workspace's id is 404. Every
// write's actor is the verified human (humanActor): a machine token never
// decides.

// AgentIdentityController serves the routes above.
type AgentIdentityController struct{ db func() *gorm.DB }

// NewAgentIdentityController reads the process database on every request.
func NewAgentIdentityController() *AgentIdentityController {
	// TENANT-EXEMPT: not a statement: the handle every service below opens its workspace transaction on.
	return &AgentIdentityController{db: func() *gorm.DB { return config.DB }}
}

// NewAgentIdentityControllerFor uses the graph controller's database.
func NewAgentIdentityControllerFor(g *IGAGraphReadController) *AgentIdentityController {
	return &AgentIdentityController{db: g.db}
}

// NewAgentIdentityControllerWith builds the controller over db (tests).
func NewAgentIdentityControllerWith(db *gorm.DB) *AgentIdentityController {
	return &AgentIdentityController{db: func() *gorm.DB { return db }}
}

// MountAgentIdentityRoutes mounts the routes on /api/iga/v1 behind auth.
func MountAgentIdentityRoutes(r gin.IRouter, ctl *AgentIdentityController, auth gin.HandlerFunc, require func(resource, action string) gin.HandlerFunc) {
	g := r.Group("/api/iga/v1")
	g.Use(GraphEnvelope(auth))
	RegisterAgentIdentityRoutes(g, ctl, GraphRequire(require))
}

// RegisterAgentIdentityRoutes is the route table (tests mount the same one).
func RegisterAgentIdentityRoutes(g gin.IRoutes, ctl *AgentIdentityController, require func(resource, action string) gin.HandlerFunc) {
	read := require("discovery", "read")
	review := require("iga", "review")
	gread := require("governance", "read")
	author := require("governance", "author")
	approve := require("governance", "approve")

	g.GET("/agent-identities", read, ctl.ListAgents)
	g.GET("/agent-identities/:id", read, ctl.GetAgent)
	g.GET("/agent-identities/:id/responder", read, ctl.GetResponder)
	for _, action := range []string{services.AgentEndRetire, services.AgentEndMerge, services.AgentEndTransfer, services.AgentEndNotAnAgent} {
		g.POST("/agent-identities/:id/"+action, review, ctl.endAgent(action))
	}
	g.PUT("/agent-identities/:id/purpose", author, ctl.SetPurpose)
	g.PUT("/agent-identities/:id/risk-class", author, ctl.SetRiskClass)
	g.POST("/agent-identities/:id/deployers", author, ctl.RecordDeployer)

	g.GET("/agent-changes", gread, ctl.ListChanges)
	g.POST("/agent-changes/:id/approve", approve, ctl.decideChange(services.PendingDecisionApprove))
	g.POST("/agent-changes/:id/reject", approve, ctl.decideChange(services.PendingDecisionReject))
	g.POST("/agent-changes/:id/withdraw", author, ctl.decideChange(services.PendingDecisionWithdraw))

	g.GET("/resources/:id/classification", read, ctl.GetClassification)
	g.PUT("/resources/:id/classification", review, ctl.SetClassification)

	g.GET("/directory/people", read, ctl.ListDirectory)
	g.GET("/agent-hygiene/findings", read, ctl.ListHygiene)

	g.GET("/responder-groups", gread, ctl.ListGroups)
	g.POST("/responder-groups", author, ctl.CreateGroup)
	g.GET("/responder-groups/:id", gread, ctl.GetGroup)
	g.PATCH("/responder-groups/:id", author, ctl.UpdateGroup)
	g.DELETE("/responder-groups/:id", author, ctl.DeleteGroup)
	g.POST("/responder-groups/:id/members", author, ctl.AddMember)
	g.DELETE("/responder-groups/:id/members/:user_id", author, ctl.RemoveMember)
	g.POST("/responder-groups/:id/accept", gread, ctl.AcceptGroup)
	g.POST("/responder-groups/:id/delegate", gread, ctl.Delegate)
	g.POST("/responder-groups/:id/scopes", author, ctl.AddScope)
	g.DELETE("/responder-groups/:id/scopes/:scope_id", author, ctl.RemoveScope)
	g.POST("/responder-groups/:id/handover", author, ctl.Handover)
}

func (ctl *AgentIdentityController) agents() *services.AgentIdentityService {
	// TENANT-EXEMPT: not a statement: the service runs every statement in a workspace transaction.
	return services.NewAgentIdentityService(ctl.db())
}

func (ctl *AgentIdentityController) groups() *services.ResponderGroupService {
	// TENANT-EXEMPT: not a statement: the service runs every statement in a workspace transaction.
	return services.NewResponderGroupService(ctl.db())
}

// actor is the verified human of this workspace (403 otherwise).
func (ctl *AgentIdentityController) actor(c *gin.Context, ws uuid.UUID) (uuid.UUID, error) {
	// TENANT-EXEMPT: humanActor runs its one statement through tenancy.QueryRowContext.
	uid, err := humanActor(c, ctl.db(), ws)
	if err != nil {
		if errors.Is(err, errNotWorkspaceHuman) {
			return uuid.Nil, services.GovForbidden("This decision requires a verified workspace member session.")
		}
		return uuid.Nil, err
	}
	return uuid.Parse(uid)
}

// pathID is a route id; a malformed one names nothing (404).
func aidPathID(c *gin.Context, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(c.Param(name))
	if err != nil {
		return uuid.Nil, services.GovNotFound()
	}
	return id, nil
}

// ListAgents handles GET /agent-identities.
func (ctl *AgentIdentityController) ListAgents(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		if err := arOnlyParams(c, "state", "kind", "cursor", "limit"); err != nil {
			return nil, nil, err
		}
		limit, err := limitParam(c)
		if err != nil {
			return nil, nil, err
		}
		items, next, err := ctl.agents().ListAgents(c.Request.Context(), ws, services.AgentListFilter{
			State: c.Query("state"), Kind: c.Query("kind"), Cursor: c.Query("cursor"), Limit: limit})
		if err != nil {
			return nil, nil, err
		}
		return items, gin.H{"next_cursor": next}, nil
	})
}

// GetAgent handles GET /agent-identities/:id.
func (ctl *AgentIdentityController) GetAgent(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := aidPathID(c, "id")
		if err != nil {
			return nil, nil, err
		}
		out, err := ctl.agents().GetAgent(c.Request.Context(), ws, id)
		return out, nil, err
	})
}

// GetResponder handles GET /agent-identities/:id/responder.
func (ctl *AgentIdentityController) GetResponder(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := aidPathID(c, "id")
		if err != nil {
			return nil, nil, err
		}
		out, err := ctl.groups().ResolveDecider(c.Request.Context(), ws, id)
		return out, nil, err
	})
}

type endBody struct {
	Reason          *string `json:"reason"`
	MergeInto       *string `json:"merge_into"`
	TransferTo      *string `json:"transfer_to"`
	ExpectedVersion *int64  `json:"expected_version"`
}

func (ctl *AgentIdentityController) endAgent(action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		arCall(c, func(ws uuid.UUID) (any, any, error) {
			id, err := aidPathID(c, "id")
			if err != nil {
				return nil, nil, err
			}
			if _, err := ctl.agents().GetAgent(c.Request.Context(), ws, id); err != nil {
				return nil, nil, err
			}
			actor, err := ctl.actor(c, ws)
			if err != nil {
				return nil, nil, err
			}
			var b endBody
			allowed := []string{"reason", "expected_version"}
			switch action {
			case services.AgentEndMerge:
				allowed = append(allowed, "merge_into")
			case services.AgentEndTransfer:
				allowed = append(allowed, "transfer_to")
			}
			if err := decodeARBody(c, &b, allowed...); err != nil {
				return nil, nil, err
			}
			req := services.AgentEndRequest{Action: action, ExpectedVersion: b.ExpectedVersion}
			if b.Reason != nil {
				req.Reason = *b.Reason
			}
			if b.MergeInto != nil {
				if req.MergeInto, err = uuid.Parse(*b.MergeInto); err != nil {
					return nil, nil, services.GovBadParam("merge_into", "merge_into must be an agent id.")
				}
			}
			if b.TransferTo != nil {
				req.TransferTo = *b.TransferTo
			}
			out, err := ctl.agents().EndAgent(c.Request.Context(), ws, id, actor, req)
			if err != nil {
				return nil, nil, err
			}
			auditAdminMutation(c, ws.String(), "agent_"+action, "agent", id.String(), http.StatusOK, nil, out)
			return out, nil, nil
		})
	}
}

// SetPurpose handles PUT /agent-identities/:id/purpose.
func (ctl *AgentIdentityController) SetPurpose(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := aidPathID(c, "id")
		if err != nil {
			return nil, nil, err
		}
		if _, err := ctl.agents().GetAgent(c.Request.Context(), ws, id); err != nil {
			return nil, nil, err
		}
		actor, err := ctl.actor(c, ws)
		if err != nil {
			return nil, nil, err
		}
		var b struct {
			Purpose *string `json:"purpose"`
		}
		if err := decodeARBody(c, &b, "purpose"); err != nil {
			return nil, nil, err
		}
		if b.Purpose == nil {
			return nil, nil, services.GovBadParam("purpose", "purpose is required.")
		}
		out, err := ctl.agents().SetPurpose(c.Request.Context(), ws, id, actor, *b.Purpose)
		if err != nil {
			return nil, nil, err
		}
		auditAdminMutation(c, ws.String(), "agent_purpose_set", "agent", id.String(), http.StatusOK, nil, out)
		return out, nil, nil
	})
}

// SetRiskClass handles PUT /agent-identities/:id/risk-class.
func (ctl *AgentIdentityController) SetRiskClass(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := aidPathID(c, "id")
		if err != nil {
			return nil, nil, err
		}
		if _, err := ctl.agents().GetAgent(c.Request.Context(), ws, id); err != nil {
			return nil, nil, err
		}
		actor, err := ctl.actor(c, ws)
		if err != nil {
			return nil, nil, err
		}
		var b struct {
			RiskClass   *string  `json:"risk_class"`
			Obligations []string `json:"obligations"`
			Reason      *string  `json:"reason"`
		}
		if err := decodeARBody(c, &b, "risk_class", "obligations", "reason"); err != nil {
			return nil, nil, err
		}
		req := services.RiskClassRequest{Obligations: b.Obligations}
		if b.RiskClass != nil {
			req.RiskClass = *b.RiskClass
		}
		if b.Reason != nil {
			req.Reason = *b.Reason
		}
		out, err := ctl.agents().SetRiskClass(c.Request.Context(), ws, id, actor, req)
		if err != nil {
			return nil, nil, err
		}
		auditAdminMutation(c, ws.String(), "agent_risk_class_set", "agent", id.String(), http.StatusOK, nil, out)
		return out, nil, nil
	})
}

// RecordDeployer handles POST /agent-identities/:id/deployers.
func (ctl *AgentIdentityController) RecordDeployer(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := aidPathID(c, "id")
		if err != nil {
			return nil, nil, err
		}
		if _, err := ctl.agents().GetAgent(c.Request.Context(), ws, id); err != nil {
			return nil, nil, err
		}
		actor, err := ctl.actor(c, ws)
		if err != nil {
			return nil, nil, err
		}
		var b struct {
			Deployer *string `json:"deployer"`
		}
		if err := decodeARBody(c, &b, "deployer"); err != nil {
			return nil, nil, err
		}
		if b.Deployer == nil {
			return nil, nil, services.GovBadParam("deployer", "deployer is required.")
		}
		out, err := ctl.agents().RecordDeployer(c.Request.Context(), ws, id, actor, *b.Deployer)
		if err != nil {
			return nil, nil, err
		}
		auditAdminMutation(c, ws.String(), "agent_deployer_recorded", "agent", id.String(), http.StatusOK, nil, out)
		return gin.H{"deployers": out}, nil, nil
	})
}

// ListChanges handles GET /agent-changes.
func (ctl *AgentIdentityController) ListChanges(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		if err := arOnlyParams(c, "state"); err != nil {
			return nil, nil, err
		}
		out, err := ctl.agents().ListPendingChanges(c.Request.Context(), ws, c.Query("state"))
		return out, nil, err
	})
}

func (ctl *AgentIdentityController) decideChange(decision string) gin.HandlerFunc {
	return func(c *gin.Context) {
		arCall(c, func(ws uuid.UUID) (any, any, error) {
			id, err := aidPathID(c, "id")
			if err != nil {
				return nil, nil, err
			}
			actor, err := ctl.actor(c, ws)
			if err != nil {
				return nil, nil, err
			}
			var b struct {
				Reason *string `json:"reason"`
			}
			if c.Request.ContentLength != 0 {
				if err := decodeARBody(c, &b, "reason"); err != nil {
					return nil, nil, err
				}
			}
			reason := ""
			if b.Reason != nil {
				reason = *b.Reason
			}
			out, err := ctl.agents().DecidePendingChange(c.Request.Context(), ws, id, actor, decision, reason)
			if err != nil {
				return nil, nil, err
			}
			auditAdminMutation(c, ws.String(), "agent_change_"+decision, "agent_pending_change", id.String(), http.StatusOK, nil, out)
			return out, nil, nil
		})
	}
}

// GetClassification handles GET /resources/:id/classification (a cloud_resource id).
func (ctl *AgentIdentityController) GetClassification(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := aidPathID(c, "id")
		if err != nil {
			return nil, nil, err
		}
		// TENANT-EXEMPT: not a statement: the service runs every statement in a workspace transaction.
		out, err := services.NewResourceClassificationService(ctl.db()).Get(c.Request.Context(), ws, id)
		return out, nil, err
	})
}

// SetClassification handles PUT /resources/:id/classification.
func (ctl *AgentIdentityController) SetClassification(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := aidPathID(c, "id")
		if err != nil {
			return nil, nil, err
		}
		// TENANT-EXEMPT: not a statement: the service runs every statement in a workspace transaction.
		svc := services.NewResourceClassificationService(ctl.db())
		if _, err := svc.Get(c.Request.Context(), ws, id); err != nil {
			return nil, nil, err
		}
		actor, err := ctl.actor(c, ws)
		if err != nil {
			return nil, nil, err
		}
		var b struct {
			Sensitivity  *string `json:"sensitivity"`
			CrownJewel   *bool   `json:"crown_jewel"`
			DataCategory *string `json:"data_category"`
			Residency    *string `json:"residency"`
			Reason       *string `json:"reason"`
		}
		if err := decodeARBody(c, &b, "sensitivity", "crown_jewel", "data_category", "residency", "reason"); err != nil {
			return nil, nil, err
		}
		req := services.ResourceClassificationRequest{Sensitivity: b.Sensitivity, CrownJewel: b.CrownJewel,
			DataCategory: b.DataCategory, Residency: b.Residency}
		if b.Reason != nil {
			req.Reason = *b.Reason
		}
		out, err := svc.Set(c.Request.Context(), ws, id, actor, req)
		if err != nil {
			return nil, nil, err
		}
		auditAdminMutation(c, ws.String(), "resource_classification_set", "cloud_resource", id.String(), http.StatusOK, nil, out)
		return out, nil, nil
	})
}

// ListDirectory handles GET /directory/people.
func (ctl *AgentIdentityController) ListDirectory(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		if err := arOnlyParams(c, "status"); err != nil {
			return nil, nil, err
		}
		// TENANT-EXEMPT: not a statement: the service runs every statement in a workspace transaction.
		out, err := services.NewDirectoryService(ctl.db()).List(c.Request.Context(), ws, c.Query("status"))
		return out, nil, err
	})
}

// ListHygiene handles GET /agent-hygiene/findings.
func (ctl *AgentIdentityController) ListHygiene(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		if err := arOnlyParams(c, "kind", "state"); err != nil {
			return nil, nil, err
		}
		out, err := ctl.agents().ListHygieneFindings(c.Request.Context(), ws, c.Query("kind"), c.Query("state"))
		return out, nil, err
	})
}

/* ----------------------------- responder groups ---------------------------- */

// ListGroups handles GET /responder-groups.
func (ctl *AgentIdentityController) ListGroups(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		out, err := ctl.groups().List(c.Request.Context(), ws)
		return out, nil, err
	})
}

// GetGroup handles GET /responder-groups/:id.
func (ctl *AgentIdentityController) GetGroup(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := aidPathID(c, "id")
		if err != nil {
			return nil, nil, err
		}
		out, err := ctl.groups().Get(c.Request.Context(), ws, id)
		return out, nil, err
	})
}

// groupWrite resolves the group (404 first), the actor, then the body.
func (ctl *AgentIdentityController) groupWrite(c *gin.Context, dst any, allowed []string,
	fn func(ws, id, actor uuid.UUID) (any, error)) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := aidPathID(c, "id")
		if err != nil {
			return nil, nil, err
		}
		if _, err := ctl.groups().Get(c.Request.Context(), ws, id); err != nil {
			return nil, nil, err
		}
		actor, err := ctl.actor(c, ws)
		if err != nil {
			return nil, nil, err
		}
		if dst != nil && c.Request.ContentLength != 0 {
			if err := decodeARBody(c, dst, allowed...); err != nil {
				return nil, nil, err
			}
		}
		out, err := fn(ws, id, actor)
		if err != nil {
			return nil, nil, err
		}
		auditAdminMutation(c, ws.String(), "responder_group_"+c.Request.Method, "responder_group", id.String(), http.StatusOK, nil, out)
		return out, nil, nil
	})
}

// CreateGroup handles POST /responder-groups.
func (ctl *AgentIdentityController) CreateGroup(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		actor, err := ctl.actor(c, ws)
		if err != nil {
			return nil, nil, err
		}
		var b struct {
			Name        *string `json:"name"`
			Description *string `json:"description"`
		}
		if err := decodeARBody(c, &b, "name", "description"); err != nil {
			return nil, nil, err
		}
		name, desc := "", ""
		if b.Name != nil {
			name = *b.Name
		}
		if b.Description != nil {
			desc = *b.Description
		}
		out, err := ctl.groups().Create(c.Request.Context(), ws, actor, name, desc)
		if err != nil {
			return nil, nil, err
		}
		auditAdminMutation(c, ws.String(), "responder_group_create", "responder_group", out.ID.String(), http.StatusOK, nil, out)
		return out, nil, nil
	})
}

// UpdateGroup handles PATCH /responder-groups/:id.
func (ctl *AgentIdentityController) UpdateGroup(c *gin.Context) {
	var b struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}
	ctl.groupWrite(c, &b, []string{"name", "description"}, func(ws, id, actor uuid.UUID) (any, error) {
		return ctl.groups().Update(c.Request.Context(), ws, id, actor, b.Name, b.Description)
	})
}

// DeleteGroup handles DELETE /responder-groups/:id.
func (ctl *AgentIdentityController) DeleteGroup(c *gin.Context) {
	ctl.groupWrite(c, nil, nil, func(ws, id, actor uuid.UUID) (any, error) {
		return gin.H{"deleted": true}, ctl.groups().Delete(c.Request.Context(), ws, id, actor)
	})
}

// AddMember handles POST /responder-groups/:id/members.
func (ctl *AgentIdentityController) AddMember(c *gin.Context) {
	var b struct {
		UserID *string `json:"user_id"`
		Role   *string `json:"role"`
	}
	ctl.groupWrite(c, &b, []string{"user_id", "role"}, func(ws, id, actor uuid.UUID) (any, error) {
		if b.UserID == nil {
			return nil, services.GovBadParam("user_id", "user_id is required.")
		}
		user, err := uuid.Parse(*b.UserID)
		if err != nil {
			return nil, services.GovBadParam("user_id", "user_id must be a uuid.")
		}
		role := ""
		if b.Role != nil {
			role = *b.Role
		}
		return ctl.groups().AddMember(c.Request.Context(), ws, id, actor, user, role)
	})
}

// RemoveMember handles DELETE /responder-groups/:id/members/:user_id.
func (ctl *AgentIdentityController) RemoveMember(c *gin.Context) {
	ctl.groupWrite(c, nil, nil, func(ws, id, actor uuid.UUID) (any, error) {
		user, err := aidPathID(c, "user_id")
		if err != nil {
			return nil, err
		}
		return gin.H{"removed": true}, ctl.groups().RemoveMember(c.Request.Context(), ws, id, actor, user)
	})
}

// AcceptGroup handles POST /responder-groups/:id/accept.
func (ctl *AgentIdentityController) AcceptGroup(c *gin.Context) {
	ctl.groupWrite(c, nil, nil, func(ws, id, actor uuid.UUID) (any, error) {
		return ctl.groups().Accept(c.Request.Context(), ws, id, actor)
	})
}

// Delegate handles POST /responder-groups/:id/delegate ({delegate_to, until};
// delegate_to null ends the delegation).
func (ctl *AgentIdentityController) Delegate(c *gin.Context) {
	var b struct {
		DelegateTo *string    `json:"delegate_to"`
		Until      *time.Time `json:"until"`
	}
	ctl.groupWrite(c, &b, []string{"delegate_to", "until"}, func(ws, id, actor uuid.UUID) (any, error) {
		var to *uuid.UUID
		if b.DelegateTo != nil {
			u, err := uuid.Parse(*b.DelegateTo)
			if err != nil {
				return nil, services.GovBadParam("delegate_to", "delegate_to must be a uuid.")
			}
			to = &u
		}
		return ctl.groups().Delegate(c.Request.Context(), ws, id, actor, to, b.Until)
	})
}

// AddScope handles POST /responder-groups/:id/scopes.
func (ctl *AgentIdentityController) AddScope(c *gin.Context) {
	var b struct {
		ScopeKind *string `json:"scope_kind"`
		ScopeRef  *string `json:"scope_ref"`
	}
	ctl.groupWrite(c, &b, []string{"scope_kind", "scope_ref"}, func(ws, id, actor uuid.UUID) (any, error) {
		kind, ref := "", ""
		if b.ScopeKind != nil {
			kind = *b.ScopeKind
		}
		if b.ScopeRef != nil {
			ref = *b.ScopeRef
		}
		return ctl.groups().AddScope(c.Request.Context(), ws, id, actor, kind, ref)
	})
}

// RemoveScope handles DELETE /responder-groups/:id/scopes/:scope_id.
func (ctl *AgentIdentityController) RemoveScope(c *gin.Context) {
	ctl.groupWrite(c, nil, nil, func(ws, id, actor uuid.UUID) (any, error) {
		sid, err := aidPathID(c, "scope_id")
		if err != nil {
			return nil, err
		}
		return gin.H{"removed": true}, ctl.groups().RemoveScope(c.Request.Context(), ws, id, actor, sid)
	})
}

// Handover handles POST /responder-groups/:id/handover ({to_group_id}).
func (ctl *AgentIdentityController) Handover(c *gin.Context) {
	var b struct {
		ToGroupID *string `json:"to_group_id"`
	}
	ctl.groupWrite(c, &b, []string{"to_group_id"}, func(ws, id, actor uuid.UUID) (any, error) {
		if b.ToGroupID == nil {
			return nil, services.GovBadParam("to_group_id", "to_group_id is required.")
		}
		to, err := uuid.Parse(*b.ToGroupID)
		if err != nil {
			return nil, services.GovBadParam("to_group_id", "to_group_id must be a uuid.")
		}
		return ctl.groups().Handover(c.Request.Context(), ws, id, actor, to)
	})
}
