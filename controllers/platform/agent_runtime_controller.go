package platform

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/services"
)

// Agent runtime visibility on AWS (SPEC-agent-runtime-visibility.md §5.2,
// §5.3, §5.5, §10 Q1/Q2):
//
//	GET  /api/iga/v1/agent-runtime/ai-workloads              discovery:read
//	GET  /api/iga/v1/agent-runtime/suggestions               discovery:read
//	POST /api/iga/v1/agent-runtime/suggestions/:id/confirm   iga:review + verified human
//	POST /api/iga/v1/agent-runtime/suggestions/:id/dismiss   iga:review + verified human
//	GET  /api/iga/v1/agent-runtime/findings                  discovery:read
//
// The workspace is the token's only (tenancy), never a parameter; another
// workspace's id is 404, exactly like an unknown one. Envelope {data, meta} /
// {error: {code, message, detail}}, as the governance routes (govCall).

// AgentRuntimeController serves the routes above.
type AgentRuntimeController struct {
	db func() *gorm.DB
	// classifier is the classification decision service a test installed;
	// nil builds one over db() per request.
	classifier *services.ClassificationService
}

// NewAgentRuntimeController reads the process database on every request.
func NewAgentRuntimeController() *AgentRuntimeController {
	// TENANT-EXEMPT: not a statement: the handle every service below opens its
	// workspace transaction on.
	return &AgentRuntimeController{db: func() *gorm.DB { return config.DB }}
}

// NewAgentRuntimeControllerWith builds the controller over an explicit
// database and classification service (tests).
func NewAgentRuntimeControllerWith(db *gorm.DB, classifier *services.ClassificationService) *AgentRuntimeController {
	return &AgentRuntimeController{db: func() *gorm.DB { return db }, classifier: classifier}
}

// MountAgentRuntimeRoutes mounts the routes on /api/iga/v1 behind auth, with
// the §5.2 envelope for an auth or permission denial (as the graph and policy
// groups).
func MountAgentRuntimeRoutes(r gin.IRouter, ctl *AgentRuntimeController, auth gin.HandlerFunc, require func(resource, action string) gin.HandlerFunc) {
	g := r.Group("/api/iga/v1")
	g.Use(GraphEnvelope(auth))
	RegisterAgentRuntimeRoutes(g, ctl, GraphRequire(require))
}

// RegisterAgentRuntimeRoutes is the route table, on a group that already
// carries auth. One table, so tests assert the same one.
func RegisterAgentRuntimeRoutes(g gin.IRoutes, ctl *AgentRuntimeController, require func(resource, action string) gin.HandlerFunc) {
	read := require("discovery", "read")
	review := require("iga", "review")
	g.GET("/agent-runtime/ai-workloads", read, ctl.ListAIWorkloads)
	g.GET("/agent-runtime/suggestions", read, ctl.ListSuggestions)
	g.POST("/agent-runtime/suggestions/:id/confirm", review, ctl.ConfirmSuggestion)
	g.POST("/agent-runtime/suggestions/:id/dismiss", review, ctl.DismissSuggestion)
	g.GET("/agent-runtime/findings", read, ctl.ListFindings)
}

// service is the agent runtime service over the controller's database.
func (ctl *AgentRuntimeController) service() *services.AgentRuntimeService {
	// TENANT-EXEMPT: not a statement here: the service runs every statement in
	// a transaction under row-level security for the token's workspace.
	s := services.NewAgentRuntimeService(ctl.db())
	if ctl.classifier != nil {
		s = s.WithClassifier(ctl.classifier)
	}
	return s
}

// arCall resolves the token workspace and renders the outcome: a GovError or
// an *igaread.Error (the classification contract's) with its status and body,
// anything else 500 without its text.
func arCall(c *gin.Context, fn func(ws uuid.UUID) (data any, meta any, err error)) {
	ws, ok := tokenWorkspace(c)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": gin.H{
			"code": "unauthenticated", "message": "No workspace in the token.", "detail": gin.H{}}})
		return
	}
	data, meta, err := fn(ws)
	if err != nil {
		var ge *services.GovError
		var ie *igaread.Error
		switch {
		case errors.As(err, &ge):
			c.AbortWithStatusJSON(ge.Status, ge.Body())
		case errors.As(err, &ie) && ie.Status < http.StatusInternalServerError:
			c.AbortWithStatusJSON(ie.Status, ie.Body())
		default:
			log.Printf("[agent-runtime] %s %s: %v", c.Request.Method, c.FullPath(), err)
			if errors.As(err, &ie) && ie.Status == http.StatusGatewayTimeout {
				c.AbortWithStatusJSON(ie.Status, ie.Body())
				return
			}
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": gin.H{
				"code": "internal_error", "message": "The request could not be completed.", "detail": gin.H{}}})
		}
		return
	}
	if meta == nil {
		meta = gin.H{}
	}
	c.JSON(http.StatusOK, gin.H{"data": data, "meta": meta})
}

// arOnlyParams refuses a query parameter the route does not take (400 naming
// it), so a client never believes a filter applied that did not.
func arOnlyParams(c *gin.Context, allowed ...string) error {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	var unknown []string
	for k := range c.Request.URL.Query() {
		if !ok[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return services.GovBadParam(unknown[0], "unknown parameter "+strconv.Quote(unknown[0])+".")
	}
	return nil
}

// ListAIWorkloads handles GET /agent-runtime/ai-workloads.
func (ctl *AgentRuntimeController) ListAIWorkloads(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		if err := arOnlyParams(c, "connector_id", "label", "cursor", "limit"); err != nil {
			return nil, nil, err
		}
		f := services.AIWorkloadFilter{Label: c.Query("label"), Cursor: c.Query("cursor")}
		var err error
		if f.ConnectorID, err = optUUIDParam(c, "connector_id"); err != nil {
			return nil, nil, err
		}
		if f.Limit, err = limitParam(c); err != nil {
			return nil, nil, err
		}
		items, next, err := ctl.service().ListAIWorkloads(c.Request.Context(), ws, f)
		if err != nil {
			return nil, nil, err
		}
		return items, gin.H{"next_cursor": next}, nil
	})
}

// ListSuggestions handles GET /agent-runtime/suggestions.
func (ctl *AgentRuntimeController) ListSuggestions(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		if err := arOnlyParams(c, "state", "connector_id", "cursor", "limit"); err != nil {
			return nil, nil, err
		}
		f := services.SuggestionFilter{State: c.Query("state"), Cursor: c.Query("cursor")}
		var err error
		if f.ConnectorID, err = optUUIDParam(c, "connector_id"); err != nil {
			return nil, nil, err
		}
		if f.Limit, err = limitParam(c); err != nil {
			return nil, nil, err
		}
		items, next, err := ctl.service().ListSuggestions(c.Request.Context(), ws, f)
		if err != nil {
			return nil, nil, err
		}
		return items, gin.H{"next_cursor": next}, nil
	})
}

// ListFindings handles GET /agent-runtime/findings.
func (ctl *AgentRuntimeController) ListFindings(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		if err := arOnlyParams(c, "kind", "state", "connector_id", "cursor", "limit"); err != nil {
			return nil, nil, err
		}
		f := services.FindingListFilter{Kind: c.Query("kind"), State: c.Query("state"), Cursor: c.Query("cursor")}
		var err error
		if f.ConnectorID, err = optUUIDParam(c, "connector_id"); err != nil {
			return nil, nil, err
		}
		if f.Limit, err = limitParam(c); err != nil {
			return nil, nil, err
		}
		items, next, err := ctl.service().ListFindings(c.Request.Context(), ws, f)
		if err != nil {
			return nil, nil, err
		}
		return items, gin.H{"next_cursor": next}, nil
	})
}

// arBodyLimit bounds a decision body: a few short fields.
const arBodyLimit = 64 << 10

// decodeARBody reads exactly one JSON object with only the allowed keys into
// dst; an unknown key, a wrong type or trailing data is 400 naming it.
func decodeARBody(c *gin.Context, dst any, allowed ...string) error {
	var raw json.RawMessage
	dec := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, arBodyLimit))
	if err := dec.Decode(&raw); err != nil {
		return services.GovBadParam("body", "the body must be a JSON object.")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return services.GovBadParam("body", "the body must be exactly one JSON object.")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return services.GovBadParam("body", "the body must be a JSON object.")
	}
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	var unknown []string
	for k := range fields {
		if !ok[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return services.GovBadParam(unknown[0], "unknown field "+strconv.Quote(unknown[0])+".")
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) && ok[te.Field] {
			return services.GovBadParam(te.Field, te.Field+" has the wrong type.")
		}
		return services.GovBadParam("body", "the body must be a JSON object.")
	}
	return nil
}

// arActor applies the classification actor rule (humanActor): only a live
// human member of this workspace decides. Not one is 403; a database failure
// while checking is 500, never a refusal.
func (ctl *AgentRuntimeController) arActor(c *gin.Context, ws uuid.UUID) (uuid.UUID, error) {
	// TENANT-EXEMPT: humanActor runs its one statement through tenancy.QueryRowContext.
	uid, err := humanActor(c, ctl.db(), ws)
	if err != nil {
		if errors.Is(err, errNotWorkspaceHuman) {
			return uuid.Nil, services.GovForbidden("Suggestion decisions require a verified workspace member session.")
		}
		return uuid.Nil, err
	}
	return uuid.Parse(uid)
}

// arSuggestionID is the route id; a malformed one names nothing (404).
func arSuggestionID(c *gin.Context) (uuid.UUID, error) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return uuid.Nil, services.GovNotFound()
	}
	return id, nil
}

// confirmBody is POST .../confirm: the classification contract's operation_id
// and version (the workload's classification_version the person saw), an
// optional purpose and reason (a default reason names the suggestion).
type confirmBody struct {
	OperationID *string `json:"operation_id"`
	Version     *int64  `json:"version"`
	Purpose     *string `json:"purpose"`
	Reason      *string `json:"reason"`
}

// ConfirmSuggestion handles POST /agent-runtime/suggestions/:id/confirm.
//
// Order: the token's workspace, the suggestion (404: another workspace's is
// not found), the actor (403), the body (400), then one transaction: the
// classification decision and the suggestion closed together.
func (ctl *AgentRuntimeController) ConfirmSuggestion(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := arSuggestionID(c)
		if err != nil {
			return nil, nil, err
		}
		svc := ctl.service()
		if _, err := svc.GetSuggestion(c.Request.Context(), ws, id); err != nil {
			return nil, nil, err
		}
		actor, err := ctl.arActor(c, ws)
		if err != nil {
			return nil, nil, err
		}
		var b confirmBody
		if err := decodeARBody(c, &b, "operation_id", "version", "purpose", "reason"); err != nil {
			return nil, nil, err
		}
		if b.OperationID == nil || *b.OperationID == "" {
			return nil, nil, services.GovBadParam("operation_id", "operation_id is required.")
		}
		op, perr := uuid.Parse(*b.OperationID)
		if perr != nil || op == uuid.Nil {
			return nil, nil, services.GovBadParam("operation_id", "operation_id must be a client-generated UUID.")
		}
		if b.Version == nil {
			return nil, nil, services.GovBadParam("version", "version is required: the workload's classification_version.")
		}
		req := services.ConfirmSuggestionRequest{SuggestionID: id, ActorUserID: actor, OperationID: op, ExpectedVersion: *b.Version}
		if b.Purpose != nil {
			req.Purpose = *b.Purpose
		}
		if b.Reason != nil {
			req.Reason = *b.Reason
		}
		res, err := svc.ConfirmSuggestion(c.Request.Context(), ws, req)
		if err != nil {
			return nil, nil, err
		}
		if res.Classification != nil && !res.Classification.Replayed {
			auditAdminMutation(c, ws.String(), "confirm_agent_suggestion", "agent_suggestion", id.String(),
				http.StatusOK, nil, res)
		}
		return res, nil, nil
	})
}

// dismissBody is POST .../dismiss.
type dismissBody struct {
	Reason *string `json:"reason"`
}

// DismissSuggestion handles POST /agent-runtime/suggestions/:id/dismiss.
func (ctl *AgentRuntimeController) DismissSuggestion(c *gin.Context) {
	arCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := arSuggestionID(c)
		if err != nil {
			return nil, nil, err
		}
		svc := ctl.service()
		if _, err := svc.GetSuggestion(c.Request.Context(), ws, id); err != nil {
			return nil, nil, err
		}
		actor, err := ctl.arActor(c, ws)
		if err != nil {
			return nil, nil, err
		}
		var b dismissBody
		if err := decodeARBody(c, &b, "reason"); err != nil {
			return nil, nil, err
		}
		if b.Reason == nil {
			return nil, nil, services.GovBadParam("reason", "reason is required: it is the audit record.")
		}
		out, replayed, err := svc.DismissSuggestion(c.Request.Context(), ws, id, actor, *b.Reason)
		if err != nil {
			return nil, nil, err
		}
		if !replayed {
			auditAdminMutation(c, ws.String(), "dismiss_agent_suggestion", "agent_suggestion", id.String(),
				http.StatusOK, nil, out)
		}
		return out, gin.H{"replayed": replayed}, nil
	})
}
