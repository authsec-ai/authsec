package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/agentgateway"
	"github.com/authsec-ai/authsec/services"
)

// Agent runtime gateway PDP (SPEC-agent-runtime-gateway.md §5, §8). No
// AuthMiddleware: the credential is the gateway's, "Authorization: Bearer
// agw_…", and it alone decides workspace and gateway; nothing in a body does.
//
//	POST /authsec/pdp/access/v1/evaluation    AuthZEN Authorization API 1.0 §6
//	POST /authsec/pdp/access/v1/evaluations   AuthZEN §7 (≤ 100 evaluations)
//	POST /authsec/pdp/v1/decisions            the gateway's own decisions and outcomes
//	GET  /authsec/pdp/v1/policy-hints         mode and deny targets (auto fail mode)
//
// A decision is a 200 whose body says true or false (as R3, DECISION R3-18);
// refusals of the request are 400 (bad request), 401 (credential), 413
// (body), 429 (per-gateway rate); an AuthSec failure is 500 and means deny
// to the gateway. Error bodies are a message string (AuthZEN §10.1.2). The
// X-Request-ID of the request is echoed (§10.1.3).

const (
	agentGatewayRequestIDHeader = "X-Request-ID"
	agentGatewayVersionHeader   = "X-AuthSec-Gateway-Version"
)

// AgentGatewayPDPController serves the routes above.
type AgentGatewayPDPController struct {
	db func() *gorm.DB
}

// NewAgentGatewayPDPController is the production controller (config.DB).
func NewAgentGatewayPDPController() *AgentGatewayPDPController {
	return &AgentGatewayPDPController{db: func() *gorm.DB { return config.DB }}
}

// NewAgentGatewayPDPControllerWith builds a controller over db (tests).
func NewAgentGatewayPDPControllerWith(db *gorm.DB) *AgentGatewayPDPController {
	return &AgentGatewayPDPController{db: func() *gorm.DB { return db }}
}

// MountAgentGatewayPDPRoutes mounts the PDP on g (the /authsec group in
// production), outside every authenticated group.
func MountAgentGatewayPDPRoutes(g gin.IRoutes, ctl *AgentGatewayPDPController) {
	g.POST("/pdp/access/v1/evaluation", ctl.Evaluation)
	g.POST("/pdp/access/v1/evaluations", ctl.Evaluations)
	g.POST("/pdp/v1/decisions", ctl.UploadDecisions)
	g.GET("/pdp/v1/policy-hints", ctl.PolicyHints)
}

// TENANT-EXEMPT: not a statement here: the service resolves the workspace from the gateway credential and runs every statement under row-level security for it.
func (ctl *AgentGatewayPDPController) svc() *services.AgentGatewayService {
	return services.AgentGatewayServiceFor(ctl.db())
}

func pdpError(c *gin.Context, status int, msg string) {
	c.Abort()
	c.Data(status, "text/plain; charset=utf-8", []byte(msg))
}

// principal authenticates the gateway, applies its rate limit and reads the
// body; false when a response was written.
func (ctl *AgentGatewayPDPController) principal(c *gin.Context, withBody bool) (*services.AgentGatewayPrincipal, []byte, bool) {
	if rid := c.GetHeader(agentGatewayRequestIDHeader); rid != "" && len(rid) <= 128 {
		c.Header(agentGatewayRequestIDHeader, rid)
	}
	c.Header("Cache-Control", "no-store")
	authz := c.GetHeader("Authorization")
	const bearer = "bearer "
	if len(authz) <= len(bearer) || !strings.EqualFold(authz[:len(bearer)], bearer) {
		c.Header("WWW-Authenticate", `Bearer realm="authsec-pdp"`)
		pdpError(c, http.StatusUnauthorized, "missing gateway credential")
		return nil, nil, false
	}
	svc := ctl.svc()
	p, err := svc.Authenticate(c.Request.Context(), strings.TrimSpace(authz[len(bearer):]))
	if err != nil {
		log.Printf("[agent-gateway-pdp] stage=auth outcome=error err=%v", err)
		pdpError(c, http.StatusInternalServerError, "could not verify the gateway credential")
		return nil, nil, false
	}
	if p == nil {
		c.Header("WWW-Authenticate", `Bearer realm="authsec-pdp", error="invalid_token"`)
		pdpError(c, http.StatusUnauthorized, "unknown or revoked gateway credential")
		return nil, nil, false
	}
	if !svc.Allow(p.GatewayID) {
		c.Header("Retry-After", "1")
		pdpError(c, http.StatusTooManyRequests, "rate limit exceeded for this gateway")
		return nil, nil, false
	}
	svc.Touch(*p, c.GetHeader(agentGatewayVersionHeader))
	if !withBody {
		return p, nil, true
	}
	if c.Request.ContentLength > services.AgentGatewayMaxBodyBytes {
		pdpError(c, http.StatusRequestEntityTooLarge, "request larger than 1 MB")
		return nil, nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, services.AgentGatewayMaxBodyBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			pdpError(c, http.StatusRequestEntityTooLarge, "request larger than 1 MB")
			return nil, nil, false
		}
		pdpError(c, http.StatusBadRequest, "could not read the request body")
		return nil, nil, false
	}
	return p, body, true
}

func decodePDPBody(body []byte, dst any) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return errors.New("the body must be a JSON object")
	}
	return json.Unmarshal(body, dst)
}

func invalidMessage(err error) string {
	return strings.TrimPrefix(err.Error(), agentgateway.ErrInvalid.Error()+": ")
}

// Evaluation handles POST /pdp/access/v1/evaluation (AuthZEN §6).
func (ctl *AgentGatewayPDPController) Evaluation(c *gin.Context) {
	p, body, ok := ctl.principal(c, true)
	if !ok {
		return
	}
	var req agentgateway.EvaluationRequest
	if err := decodePDPBody(body, &req); err != nil {
		pdpError(c, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	d, err := ctl.svc().Decide(c.Request.Context(), *p, req)
	if services.IsInvalidEvaluation(err) {
		pdpError(c, http.StatusBadRequest, invalidMessage(err))
		return
	}
	if err != nil {
		log.Printf("[agent-gateway-pdp] stage=decide workspace=%s gateway=%s outcome=error err=%v", p.WorkspaceID, p.GatewayID, err)
		pdpError(c, http.StatusInternalServerError, "the decision could not be made; deny")
		return
	}
	c.JSON(http.StatusOK, d.Response)
}

// Evaluations handles POST /pdp/access/v1/evaluations (AuthZEN §7).
func (ctl *AgentGatewayPDPController) Evaluations(c *gin.Context) {
	p, body, ok := ctl.principal(c, true)
	if !ok {
		return
	}
	var req agentgateway.EvaluationsRequest
	if err := decodePDPBody(body, &req); err != nil {
		pdpError(c, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	evals, single, err := req.Expand()
	if err != nil {
		pdpError(c, http.StatusBadRequest, err.Error())
		return
	}
	svc := ctl.svc()
	semantic := req.Semantic()
	out := agentgateway.EvaluationsResponse{Evaluations: make([]agentgateway.EvaluationResponse, 0, len(evals))}
	for _, e := range evals {
		d, err := svc.Decide(c.Request.Context(), *p, e)
		var r agentgateway.EvaluationResponse
		switch {
		case services.IsInvalidEvaluation(err):
			if single {
				pdpError(c, http.StatusBadRequest, invalidMessage(err))
				return
			}
			r = agentgateway.ErrorResponse(http.StatusBadRequest, invalidMessage(err))
		case err != nil:
			log.Printf("[agent-gateway-pdp] stage=decide workspace=%s gateway=%s outcome=error err=%v", p.WorkspaceID, p.GatewayID, err)
			pdpError(c, http.StatusInternalServerError, "the decisions could not be made; deny")
			return
		default:
			r = d.Response
		}
		if single {
			c.JSON(http.StatusOK, r)
			return
		}
		out.Evaluations = append(out.Evaluations, r)
		if agentgateway.Stop(semantic, r.Decision) {
			break
		}
	}
	c.JSON(http.StatusOK, out)
}

// UploadDecisions handles POST /pdp/v1/decisions.
func (ctl *AgentGatewayPDPController) UploadDecisions(c *gin.Context) {
	p, body, ok := ctl.principal(c, true)
	if !ok {
		return
	}
	var up services.AgentGatewayUpload
	if err := decodePDPBody(body, &up); err != nil {
		pdpError(c, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if len(up.Records) == 0 {
		pdpError(c, http.StatusBadRequest, "records is required")
		return
	}
	if len(up.Records) > services.AgentGatewayMaxUploadRecords {
		pdpError(c, http.StatusRequestEntityTooLarge, "at most 1000 records per request")
		return
	}
	res, err := ctl.svc().Upload(c.Request.Context(), *p, up)
	if err != nil {
		log.Printf("[agent-gateway-pdp] stage=upload workspace=%s gateway=%s outcome=error err=%v", p.WorkspaceID, p.GatewayID, err)
		c.Header("Retry-After", "5")
		pdpError(c, http.StatusServiceUnavailable, "the records could not be stored; retry")
		return
	}
	if res.Rejected > 0 {
		log.Printf("[agent-gateway-pdp] workspace=%s gateway=%s received=%d rejected=%d", p.WorkspaceID, p.GatewayID, res.Received, res.Rejected)
	}
	c.JSON(http.StatusAccepted, res)
}

// PolicyHints handles GET /pdp/v1/policy-hints.
func (ctl *AgentGatewayPDPController) PolicyHints(c *gin.Context) {
	p, _, ok := ctl.principal(c, false)
	if !ok {
		return
	}
	h, err := ctl.svc().PolicyHints(c.Request.Context(), *p)
	if err != nil {
		log.Printf("[agent-gateway-pdp] stage=hints workspace=%s gateway=%s outcome=error err=%v", p.WorkspaceID, p.GatewayID, err)
		pdpError(c, http.StatusInternalServerError, "the hints could not be read")
		return
	}
	c.JSON(http.StatusOK, h)
}
