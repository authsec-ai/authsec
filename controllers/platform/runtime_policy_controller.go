package platform

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// RuntimePolicyController is the /api/iga/v2/runtime-policies admin API.
type RuntimePolicyController struct {
	svc *services.RuntimePolicyService
}

// NewRuntimePolicyController builds the controller.
func NewRuntimePolicyController(svc *services.RuntimePolicyService) *RuntimePolicyController {
	return &RuntimePolicyController{svc: svc}
}

func (ctl *RuntimePolicyController) Create(c *gin.Context) {
	ctl.mutate(c, false, func(actor services.Actor, key, match string, body []byte) (int, []byte, error) {
		return ctl.svc.Create(c.Request.Context(), actor, key, body)
	})
}

func (ctl *RuntimePolicyController) List(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	status, body, err := ctl.svc.List(c.Request.Context(), actor.WorkspaceID)
	writePolicy(c, status, body, err)
}

func (ctl *RuntimePolicyController) Get(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	id, ok := policyID(c)
	if !ok {
		return
	}
	status, body, err := ctl.svc.Get(c.Request.Context(), actor.WorkspaceID, id)
	writePolicy(c, status, body, err)
}

func (ctl *RuntimePolicyController) PutDraft(c *gin.Context) {
	ctl.mutate(c, true, func(actor services.Actor, key, match string, body []byte) (int, []byte, error) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			return 0, nil, &services.StatusError{Status: http.StatusNotFound, Code: "not_found", Message: "Not found."}
		}
		return ctl.svc.PutDraft(c.Request.Context(), actor, id, key, match, body)
	})
}

func (ctl *RuntimePolicyController) Validate(c *gin.Context) {
	ctl.mutate(c, true, func(actor services.Actor, key, match string, body []byte) (int, []byte, error) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			return 0, nil, &services.StatusError{Status: http.StatusNotFound, Code: "not_found", Message: "Not found."}
		}
		return ctl.svc.Validate(c.Request.Context(), actor, id, key, match, body)
	})
}

func (ctl *RuntimePolicyController) Approve(c *gin.Context) {
	ctl.mutate(c, true, func(actor services.Actor, key, match string, body []byte) (int, []byte, error) {
		if models.IsRuntimePolicyCandidateSystem(actor.UserID, actor.Kind) {
			return 0, nil, &services.StatusError{Status: http.StatusForbidden, Code: "candidate_system_forbidden", Message: "The candidate generator cannot approve or enforce."}
		}
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			return 0, nil, &services.StatusError{Status: http.StatusNotFound, Code: "not_found", Message: "Not found."}
		}
		return ctl.svc.Approve(c.Request.Context(), actor, id, key, match, body)
	})
}

// NotImplemented is the A7 route table. Permissions are enforced by the route.
// Enforce routes refuse the candidate-generator account before the 501.
func (ctl *RuntimePolicyController) NotImplemented(enforce bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		actor, ok := policyActor(c)
		if !ok {
			return
		}
		if enforce && models.IsRuntimePolicyCandidateSystem(actor.UserID, actor.Kind) {
			writePolicy(c, 0, nil, &services.StatusError{Status: http.StatusForbidden, Code: "candidate_system_forbidden", Message: "The candidate generator cannot approve or enforce."})
			return
		}
		if c.Request.Method == http.MethodGet {
			writePolicy(c, 0, nil, &services.StatusError{Status: http.StatusNotImplemented, Code: "not_implemented", Message: "This runtime-policy route is implemented with delivery."})
			return
		}
		if strings.TrimSpace(c.GetHeader("Idempotency-Key")) == "" {
			writePolicy(c, 0, nil, &services.StatusError{Status: http.StatusBadRequest, Code: "idempotency_key_required", Message: "Idempotency-Key is required."})
			return
		}
		if c.Param("id") != "" && strings.Trim(c.GetHeader("If-Match"), `"`) == "" {
			writePolicy(c, 0, nil, &services.StatusError{Status: http.StatusPreconditionRequired, Code: "precondition_required", Message: "If-Match is required."})
			return
		}
		writePolicy(c, 0, nil, &services.StatusError{Status: http.StatusNotImplemented, Code: "not_implemented", Message: "This runtime-policy route is implemented with delivery."})
	}
}

func (ctl *RuntimePolicyController) mutate(c *gin.Context, match bool, fn func(services.Actor, string, string, []byte) (int, []byte, error)) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	key := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	ifMatch := strings.Trim(c.GetHeader("If-Match"), `"`)
	if match && ifMatch == "" {
		writePolicy(c, 0, nil, &services.StatusError{Status: http.StatusPreconditionRequired, Code: "precondition_required", Message: "If-Match is required."})
		return
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		writePolicy(c, 0, nil, &services.StatusError{Status: http.StatusBadRequest, Code: "invalid_document", Message: "The body could not be read."})
		return
	}
	status, out, err := fn(actor, key, ifMatch, body)
	writePolicy(c, status, out, err)
}

func writePolicy(c *gin.Context, status int, body []byte, err error) {
	if err != nil {
		se, ok := err.(*services.StatusError)
		if !ok {
			se = &services.StatusError{Status: http.StatusInternalServerError, Code: "internal", Message: "Internal error."}
		}
		payload := gin.H{"code": se.Code, "message": se.Message}
		for k, v := range se.Extra {
			payload[k] = v
		}
		c.JSON(se.Status, gin.H{"error": payload})
		return
	}
	var probe struct {
		ETag string `json:"etag"`
	}
	_ = json.Unmarshal(body, &probe)
	if probe.ETag != "" {
		c.Header("ETag", `"`+probe.ETag+`"`)
	}
	c.Data(status, "application/json", body)
}

func policyActor(c *gin.Context) (services.Actor, bool) {
	ws, ok := uuidFromContext(c, "workspace_id")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": gin.H{"code": "unauthenticated", "message": "No workspace."}})
		return services.Actor{}, false
	}
	uid, ok := uuidFromContext(c, "user_id")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": gin.H{"code": "unauthenticated", "message": "No actor."}})
		return services.Actor{}, false
	}
	kind, _ := c.Get("actor_kind")
	kindStr, _ := kind.(string)
	if claims, ok := c.Get("claims"); ok {
		if m, ok := claims.(jwt.MapClaims); ok {
			if v, ok := m["actor_kind"].(string); ok && kindStr == "" {
				kindStr = v
			}
		}
	}
	return services.Actor{UserID: uid, WorkspaceID: ws, Kind: kindStr}, true
}

func uuidFromContext(c *gin.Context, key string) (uuid.UUID, bool) {
	v, ok := c.Get(key)
	if !ok {
		return uuid.Nil, false
	}
	switch t := v.(type) {
	case uuid.UUID:
		return t, t != uuid.Nil
	case string:
		id, err := uuid.Parse(t)
		return id, err == nil
	default:
		return uuid.Nil, false
	}
}

func policyID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "not_found", "message": "Not found."}})
		return uuid.Nil, false
	}
	return id, true
}
