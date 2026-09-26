package platform

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/services"
)

// RegisterWorkloadAgent handles POST /api/iga/v1/workloads/:id/agent-registration.
//
// Permission is discovery:claim (the route table). The actor is a verified
// human of the token's workspace, the same rule as classification. A workload
// in another workspace is 404, and that check runs before a missing
// Idempotency-Key is 400, so a probe that names a foreign id does not reveal
// whether the body was acceptable.
//
// 200 is the stored JSON. A replay of the same key and the same body returns
// those bytes again. The same key with a different body is 409
// idempotency_key_reused and is not stored.
func (ctl *IGAGraphReadController) RegisterWorkloadAgent(c *gin.Context) {
	if mode, reason, _ := ctl.gate().Status(); mode != services.GraphProjectionOn {
		writeGraphError(c, igaread.GraphUnavailable(mode, reason))
		return
	}
	ws, ok := tokenWorkspace(c)
	if !ok {
		writeGraphError(c, igaread.Unauthenticated())
		return
	}
	actor, err := humanActor(c, ctl.db(), ws)
	if err != nil {
		if errors.Is(err, errNotWorkspaceHuman) {
			writeGraphError(c, igaread.Forbidden("Agent registration requires a verified workspace member session."))
			return
		}
		writeGraphError(c, igaread.Internal(err))
		return
	}
	actorID, err := uuid.Parse(actor)
	if err != nil {
		writeGraphError(c, igaread.Internal(err))
		return
	}
	id, e := igaread.RouteID(igaread.RefWorkload, c.Param("id"))
	if e != nil {
		writeGraphError(c, e)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
	if err != nil {
		writeGraphError(c, igaread.InvalidParameter("body", "could not read the request body"))
		return
	}
	in, e := parseAgentRegistration(raw)
	if e != nil {
		writeGraphError(c, e)
		return
	}
	in.WorkloadID = id
	in.ActorUserID = actorID
	in.IdempotencyKey = strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	in.RawBody = raw

	body, replayed, err := services.NewAgentRegistrationService(ctl.db()).Register(c.Request.Context(), ws, in)
	if err != nil {
		writeGraphError(c, igaread.AsError(err))
		return
	}
	if !replayed {
		auditAdminMutation(c, ws.String(), "agent_registration", "iga_workload", id.String(),
			http.StatusOK, nil, json.RawMessage(body))
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", body)
}

type agentRegistrationBody struct {
	ExpectedVersion *int64  `json:"expected_version"`
	Purpose         *string `json:"purpose"`
	OwnerUserID     *string `json:"owner_user_id"`
	AgentID         *string `json:"agent_id"`
	CreateAgent     *struct {
		DisplayName string `json:"display_name"`
	} `json:"create_agent"`
	ObservationID      *string `json:"observation_id"`
	CloudObservationID *string `json:"cloud_observation_id"`
}

func parseAgentRegistration(raw []byte) (services.WorkloadAgentRegistration, *igaread.Error) {
	var zero services.WorkloadAgentRegistration
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var b agentRegistrationBody
	if err := dec.Decode(&b); err != nil {
		return zero, igaread.InvalidParameter("body", "request body is not a registration object")
	}
	if dec.More() {
		return zero, igaread.InvalidParameter("body", "request body must be one JSON object")
	}
	if b.ExpectedVersion == nil || *b.ExpectedVersion < 0 {
		return zero, igaread.InvalidParameter("expected_version", "expected_version is required and must be zero or greater")
	}
	if b.Purpose == nil {
		return zero, igaread.InvalidParameter("purpose", "purpose is required")
	}
	purpose := strings.TrimSpace(*b.Purpose)
	if len(purpose) > 500 {
		return zero, igaread.InvalidParameter("purpose", "purpose must be at most 500 characters")
	}
	if b.OwnerUserID == nil {
		return zero, igaread.InvalidParameter("owner_user_id", "owner_user_id is required")
	}
	owner, err := uuid.Parse(*b.OwnerUserID)
	if err != nil {
		return zero, igaread.InvalidParameter("owner_user_id", "owner_user_id must be a UUID")
	}
	in := services.WorkloadAgentRegistration{
		ExpectedVersion: *b.ExpectedVersion,
		Purpose:         purpose,
		OwnerUserID:     owner,
	}
	switch {
	case b.AgentID != nil && b.CreateAgent != nil:
		return zero, igaread.InvalidParameter("agent_id", "set agent_id or create_agent, not both")
	case b.CreateAgent != nil:
		name := strings.TrimSpace(b.CreateAgent.DisplayName)
		if name == "" || len(name) > 500 {
			return zero, igaread.InvalidParameter("create_agent.display_name", "display_name is required and must be at most 500 characters")
		}
		in.CreateDisplayName = &name
	case b.AgentID != nil:
		id, err := uuid.Parse(*b.AgentID)
		if err != nil {
			return zero, igaread.InvalidParameter("agent_id", "agent_id must be a UUID")
		}
		in.AgentID = &id
	default:
		return zero, igaread.InvalidParameter("agent_id", "set agent_id or create_agent")
	}
	switch {
	case b.ObservationID != nil && b.CloudObservationID != nil:
		return zero, igaread.InvalidParameter("observation_id", "set exactly one of observation_id and cloud_observation_id")
	case b.ObservationID != nil:
		id, err := uuid.Parse(*b.ObservationID)
		if err != nil {
			return zero, igaread.InvalidParameter("observation_id", "observation_id must be a UUID")
		}
		in.ObservationID = &id
	case b.CloudObservationID != nil:
		id, err := uuid.Parse(*b.CloudObservationID)
		if err != nil {
			return zero, igaread.InvalidParameter("cloud_observation_id", "cloud_observation_id must be a UUID")
		}
		in.CloudObservationID = &id
	default:
		return zero, igaread.InvalidParameter("observation_id", "set exactly one of observation_id and cloud_observation_id")
	}
	return in, nil
}
