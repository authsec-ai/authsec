package platform

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/authz"
	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/services"
)

// Classification (§5.3 Classification, §5.5, §2.14.3, T6.6).
//
//	POST /api/iga/v1/workloads/:id/classification   iga:review (route) + verified human (here)
//	GET  /api/iga/v1/workloads/:id/classification   iga:read: the decision history, newest first
//
// The decision transaction is services.ClassificationService; this file
// establishes the actor, parses the request and renders.

// classifyBodyLimit bounds a decision request body. The largest legitimate
// body is two short free-text fields and four scalars.
const classifyBodyLimit = 64 << 10

// classificationService is the decision service: the one a test installed, or
// one over the controller's database.
func (ctl *IGAGraphReadController) classificationService() *services.ClassificationService {
	if ctl.classifier != nil {
		return ctl.classifier
	}
	return services.NewClassificationService(ctl.db())
}

// WithClassificationService installs the decision service the POST uses.
// Tests use it to hold a decision before its commit (B22) or to shorten the
// lock wait; production builds one over the controller's database. Call it
// before serving requests.
func (ctl *IGAGraphReadController) WithClassificationService(s *services.ClassificationService) *IGAGraphReadController {
	ctl.classifier = s
	return ctl
}

// verifiedHuman applies the actor rule (humanActor) and maps it to the §5.2
// vocabulary: not a live human member of this workspace is 403 forbidden; a
// database failure while checking is 500, never a refusal.
func (ctl *IGAGraphReadController) verifiedHuman(c *gin.Context, ws uuid.UUID) (uuid.UUID, error) {
	uid, err := humanActor(c, ctl.db(), ws)
	if err != nil {
		if errors.Is(err, errNotWorkspaceHuman) {
			return uuid.Nil, igaread.Forbidden("Classification decisions require a verified workspace member session.")
		}
		return uuid.Nil, igaread.Internal(err)
	}
	return uuid.Parse(uid)
}

// classifyCaller is what meta.capabilities.can_classify is computed from
// (igaread.CanClassify): whether the token is a verified human of this
// workspace -- the SAME actor rule the POST applies -- and whether it carries
// iga:review by the SAME test the POST's Require middleware applies
// (authz.Allows). A detail route calls it once per request, in the handler.
//
// A database error while checking membership is returned (500): a capability
// the server could not establish is not reported as either answer.
func (ctl *IGAGraphReadController) classifyCaller(c *gin.Context, ws uuid.UUID) (igaread.ClassifyCaller, error) {
	caller := igaread.ClassifyCaller{CanReview: authz.Allows(c, "iga", "review")}
	_, err := humanActor(c, ctl.db(), ws)
	switch {
	case err == nil:
		caller.Human = true
	case errors.Is(err, errNotWorkspaceHuman):
	default:
		return igaread.ClassifyCaller{}, igaread.Internal(err)
	}
	return caller, nil
}

// classifyBody is the POST body (§5.5). Pointers tell "absent" from a zero
// value: expected_version 0 is a real version, and a missing one is 400.
type classifyBody struct {
	OperationID      *string `json:"operation_id"`
	Decision         *string `json:"decision"`
	Purpose          *string `json:"purpose"`
	Reason           *string `json:"reason"`
	ExpectedVersion  *int64  `json:"expected_version"`
	UndoesDecisionID *string `json:"undoes_decision_id"`
}

// parseClassifyBody reads the request into a ClassifyRequest (without the
// workload and actor). Missing operation_id, decision, reason or
// expected_version, a malformed UUID, or a body that is not the JSON object
// above is 400 invalid_parameter (D-30); the service validates the values.
func parseClassifyBody(c *gin.Context) (services.ClassifyRequest, *igaread.Error) {
	var req services.ClassifyRequest
	var b classifyBody
	dec := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, classifyBodyLimit))
	if err := dec.Decode(&b); err != nil {
		return req, igaread.InvalidParameter("body", "the body must be a JSON object: "+err.Error())
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return req, igaread.InvalidParameter("body", "the body must be exactly one JSON object")
	}
	if b.OperationID == nil || *b.OperationID == "" {
		return req, igaread.InvalidParameter("operation_id", "operation_id is required")
	}
	op, err := uuid.Parse(*b.OperationID)
	if err != nil {
		return req, igaread.InvalidParameter("operation_id", "operation_id must be a UUID")
	}
	if b.Decision == nil {
		return req, igaread.InvalidParameter("decision", "decision is required")
	}
	if b.Reason == nil {
		return req, igaread.InvalidParameter("reason", "reason is required: it is the audit record")
	}
	if b.ExpectedVersion == nil {
		return req, igaread.InvalidParameter("expected_version", "expected_version is required")
	}
	req.OperationID, req.Decision, req.Reason, req.ExpectedVersion = op, *b.Decision, *b.Reason, *b.ExpectedVersion
	if b.Purpose != nil {
		req.Purpose = *b.Purpose
	}
	if b.UndoesDecisionID != nil {
		u, err := uuid.Parse(*b.UndoesDecisionID)
		if err != nil {
			return req, igaread.InvalidParameter("undoes_decision_id", "undoes_decision_id must be a UUID or null")
		}
		req.UndoesDecisionID = &u
	}
	return req, nil
}

// ClassifyWorkload handles POST /workloads/:id/classification (§5.5).
//
// Order: 503 gate and the token's workspace (serve), then the actor (403: a
// decision is refused before its content is even read), then the route id
// (404), then the body (400), then the transaction.
//
// 200 {"data": {classification, classification_version, decision, replayed}};
// a replay is 200 with the stored outcome and replayed:true.
func (ctl *IGAGraphReadController) ClassifyWorkload(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		actor, err := ctl.verifiedHuman(c, g.WS)
		if err != nil {
			return nil, err
		}
		id, e := igaread.RouteID(igaread.RefWorkload, c.Param("id"))
		if e != nil {
			return nil, e
		}
		req, e := parseClassifyBody(c)
		if e != nil {
			return nil, e
		}
		req.WorkloadID, req.ActorUserID = id, actor

		res, err := ctl.classificationService().Classify(c.Request.Context(), g.WS, req)
		if err != nil {
			return nil, err
		}
		if !res.Replayed {
			// A security-relevant mutation (AGENTS.md). The decision row is the
			// audit record of the decision itself (§2.14.3); this is the
			// platform's audit trail of the request. A replay changed nothing
			// and is not logged twice.
			auditAdminMutation(c, g.WS.String(), "classify", "iga_workload", id.String(),
				http.StatusOK, nil, res)
		}
		return gin.H{"data": res}, nil
	})
}

// GetWorkloadClassification handles GET /workloads/:id/classification: the
// workload's decision history, newest first by result_version (D-33), 100 per
// page (limit 1-200), keyset cursor.
//
// Classification is not part of a revision, so the history is read in the
// request's snapshot but NOT bound to a revision: rev is not checked, and a
// publication between pages does not invalidate the cursor. A retired
// workload's history is served like any other detail (§5.2 "Retired
// objects"); a workload not in this workspace is 404.
func (ctl *IGAGraphReadController) GetWorkloadClassification(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		id, e := igaread.RouteID(igaread.RefWorkload, c.Param("id"))
		if e != nil {
			return nil, e
		}
		limit := igaread.DefaultLimit
		if l := c.Query("limit"); l != "" {
			n, err := strconv.Atoi(l)
			if err != nil || n < 1 || n > igaread.MaxLimit {
				return nil, igaread.InvalidParameter("limit", "limit must be 1-200")
			}
			limit = n
		}
		var after *igaread.HistoryKey
		if tok := c.Query("cursor"); tok != "" {
			k, e := g.Reader.OpenHistoryCursor(tok, g.WS, id)
			if e != nil {
				return nil, e
			}
			after = k
		}

		var env igaread.Envelope
		err := g.Reader.Read(c.Request.Context(), g.WS, igaread.Pin{}, func(q *igaread.Query) error {
			var found []uuid.UUID
			if err := q.DB().Raw(`SELECT id FROM iga_workload
				WHERE workspace_id = ? AND id = ? AND provider = 'aws'`, q.WS, id).Scan(&found).Error; err != nil {
				return err
			}
			if len(found) == 0 {
				return igaread.NotFound()
			}
			items, next, err := igaread.ClassificationHistory(q, id, after, limit)
			if err != nil {
				return err
			}
			meta := igaread.NewListMeta(q, limit)
			if next != nil {
				tok := g.Reader.HistoryCursor(q.WS, id, *next)
				meta.NextCursor = &tok
			}
			n, known, err := q.CountUpTo(func(tx *gorm.DB) *gorm.DB {
				return tx.Table("iga_workload_classification").
					Where("workspace_id = ? AND workload_id = ?", q.WS, id)
			})
			if err != nil {
				return err
			}
			meta.SetTotal(n, known)
			env = igaread.Envelope{Data: items, Meta: meta}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return env, nil
	})
}
