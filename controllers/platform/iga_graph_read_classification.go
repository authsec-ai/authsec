package platform

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
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

// classificationCapability is meta.capabilities.can_classify for one workload
// (D-83): classifyCaller's two facts about the caller, then igaread.CanClassify
// over the workload's classification and lifecycle as the detail read them.
// The workload detail (GET /workloads/:id) calls it once per request and
// always states the answer; a database error while checking the membership is
// the request's 500, never a false or a true.
func (ctl *IGAGraphReadController) classificationCapability(c *gin.Context, ws uuid.UUID, classification, lifecycle string) (bool, error) {
	caller, err := ctl.classifyCaller(c, ws)
	if err != nil {
		return false, err
	}
	return igaread.CanClassify(caller, classification, lifecycle), nil
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

// classifyBodyFields are the only keys a decision body may carry (§5.5),
// spelled exactly. encoding/json alone would ignore any other key and match
// these case-insensitively; neither is acceptable here. A field the server
// ignored is one the request hash does not bind, so a client could believe it
// had set something (a workload, a version under another spelling) that the
// recorded decision never saw. An unknown key is therefore 400 naming it, as
// an unknown list parameter is (D-75).
var classifyBodyFields = map[string]bool{
	"operation_id": true, "decision": true, "purpose": true,
	"reason": true, "expected_version": true, "undoes_decision_id": true,
}

// parseClassifyBody reads the request into a ClassifyRequest (without the
// workload and actor). Missing operation_id, decision, reason or
// expected_version, a malformed UUID, a field of the wrong JSON type, an
// unknown field, or a body that is not exactly one JSON object is 400
// invalid_parameter (D-30), naming the field where there is one; the service
// validates the values.
func parseClassifyBody(c *gin.Context) (services.ClassifyRequest, *igaread.Error) {
	var req services.ClassifyRequest
	var raw json.RawMessage
	dec := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, classifyBodyLimit))
	if err := dec.Decode(&raw); err != nil {
		return req, igaread.InvalidParameter("body", "the body must be a JSON object: "+err.Error())
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return req, igaread.InvalidParameter("body", "the body must be exactly one JSON object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return req, igaread.InvalidParameter("body", "the body must be a JSON object")
	}
	var unknown []string
	for k := range fields {
		if !classifyBodyFields[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown) // the same body always names the same field
		return req, igaread.InvalidParameter(unknown[0], "unknown field "+strconv.Quote(unknown[0])+
			": a decision takes only operation_id, decision, purpose, reason, expected_version and undoes_decision_id")
	}
	var b classifyBody
	if err := json.Unmarshal(raw, &b); err != nil {
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) && classifyBodyFields[te.Field] {
			return req, igaread.InvalidParameter(te.Field, te.Field+" has the wrong type: "+err.Error())
		}
		return req, igaread.InvalidParameter("body", "the body must be a JSON object: "+err.Error())
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

// classHistoryParams are the only parameters the history accepts: it has no
// filters, sorts or facets (D-33), and an unknown parameter is 400 naming it
// rather than silently ignored (D-75), so a client never believes a filter
// applied that did not.
var classHistoryParams = map[string]bool{"limit": true, "cursor": true, "rev": true}

// GetWorkloadClassification handles GET /workloads/:id/classification: the
// workload's decision history, newest first by result_version (D-33), in the
// §5.2 list envelope (D-77): 100 per page, limit 1-200, keyset cursor.
//
// It runs under §5.1 like every route (D-33): a stale rev, or a cursor issued
// at an older revision, is 409 revision_stale, although no decision is part of
// a revision. Nothing published is 404 (D-4: no workload can exist before the
// first publication). A retired workload's history is served like any other
// detail (§5.2 "Retired objects"); a workload the graph routes cannot read
// (another workspace's, or not the projector's, D-6) is 404.
func (ctl *IGAGraphReadController) GetWorkloadClassification(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		id, e := igaread.RouteID(igaread.RefWorkload, c.Param("id"))
		if e != nil {
			return nil, e
		}
		vals := c.Request.URL.Query()
		for k := range vals {
			if !classHistoryParams[k] {
				return nil, igaread.InvalidParameter(k, "unknown parameter "+k+": the classification history accepts only limit, cursor and rev")
			}
		}
		limit := igaread.DefaultLimit
		if l := vals.Get("limit"); l != "" {
			n, err := strconv.Atoi(l)
			if err != nil || n < 1 || n > igaread.MaxLimit {
				return nil, igaread.InvalidParameter("limit", "limit must be 1-200")
			}
			limit = n
		}
		rev, e := igaread.ParseRev(vals)
		if e != nil {
			return nil, e
		}
		pin := igaread.Pin{Rev: rev}
		var after *igaread.HistoryKey
		if tok := vals.Get("cursor"); tok != "" {
			k, cursorRev, e := g.Reader.OpenHistoryCursor(tok, g.WS, id)
			if e != nil {
				return nil, e
			}
			after, pin.CursorRev = k, &cursorRev
		}

		var env igaread.Envelope
		err := g.Reader.Read(c.Request.Context(), g.WS, pin, func(q *igaread.Query) error {
			if !q.Published() {
				return igaread.NotFound()
			}
			ok, err := igaread.ClassificationWorkloadReadable(q, id)
			if err != nil {
				return err
			}
			if !ok {
				return igaread.NotFound()
			}
			items, next, err := igaread.ClassificationHistory(q, id, after, limit)
			if err != nil {
				return err
			}
			meta := igaread.NewListMeta(q, limit)
			if next != nil {
				tok := g.Reader.HistoryCursor(q.WS, id, q.Rev.Rev, *next)
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
