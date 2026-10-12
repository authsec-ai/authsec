package platform

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/services"
)

// The §7.1 / §7.2 reads of the Phase 3 policy surface (T3.06b):
//
//	GET  /findings                         findings at ?rev (default: newest complete evaluation)
//	GET  /findings/summary                 counts by kind/status/severity at ?rev
//	GET  /findings/:id                     one finding at ?rev with evidence, owners, linked policy, gap
//	GET  /identities/:id/activity-evidence the evidence rows behind a role's findings at ?rev
//	GET  /readiness                        remediation readiness per role (§7.1, A63)
//	POST /targets/resolve                  target resolution by immutable key (§2.12)
//	GET  /evidence-bundles/:id             one evidence bundle, re-verified
//
// All are governance:read, the workspace only from the token, another
// workspace's id 404, envelope {data, meta} / {error: {code, message,
// detail}}. None mutates: POST /targets/resolve is a read with a body, so it
// writes neither iga_gov_event nor audit_events.

func (ctl *IGAGovPolicyController) reader() *services.GovReader {
	return services.NewGovReader(ctl.db(), ctl.key)
}

// govCall resolves the token workspace and renders a GovError or any other
// error in the §7 envelope.
func govCall(c *gin.Context, fn func(ws uuid.UUID) (data any, meta any, err error)) {
	ws, ok := tokenWorkspace(c)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": gin.H{
			"code": "unauthenticated", "message": "No workspace in the token.", "detail": gin.H{}}})
		return
	}
	data, meta, err := fn(ws)
	if err != nil {
		var ge *services.GovError
		if errors.As(err, &ge) {
			c.AbortWithStatusJSON(ge.Status, ge.Body())
			return
		}
		log.Printf("[policy] %s %s: %v", c.Request.Method, c.FullPath(), err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": gin.H{
			"code": "internal_error", "message": "The request could not be completed.", "detail": gin.H{}}})
		return
	}
	if meta == nil {
		meta = gin.H{}
	}
	c.JSON(http.StatusOK, gin.H{"data": data, "meta": meta})
}

// revParam parses ?rev (absent: nil).
func revParam(c *gin.Context) (*int64, error) {
	s, ok := c.GetQuery("rev")
	if !ok {
		return nil, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return nil, services.GovBadParam("rev", "rev must be a positive revision number.")
	}
	return &n, nil
}

func uuidParam(c *gin.Context, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(c.Param(name))
	if err != nil {
		// A malformed id names nothing in any workspace.
		return uuid.Nil, services.GovNotFound()
	}
	return id, nil
}

func listParam(c *gin.Context, name string) []string {
	var out []string
	for _, v := range c.QueryArray(name) {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func optUUIDParam(c *gin.Context, name string) (*uuid.UUID, error) {
	s := c.Query(name)
	if s == "" {
		return nil, nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return nil, services.GovBadParam(name, name+" must be a uuid.")
	}
	return &id, nil
}

func limitParam(c *gin.Context) (int, error) {
	s := c.Query("limit")
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > services.MaxGovPage {
		return 0, services.GovBadParam("limit", "limit must be 1..200.")
	}
	return n, nil
}

// ListFindings handles GET /findings.
func (ctl *IGAGovPolicyController) ListFindings(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		req, err := revParam(c)
		if err != nil {
			return nil, nil, err
		}
		f := services.FindingFilter{Statuses: listParam(c, "status"), Kinds: listParam(c, "kind"),
			Severities: listParam(c, "severity"), Confidences: listParam(c, "confidence"),
			Account: c.Query("account"), Q: c.Query("q"), Cursor: c.Query("cursor"), GroupByRole: c.Query("group") == "role"}
		if g := c.Query("group"); g != "" && g != "role" {
			return nil, nil, services.GovBadParam("group", "group must be role.")
		}
		if f.IdentityID, err = optUUIDParam(c, "identity_id"); err != nil {
			return nil, nil, err
		}
		if f.WorkloadID, err = optUUIDParam(c, "workload_id"); err != nil {
			return nil, nil, err
		}
		if f.Limit, err = limitParam(c); err != nil {
			return nil, nil, err
		}
		if err := services.ValidateFindingFilter(f); err != nil {
			return nil, nil, err
		}
		r := ctl.reader()
		rev, meta, err := r.ResolveRev(ws, req)
		if err != nil {
			return nil, nil, err
		}
		list, next, err := r.ListFindings(ws, rev, f)
		if err != nil {
			return nil, nil, err
		}
		meta.NextCursor = next
		if f.GroupByRole {
			return services.GroupByRole(list), meta, nil
		}
		return list, meta, nil
	})
}

// FindingsSummary handles GET /findings/summary.
func (ctl *IGAGovPolicyController) FindingsSummary(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		req, err := revParam(c)
		if err != nil {
			return nil, nil, err
		}
		r := ctl.reader()
		rev, meta, err := r.ResolveRev(ws, req)
		if err != nil {
			return nil, nil, err
		}
		s, err := r.Summary(ws, rev)
		return s, meta, err
	})
}

// GetFinding handles GET /findings/:id.
func (ctl *IGAGovPolicyController) GetFinding(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		req, err := revParam(c)
		if err != nil {
			return nil, nil, err
		}
		r := ctl.reader()
		rev, meta, err := r.ResolveRev(ws, req)
		if err != nil {
			return nil, nil, err
		}
		d, err := r.Finding(ws, id, rev)
		return d, meta, err
	})
}

// ActivityEvidence handles GET /identities/:id/activity-evidence.
func (ctl *IGAGovPolicyController) ActivityEvidence(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		req, err := revParam(c)
		if err != nil {
			return nil, nil, err
		}
		r := ctl.reader()
		rev, meta, err := r.ResolveRev(ws, req)
		if err != nil {
			return nil, nil, err
		}
		rows, err := r.ActivityEvidence(ws, id, rev)
		return rows, meta, err
	})
}

// GetReadiness handles GET /readiness.
func (ctl *IGAGovPolicyController) GetReadiness(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		limit, err := limitParam(c)
		if err != nil {
			return nil, nil, err
		}
		rd, err := ctl.reader().Readiness(c.Request.Context(), ws, c.Query("account"), c.Query("cursor"), limit)
		if err != nil {
			return nil, nil, err
		}
		return gin.H{"roles_reviewed": rd.RolesReviewed, "counts": rd.Counts, "categories": services.ReadinessOrder,
				"roles": rd.Roles},
			gin.H{"evaluated_rev": rd.Rev, "next_cursor": rd.Next}, nil
	})
}

// ResolveTargets handles POST /targets/resolve (§2.12, §7.2).
func (ctl *IGAGovPolicyController) ResolveTargets(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		var body struct {
			Keys []services.TargetKey `json:"keys"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			return nil, nil, services.GovBadParam("body", "The body must be {\"keys\": [...]}.")
		}
		if err := services.ValidateTargetKeys(body.Keys); err != nil {
			return nil, nil, err
		}
		out, err := services.NewGovTargets(ctl.db()).Resolve(c.Request.Context(), ws, body.Keys)
		return out, gin.H{}, err
	})
}

// GetEvidenceBundle handles GET /evidence-bundles/:id.
func (ctl *IGAGovPolicyController) GetEvidenceBundle(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		b, err := ctl.reader().EvidenceBundle(ws, id)
		return b, gin.H{}, err
	})
}
