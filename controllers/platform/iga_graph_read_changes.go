package platform

import (
	"github.com/gin-gonic/gin"

	"github.com/authsec-ai/authsec/internal/igaread"
)

// Changes (§5.3 Changes, T5.4 read side; P2-DECISIONS D-26..D-28, D-68..D-70):
//
//	GET /api/iga/v1/workloads/:id/changes    iga:read
//	GET /api/iga/v1/identities/:id/changes   iga:read
//	GET /api/iga/v1/resources/:id/changes    iga:read
//
// Query: kind=configuration|coverage (default configuration; the two never
// share a list), limit 1-200 (default 50), cursor, rev. Any other parameter is
// 400 invalid_parameter.
//
// Response: the §5.2 list envelope (D-77). data is the object's events, newest
// first, keyset on (at, event, id); meta adds kind and history_begins (D-70).
// Each event:
//
//	{
//	  "id": "policy_detached:<uuid>",
//	  "event": "policy_detached",
//	  "at": "2026-09-21T14:02:00.000000Z",       the projection pass's one timestamp (D-26)
//	  "rev": 42, "run": "cloud_scan_run:<uuid>",  the publication that recorded it; null
//	                                              when no single publication carries at
//	  "subject": "assignment:<uuid>",
//	  "claims": ["assignment:<uuid>", "policy:<uuid>", "identity:<uuid>"],
//	  "reason": "not_seen",                        lifecycle reason / ended_reason, or null
//	  "via": "identity:<uuid>",                    workload Changes only: the execution
//	                                              identity the event came through
//	  "detail": {"policy": ..., "holder": ..., "assignment_kind": "attached", "state": "ended"},
//	  "remaining": [{"grant", "state", "last_confirmed_at", "policy", "statement", "targets"}],
//	  "paths": [{"target": "resource:<uuid>", "remains": "current|stale|none"}],
//	  "labels": {"policy:<uuid>": "TicketRead", ...}
//	}
//
// Events: first_seen, retired (reason unsupported|recreated|policy_recreated)
// and restored from iga_lifecycle_event -- never the node row (B24);
// relationship_started/_ended; policy_attached/_detached; grant_started/_ended
// (remaining and paths on the ends, D-28); statement_revised (before/after:
// statement, policy_version_id, content_hash); statement_replaced
// (before/after: the Sid-less statements that ended and those that began in
// the policy in that run); and, for kind=coverage only, coverage_changed
// (before/after state per surface). The full contract, and which events
// belong to which object (D-68), is internal/igaread/changes.go.
//
// serve() has applied the 503 gate and taken the workspace from the token;
// the object must be this workspace's graph row, else 404 with no hint.

// GetWorkloadChanges handles GET /api/iga/v1/workloads/:id/changes.
func (ctl *IGAGraphReadController) GetWorkloadChanges(c *gin.Context) {
	ctl.changes(c, igaread.RefWorkload)
}

// GetIdentityChanges handles GET /api/iga/v1/identities/:id/changes.
func (ctl *IGAGraphReadController) GetIdentityChanges(c *gin.Context) {
	ctl.changes(c, igaread.RefIdentity)
}

// GetResourceChanges handles GET /api/iga/v1/resources/:id/changes.
func (ctl *IGAGraphReadController) GetResourceChanges(c *gin.Context) {
	ctl.changes(c, igaread.RefResource)
}

func (ctl *IGAGraphReadController) changes(c *gin.Context, refType string) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.Changes(g.C.Request.Context(), g.WS, refType, g.C.Param("id"), g.C.Request.URL.Query())
	})
}
