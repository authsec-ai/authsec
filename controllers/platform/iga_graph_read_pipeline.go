package platform

import (
	"net/url"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/authsec-ai/authsec/internal/igaread"
)

// Pipeline and coverage (§5.3 Integration, scan and pipeline; §2.14.7,
// §2.14.13; T2.3; D-55..D-59, D-72, D-82, D-92).
//
// Both run behind serve(): 503 graph_unavailable while IGA_GRAPH_PROJECTION is
// off or misconfigured (D-10, D-11) -- with the switch off there is no barrier,
// no job and no publication, so every account would sit in "first publication
// pending" forever, which is a lie the Unavailable state does not tell. Both
// read inside ONE §5.1 snapshot, so the barrier, the runs and the revision they
// report are one moment of the pipeline.

// GetPipeline handles GET /api/iga/v1/pipeline: the barrier, each AWS
// account's latest run, its projection, the revision the graph is at for it,
// and the current revision.
//
// Not revision-pinned (D-82): the pipeline is the live state around the graph,
// not a read of it, and a queued scan must be visible the moment it is queued
// (§2.15 step 1) whatever revision the client holds. So a rev parameter is 400
// -- honouring it would claim a pin the route does not give. The only
// parameter is include=stuck_snapshots, which adds collector_deferrals.
// Without it that block is omitted and the body stays the AWS pipeline shape.
func (ctl *IGAGraphReadController) GetPipeline(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		vals := c.Request.URL.Query()
		if perr := onlyParams(vals, "include"); perr != nil {
			return nil, perr
		}
		includeStuck, perr := pipelineInclude(vals)
		if perr != nil {
			return nil, perr
		}
		var body igaread.Envelope
		err := g.Reader.Read(c.Request.Context(), g.WS, igaread.Pin{}, func(q *igaread.Query) error {
			view, err := q.Pipeline()
			if err != nil {
				return err
			}
			if includeStuck {
				block, err := q.CollectorDeferrals()
				if err != nil {
					return err
				}
				view.CollectorDeferrals = block
			}
			body = igaread.Envelope{Data: view, Meta: igaread.NewDetailMeta(q)}
			return nil
		})
		return body, err
	})
}

// pipelineInclude is the opt-in for the stuck-snapshot block. The parameter
// is absent on the default read. Any other value is 400, naming include.
func pipelineInclude(vals url.Values) (bool, *igaread.Error) {
	raw, ok := vals["include"]
	if !ok {
		return false, nil
	}
	if len(raw) == 0 {
		return false, igaread.InvalidParameter("include", "include must be stuck_snapshots")
	}
	for _, v := range raw {
		if strings.TrimSpace(v) != "stuck_snapshots" {
			return false, igaread.InvalidParameter("include", "include must be stuck_snapshots")
		}
	}
	return true, nil
}

// GetCoverage handles GET /api/iga/v1/coverage[?account=<id>][&rev=N]: per
// account and surface, from the runs the current revision was built from --
// state, count, error_code, api, since, prevents and run (§5.3, D-58, D-72).
// Revision-bound (D-82): meta.rev is echoed, and a rev that is no longer
// current is 409 revision_stale; nothing published is 200 with empty data and
// graph_state not_published (§5.1). account and rev are the only parameters.
func (ctl *IGAGraphReadController) GetCoverage(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		vals := c.Request.URL.Query()
		if perr := onlyParams(vals, "account", "rev"); perr != nil {
			return nil, perr
		}
		rev, perr := igaread.ParseRev(vals)
		if perr != nil {
			return nil, perr
		}
		accounts, perr := coverageAccounts(vals["account"])
		if perr != nil {
			return nil, perr
		}
		var body igaread.Envelope
		err := g.Reader.Read(c.Request.Context(), g.WS, igaread.Pin{Rev: rev}, func(q *igaread.Query) error {
			data, err := q.Coverage(accounts)
			if err != nil {
				return err
			}
			body = igaread.Envelope{Data: data, Meta: igaread.NewDetailMeta(q)}
			return nil
		})
		return body, err
	})
}

// onlyParams refuses any query parameter outside allowed, naming it: a
// parameter the route does not read would otherwise be silently ignored, and
// the caller would believe it filtered or pinned something (D-75, D-82).
func onlyParams(vals url.Values, allowed ...string) *igaread.Error {
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys) // name the same offender every time
	for _, k := range keys {
		ok := false
		for _, a := range allowed {
			ok = ok || k == a
		}
		if ok {
			continue
		}
		if k == "rev" {
			return igaread.InvalidParameter("rev",
				"this route reports live state and cannot be pinned to a revision")
		}
		if len(allowed) == 0 {
			return igaread.InvalidParameter(k, "this route takes no parameters")
		}
		return igaread.InvalidParameter(k, "unknown parameter; this route takes "+strings.Join(allowed, ", "))
	}
	return nil
}

// coverageAccounts validates ?account= (repeatable, §5.2). Coverage is always
// of a connected account's read, so "unknown" names nothing here and is 400
// like any other value that is not a 12-digit account id.
func coverageAccounts(raw []string) ([]string, *igaread.Error) {
	var out []string
	for _, a := range raw {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		ok := len(a) == 12
		for _, r := range a {
			ok = ok && r >= '0' && r <= '9'
		}
		if !ok {
			return nil, igaread.InvalidParameter("account", "account must be a 12-digit AWS account id")
		}
		out = append(out, a)
	}
	return out, nil
}
