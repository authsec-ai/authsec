package igaread

// Changes, kind=coverage (§5.3 "coverage_changed: consecutive runs' coverage
// for the object's account and surfaces"; D-70), and the Changes envelope's
// meta.coverage (D-73).
//
// The object's surfaces are its partitions' RequiredSurfaces and
// RequiredScanners -- the partitions of its support rows, rebuilt by the
// projector's own table (partitionOf) and accepted only when the rebuilt key
// is the stored one. The sequence per supporting connector is that
// connector's PUBLISHED runs (a run with an iga_publication row in this
// snapshot, so never past the current revision), in revision order, from the
// support row's first pass; only transitions are events. An ended support
// speaks only up to the run that last confirmed it: after that the connector
// no longer vouches for the object, and its coverage says nothing about it.
//
// An absent entry means what reconciliation reads it as (canEnd): a required
// surface absent from a run's report was not looked at (unknown); a scanner
// marker (permission_scan, workload_scan, compute:<region>) is written only
// on failure or deselection, so its absence means the scanner ran (reached).

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// changesLane is one (connector, surface) whose transitions bear on the
// object, over the published runs from From up to revision ToRev.
type changesLane struct {
	ConnectorID uuid.UUID
	Surface     string
	Absent      string
	From        time.Time
	ToRev       int64
}

// changesLanes derives the object's coverage lanes from its support rows.
func changesLanes(q *Query, obj changesObject, node *changesNode, supports []changesSupport) ([]changesLane, error) {
	// The revision of each ended support's last confirming run: one query.
	var endedRuns []uuid.UUID
	for _, s := range supports {
		if s.State == StateEnded && s.LastConfirmedRunID != nil {
			endedRuns = append(endedRuns, *s.LastConfirmedRunID)
		}
	}
	revOfRun := map[uuid.UUID]int64{}
	if len(endedRuns) > 0 {
		var rows []struct {
			ScanRunID uuid.UUID
			Rev       int64
		}
		if err := q.DB().Raw(`SELECT scan_run_id, rev FROM iga_publication WHERE workspace_id = ? AND scan_run_id IN ?`,
			q.WS, endedRuns).Scan(&rows).Error; err != nil {
			return nil, err
		}
		for _, r := range rows {
			revOfRun[r.ScanRunID] = r.Rev
		}
	}

	type laneKey struct {
		connector uuid.UUID
		surface   string
	}
	merged := map[laneKey]*changesLane{}
	add := func(s changesSupport, surface, absent string, toRev int64) {
		k := laneKey{s.ConnectorID, surface}
		if l, ok := merged[k]; ok {
			if s.FirstSeenAt.Before(l.From) {
				l.From = s.FirstSeenAt
			}
			if toRev > l.ToRev {
				l.ToRev = toRev
			}
			return
		}
		merged[k] = &changesLane{ConnectorID: s.ConnectorID, Surface: surface, Absent: absent, From: s.FirstSeenAt, ToRev: toRev}
	}
	for _, s := range supports {
		part, ok := changesPartition(obj, node, s)
		if !ok {
			// A partition this build cannot rebuild names no surfaces: no
			// transitions are claimed for it rather than guessed ones.
			continue
		}
		toRev := q.Rev.Rev
		if s.State == StateEnded {
			if s.LastConfirmedRunID == nil {
				continue
			}
			rev, ok := revOfRun[*s.LastConfirmedRunID]
			if !ok {
				continue
			}
			toRev = rev
		}
		for _, name := range part.RequiredSurfaces {
			add(s, name, models.CloudCoverageUnknown, toRev)
		}
		for _, name := range part.RequiredScanners {
			add(s, name, models.CloudCoverageReached, toRev)
		}
	}
	out := make([]changesLane, 0, len(merged))
	for _, l := range merged {
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ConnectorID != out[j].ConnectorID {
			return out[i].ConnectorID.String() < out[j].ConnectorID.String()
		}
		return out[i].Surface < out[j].Surface
	})
	return out, nil
}

// changesCoverageSQL is the kind=coverage union: per lane, each published run's
// state for the surface beside the previous run's (lag over revision order),
// kept where they differ. The event id is derived from (run, surface), so it
// is stable across requests. "" when the object has no lanes.
func changesCoverageSQL(ws uuid.UUID, lanes []changesLane) (string, []any) {
	if len(lanes) == 0 {
		return "", nil
	}
	values := make([]string, 0, len(lanes))
	args := make([]any, 0, len(lanes)*5+1)
	for _, l := range lanes {
		values = append(values, `(?::uuid, ?::text, ?::text, ?::timestamptz, ?::bigint)`)
		args = append(args, l.ConnectorID, l.Surface, l.Absent, l.From, l.ToRev)
	}
	args = append(args, ws)
	return `WITH lanes(connector_id, surface, absent_state, from_at, to_rev) AS (VALUES ` + strings.Join(values, ", ") + `),
	     seq AS (
	         SELECT l.connector_id, l.surface, sr.id AS run_id, pb.rev, pb.published_at AS at,
	                COALESCE(sr.coverage->'surfaces'->l.surface->>'state', l.absent_state) AS state,
	                sr.coverage->'surfaces'->l.surface AS detail
	           FROM lanes l
	           JOIN cloud_scan_run sr ON sr.workspace_id = ? AND sr.connector_id = l.connector_id
	           JOIN iga_publication pb ON pb.workspace_id = sr.workspace_id AND pb.scan_run_id = sr.id
	          WHERE pb.published_at >= l.from_at AND pb.rev <= l.to_rev),
	     tr AS (
	         SELECT seq.*, lag(seq.run_id) OVER w AS prev_run, lag(seq.state) OVER w AS prev_state,
	                lag(seq.detail) OVER w AS prev_detail
	           FROM seq
	         WINDOW w AS (PARTITION BY seq.connector_id, seq.surface ORDER BY seq.rev))
	SELECT tr.at, '` + ChangeCoverageChanged + `'::text AS event, md5(tr.run_id::text || ':' || tr.surface)::uuid AS id,
	       tr.rev, tr.run_id, tr.connector_id, tr.surface, tr.state, tr.prev_state, tr.prev_run,
	       tr.detail, tr.prev_detail
	  FROM tr
	 WHERE tr.prev_run IS NOT NULL AND tr.state IS DISTINCT FROM tr.prev_state`, args
}

// changesCoverageDetail is the per-surface detail a run recorded (D-71).
type changesCoverageDetail struct {
	State     string `json:"state"`
	Error     string `json:"error"`
	API       string `json:"api"`
	ErrorCode string `json:"error_code"`
}

// changesRenderCoverage turns coverage rows into events. A reached surface
// failed nothing, so it carries no call, code or error whatever was written.
func changesRenderCoverage(q *Query, accts *Accounts, rows []changesRow) ([]ChangeEvent, error) {
	out := make([]ChangeEvent, 0, len(rows))
	for _, r := range rows {
		if r.PrevRun == nil || r.RunID == nil {
			return nil, fmt.Errorf("igaread: coverage transition without its runs")
		}
		acct, label := "", r.ConnectorID.String()
		if c := accts.Connector(r.ConnectorID); c != nil {
			acct, label = c.AccountID, c.Label
		}
		subject := CoverageRef(*r.RunID, r.Surface)
		prev := CoverageRef(*r.PrevRun, r.Surface)
		conn := R(RefConnector, r.ConnectorID)
		run := R(RefScanRun, *r.RunID)
		rev := r.Rev

		after := map[string]any{"state": r.State, "recorded": len(r.Detail) > 0 && string(r.Detail) != "null",
			"error_code": nil, "api": nil, "error": nil, "prevents": Prevents(r.Surface, r.State)}
		var d changesCoverageDetail
		if after["recorded"] == true && json.Unmarshal(r.Detail, &d) == nil && r.State != models.CloudCoverageReached {
			after["error_code"], after["api"], after["error"] = nullIfBlank(d.ErrorCode), nullIfBlank(d.API), nullIfBlank(d.Error)
		}
		before := map[string]any{"state": r.PrevState, "recorded": len(r.PrevDetail) > 0 && string(r.PrevDetail) != "null",
			"run": R(RefScanRun, *r.PrevRun), "coverage": prev}

		out = append(out, ChangeEvent{
			ID:      r.Event + ":" + r.ID.String(),
			Event:   r.Event,
			At:      ChangeTime(r.At),
			Rev:     rev,
			Run:     &run,
			Subject: subject,
			Claims:  []string{subject, prev, conn},
			Detail:  map[string]any{"integration": conn, "account_id": acct, "surface": r.Surface},
			Before:  before,
			After:   after,
			Labels: map[string]string{
				subject: r.Surface + " in " + label,
				prev:    r.Surface + " in " + label,
				conn:    label,
			},
		})
	}
	return out, nil
}

// changesMetaCoverage is the Changes envelope's meta.coverage (D-73: "detail
// responses carry entries for the object's own partitions"): for each
// non-ended support row, what the run the current revision holds its
// partition from did not reach of that partition's surfaces (partitionGaps,
// the rule stale_reason uses). not_selected reads as stale (D-58);
// unsupported is ours to build, not a gap in the customer's estate. A support
// whose partition cannot be rebuilt shows every non-reached surface of its
// run: a gap too many is a claim of less, a hidden one a claim of more.
func changesMetaCoverage(q *Query, accts *Accounts, obj changesObject, node *changesNode, supports []changesSupport) ([]CoverageNote, error) {
	notes := []CoverageNote{}
	var runIDs []uuid.UUID
	seen := map[uuid.UUID]bool{}
	for _, s := range supports {
		if s.State != StateEnded && s.LastRunID != nil && !seen[*s.LastRunID] {
			seen[*s.LastRunID] = true
			runIDs = append(runIDs, *s.LastRunID)
		}
	}
	if len(runIDs) == 0 {
		return notes, nil
	}
	var runs []staleRun
	if err := q.DB().Raw(`SELECT id, connector_id, published_at, coverage FROM cloud_scan_run
	                       WHERE workspace_id = ? AND id IN ?`, q.WS, runIDs).Scan(&runs).Error; err != nil {
		return nil, err
	}
	byID := map[uuid.UUID]*staleRun{}
	for i := range runs {
		runs[i].decode()
		byID[runs[i].ID] = &runs[i]
	}
	affects := "changes of this " + obj.refType
	type key struct{ account, surface string }
	done := map[key]bool{}
	for _, s := range supports {
		if s.State == StateEnded || s.LastRunID == nil {
			continue
		}
		run := byID[*s.LastRunID]
		if run == nil {
			continue
		}
		acct := ""
		if c := accts.Connector(s.ConnectorID); c != nil {
			acct = c.AccountID
		}
		var gaps []surfaceGap
		if part, ok := changesPartition(obj, node, s); ok {
			gaps = partitionGaps(part, run.cov, obj.class)
		} else {
			for name, sc := range run.cov.Surfaces {
				if sc.State != models.CloudCoverageReached {
					gaps = append(gaps, surfaceGap{name, sc.State})
				}
			}
		}
		for _, g := range gaps {
			state := g.state
			switch state {
			case models.CloudCoverageUnsupported:
				continue
			case models.CloudCoverageNotSelected:
				state = models.CloudCoverageStale
			}
			k := key{acct, g.surface}
			if done[k] {
				continue
			}
			done[k] = true
			notes = append(notes, CoverageNote{AccountID: acct, Surface: g.surface, State: state, Affects: affects})
		}
	}
	sort.Slice(notes, func(i, j int) bool {
		if notes[i].AccountID != notes[j].AccountID {
			return notes[i].AccountID < notes[j].AccountID
		}
		return notes[i].Surface < notes[j].Surface
	})
	return notes, nil
}
