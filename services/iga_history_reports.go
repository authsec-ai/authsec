package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
)

// Reports (SPEC-secops-backend-upgrade.md W9):
//
//	GET /api/iga/v1/reports/ciso?month=YYYY-MM       seven headline numbers
//	GET /api/iga/v1/reports/population?from=&to=     the auditor's whole population
//
// Same rules as the metrics: one read-only transaction under row-level
// security for the token's workspace, and "unavailable" with a reason for a
// source this database does not have.

/* ---------------------------------- CISO ------------------------------------ */

// CISO headline ids.
const (
	CISOAgentsInEstate    = "ciso.agents_in_estate"
	CISOPercentGoverned   = "ciso.percent_governed"
	CISOIncidents         = "ciso.incidents"
	CISOMedianTimeContain = "ciso.median_time_to_contain"
	CISOUnprovenStops     = "ciso.unproven_stops"
	CISOCoveragePercent   = "ciso.coverage_percent"
	CISOOverdueExceptions = "ciso.overdue_exceptions"
)

// CISOReport is GET /reports/ciso.
type CISOReport struct {
	Month          string         `json:"month"`
	Window         MetricWindow   `json:"window"`
	PreviousWindow MetricWindow   `json:"previous_window"`
	Headlines      []MetricResult `json:"headlines"`
}

// CISO computes the seven headline numbers of month and the month before.
// Estate numbers (agents, governed, coverage, overdue exceptions) are taken
// at the month's end -- live for the current month, else from the daily
// snapshots; activity numbers (incidents, time to contain, unproven stops)
// are computed over the month.
func (s *HistoryService) CISO(ctx context.Context, ws uuid.UUID, month string) (*CISOReport, error) {
	now := s.now().UTC()
	if month == "" {
		month = now.Format("2006-01")
	}
	cur, prev, ok := monthWindow(month)
	if !ok {
		return nil, GovBadParam("month", "month must be YYYY-MM.")
	}
	if !cur.From.Before(now) {
		return nil, GovBadParam("month", "month must not be in the future.")
	}
	out := &CISOReport{Month: month, Window: cur, PreviousWindow: prev}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		c, err := cisoMonth(tx, ws, cur, now)
		if err != nil {
			return err
		}
		p, err := cisoMonth(tx, ws, prev, now)
		if err != nil {
			return err
		}
		for i := range c {
			out.Headlines = append(out.Headlines, withPrevious(c[i], &p[i]))
		}
		return nil
	})
	return out, err
}

// cisoMonth is the seven numbers for one month window.
func cisoMonth(tx *gorm.DB, ws uuid.UUID, w MetricWindow, now time.Time) ([]MetricResult, error) {
	end := w.To
	if end.After(now) {
		end = now
	}
	var posture map[string]MetricResult
	var err error
	if !w.To.After(now) {
		posture, err = postureFromSnapshots(tx, ws, dateOnly(w.To.AddDate(0, 0, -1)))
	} else {
		posture, err = postureLive(tx, ws, now)
	}
	if err != nil {
		return nil, err
	}
	probe := newSchemaProbe(tx)
	v := probeSOC(probe)
	cov, err := streamCoverage(tx, ws, probe, now)
	if err != nil {
		return nil, err
	}
	sw := MetricWindow{From: w.From, To: end}
	contain, err := socMetric(tx, ws, v, SOCTimeToContain, sw, now, cov)
	if err != nil {
		return nil, err
	}
	unproven, err := socMetric(tx, ws, v, SOCUnprovenStops, sw, now, cov)
	if err != nil {
		return nil, err
	}
	derive := func(id, label, unit string, src MetricResult, scale float64, text string) MetricResult {
		m := src
		m.ID, m.Label, m.Unit = id, label, unit
		m.Definition = MetricDefinition{ID: id, Version: src.Definition.Version, Text: text + " (from " + src.Definition.ID + ")"}
		m.Window = &sw
		if m.Value != nil && scale != 1 {
			m.Value = fptr(round2(*m.Value * scale))
		}
		return m
	}
	out := []MetricResult{
		derive(CISOAgentsInEstate, "Agents in the estate", "count", posture[PostureAgentsTotal], 1, "Agents labelled and awaiting a label at the month's end"),
		derive(CISOPercentGoverned, "Agents governed", "percent", posture[PosturePercentGoverned], 100, "Percent of labelled agents under an active AuthSec control at the month's end"),
	}
	// Incidents: cases closed true_positive (W3).
	inc := MetricResult{ID: CISOIncidents, Label: "Incidents", Unit: "count", Status: MetricAvailable, Coverage: cov, Window: &sw, Source: "live",
		Definition: MetricDefinition{ID: CISOIncidents, Version: 1, Text: "Cases closed in the month with outcome true_positive."}}
	if probe.Has("agent_case", "outcome", "closed_at") {
		var n int64
		if err := tx.Raw(`SELECT count(*) FROM agent_case WHERE workspace_id = ? AND outcome::text = 'true_positive'
		                   AND closed_at >= ? AND closed_at < ?`, ws, sw.From, sw.To).Scan(&n).Error; err != nil {
			return nil, err
		}
		inc.Value = fptr(float64(n))
	} else {
		inc = metricUnavailable(CISOIncidents, inc.Label, inc.Unit, inc.Definition,
			"source_missing: cases with outcome codes (agent_case, W3) are not in this database")
		inc.Window = &sw
	}
	out = append(out, inc,
		derive(CISOMedianTimeContain, "Median time to contain", "seconds", contain, 1, "Median seconds from alert to a stop at a covering level, alerts created in the month"),
		derive(CISOUnprovenStops, "Unproven stops", "count", unproven, 1, "Stops started in the month still not proven"),
		derive(CISOCoveragePercent, "Coverage", "percent", posture[PostureCapabilityCoverage], 100, "Percent coverage across the capabilities measured at the month's end"),
		derive(CISOOverdueExceptions, "Overdue exceptions", "count", posture[PostureOverdueExceptions], 1, "Exceptions in force past their end date at the month's end"),
	)
	return out, probe.err
}

/* -------------------------------- population -------------------------------- */

// Population kinds.
const (
	PopulationAlert          = "alert"
	PopulationCase           = "case"
	PopulationContainment    = "containment"
	PopulationAccessDecision = "access_decision"
	PopulationAccessChange   = "access_change"
	PopulationException      = "exception"
)

// PopulationKinds lists every population kind.
var PopulationKinds = []string{PopulationAccessChange, PopulationAccessDecision, PopulationAlert, PopulationCase,
	PopulationContainment, PopulationException}

func validPopulationKind(k string) bool {
	for _, x := range PopulationKinds {
		if x == k {
			return true
		}
	}
	return false
}

// PopulationItem is one record of the population: a stable id and the
// sha256 of the record as read (to_jsonb), so a sample can be traced.
type PopulationItem struct {
	Kind       string          `json:"kind"`
	ID         string          `json:"id"`
	OccurredAt time.Time       `json:"occurred_at"`
	Hash       string          `json:"hash"`
	Record     json.RawMessage `json:"record,omitempty"`
}

type populationSource struct {
	kind, table, timeCol, idCol, extra string
	cols                               []string
}

// populationSources: alerts, cases (W3), containments, gateway access
// decisions, governance changes (iga_gov_event), finding exceptions and
// alert suppressions (W5).
var populationSources = []populationSource{
	{PopulationAlert, "agent_alert", "created_at", "id", "", []string{"id", "created_at"}},
	{PopulationCase, "agent_case", "opened_at", "id", "", []string{"id", "opened_at"}},
	{PopulationContainment, "agent_containment", "created_at", "id", "", []string{"id", "created_at"}},
	{PopulationAccessDecision, "agent_gateway_decision", "decided_at", "id", "AND x.record_type = 'decision'", []string{"id", "decided_at", "record_type"}},
	{PopulationAccessChange, "iga_gov_event", "occurred_at", "id", "", []string{"id", "occurred_at"}},
	{PopulationException, "iga_gov_finding", "status_changed_at", "id", "AND x.excepted_until IS NOT NULL", []string{"id", "status_changed_at", "excepted_until"}},
	{PopulationException, "agent_alert_suppression", "created_at", "id", "", []string{"id", "created_at"}},
}

type populationCursor struct {
	At   time.Time `json:"at"`
	Kind string    `json:"kind"`
	ID   string    `json:"id"`
}

// populationRows reads up to limit records of kinds in [from, to) after the
// cursor, ordered by (time, kind, id).
func populationRows(tx *gorm.DB, ws uuid.UUID, p SchemaProbe, kinds []string, from, to time.Time, after *populationCursor, limit int, withRecord bool) ([]PopulationItem, error) {
	want := map[string]bool{}
	for _, k := range kinds {
		want[k] = true
	}
	var parts []string
	var args []any
	rec := "NULL::text"
	if withRecord {
		rec = "to_jsonb(x)::text"
	}
	for _, src := range populationSources {
		if !want[src.kind] || !p.Has(src.table, src.cols...) {
			continue
		}
		q := `(SELECT '` + src.kind + `'::text AS kind, x.` + src.idCol + `::text AS id, x.` + src.timeCol + ` AS occurred_at,
		        encode(sha256(convert_to(to_jsonb(x)::text, 'UTF8')), 'hex') AS hash, ` + rec + ` AS record
		       FROM ` + src.table + ` x
		      WHERE x.workspace_id = ? AND x.` + src.timeCol + ` >= ? AND x.` + src.timeCol + ` < ? ` + src.extra
		a := []any{ws, from, to}
		if after != nil {
			q += ` AND (x.` + src.timeCol + `, '` + src.kind + `'::text, x.` + src.idCol + `::text) > (?, ?, ?)`
			a = append(a, after.At, after.Kind, after.ID)
		}
		q += ` ORDER BY 3, 2 LIMIT ?)`
		a = append(a, limit)
		parts = append(parts, q)
		args = append(args, a...)
	}
	if len(parts) == 0 {
		return []PopulationItem{}, nil
	}
	var rows []struct {
		Kind       string
		ID         string
		OccurredAt time.Time
		Hash       string
		Record     *string
	}
	q := `SELECT kind, id, occurred_at, hash, record FROM (` + strings.Join(parts, " UNION ALL ") + `) u ORDER BY occurred_at, kind, id LIMIT ?`
	args = append(args, limit)
	if err := tx.Raw(q, args...).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]PopulationItem, 0, len(rows))
	for _, r := range rows {
		it := PopulationItem{Kind: r.Kind, ID: r.ID, OccurredAt: r.OccurredAt.UTC(), Hash: r.Hash}
		if r.Record != nil {
			it.Record = json.RawMessage(*r.Record)
		}
		out = append(out, it)
	}
	return out, nil
}

// PopulationKindStatus says whether a kind was read and how many records it
// has in the window.
type PopulationKindStatus struct {
	Kind   string `json:"kind"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	Count  int64  `json:"count"`
}

// PopulationPage is GET /reports/population.
type PopulationPage struct {
	Window     MetricWindow           `json:"window"`
	Kinds      []PopulationKindStatus `json:"kinds"`
	Items      []PopulationItem       `json:"items"`
	NextCursor *string                `json:"next_cursor"`
}

// Population pages through every record of kinds in [from, to).
func (s *HistoryService) Population(ctx context.Context, ws uuid.UUID, from, to time.Time, kinds []string, cursor string, limit int) (*PopulationPage, error) {
	if !from.Before(to) {
		return nil, GovBadParam("to", "to must be after from.")
	}
	if to.Sub(from) > 400*24*time.Hour {
		return nil, GovBadParam("to", "The window must be at most 400 days.")
	}
	if len(kinds) == 0 {
		kinds = PopulationKinds
	}
	for _, k := range kinds {
		if !validPopulationKind(k) {
			return nil, GovBadParam("kind", "kind must be among "+strings.Join(PopulationKinds, ", ")+".")
		}
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var after *populationCursor
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return nil, GovBadParam("cursor", "Invalid cursor.")
		}
		after = &populationCursor{}
		if err := json.Unmarshal(raw, after); err != nil {
			return nil, GovBadParam("cursor", "Invalid cursor.")
		}
	}
	out := &PopulationPage{Window: MetricWindow{From: from, To: to}}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		probe := newSchemaProbe(tx)
		for _, k := range kinds {
			st := PopulationKindStatus{Kind: k, Status: MetricUnavailable, Reason: "source_missing: no table recording this kind is in this database"}
			for _, src := range populationSources {
				if src.kind != k || !probe.Has(src.table, src.cols...) {
					continue
				}
				var n int64
				if err := tx.Raw(`SELECT count(*) FROM `+src.table+` x WHERE x.workspace_id = ? AND x.`+src.timeCol+` >= ? AND x.`+src.timeCol+` < ? `+src.extra,
					ws, from, to).Scan(&n).Error; err != nil {
					return err
				}
				st.Status, st.Reason = MetricAvailable, ""
				st.Count += n
			}
			out.Kinds = append(out.Kinds, st)
		}
		items, err := populationRows(tx, ws, probe, kinds, from, to, after, limit+1, false)
		if err != nil {
			return err
		}
		if len(items) > limit {
			items = items[:limit]
			last := items[limit-1]
			raw, _ := json.Marshal(populationCursor{At: last.OccurredAt, Kind: last.Kind, ID: last.ID})
			c := base64.RawURLEncoding.EncodeToString(raw)
			out.NextCursor = &c
		}
		out.Items = items
		return probe.err
	})
	return out, err
}
