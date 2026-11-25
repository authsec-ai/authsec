package services

import (
	"context"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
)

// SOC and posture metrics (SPEC-secops-backend-upgrade.md W9, §4).
//
//	GET /api/iga/v1/metrics/soc?period=7d|30d|90d
//	GET /api/iga/v1/metrics/posture?as_of=
//
// Every statement runs in one read-only transaction under row-level security
// for the token's workspace (tenancy.InWorkspaceRead), and names
// workspace_id itself. A metric whose source table or column is not in this
// database answers status "unavailable" with the reason (see
// iga_history_schema.go); the previous period is always measured under the
// same definition version.

// nullableSecs is one duration row; NULL when the event has not happened.
type nullableSecs struct{ Secs *float64 }

// metricRowCap bounds the rows one duration metric reads.
const metricRowCap = 100000

// agentClassifications are the workload classifications that make an agent.
const agentClassificationsSQL = `('provider_native_agent', 'classified_agent')`

// SOCReport is GET /metrics/soc.
type SOCReport struct {
	Period   string         `json:"period"`
	Window   MetricWindow   `json:"window"`
	Previous MetricWindow   `json:"previous_window"`
	Metrics  []MetricResult `json:"metrics"`
}

// PostureReport is GET /metrics/posture.
type PostureReport struct {
	AsOf         time.Time      `json:"as_of"`
	Source       string         `json:"source"`
	PreviousAsOf time.Time      `json:"previous_as_of"`
	Metrics      []MetricResult `json:"metrics"`
}

// HistoryService serves snapshots, metrics, reports, holds, redaction and
// exports (W9).
type HistoryService struct {
	db  *gorm.DB
	now func() time.Time
}

// NewHistoryService returns the service over db.
func NewHistoryService(db *gorm.DB) *HistoryService {
	return &HistoryService{db: db, now: time.Now}
}

// WithClock replaces the clock (tests).
func (s *HistoryService) WithClock(now func() time.Time) *HistoryService {
	s.now = now
	return s
}

// SOC computes the SOC metrics for the period ending now and the period
// before it.
func (s *HistoryService) SOC(ctx context.Context, ws uuid.UUID, period string) (*SOCReport, error) {
	d, ok := parsePeriod(period)
	if !ok {
		return nil, GovBadParam("period", "period must be 7d, 30d or 90d.")
	}
	if period == "" {
		period = "30d"
	}
	now := s.now().UTC()
	cur := periodWindow(now, d)
	prev := periodWindow(cur.From, d)
	out := &SOCReport{Period: period, Window: cur, Previous: prev}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		probe := newSchemaProbe(tx)
		v := probeSOC(probe)
		if probe.err != nil {
			return probe.err
		}
		cov, err := streamCoverage(tx, ws, probe, now)
		if err != nil {
			return err
		}
		for _, id := range SOCMetricIDs {
			c, err := socMetric(tx, ws, v, id, cur, now, cov)
			if err != nil {
				return err
			}
			p, err := socMetric(tx, ws, v, id, prev, now, cov)
			if err != nil {
				return err
			}
			out.Metrics = append(out.Metrics, withPrevious(c, &p))
		}
		return nil
	})
	return out, err
}

// socMetric computes one SOC metric over w.
func socMetric(tx *gorm.DB, ws uuid.UUID, v socVariants, id string, w MetricWindow, now time.Time, cov MetricCoverage) (MetricResult, error) {
	lbl := socLabels[id]
	def := socDefinition(id, v)
	if r := socUnavailableReason(id, v); r != "" {
		m := metricUnavailable(id, lbl[0], lbl[1], def, r)
		m.Window = &w
		return m, nil
	}
	m := MetricResult{ID: id, Label: lbl[0], Unit: lbl[1], Status: MetricAvailable, Definition: def, Coverage: cov, Window: &w, Source: "live"}
	var err error
	switch id {
	case SOCTimeToFirstAction:
		err = socTimeToFirstAction(tx, ws, v, w, &m)
	case SOCTimeToContain:
		err = socTimeToContain(tx, ws, w, &m)
	case SOCUnprovenStops:
		err = socUnprovenStops(tx, ws, v, w, now, &m)
	case SOCTimeToResolve:
		err = socTimeToResolve(tx, ws, v, w, &m)
	case SOCOutcomeMix:
		err = socOutcomeMix(tx, ws, v, w, &m)
	case SOCSuccessAfterRefusal:
		err = socSuccessAfterRefusal(tx, ws, w, &m)
	}
	return m, err
}

func socTimeToFirstAction(tx *gorm.DB, ws uuid.UUID, v socVariants, w MetricWindow, m *MetricResult) error {
	ack := "CASE WHEN a.state = 'acknowledged' THEN a.state_changed_at END"
	if v.ackCol {
		ack = "a.acknowledged_at"
	}
	res := "CASE WHEN a.state = 'resolved' THEN a.state_changed_at END"
	if v.resolvedCol {
		res = "a.resolved_at"
	}
	assign := "NULL::timestamptz"
	if v.caseAssign {
		assign = `(SELECT min(k.assigned_at) FROM agent_case_alert ca
		            JOIN agent_case k ON k.workspace_id = ca.workspace_id AND k.id = ca.case_id
		           WHERE ca.workspace_id = a.workspace_id AND ca.alert_id = a.id)`
	}
	contain := "NULL::timestamptz"
	if v.containment {
		contain = `(SELECT min(c.created_at) FROM agent_containment c
		             WHERE c.workspace_id = a.workspace_id AND c.identity_id = a.identity_id AND c.created_at >= a.created_at)`
	}
	var secs []nullableSecs
	if err := tx.Raw(`SELECT EXTRACT(EPOCH FROM (LEAST(`+ack+`, `+res+`, `+assign+`, `+contain+`) - a.created_at))::float8 AS secs
	                    FROM agent_alert a
	                   WHERE a.workspace_id = ? AND a.created_at >= ? AND a.created_at < ?
	                   ORDER BY a.created_at LIMIT ?`, ws, w.From, w.To, metricRowCap).Scan(&secs).Error; err != nil {
		return err
	}
	var vals []float64
	noAction := 0
	for _, s := range secs {
		if s.Secs == nil {
			noAction++
			continue
		}
		vals = append(vals, *s.Secs)
	}
	durationStats(m, vals)
	m.Breakdown = map[string]float64{"alerts": float64(len(secs)), "acted_on": float64(len(vals)), "no_action_yet": float64(noAction)}
	return nil
}

// coveringLevelSQL is the condition that a containment c covers alert a's
// principal: its identity at identity or key level, or every workload the
// alert names at workload level. A model-level stop never covers.
const coveringLevelSQL = `(c.level IN ('identity', 'key', 'credential')
	OR (c.level = 'workload' AND jsonb_typeof(a.workload_ids) = 'array' AND jsonb_array_length(a.workload_ids) > 0
	    AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(a.workload_ids) wl(v)
	                     WHERE NOT (wl.v = ANY (c.workload_ids::text[])))))`

func socTimeToContain(tx *gorm.DB, ws uuid.UUID, w MetricWindow, m *MetricResult) error {
	var rows []struct {
		Secs  *float64
		Other bool
	}
	if err := tx.Raw(`SELECT EXTRACT(EPOCH FROM (cov.t - a.created_at))::float8 AS secs,
	                         EXISTS (SELECT 1 FROM agent_containment c
	                                  WHERE c.workspace_id = a.workspace_id AND c.identity_id = a.identity_id
	                                    AND c.contained_at IS NOT NULL AND c.created_at >= a.created_at) AS other
	                    FROM agent_alert a
	                    LEFT JOIN LATERAL (
	                         SELECT min(c.contained_at) AS t FROM agent_containment c
	                          WHERE c.workspace_id = a.workspace_id AND c.identity_id = a.identity_id
	                            AND c.contained_at IS NOT NULL AND c.created_at >= a.created_at
	                            AND `+coveringLevelSQL+`) cov ON true
	                   WHERE a.workspace_id = ? AND a.created_at >= ? AND a.created_at < ?
	                   ORDER BY a.created_at LIMIT ?`, ws, w.From, w.To, metricRowCap).Scan(&rows).Error; err != nil {
		return err
	}
	var vals []float64
	notCovering, none := 0, 0
	for _, r := range rows {
		switch {
		case r.Secs != nil:
			vals = append(vals, *r.Secs)
		case r.Other:
			notCovering++
		default:
			none++
		}
	}
	durationStats(m, vals)
	m.Breakdown = map[string]float64{"alerts": float64(len(rows)), "contained_covering": float64(len(vals)),
		"contained_not_covering": float64(notCovering), "not_contained": float64(none)}
	return nil
}

func socUnprovenStops(tx *gorm.DB, ws uuid.UUID, v socVariants, w MetricWindow, now time.Time, m *MetricResult) error {
	unproven := "c.effective IS NOT TRUE"
	if v.proofState {
		unproven = "c.proof_state IN ('applied', 'unproven', 'cannot_verify')"
	}
	var raw []nullableSecs
	if err := tx.Raw(`SELECT EXTRACT(EPOCH FROM (CAST(? AS timestamptz) - COALESCE(c.contained_at, c.created_at)))::float8 AS secs
	                    FROM agent_containment c
	                   WHERE c.workspace_id = ? AND c.created_at >= ? AND c.created_at < ?
	                     AND c.state IN ('contained', 'partially_contained') AND `+unproven+`
	                   LIMIT ?`, now, ws, w.From, w.To, metricRowCap).Scan(&raw).Error; err != nil {
		return err
	}
	ages := make([]float64, 0, len(raw))
	for _, a := range raw {
		if a.Secs != nil {
			ages = append(ages, *a.Secs)
		}
	}
	m.Value = fptr(float64(len(ages)))
	m.N = iptr(len(ages))
	m.Breakdown = bucketAges(ages)
	return nil
}

func socTimeToResolve(tx *gorm.DB, ws uuid.UUID, v socVariants, w MetricWindow, m *MetricResult) error {
	res := "CASE WHEN a.state = 'resolved' THEN a.state_changed_at END"
	if v.resolvedCol {
		res = "a.resolved_at"
	}
	var secs []nullableSecs
	if err := tx.Raw(`SELECT EXTRACT(EPOCH FROM (`+res+` - a.created_at))::float8 AS secs FROM agent_alert a
	                   WHERE a.workspace_id = ? AND a.created_at >= ? AND a.created_at < ?
	                   ORDER BY a.created_at LIMIT ?`, ws, w.From, w.To, metricRowCap).Scan(&secs).Error; err != nil {
		return err
	}
	var vals []float64
	open := 0
	for _, s := range secs {
		if s.Secs == nil {
			open++
			continue
		}
		vals = append(vals, *s.Secs)
	}
	durationStats(m, vals)
	m.Breakdown = map[string]float64{"alerts": float64(len(secs)), "resolved": float64(len(vals)), "unresolved": float64(open)}
	return nil
}

func socOutcomeMix(tx *gorm.DB, ws uuid.UUID, v socVariants, w MetricWindow, m *MetricResult) error {
	var rows []struct {
		Outcome string
		N       int64
	}
	q := `SELECT outcome::text AS outcome, count(*) AS n FROM agent_case
	       WHERE workspace_id = ? AND closed_at >= ? AND closed_at < ? AND COALESCE(outcome::text, '') <> ''
	       GROUP BY 1`
	if !v.caseOutcome {
		q = `SELECT outcome::text AS outcome, count(*) AS n FROM agent_alert
		      WHERE workspace_id = ? AND resolved_at >= ? AND resolved_at < ? AND COALESCE(outcome::text, '') <> ''
		      GROUP BY 1`
	}
	if err := tx.Raw(q, ws, w.From, w.To).Scan(&rows).Error; err != nil {
		return err
	}
	b := map[string]float64{"true_positive": 0, "benign": 0, "false_positive": 0, "duplicate": 0}
	var total int64
	for _, r := range rows {
		b[r.Outcome] += float64(r.N)
		total += r.N
	}
	m.Breakdown = b
	m.Value = fptr(float64(total))
	m.N = iptr(int(total))
	return nil
}

func socSuccessAfterRefusal(tx *gorm.DB, ws uuid.UUID, w MetricWindow, m *MetricResult) error {
	var n int64
	if err := tx.Raw(`SELECT count(*) FROM (
	                    SELECT DISTINCT d.identity_id, d.action FROM agent_activity_event d
	                     WHERE d.workspace_id = ? AND d.outcome = 'denied' AND d.occurred_at >= ? AND d.occurred_at < ?
	                       AND d.identity_id IS NOT NULL AND d.action <> ''
	                       AND EXISTS (SELECT 1 FROM agent_activity_event s
	                                    WHERE s.workspace_id = d.workspace_id AND s.identity_id = d.identity_id
	                                      AND s.action = d.action AND s.outcome = 'success'
	                                      AND s.occurred_at > d.occurred_at AND s.occurred_at <= d.occurred_at + interval '1 hour')) x`,
		ws, w.From, w.To).Scan(&n).Error; err != nil {
		return err
	}
	m.Value = fptr(float64(n))
	m.N = iptr(int(n))
	return nil
}

// streamCoverage is the share of the estate whose event stream (C1) AuthSec
// sees: from agent_capability_state when it exists (W1), else the AWS
// CloudTrail reader's current state per active connector.
func streamCoverage(tx *gorm.DB, ws uuid.UUID, p SchemaProbe, now time.Time) (MetricCoverage, error) {
	var r struct{ On, Total int64 }
	if p.Has("agent_capability_state", "capability", "state") {
		if err := tx.Raw(`SELECT count(*) FILTER (WHERE state::text = 'on') AS on, count(*) AS total
		                    FROM agent_capability_state WHERE workspace_id = ? AND capability::text = 'C1'`, ws).Scan(&r).Error; err != nil {
			return MetricCoverage{}, err
		}
		c := MetricCoverage{Share: share(r.On, r.Total), Basis: "estate scopes with capability C1 (event streams) on"}
		if r.Total == 0 {
			c.Note = "No estate scope reports capability C1."
		}
		return c, nil
	}
	if !p.Has("cloud_connector") || !p.Has("cloud_trail_cursor") {
		return MetricCoverage{Basis: "none", Note: "Neither capability state (W1) nor the CloudTrail reader is in this database."}, nil
	}
	if err := tx.Raw(`SELECT count(*) FILTER (WHERE x.ok) AS on, count(*) AS total FROM (
	                    SELECT EXISTS (SELECT 1 FROM cloud_trail_cursor t
	                                    WHERE t.workspace_id = c.workspace_id AND t.connector_id = c.id AND t.stream = 'general'
	                                      AND t.read_to > ?::timestamptz - interval '48 hours' AND NOT t.partial AND t.last_error = '') AS ok
	                      FROM cloud_connector c
	                     WHERE c.workspace_id = ? AND c.provider = 'aws' AND c.status = 'active') x`, now, ws).Scan(&r).Error; err != nil {
		return MetricCoverage{}, err
	}
	c := MetricCoverage{Share: share(r.On, r.Total), Basis: "active AWS connectors whose CloudTrail was read in the last 48 hours without a gap",
		Note: "Capability state (C1, W1) is not recorded in this build: this is the CloudTrail reader's current state, not the period's."}
	if r.Total == 0 {
		c.Note = "No active AWS connector."
	}
	return c, nil
}

// inventoryCoverage is the share of active connectors with a published
// discovery scan in the last 48 hours.
func inventoryCoverage(tx *gorm.DB, ws uuid.UUID, p SchemaProbe, now time.Time) (MetricCoverage, error) {
	if !p.Has("cloud_connector") || !p.Has("cloud_scan_run") {
		return MetricCoverage{Basis: "none", Note: "Connector scan state is not in this database."}, nil
	}
	var r struct{ On, Total int64 }
	if err := tx.Raw(`SELECT count(*) FILTER (WHERE x.ok) AS on, count(*) AS total FROM (
	                    SELECT EXISTS (SELECT 1 FROM cloud_scan_run s
	                                    WHERE s.workspace_id = c.workspace_id AND s.connector_id = c.id AND s.status = 'published'
	                                      AND s.published_at > ?::timestamptz - interval '48 hours') AS ok
	                      FROM cloud_connector c WHERE c.workspace_id = ? AND c.status = 'active') x`, now, ws).Scan(&r).Error; err != nil {
		return MetricCoverage{}, err
	}
	c := MetricCoverage{Share: share(r.On, r.Total), Basis: "active connectors with a discovery scan published in the last 48 hours"}
	if r.Total == 0 {
		c.Note = "No active connector."
	}
	return c, nil
}

/* --------------------------------- posture -------------------------------- */

// Posture metric ids.
const (
	PostureAgentsTotal        = "posture.agents_total"
	PostureAgentsLabelled     = "posture.agents_labelled"
	PostureAgentsUnlabelled   = "posture.agents_unlabelled"
	PostureNoResponder        = "posture.agents_without_responder"
	PostureCrownJewelReach    = "posture.crown_jewel_reach"
	PostureStandingVsTimed    = "posture.standing_vs_time_bound_access"
	PostureStaleAgents        = "posture.stale_agents"
	PostureOverdueKeys        = "posture.overdue_keys"
	PosturePercentGoverned    = "posture.percent_governed"
	PostureOverdueExceptions  = "posture.overdue_exceptions"
	PostureCapabilityCoverage = "posture.capability_coverage"
)

// PostureMetricIDs is the order the posture report lists its metrics in.
var PostureMetricIDs = []string{PostureAgentsTotal, PostureAgentsLabelled, PostureAgentsUnlabelled, PostureNoResponder,
	PostureCrownJewelReach, PostureStandingVsTimed, PostureStaleAgents, PostureOverdueKeys, PosturePercentGoverned,
	PostureOverdueExceptions, PostureCapabilityCoverage}

type postureVariants struct {
	responder     bool // agent.responder_group_id (W7)
	agentEnded    bool // agent.ended_at (W7)
	crownJewel    bool // iga_resources.crown_jewel (W7, C12)
	capability    bool // agent_capability_state (W1)
	tempGrant     bool
	findings      bool
	agentFindings bool
	controls      bool
}

func probePosture(p SchemaProbe) postureVariants {
	return postureVariants{
		responder:     p.Has("agent", "workspace_id", "responder_group_id"),
		agentEnded:    p.Has("agent", "ended_at"),
		crownJewel:    p.Has("iga_resources", "crown_jewel"),
		capability:    p.Has("agent_capability_state", "capability", "state"),
		tempGrant:     p.Has("iga_gov_temp_grant", "identity_account_id", "state"),
		findings:      p.Has("iga_gov_finding", "status", "excepted_until"),
		agentFindings: p.Has("agent_finding", "kind", "state"),
		controls:      p.Has("iga_gov_control", "identity_account_id", "state"),
	}
}

var postureLabels = map[string][2]string{
	PostureAgentsTotal:        {"Agents (labelled and awaiting a label)", "count"},
	PostureAgentsLabelled:     {"Agents labelled", "count"},
	PostureAgentsUnlabelled:   {"AI workloads awaiting a label", "count"},
	PostureNoResponder:        {"Agents without a responder", "count"},
	PostureCrownJewelReach:    {"Agent identities reaching a crown jewel", "count"},
	PostureStandingVsTimed:    {"Agent access: standing vs time-bound", "ratio"},
	PostureStaleAgents:        {"Stale agents", "count"},
	PostureOverdueKeys:        {"Overdue keys", "count"},
	PosturePercentGoverned:    {"Agents governed", "ratio"},
	PostureOverdueExceptions:  {"Overdue exceptions", "count"},
	PostureCapabilityCoverage: {"Coverage per capability", "ratio"},
}

func postureDefinition(id string, v postureVariants) MetricDefinition {
	switch id {
	case PostureAgentsTotal:
		return MetricDefinition{ID: id, Version: 1, Text: "Active workloads labelled agent (provider-native or classified) plus active unclassified workloads with a pending agent suggestion."}
	case PostureAgentsLabelled:
		return MetricDefinition{ID: id, Version: 1, Text: "Active workloads labelled agent (provider-native or classified)."}
	case PostureAgentsUnlabelled:
		return MetricDefinition{ID: id, Version: 1, Text: "Active unclassified workloads with a pending agent suggestion (AI workloads awaiting a label)."}
	case PostureNoResponder:
		if v.agentEnded {
			return MetricDefinition{ID: id, Version: 2, Text: "Agents (agent table) not ended and with no responder group."}
		}
		return MetricDefinition{ID: id, Version: 1, Text: "Agents (agent table) with no responder group."}
	case PostureCrownJewelReach:
		return MetricDefinition{ID: id, Version: 1, Text: "Distinct identities behind labelled agents holding a current allow grant whose statement names a resource classified crown jewel."}
	case PostureStandingVsTimed:
		return MetricDefinition{ID: id, Version: 1, Text: "Identities behind labelled agents: current allow grants with no end (standing) and active AuthSec temporary grants (time-bound); value is the time-bound share."}
	case PostureStaleAgents:
		return MetricDefinition{ID: id, Version: 1, Text: "Labelled agent workloads not seen by discovery for 30 days, plus agents marked stale (iga_agents.rollup_state)."}
	case PostureOverdueKeys:
		return MetricDefinition{ID: id, Version: 1, Text: "Open long-lived access key findings (keys past the rotation age)."}
	case PosturePercentGoverned:
		return MetricDefinition{ID: id, Version: 1, Text: "Share of labelled agent workloads whose identity is under an active AuthSec control (iga_gov_control active or removing)."}
	case PostureOverdueExceptions:
		return MetricDefinition{ID: id, Version: 1, Text: "Finding exceptions still in force after their end date (status excepted, excepted_until in the past)."}
	case PostureCapabilityCoverage:
		if v.capability {
			return MetricDefinition{ID: id, Version: 2, Text: "Per capability (C1..C13), the share of estate scopes with the capability on; value is the mean share over the capabilities reported."}
		}
		return MetricDefinition{ID: id, Version: 1, Text: "Per capability, the share of the estate covered; only C1 (event streams) is measured in this build, from the CloudTrail reader; value is the C1 share."}
	}
	return MetricDefinition{ID: id}
}

// Posture computes the posture metrics. as_of in the past (before today,
// UTC) reads them from the daily snapshots; otherwise they are computed
// live. The previous period is 30 days before as_of, from snapshots.
func (s *HistoryService) Posture(ctx context.Context, ws uuid.UUID, asOf *time.Time) (*PostureReport, error) {
	now := s.now().UTC()
	at := now
	if asOf != nil {
		at = asOf.UTC()
	}
	today := dateOnly(now)
	out := &PostureReport{AsOf: at, PreviousAsOf: at.AddDate(0, 0, -30)}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var cur map[string]MetricResult
		var err error
		if dateOnly(at).Before(today) {
			out.Source = "snapshot"
			cur, err = postureFromSnapshots(tx, ws, dateOnly(at))
		} else {
			out.Source = "live"
			cur, err = postureLive(tx, ws, now)
		}
		if err != nil {
			return err
		}
		prev, err := postureFromSnapshots(tx, ws, dateOnly(out.PreviousAsOf))
		if err != nil {
			return err
		}
		for _, id := range PostureMetricIDs {
			c := cur[id]
			p := prev[id]
			out.Metrics = append(out.Metrics, withPrevious(c, &p))
		}
		return nil
	})
	return out, err
}

// postureLive computes every posture metric now.
func postureLive(tx *gorm.DB, ws uuid.UUID, now time.Time) (map[string]MetricResult, error) {
	probe := newSchemaProbe(tx)
	v := probePosture(probe)
	if probe.err != nil {
		return nil, probe.err
	}
	invCov, err := inventoryCoverage(tx, ws, probe, now)
	if err != nil {
		return nil, err
	}
	streamCov, err := streamCoverage(tx, ws, probe, now)
	if err != nil {
		return nil, err
	}
	out := map[string]MetricResult{}
	mk := func(id string) MetricResult {
		l := postureLabels[id]
		at := now
		return MetricResult{ID: id, Label: l[0], Unit: l[1], Status: MetricAvailable, Definition: postureDefinition(id, v),
			Coverage: invCov, AsOf: &at, Source: "live"}
	}
	un := func(id, reason string) {
		l := postureLabels[id]
		m := metricUnavailable(id, l[0], l[1], postureDefinition(id, v), reason)
		at := now
		m.AsOf = &at
		out[id] = m
	}

	// Agents.
	var agents struct{ Labelled, Unlabelled int64 }
	if err := tx.Raw(`SELECT
	        (SELECT count(*) FROM iga_workload w WHERE w.workspace_id = ? AND w.lifecycle = 'active'
	            AND w.classification IN `+agentClassificationsSQL+`) AS labelled,
	        (SELECT count(*) FROM agent_suggestion s JOIN iga_workload w ON w.workspace_id = s.workspace_id AND w.id = s.workload_id
	          WHERE s.workspace_id = ? AND s.state = 'pending' AND w.lifecycle = 'active' AND w.classification = 'unclassified') AS unlabelled`,
		ws, ws).Scan(&agents).Error; err != nil {
		return nil, err
	}
	m := mk(PostureAgentsTotal)
	m.Value = fptr(float64(agents.Labelled + agents.Unlabelled))
	m.Breakdown = map[string]float64{"labelled": float64(agents.Labelled), "unlabelled": float64(agents.Unlabelled)}
	out[m.ID] = m
	m = mk(PostureAgentsLabelled)
	m.Value = fptr(float64(agents.Labelled))
	out[m.ID] = m
	m = mk(PostureAgentsUnlabelled)
	m.Value = fptr(float64(agents.Unlabelled))
	out[m.ID] = m

	// Responders (W7).
	if v.responder {
		q := `SELECT count(*) FROM agent WHERE workspace_id = ? AND responder_group_id IS NULL`
		if v.agentEnded {
			q += ` AND ended_at IS NULL`
		}
		var n int64
		if err := tx.Raw(q, ws).Scan(&n).Error; err != nil {
			return nil, err
		}
		m = mk(PostureNoResponder)
		m.Value = fptr(float64(n))
		out[m.ID] = m
	} else {
		un(PostureNoResponder, "source_missing: responder groups (agent.responder_group_id, W7) are not in this database")
	}

	agentIdentityCTE := `WITH agent_identity AS (
	    SELECT DISTINCT r.target_identity_account_id AS id FROM iga_relationship r
	      JOIN iga_workload w ON w.workspace_id = r.workspace_id AND w.id = r.source_workload_id
	     WHERE r.workspace_id = ? AND r.state = 'current' AND r.target_identity_account_id IS NOT NULL
	       AND w.lifecycle = 'active' AND w.classification IN ` + agentClassificationsSQL + `)`

	// Crown jewels (W7, C12).
	if v.crownJewel {
		var n int64
		if err := tx.Raw(agentIdentityCTE+`
	        SELECT count(DISTINCT g.subject_identity_account_id) FROM iga_access_edges g
	          JOIN iga_entitlements e ON e.workspace_id = g.workspace_id AND e.id = g.entitlement_id
	          JOIN iga_entitlement_target t ON t.workspace_id = e.workspace_id AND t.entitlement_id = e.id AND t.target_mode = 'resource'
	          JOIN iga_resources rs ON rs.workspace_id = t.workspace_id AND rs.id = t.resource_id AND rs.crown_jewel IS TRUE
	         WHERE g.workspace_id = ? AND g.state = 'current' AND e.effect = 'allow'
	           AND g.subject_identity_account_id IN (SELECT id FROM agent_identity)`, ws, ws).Scan(&n).Error; err != nil {
			return nil, err
		}
		m = mk(PostureCrownJewelReach)
		m.Value = fptr(float64(n))
		out[m.ID] = m
	} else {
		un(PostureCrownJewelReach, "source_missing: crown-jewel classification (iga_resources.crown_jewel, C12 / W7) is not in this database")
	}

	// Standing vs time-bound.
	var acc struct{ Standing, TimeBound int64 }
	timeBound := `0::bigint`
	args := []any{ws, ws}
	if v.tempGrant {
		timeBound = `(SELECT count(*) FROM iga_gov_temp_grant t WHERE t.workspace_id = ? AND t.state IN ('active', 'expiring')
		               AND t.identity_account_id IN (SELECT id FROM agent_identity))`
		args = append(args, ws)
	}
	if err := tx.Raw(agentIdentityCTE+`
	    SELECT (SELECT count(*) FROM iga_access_edges g
	              JOIN iga_entitlements e ON e.workspace_id = g.workspace_id AND e.id = g.entitlement_id
	             WHERE g.workspace_id = ? AND g.state = 'current' AND g.valid_to IS NULL AND e.effect = 'allow'
	               AND g.subject_identity_account_id IN (SELECT id FROM agent_identity)) AS standing,
	           `+timeBound+` AS time_bound`, args...).Scan(&acc).Error; err != nil {
		return nil, err
	}
	m = mk(PostureStandingVsTimed)
	m.Value = share(acc.TimeBound, acc.Standing+acc.TimeBound)
	m.Breakdown = map[string]float64{"standing": float64(acc.Standing), "time_bound": float64(acc.TimeBound)}
	out[m.ID] = m

	// Stale agents.
	var stale int64
	if err := tx.Raw(`SELECT
	        (SELECT count(*) FROM iga_workload w WHERE w.workspace_id = ? AND w.lifecycle = 'active'
	            AND w.classification IN `+agentClassificationsSQL+` AND w.last_seen_at < ?::timestamptz - interval '30 days')
	      + (SELECT count(*) FROM iga_agents a WHERE a.workspace_id = ? AND a.lifecycle = 'active' AND a.rollup_state = 'stale')`,
		ws, now, ws).Scan(&stale).Error; err != nil {
		return nil, err
	}
	m = mk(PostureStaleAgents)
	m.Value = fptr(float64(stale))
	out[m.ID] = m

	// Overdue keys.
	if v.agentFindings {
		var n int64
		if err := tx.Raw(`SELECT count(*) FROM agent_finding WHERE workspace_id = ? AND kind = 'long_lived_key' AND state = 'open'`, ws).
			Scan(&n).Error; err != nil {
			return nil, err
		}
		m = mk(PostureOverdueKeys)
		m.Value = fptr(float64(n))
		out[m.ID] = m
	} else {
		un(PostureOverdueKeys, "source_missing: agent_finding is not in this database")
	}

	// Governed.
	if v.controls {
		var g struct{ Agents, Governed int64 }
		if err := tx.Raw(`WITH agents AS (
	            SELECT w.id FROM iga_workload w WHERE w.workspace_id = ? AND w.lifecycle = 'active'
	               AND w.classification IN `+agentClassificationsSQL+`)
	        SELECT (SELECT count(*) FROM agents) AS agents,
	               (SELECT count(DISTINCT r.source_workload_id) FROM iga_relationship r
	                  JOIN iga_gov_control k ON k.workspace_id = r.workspace_id AND k.identity_account_id = r.target_identity_account_id
	                 WHERE r.workspace_id = ? AND r.state = 'current' AND k.state IN ('active', 'removing')
	                   AND r.source_workload_id IN (SELECT id FROM agents)) AS governed`, ws, ws).Scan(&g).Error; err != nil {
			return nil, err
		}
		m = mk(PosturePercentGoverned)
		m.Value = share(g.Governed, g.Agents)
		m.Breakdown = map[string]float64{"agents": float64(g.Agents), "governed": float64(g.Governed)}
		out[m.ID] = m
	} else {
		un(PosturePercentGoverned, "source_missing: iga_gov_control is not in this database")
	}

	// Overdue exceptions.
	if v.findings {
		var n int64
		if err := tx.Raw(`SELECT count(*) FROM iga_gov_finding WHERE workspace_id = ? AND status = 'excepted' AND excepted_until < ?`, ws, now).
			Scan(&n).Error; err != nil {
			return nil, err
		}
		m = mk(PostureOverdueExceptions)
		m.Value = fptr(float64(n))
		m.Coverage = MetricCoverage{Share: fptr(1), Basis: "finding exceptions",
			Note: "Alert suppressions (W5) are not in this build and are not counted."}
		out[m.ID] = m
	} else {
		un(PostureOverdueExceptions, "source_missing: iga_gov_finding is not in this database")
	}

	// Capability coverage.
	m = mk(PostureCapabilityCoverage)
	m.Breakdown = map[string]float64{}
	if v.capability {
		var rows []struct {
			Capability string
			On, Total  int64
		}
		if err := tx.Raw(`SELECT capability::text AS capability, count(*) FILTER (WHERE state::text = 'on') AS on, count(*) AS total
		                    FROM agent_capability_state WHERE workspace_id = ? GROUP BY 1 ORDER BY 1`, ws).Scan(&rows).Error; err != nil {
			return nil, err
		}
		var sum float64
		var n int
		for _, r := range rows {
			if sh := share(r.On, r.Total); sh != nil {
				m.Breakdown[r.Capability] = *sh
				sum += *sh
				n++
			}
		}
		if n > 0 {
			m.Value = fptr(round4(sum / float64(n)))
		}
		m.Coverage = MetricCoverage{Share: m.Value, Basis: "estate scopes per capability"}
	} else {
		if streamCov.Share != nil {
			m.Breakdown["C1"] = *streamCov.Share
		}
		m.Value = streamCov.Share
		m.Coverage = streamCov
		m.Coverage.Note = "Only C1 (event streams) is measured in this build; capability state per scope (W1) is not in this database."
	}
	out[m.ID] = m
	return out, nil
}

// postureFromSnapshots reads every posture metric from its metric_value
// snapshot at or before day.
func postureFromSnapshots(tx *gorm.DB, ws uuid.UUID, day time.Time) (map[string]MetricResult, error) {
	out := map[string]MetricResult{}
	snaps, err := latestSnapshots(tx, ws, SnapshotKindMetricValue, PostureMetricIDs, day)
	if err != nil {
		return nil, err
	}
	for _, id := range PostureMetricIDs {
		l := postureLabels[id]
		sn, ok := snaps[id]
		if !ok || sn.Absent || sn.Redacted {
			reason := "no_snapshot: no snapshot of this metric at or before " + day.Format("2006-01-02")
			if ok && sn.Redacted {
				reason = "redacted: the snapshot of this metric was redacted"
			}
			m := MetricResult{ID: id, Label: l[0], Unit: l[1], Status: MetricUnavailable, Reason: reason,
				Definition: MetricDefinition{ID: id}, Coverage: MetricCoverage{Basis: "none"}, Source: "snapshot"}
			d := day
			m.AsOf = &d
			out[id] = m
			continue
		}
		m, err := metricFromSnapshotBody(sn.Body)
		if err != nil {
			return nil, err
		}
		m.Source = "snapshot"
		m.SnapshotDate = sn.SnapshotDate.Format("2006-01-02")
		out[id] = m
	}
	return out, nil
}
