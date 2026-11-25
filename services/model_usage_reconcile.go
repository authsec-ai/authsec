package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentruntime/detect"
	"github.com/authsec-ai/authsec/internal/modelprovider"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

/* model_usage_reconcile.go: provider usage per minute and the usage
   reconciliation (W6, C5, P15).

   Per-minute usage. For each connected organisation, the keys used in the
   last day (and those an AuthSec-held gateway key is tied to) are read in
   1-minute buckets (OpenAI and Anthropic usage APIs both report 1m buckets)
   into model_provider_usage_minute (resolution 1m); cost, which both
   providers report daily only, is stored as 1d rows (OpenAI per key,
   Anthropic per workspace).

   Reconciliation. Every 5 minutes (AUTHSEC_DISABLE_USAGE_RECONCILE=true
   turns it off), for each workspace, each provider key and minute of the
   last six hours is labelled:
     observed     the gateway's decision log has calls with the key that minute;
     bypass       an estate workload looked the provider up or sent it traffic
                  in that minute (+-1) and the gateway saw no call;
     outside_use  the provider reports usage of the key and neither the gateway
                  nor any estate lookup or flow explains it.
   Estate traffic to a provider in a minute the gateway saw no call for that
   provider, and with no key usage to tie it to, is a bypass with key_ref ''.
   Labels carry evidence references; outside_use raises USAGE-02 and bypass
   USAGE-03 through the agent_alert path (one open alert per key / workload). */

const (
	usageMinuteLookback   = 24 * time.Hour
	usageMinuteOverlap    = 15 * time.Minute
	usageMinuteRetention  = 30 * 24 * time.Hour
	usageCostEvery        = time.Hour
	usageCostLookback     = 7 * 24 * time.Hour
	reconcileEvery        = 5 * time.Minute
	reconcileLookback     = 6 * time.Hour
	reconcileSettle       = 5 * time.Minute
	reconcileMaxEvidence  = 10
	reconcileMaxWorkloads = 20
	// Reconciliation labels.
	UsageObserved   = "observed"
	UsageBypass     = "bypass"
	UsageOutsideUse = "outside_use"
	usageAlertLabel = "provider_key"
)

// UsageMinuteResult counts one per-minute sync.
type UsageMinuteResult struct {
	Keys      int
	Rows      int
	CostRows  int
	From, To  time.Time
	CostError string
}

// SyncUsageMinutes reads one connection's per-minute usage for its active
// keys, and its daily cost at most hourly.
func (s *ModelProviderService) SyncUsageMinutes(ctx context.Context, ws, id uuid.UUID) (*UsageMinuteResult, error) {
	now := s.now().UTC()
	var conn []struct {
		Provider          string
		SecretRef         string
		Status            string
		UsageMinuteCursor *time.Time
		CostCursor        *time.Time
	}
	var keys []string
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		if err := tx.Raw(`SELECT provider, secret_ref, status, usage_minute_cursor, cost_cursor FROM model_provider_connection
		                   WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&conn).Error; err != nil {
			return err
		}
		return tx.Raw(`SELECT provider_key_id FROM model_provider_key
		                WHERE workspace_id = ? AND connection_id = ? AND status <> 'deleted' AND last_used_at >= ?
		               UNION
		               SELECT provider_key_id FROM agent_gateway_provider_key
		                WHERE workspace_id = ? AND connection_id = ? AND state = 'active' AND provider_key_id <> ''
		               ORDER BY 1 LIMIT 200`, ws, id, now.Add(-usageMinuteLookback), ws, id).Scan(&keys).Error
	}); err != nil {
		return nil, err
	}
	if len(conn) == 0 {
		return nil, GovNotFound()
	}
	c := conn[0]
	res := &UsageMinuteResult{Keys: len(keys)}
	if c.Status == ModelProviderRevoked {
		return res, nil
	}
	vc := modelProviderVault()
	if vc == nil {
		return nil, errModelProviderSecret{"the secrets store is not configured"}
	}
	sec, err := vc.ReadSecret(c.SecretRef)
	if err != nil {
		return nil, errModelProviderSecret{"the admin key could not be read from the secrets store"}
	}
	adminKey, _ := sec["admin_key"].(string)
	if adminKey == "" {
		return nil, errModelProviderSecret{"the stored admin key is empty"}
	}
	client, err := s.newClient(c.Provider, adminKey)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, modelProviderCallTimeout)
	defer cancel()
	res.To = now.Truncate(time.Minute)
	res.From = res.To.Add(-usageMinuteLookback)
	if c.UsageMinuteCursor != nil {
		if f := c.UsageMinuteCursor.UTC().Add(-usageMinuteOverlap).Truncate(time.Minute); f.After(res.From) {
			res.From = f
		}
	}
	var usage []modelprovider.UsageRow
	if len(keys) > 0 && res.From.Before(res.To) {
		if usage, err = client.UsageMinutes(cctx, res.From, res.To, keys); err != nil {
			return res, err
		}
	}
	var costs []modelprovider.CostRow
	costRead := c.CostCursor == nil || now.Sub(*c.CostCursor) >= usageCostEvery
	if costRead {
		from := now.Add(-usageCostLookback).Truncate(24 * time.Hour)
		if costs, err = client.Costs(cctx, from, now); err != nil {
			// Cost is optional (an organisation may not expose it): the usage stands.
			res.CostError = modelprovider.Scrub(err.Error())
			costRead = false
		}
	}
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		for _, u := range usage {
			if err := tx.Exec(`INSERT INTO model_provider_usage_minute (workspace_id, connection_id, provider, provider_key_id, key_hint,
			                       project_id, model, bucket_start, resolution, requests, input_tokens, cached_input_tokens,
			                       output_tokens, updated_at)
			                   SELECT ?, ?, ?, ?, COALESCE((SELECT key_hint FROM model_provider_key k WHERE k.workspace_id = ?
			                          AND k.connection_id = ? AND k.provider_key_id = ?), ''), ?, ?, ?, '1m', ?::bigint, ?, ?, ?, ?
			                   ON CONFLICT (workspace_id, connection_id, resolution, provider_key_id, project_id, model, bucket_start)
			                   DO UPDATE SET requests = EXCLUDED.requests, input_tokens = EXCLUDED.input_tokens,
			                       cached_input_tokens = EXCLUDED.cached_input_tokens, output_tokens = EXCLUDED.output_tokens,
			                       updated_at = EXCLUDED.updated_at`,
				ws, id, c.Provider, truncate(u.KeyID, 200), ws, id, u.KeyID, truncate(u.ProjectID, 200), truncate(u.Model, 200),
				u.BucketStart.UTC().Truncate(time.Minute), u.Requests, u.InputTokens, u.CachedInputTokens, u.OutputTokens, now).Error; err != nil {
				return fmt.Errorf("usage minute: %w", err)
			}
			res.Rows++
		}
		for _, k := range costs {
			if err := tx.Exec(`INSERT INTO model_provider_usage_minute (workspace_id, connection_id, provider, provider_key_id,
			                       project_id, model, bucket_start, resolution, cost_usd, updated_at)
			                   VALUES (?, ?, ?, ?, ?, '', ?, '1d', ?, ?)
			                   ON CONFLICT (workspace_id, connection_id, resolution, provider_key_id, project_id, model, bucket_start)
			                   DO UPDATE SET cost_usd = EXCLUDED.cost_usd, updated_at = EXCLUDED.updated_at`,
				ws, id, c.Provider, truncate(k.KeyID, 200), truncate(k.ProjectID, 200), k.BucketStart, k.USD, now).Error; err != nil {
				return fmt.Errorf("cost: %w", err)
			}
			res.CostRows++
		}
		if err := tx.Exec(`DELETE FROM model_provider_usage_minute WHERE workspace_id = ? AND connection_id = ? AND bucket_start < ?`,
			ws, id, now.Add(-usageMinuteRetention)).Error; err != nil {
			return err
		}
		set := `usage_minute_cursor = ?`
		args := []any{res.To}
		if costRead {
			set += `, cost_cursor = ?`
			args = append(args, now)
		}
		args = append(args, ws, id)
		return tx.Exec(`UPDATE model_provider_connection SET `+set+` WHERE workspace_id = ? AND id = ?`, args...).Error
	})
	return res, err
}

/* --------------------------------- reconciliation --------------------------- */

// UsageReconcileService labels provider key-minutes and raises USAGE-02/03.
type UsageReconcileService struct {
	db  *gorm.DB
	now func() time.Time
}

// NewUsageReconcileService builds the service over db.
func NewUsageReconcileService(db *gorm.DB) *UsageReconcileService {
	return &UsageReconcileService{db: db, now: time.Now}
}

// WithClock overrides the clock (tests).
func (s *UsageReconcileService) WithClock(f func() time.Time) *UsageReconcileService {
	cp := *s
	cp.now = f
	return &cp
}

// UsageEvidenceRef points at a row behind a label.
type UsageEvidenceRef struct {
	Table string    `json:"table"`
	ID    uuid.UUID `json:"id"`
}

// UsageReconcileResult counts one workspace's run.
type UsageReconcileResult struct {
	Observed      int `json:"observed"`
	Bypass        int `json:"bypass"`
	OutsideUse    int `json:"outside_use"`
	AlertsOpened  int `json:"alerts_opened"`
	AlertsUpdated int `json:"alerts_updated"`
}

type usageKeyMinute struct {
	provider     string
	keyRef       string
	minute       time.Time
	connectionID *uuid.UUID
	gateway      int
	requests     *int64
	in, out      int64
	usageSeen    bool
	evidence     []UsageEvidenceRef
}

type estateMinute struct {
	lookups   int64
	bytes     int64
	workloads map[uuid.UUID]bool
	connector *uuid.UUID
	evidence  []UsageEvidenceRef
}

func addEvidence(list []UsageEvidenceRef, table string, ids []uuid.UUID) []UsageEvidenceRef {
	for _, id := range ids {
		if len(list) >= reconcileMaxEvidence {
			break
		}
		list = append(list, UsageEvidenceRef{Table: table, ID: id})
	}
	return list
}

// uuidArray scans a Postgres uuid[] read as text ("{a,b}").
func uuidArray(s string) []uuid.UUID {
	s = strings.Trim(s, "{}")
	if s == "" {
		return nil
	}
	var out []uuid.UUID
	for _, p := range strings.Split(s, ",") {
		if id, err := uuid.Parse(strings.Trim(p, `"`)); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// ReconcileWorkspace labels ws's key-minutes of the last six hours (up to
// five minutes ago) and raises the alerts.
func (s *UsageReconcileService) ReconcileWorkspace(ctx context.Context, ws uuid.UUID) (UsageReconcileResult, error) {
	var res UsageReconcileResult
	now := s.now().UTC()
	to := now.Add(-reconcileSettle).Truncate(time.Minute)
	from := to.Add(-reconcileLookback)
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		res = UsageReconcileResult{}
		keys := map[string]*usageKeyMinute{}
		key := func(p, k string, m time.Time) *usageKeyMinute {
			id := p + "\x1f" + k + "\x1f" + m.Format(time.RFC3339)
			km := keys[id]
			if km == nil {
				km = &usageKeyMinute{provider: p, keyRef: k, minute: m}
				keys[id] = km
			}
			return km
		}
		// 1. Provider usage per key and minute.
		var usage []struct {
			ConnectionID  uuid.UUID
			Provider      string
			ProviderKeyID string
			Minute        time.Time
			Requests      *int64
			InputTokens   int64
			OutputTokens  int64
			IDs           string
		}
		if err := tx.Raw(`SELECT connection_id, provider, provider_key_id, bucket_start AS minute,
		                         CASE WHEN count(requests) = 0 THEN NULL ELSE sum(requests) END AS requests,
		                         sum(input_tokens) AS input_tokens, sum(output_tokens) AS output_tokens,
		                         (array_agg(id))[1:5]::text AS ids
		                    FROM model_provider_usage_minute
		                   WHERE workspace_id = ? AND resolution = '1m' AND provider_key_id <> ''
		                     AND bucket_start >= ? AND bucket_start < ?
		                   GROUP BY connection_id, provider, provider_key_id, bucket_start`, ws, from, to).Scan(&usage).Error; err != nil {
			return err
		}
		for _, u := range usage {
			km := key(u.Provider, u.ProviderKeyID, u.Minute.UTC())
			conn := u.ConnectionID
			km.connectionID, km.requests, km.in, km.out = &conn, u.Requests, u.InputTokens, u.OutputTokens
			km.usageSeen = u.InputTokens > 0 || u.OutputTokens > 0 || (u.Requests != nil && *u.Requests > 0)
			km.evidence = addEvidence(km.evidence, "model_provider_usage_minute", uuidArray(u.IDs))
		}
		// 2. Gateway model calls per key and minute (and per provider).
		var gw []struct {
			Provider     string
			KeyRef       string
			ConnectionID *uuid.UUID
			Minute       time.Time
			Calls        int
			IDs          string
		}
		if err := tx.Raw(`SELECT COALESCE(pk.provider, d.resource->>'provider', '') AS provider,
		                         CASE WHEN COALESCE(pk.provider_key_id, '') <> '' THEN pk.provider_key_id
		                              WHEN d.provider_key_ref IS NOT NULL THEN 'agw:' || d.provider_key_ref::text
		                              ELSE 'agw:local' END AS key_ref,
		                         pk.connection_id, date_trunc('minute', d.decided_at) AS minute, count(*) AS calls,
		                         (array_agg(d.id))[1:5]::text AS ids
		                    FROM agent_gateway_decision d
		                    LEFT JOIN agent_gateway_provider_key pk ON pk.workspace_id = d.workspace_id AND pk.id = d.provider_key_ref
		                   WHERE d.workspace_id = ? AND d.kind = 'model' AND d.record_type = 'outcome'
		                     AND d.decided_at >= ? AND d.decided_at < ?
		                   GROUP BY 1, 2, 3, 4`, ws, from, to).Scan(&gw).Error; err != nil {
			return err
		}
		gwByProvider := map[string]int{}
		for _, g := range gw {
			if g.Provider == "" {
				continue
			}
			km := key(g.Provider, g.KeyRef, g.Minute.UTC())
			km.gateway += g.Calls
			if km.connectionID == nil {
				km.connectionID = g.ConnectionID
			}
			km.evidence = addEvidence(km.evidence, "agent_gateway_decision", uuidArray(g.IDs))
			gwByProvider[g.Provider+"\x1f"+g.Minute.UTC().Format(time.RFC3339)] += g.Calls
		}
		// 3. Estate traffic per provider and minute: lookups and flows.
		estate := map[string]*estateMinute{}
		emin := func(p string, m time.Time) *estateMinute {
			id := p + "\x1f" + m.Format(time.RFC3339)
			e := estate[id]
			if e == nil {
				e = &estateMinute{workloads: map[uuid.UUID]bool{}}
				estate[id] = e
			}
			return e
		}
		var dns []struct {
			Provider  string
			Minute    time.Time
			Queries   int64
			Holders   string
			Connector uuid.UUID
			IDs       string
		}
		if err := tx.Raw(`SELECT provider, observed_at AS minute, sum(queries) AS queries,
		                         array_agg(DISTINCT holder_workload_id) FILTER (WHERE holder_workload_id IS NOT NULL)::text AS holders,
		                         (array_agg(connector_id))[1] AS connector, (array_agg(id))[1:5]::text AS ids
		                    FROM agent_dns_lookup
		                   WHERE workspace_id = ? AND host_kind = 'provider' AND provider <> ''
		                     AND observed_at >= ? AND observed_at < ?
		                   GROUP BY provider, observed_at`, ws, from.Add(-time.Minute), to.Add(time.Minute)).Scan(&dns).Error; err != nil {
			return err
		}
		for _, d := range dns {
			e := emin(d.Provider, d.Minute.UTC())
			e.lookups += d.Queries
			for _, h := range uuidArray(d.Holders) {
				e.workloads[h] = true
			}
			c := d.Connector
			e.connector = &c
			e.evidence = addEvidence(e.evidence, "agent_dns_lookup", uuidArray(d.IDs))
		}
		var flows []struct {
			Provider  string
			Minute    time.Time
			Bytes     int64
			Holders   string
			Connector uuid.UUID
			IDs       string
		}
		if err := tx.Raw(`SELECT provider, minute, sum(bytes_out) AS bytes,
		                         array_agg(DISTINCT holder_workload_id) FILTER (WHERE holder_workload_id IS NOT NULL)::text AS holders,
		                         (array_agg(connector_id))[1] AS connector, (array_agg(id))[1:5]::text AS ids
		                    FROM agent_flow_summary
		                   WHERE workspace_id = ? AND provider <> '' AND minute >= ? AND minute < ?
		                   GROUP BY provider, minute`, ws, from.Add(-time.Minute), to.Add(time.Minute)).Scan(&flows).Error; err != nil {
			return err
		}
		for _, f := range flows {
			e := emin(f.Provider, f.Minute.UTC())
			e.bytes += f.Bytes
			for _, h := range uuidArray(f.Holders) {
				e.workloads[h] = true
			}
			c := f.Connector
			e.connector = &c
			e.evidence = addEvidence(e.evidence, "agent_flow_summary", uuidArray(f.IDs))
		}
		// estateNear merges the provider's estate traffic of minute m +-1.
		estateNear := func(p string, m time.Time) *estateMinute {
			var out *estateMinute
			for _, d := range []time.Duration{-time.Minute, 0, time.Minute} {
				e := estate[p+"\x1f"+m.Add(d).Format(time.RFC3339)]
				if e == nil {
					continue
				}
				if out == nil {
					out = &estateMinute{workloads: map[uuid.UUID]bool{}}
				}
				out.lookups += e.lookups
				out.bytes += e.bytes
				for w := range e.workloads {
					out.workloads[w] = true
				}
				if out.connector == nil {
					out.connector = e.connector
				}
				out.evidence = append(out.evidence, e.evidence...)
			}
			return out
		}

		// 4. Labels.
		type labelled struct {
			km     *usageKeyMinute
			label  string
			estate *estateMinute
		}
		var out []labelled
		explained := map[string]bool{} // provider/minute estate traffic tied to a key-minute
		for _, km := range keys {
			if km.minute.Before(from) || !km.minute.Before(to) {
				continue
			}
			switch {
			case km.gateway > 0:
				out = append(out, labelled{km: km, label: UsageObserved})
			case km.usageSeen:
				if e := estateNear(km.provider, km.minute); e != nil {
					out = append(out, labelled{km: km, label: UsageBypass, estate: e})
					explained[km.provider+"\x1f"+km.minute.Format(time.RFC3339)] = true
				} else {
					out = append(out, labelled{km: km, label: UsageOutsideUse})
				}
			}
		}
		for id, e := range estate {
			p, ms, _ := strings.Cut(id, "\x1f")
			m, _ := time.Parse(time.RFC3339, ms)
			if m.Before(from) || !m.Before(to) || explained[id] || gwByProvider[id] > 0 {
				continue
			}
			out = append(out, labelled{km: &usageKeyMinute{provider: p, keyRef: "", minute: m}, label: UsageBypass, estate: e})
		}
		sort.Slice(out, func(i, j int) bool {
			if !out[i].km.minute.Equal(out[j].km.minute) {
				return out[i].km.minute.Before(out[j].km.minute)
			}
			return out[i].km.provider+out[i].km.keyRef < out[j].km.provider+out[j].km.keyRef
		})

		settings, err := readAgentAlertSettings(tx, ws)
		if err != nil {
			return err
		}
		for _, l := range out {
			ev := append([]UsageEvidenceRef{}, l.km.evidence...)
			var workloads []uuid.UUID
			var lookups, bytes int64
			if l.estate != nil {
				ev = append(ev, l.estate.evidence...)
				for w := range l.estate.workloads {
					workloads = append(workloads, w)
				}
				sort.Slice(workloads, func(i, j int) bool { return workloads[i].String() < workloads[j].String() })
				if len(workloads) > reconcileMaxWorkloads {
					workloads = workloads[:reconcileMaxWorkloads]
				}
				lookups, bytes = l.estate.lookups, l.estate.bytes
			}
			if len(ev) > 2*reconcileMaxEvidence {
				ev = ev[:2*reconcileMaxEvidence]
			}
			if workloads == nil {
				workloads = []uuid.UUID{}
			}
			var prev []struct {
				ID    uuid.UUID
				Label string
			}
			if err := tx.Raw(`INSERT INTO model_usage_reconciliation (workspace_id, provider, key_ref, connection_id, minute, label,
			                       gateway_calls, provider_requests, input_tokens, output_tokens, dns_lookups, flow_bytes,
			                       workload_ids, evidence, updated_at)
			                   VALUES (?, ?, ?, ?, ?, ?, ?, ?::bigint, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?)
			                   ON CONFLICT (workspace_id, provider, key_ref, minute) DO UPDATE SET
			                       label = EXCLUDED.label, connection_id = COALESCE(EXCLUDED.connection_id, model_usage_reconciliation.connection_id),
			                       gateway_calls = EXCLUDED.gateway_calls, provider_requests = EXCLUDED.provider_requests,
			                       input_tokens = EXCLUDED.input_tokens, output_tokens = EXCLUDED.output_tokens,
			                       dns_lookups = EXCLUDED.dns_lookups, flow_bytes = EXCLUDED.flow_bytes,
			                       workload_ids = EXCLUDED.workload_ids, evidence = EXCLUDED.evidence, updated_at = EXCLUDED.updated_at
			                   RETURNING id, label`,
				ws, l.km.provider, truncate(l.km.keyRef, 200), l.km.connectionID, l.km.minute, l.label, l.km.gateway, l.km.requests,
				l.km.in, l.km.out, lookups, bytes, agwJSON(workloads), agwJSON(ev), now).Scan(&prev).Error; err != nil {
				return fmt.Errorf("reconciliation row: %w", err)
			}
			switch l.label {
			case UsageObserved:
				res.Observed++
				continue
			case UsageBypass:
				res.Bypass++
			case UsageOutsideUse:
				res.OutsideUse++
			}
			if len(prev) != 1 {
				continue
			}
			opened, alertID, err := raiseUsageAlert(tx, ws, l.km, l.label, workloads, l.estate, settings, now)
			if err != nil {
				return err
			}
			if alertID != uuid.Nil {
				if opened {
					res.AlertsOpened++
				} else {
					res.AlertsUpdated++
				}
				if err := tx.Exec(`UPDATE model_usage_reconciliation SET alert_id = ? WHERE workspace_id = ? AND id = ?`,
					alertID, ws, prev[0].ID).Error; err != nil {
					return err
				}
			}
		}
		return tx.Exec(`DELETE FROM model_usage_reconciliation WHERE workspace_id = ? AND minute < ?`,
			ws, now.Add(-usageMinuteRetention)).Error
	})
	return res, err
}

// raiseUsageAlert opens (or keeps fresh) the USAGE-02 / USAGE-03 alert of a
// key (outside use) or a workload / provider (bypass). One open alert per
// dedupe key (uq_agent_alert_usage_open); a detection switched off in the
// workspace's rules raises nothing.
func raiseUsageAlert(tx *gorm.DB, ws uuid.UUID, km *usageKeyMinute, label string, workloads []uuid.UUID,
	e *estateMinute, st AgentAlertSettings, now time.Time) (bool, uuid.UUID, error) {
	det := detect.USAGE02
	if label == UsageBypass {
		det = detect.USAGE03
	}
	if d, ok := st.Detections[string(det)]; ok && !d.Enabled {
		return false, uuid.Nil, nil
	}
	severity := detect.SeverityHigh
	subjectLabel, subjectName := usageAlertLabel, km.provider+" key "+km.keyRef
	var connector, identity uuid.UUID
	var dedupe, title, detail string
	if det == detect.USAGE02 {
		if km.connectionID != nil {
			connector = *km.connectionID
		}
		var ids []uuid.UUID
		if err := tx.Raw(`SELECT id FROM model_provider_key WHERE workspace_id = ? AND connection_id = ? AND provider_key_id = ? LIMIT 1`,
			ws, connector, km.keyRef).Scan(&ids).Error; err != nil {
			return false, uuid.Nil, err
		}
		identity = uuid.NewSHA1(ws, []byte("provider_key:"+km.provider+":"+km.keyRef))
		if len(ids) == 1 {
			identity = ids[0]
		}
		dedupe = string(det) + "/" + km.provider + "/" + km.keyRef
		title = "Provider key used outside AuthSec's view: " + subjectName
		detail = "provider usage with no gateway call and no estate lookup or flow in the minute"
	} else {
		severity = detect.SeverityMedium
		if e != nil && e.connector != nil {
			connector = *e.connector
		}
		identity = uuid.NewSHA1(ws, []byte("provider:"+km.provider))
		dedupe = string(det) + "/" + km.provider
		subjectLabel, subjectName = "ai_workload", "traffic to "+km.provider
		if len(workloads) == 1 {
			identity = workloads[0]
			dedupe += "/" + workloads[0].String()
			subjectName = "workload " + workloads[0].String() + " to " + km.provider
		}
		title = "Model provider reached around the gateway: " + subjectName
		detail = "estate lookup or flow to the provider with no gateway call in the minute"
		if km.keyRef != "" {
			detail += " (key " + km.keyRef + " used)"
		}
	}
	if d, ok := st.Detections[string(det)]; ok && d.Severity != "" {
		severity = d.Severity
	}
	if connector == uuid.Nil {
		connector = identity
	}
	ref := AgentAlertEventRef{EventID: "usage:" + km.provider + ":" + km.keyRef + ":" + km.minute.Format(time.RFC3339),
		Time: km.minute, Source: "usage_reconciliation", Name: label, Detail: truncate(detail, 300)}
	evRaw, err := json.Marshal(ref)
	if err != nil {
		return false, uuid.Nil, err
	}
	var upd []uuid.UUID
	if err := tx.Raw(`UPDATE agent_alert SET last_seen = GREATEST(last_seen, ?),
	                        event_count = event_count + CASE WHEN ? > last_seen THEN 1 ELSE 0 END,
	                        evidence = CASE WHEN ? > last_seen AND jsonb_array_length(evidence) < 50
	                                        THEN evidence || jsonb_build_array(?::jsonb) ELSE evidence END
	                   WHERE workspace_id = ? AND dedupe_key = ? AND detection = ? AND state <> 'resolved'
	                   RETURNING id`, km.minute, km.minute, km.minute, string(evRaw), ws, dedupe, string(det)).Scan(&upd).Error; err != nil {
		return false, uuid.Nil, err
	}
	if len(upd) > 0 {
		return false, upd[0], nil
	}
	evs, _ := json.Marshal([]AgentAlertEventRef{ref})
	wl, _ := json.Marshal(workloads)
	var ids []uuid.UUID
	if err := tx.Raw(`INSERT INTO agent_alert (workspace_id, connector_id, identity_id, workload_ids, subject_label, subject_name,
	                         detection, severity, title, dedupe_key, first_seen, last_seen, event_count, evidence, state, created_at)
	                  VALUES (?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?::jsonb, 'open', ?)
	                  ON CONFLICT (workspace_id, dedupe_key) WHERE detection IN ('USAGE-02', 'USAGE-03') AND state <> 'resolved' DO NOTHING
	                  RETURNING id`,
		ws, connector, identity, string(wl), subjectLabel, truncate(subjectName, 300), string(det), severity,
		truncate(title, 300), dedupe, km.minute, km.minute, string(evs), now).Scan(&ids).Error; err != nil {
		return false, uuid.Nil, err
	}
	if len(ids) != 1 {
		return false, uuid.Nil, nil
	}
	if err := appendGovEvent(tx, ws, GovEventAgentAlertOpened, models.GovActorSystem, "usage_reconciliation", govEventRefs{},
		map[string]any{"alert_id": ids[0], "detection": string(det), "severity": severity, "provider": km.provider,
			"key_ref": km.keyRef, "minute": km.minute}); err != nil {
		return false, uuid.Nil, err
	}
	return true, ids[0], enqueueAgentAlertDeliveries(tx, ws, ids[0], st)
}

// UsageReconciliationRow is one label as the console shows it.
type UsageReconciliationRow struct {
	ID               uuid.UUID       `json:"id" gorm:"column:id"`
	Provider         string          `json:"provider" gorm:"column:provider"`
	KeyRef           string          `json:"key_ref" gorm:"column:key_ref"`
	ConnectionID     *uuid.UUID      `json:"connection_id" gorm:"column:connection_id"`
	Minute           time.Time       `json:"minute" gorm:"column:minute"`
	Label            string          `json:"label" gorm:"column:label"`
	GatewayCalls     int             `json:"gateway_calls" gorm:"column:gateway_calls"`
	ProviderRequests *int64          `json:"provider_requests" gorm:"column:provider_requests"`
	InputTokens      int64           `json:"input_tokens" gorm:"column:input_tokens"`
	OutputTokens     int64           `json:"output_tokens" gorm:"column:output_tokens"`
	DNSLookups       int64           `json:"dns_lookups" gorm:"column:dns_lookups"`
	FlowBytes        int64           `json:"flow_bytes" gorm:"column:flow_bytes"`
	WorkloadIDs      json.RawMessage `json:"workload_ids" gorm:"column:workload_ids"`
	Evidence         json.RawMessage `json:"evidence" gorm:"column:evidence"`
	AlertID          *uuid.UUID      `json:"alert_id" gorm:"column:alert_id"`
}

// List reads ws's labels, newest first (label filter optional).
func (s *UsageReconcileService) List(ctx context.Context, ws uuid.UUID, label string, from, to *time.Time) ([]UsageReconciliationRow, error) {
	switch label {
	case "", UsageObserved, UsageBypass, UsageOutsideUse:
	default:
		return nil, GovBadParam("label", "label must be observed, bypass or outside_use.")
	}
	q := `SELECT id, provider, key_ref, connection_id, minute, label, gateway_calls, provider_requests, input_tokens, output_tokens,
	             dns_lookups, flow_bytes, workload_ids::text AS workload_ids, evidence::text AS evidence, alert_id
	        FROM model_usage_reconciliation WHERE workspace_id = ?`
	args := []any{ws}
	if label != "" {
		q, args = q+` AND label = ?`, append(args, label)
	}
	if from != nil {
		q, args = q+` AND minute >= ?`, append(args, *from)
	}
	if to != nil {
		q, args = q+` AND minute < ?`, append(args, *to)
	}
	out := []UsageReconciliationRow{}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(q+` ORDER BY minute DESC, provider, key_ref LIMIT 1000`, args...).Scan(&out).Error
	})
	return out, err
}

/* ------------------------------------ worker -------------------------------- */

// RunUsageReconcileWorker reads per-minute usage and reconciles every 5
// minutes until ctx ends. AUTHSEC_DISABLE_USAGE_RECONCILE=true turns it off.
func RunUsageReconcileWorker(ctx context.Context, db *gorm.DB) {
	if os.Getenv("AUTHSEC_DISABLE_USAGE_RECONCILE") == "true" {
		log.Printf("[usage-reconcile] worker not started: AUTHSEC_DISABLE_USAGE_RECONCILE=true")
		return
	}
	for {
		if err := RunUsageReconcileOnce(ctx, db); err != nil && ctx.Err() == nil {
			log.Printf("[usage-reconcile] %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(reconcileEvery):
		}
	}
}

// RunUsageReconcileOnce is one pass over the workspaces with something to
// reconcile, each in its own workspace transactions.
func RunUsageReconcileOnce(ctx context.Context, db *gorm.DB) error {
	var rows []struct {
		WorkspaceID  uuid.UUID
		ConnectionID *uuid.UUID
	}
	since := time.Now().UTC().Add(-reconcileLookback)
	// TENANT-EXEMPT: the usage reconciliation worker runs across workspaces (no request tenant) and lists workspace and connection ids only; each workspace is synced and reconciled in its own workspace_id-bound transactions (tenancy.InWorkspace).
	if err := db.WithContext(ctx).Raw(`SELECT workspace_id, id AS connection_id FROM model_provider_connection WHERE status <> 'revoked'
	                                    UNION SELECT DISTINCT workspace_id, NULL::uuid FROM agent_gateway_decision WHERE decided_at >= ? AND kind = 'model'
	                                    UNION SELECT DISTINCT workspace_id, NULL::uuid FROM agent_dns_lookup WHERE observed_at >= ? AND host_kind = 'provider'
	                                    LIMIT 5000`, since, since).Scan(&rows).Error; err != nil {
		return err
	}
	mp := NewModelProviderService(db)
	rec := NewUsageReconcileService(db)
	seen := map[uuid.UUID]bool{}
	var first error
	for _, r := range rows {
		if r.ConnectionID != nil {
			if _, err := mp.SyncUsageMinutes(ctx, r.WorkspaceID, *r.ConnectionID); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("[usage-reconcile] workspace %s connection %s: per-minute usage: %s", r.WorkspaceID, *r.ConnectionID,
					modelprovider.Scrub(err.Error()))
			}
		}
		seen[r.WorkspaceID] = true
	}
	for ws := range seen {
		if _, err := rec.ReconcileWorkspace(ctx, ws); err != nil {
			log.Printf("[usage-reconcile] workspace %s: %v", ws, err)
			if first == nil {
				first = err
			}
		}
	}
	return first
}
