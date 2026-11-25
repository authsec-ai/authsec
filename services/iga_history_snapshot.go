package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// Daily history snapshots (SPEC-secops-backend-upgrade.md P9 / W9;
// migration 200).
//
// Once a day (UTC) per workspace the job reads the inventory, access-policy
// text and versions, reach per identity, metric values and definitions and
// alert rule settings, each object under a stable id with its canonical
// (RFC 8785) body. A row is written only when the body's sha256 differs from
// the previous row of that stable id; an object no longer present gets an
// "absent" row. Every day is still recorded (iga_snapshot_day: counts, the
// content hash of the rows written, and the workspace's day chain), so an
// as-of read for any day answers with the latest row at or before it.
//
// Chains: each row's chain_hash covers the previous row of its stable id;
// each day's chain_hash covers the previous day and the day's content hash,
// and is the daily anchor (also logged to audit_events). Redaction replaces
// a body with a tombstone but never the hash, so both chains still verify.
//
// Every statement runs in a transaction under row-level security for one
// workspace (tenancy.InWorkspace / InWorkspaceRead); only the list of
// workspace ids the job visits is read outside one.

// Snapshot kinds.
const (
	SnapshotKindInventory        = "inventory"
	SnapshotKindPolicyText       = "policy_text"
	SnapshotKindReach            = "reach"
	SnapshotKindMetricValue      = "metric_value"
	SnapshotKindMetricDefinition = "metric_definition"
	SnapshotKindRuleVersion      = "rule_version"
)

// SnapshotKinds lists every kind.
var SnapshotKinds = []string{SnapshotKindInventory, SnapshotKindPolicyText, SnapshotKindReach,
	SnapshotKindMetricValue, SnapshotKindMetricDefinition, SnapshotKindRuleVersion}

func validSnapshotKind(k string) bool {
	for _, x := range SnapshotKinds {
		if x == k {
			return true
		}
	}
	return false
}

// snapshotSourceCap bounds the objects one source contributes per day; a
// source that reaches it is marked truncated and writes no absent rows.
const snapshotSourceCap = 25000

// DefaultSnapshotRetentionDays applies without an iga_snapshot_setting row.
const DefaultSnapshotRetentionDays = 400

// socSnapshotPeriod is the SOC window stored daily (metric id + "@30d").
const socSnapshotPeriod = "30d"

// HistorySnapshot is one iga_snapshot row.
type HistorySnapshot struct {
	ID              uuid.UUID       `json:"id"`
	SnapshotDate    time.Time       `json:"-"`
	Date            string          `json:"snapshot_date" gorm:"-"`
	Kind            string          `json:"kind"`
	StableID        string          `json:"stable_id"`
	Hash            string          `json:"hash"`
	Body            json.RawMessage `json:"body"`
	Absent          bool            `json:"absent"`
	LegalHold       bool            `json:"legal_hold"`
	Redacted        bool            `json:"redacted"`
	RedactedAt      *time.Time      `json:"redacted_at,omitempty"`
	RedactionReason string          `json:"redaction_reason,omitempty"`
	PrevChainHash   string          `json:"prev_chain_hash"`
	ChainHash       string          `json:"chain_hash"`
	CreatedAt       time.Time       `json:"created_at"`
}

const historySnapshotColumns = `id, snapshot_date, kind, stable_id, hash, body, absent, legal_hold, redacted, redacted_at,
	redaction_reason, prev_chain_hash, chain_hash, created_at`

func (h *HistorySnapshot) fill() { h.Date = h.SnapshotDate.Format("2006-01-02") }

// SnapshotDay is one iga_snapshot_day row.
type SnapshotDay struct {
	SnapshotDate  time.Time       `json:"-"`
	Date          string          `json:"snapshot_date" gorm:"-"`
	Kinds         json.RawMessage `json:"kinds"`
	RowsWritten   int             `json:"rows_written"`
	ContentHash   string          `json:"content_hash"`
	PrevChainHash string          `json:"prev_chain_hash"`
	ChainHash     string          `json:"chain_hash"`
	Purged        bool            `json:"purged"`
	CreatedAt     time.Time       `json:"created_at"`
}

func dateOnly(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func historySHA(parts ...string) string {
	h := sha256.New()
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte{0x1f})
		}
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// snapshotRowChain is a row's chain_hash.
func snapshotRowChain(ws uuid.UUID, prev string, day time.Time, kind, stableID, hash string) string {
	return historySHA("iga_snapshot", ws.String(), prev, day.Format("2006-01-02"), kind, stableID, hash)
}

// snapshotContentHash is the content hash of the rows written on one day:
// sha256 over the sorted "kind US stable_id US hash" lines.
func snapshotContentHash(rows [][3]string) string {
	lines := make([]string, len(rows))
	for i, r := range rows {
		lines[i] = r[0] + "\x1f" + r[1] + "\x1f" + r[2]
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// snapshotDayChain is a day's chain_hash.
func snapshotDayChain(ws uuid.UUID, prev string, day time.Time, content string, rows int, kindsCanonical string) string {
	return historySHA("iga_snapshot_day", ws.String(), prev, day.Format("2006-01-02"), content, strconv.Itoa(rows), kindsCanonical)
}

// canonicalBody returns the canonical bytes of a JSON text and their hash.
func canonicalBody(raw []byte) ([]byte, string, error) {
	c, err := igagov.Canonicalize(raw)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(c)
	return c, hex.EncodeToString(sum[:]), nil
}

var absentBody = []byte(`{"absent":true}`)

/* -------------------------------- collection -------------------------------- */

type snapItem struct {
	kind, stableID string
	body           []byte
	hash           string
	absent         bool
}

type snapSource struct {
	kind  string
	name  string
	table string
	cols  []string
	sql   string // args: workspace, limit
}

// snapshotSources are the SQL sources. Bodies leave out what changes without
// the object changing (last seen times, provider attributes).
func snapshotSources() []snapSource {
	return []snapSource{
		{SnapshotKindInventory, "iga_workload", "iga_workload", []string{"classification"}, `SELECT 'iga_workload:' || id::text AS stable_id,
		    jsonb_build_object('type', 'iga_workload', 'id', id, 'provider', provider, 'runtime_kind', runtime_kind,
		      'display_name', display_name, 'region', region, 'stage', stage, 'lifecycle', lifecycle,
		      'classification', classification, 'execution_role_arn', execution_role_arn, 'source_key', source_key)::text AS body
		  FROM iga_workload WHERE workspace_id = ? ORDER BY id LIMIT ?`},
		{SnapshotKindInventory, "iga_identity_accounts", "iga_identity_accounts", []string{"source_key"}, `SELECT 'iga_identity_account:' || id::text,
		    jsonb_build_object('type', 'iga_identity_account', 'id', id, 'provider', provider, 'account_kind', account_kind,
		      'display_name', display_name, 'lifecycle', lifecycle, 'identity_backing', identity_backing, 'source_key', source_key)::text
		  FROM iga_identity_accounts WHERE workspace_id = ? ORDER BY id LIMIT ?`},
		{SnapshotKindInventory, "iga_resources", "iga_resources", []string{"source_key"}, `SELECT 'iga_resource:' || id::text,
		    jsonb_build_object('type', 'iga_resource', 'id', id, 'provider', provider, 'resource_kind', resource_kind,
		      'display_name', display_name, 'stage', stage, 'lifecycle', lifecycle, 'source_key', source_key)::text
		  FROM iga_resources WHERE workspace_id = ? ORDER BY id LIMIT ?`},
		{SnapshotKindInventory, "iga_agents", "iga_agents", []string{"rollup_state"}, `SELECT 'iga_agent:' || id::text,
		    jsonb_build_object('type', 'iga_agent', 'id', id, 'display_name', display_name, 'classification', classification,
		      'status', status, 'lifecycle', lifecycle, 'rollup_state', rollup_state)::text
		  FROM iga_agents WHERE workspace_id = ? ORDER BY id LIMIT ?`},
		{SnapshotKindInventory, "cloud_identity", "cloud_identity", []string{"native_id"}, `SELECT 'cloud_identity:' || id::text,
		    jsonb_build_object('type', 'cloud_identity', 'id', id, 'connector_id', connector_id, 'kind', kind,
		      'native_id', native_id, 'name', name, 'enabled', enabled)::text
		  FROM cloud_identity WHERE workspace_id = ? ORDER BY id LIMIT ?`},
		{SnapshotKindInventory, "cloud_workload", "cloud_workload", []string{"native_id"}, `SELECT 'cloud_workload:' || id::text,
		    jsonb_build_object('type', 'cloud_workload', 'id', id, 'connector_id', connector_id, 'identity_id', identity_id,
		      'runtime_kind', runtime_kind, 'native_id', native_id, 'name', name, 'region', region)::text
		  FROM cloud_workload WHERE workspace_id = ? ORDER BY id LIMIT ?`},
		// W7's agent table, once merged.
		{SnapshotKindInventory, "agent", "agent", []string{"id", "workspace_id"}, `SELECT 'agent:' || a.id::text,
		    (to_jsonb(a) - 'updated_at' - 'last_seen_at' - 'last_seen' - 'version')::text
		  FROM agent a WHERE a.workspace_id = ? ORDER BY a.id LIMIT ?`},
		{SnapshotKindPolicyText, "iga_gov_policy", "iga_gov_policy", []string{"current_version_id"}, `SELECT 'iga_gov_policy:' || p.id::text,
		    jsonb_build_object('id', p.id, 'name', p.name, 'purpose', p.purpose, 'family', p.family, 'provider', p.provider,
		      'lifecycle', p.lifecycle, 'current_version_id', p.current_version_id, 'deleted_at', to_jsonb(p) -> 'deleted_at',
		      'versions', COALESCE((SELECT jsonb_agg(jsonb_build_object('version_no', v.version_no, 'status', v.status,
		            'intent', v.intent, 'intent_hash', v.intent_hash, 'created_by', v.created_by, 'created_at', v.created_at)
		            ORDER BY v.version_no)
		          FROM iga_gov_policy_version v WHERE v.workspace_id = p.workspace_id AND v.policy_id = p.id), '[]'::jsonb),
		      'access_versions', COALESCE((SELECT jsonb_agg(to_jsonb(av) - 'workspace_id' ORDER BY av.version_no)
		          FROM iga_gov_access_policy_version av WHERE av.workspace_id = p.workspace_id AND av.policy_id = p.id), '[]'::jsonb))::text
		  FROM iga_gov_policy p WHERE p.workspace_id = ? ORDER BY p.id LIMIT ?`},
		{SnapshotKindReach, "identity_reach", "iga_access_edges", []string{"subject_identity_account_id", "state"}, `SELECT 'identity:' || x.id::text,
		    jsonb_build_object('identity_id', x.id, 'grants', x.grants, 'resources', x.resources,
		      'resource_ids', to_jsonb(x.ids[1:500]), 'truncated', x.resources > 500)::text
		  FROM (SELECT g.subject_identity_account_id AS id, count(DISTINCT g.id) AS grants,
		               count(DISTINCT t.resource_id) AS resources,
		               array_agg(DISTINCT t.resource_id ORDER BY t.resource_id) FILTER (WHERE t.resource_id IS NOT NULL) AS ids
		          FROM iga_access_edges g
		          JOIN iga_entitlements e ON e.workspace_id = g.workspace_id AND e.id = g.entitlement_id
		          LEFT JOIN iga_entitlement_target t ON t.workspace_id = e.workspace_id AND t.entitlement_id = e.id AND t.target_mode = 'resource'
		         WHERE g.workspace_id = ? AND g.state = 'current' AND g.subject_identity_account_id IS NOT NULL AND e.effect = 'allow'
		         GROUP BY g.subject_identity_account_id ORDER BY g.subject_identity_account_id LIMIT ?) x`},
		{SnapshotKindRuleVersion, "agent_alert_setting", "agent_alert_setting", []string{"detections"}, `SELECT 'agent_alert_setting',
		    jsonb_build_object('detections', detections, 'slack_enabled', slack_enabled, 'dedupe_window_minutes', dedupe_window_minutes,
		      'retention_days', retention_days, 'updated_by', updated_by, 'updated_at', updated_at)::text
		  FROM agent_alert_setting WHERE workspace_id = ? LIMIT ?`},
		// F6's versioned detection rules, once merged.
		{SnapshotKindRuleVersion, "agent_detection_rule_version", "agent_detection_rule_version", []string{"id", "workspace_id"}, `SELECT 'agent_detection_rule_version:' || r.id::text,
		    (to_jsonb(r) - 'workspace_id')::text
		  FROM agent_detection_rule_version r WHERE r.workspace_id = ? ORDER BY r.id LIMIT ?`},
	}
}

// collectSnapshot reads every source and the metrics; truncated names the
// kinds where a source hit its cap.
func collectSnapshot(tx *gorm.DB, ws uuid.UUID, now time.Time) ([]snapItem, map[string]bool, error) {
	probe := newSchemaProbe(tx)
	var items []snapItem
	truncated := map[string]bool{}
	for _, src := range snapshotSources() {
		if !probe.Has(src.table, src.cols...) {
			continue
		}
		var rows []struct {
			StableID string
			Body     string
		}
		if err := tx.Raw(`SELECT stable_id, body FROM (`+src.sql+`) AS q(stable_id, body)`, ws, snapshotSourceCap).Scan(&rows).Error; err != nil {
			return nil, nil, fmt.Errorf("snapshot source %s: %w", src.name, err)
		}
		if len(rows) >= snapshotSourceCap {
			truncated[src.kind] = true
		}
		for _, r := range rows {
			c, h, err := canonicalBody([]byte(r.Body))
			if err != nil {
				return nil, nil, fmt.Errorf("snapshot source %s: %w", src.name, err)
			}
			items = append(items, snapItem{kind: src.kind, stableID: r.StableID, body: c, hash: h})
		}
	}
	if probe.err != nil {
		return nil, nil, probe.err
	}
	metrics, err := snapshotMetrics(tx, ws, now)
	if err != nil {
		return nil, nil, err
	}
	for _, m := range metrics {
		items = append(items, m)
	}
	return items, truncated, nil
}

// snapshotMetrics is the metric values (posture now, SOC over the trailing
// 30 days) and their definitions, without the fields that change every day.
func snapshotMetrics(tx *gorm.DB, ws uuid.UUID, now time.Time) ([]snapItem, error) {
	posture, err := postureLive(tx, ws, now)
	if err != nil {
		return nil, err
	}
	probe := newSchemaProbe(tx)
	v := probeSOC(probe)
	cov, err := streamCoverage(tx, ws, probe, now)
	if err != nil {
		return nil, err
	}
	d, _ := parsePeriod(socSnapshotPeriod)
	w := periodWindow(now, d)
	var all []MetricResult
	for _, id := range PostureMetricIDs {
		all = append(all, posture[id])
	}
	for _, id := range SOCMetricIDs {
		m, err := socMetric(tx, ws, v, id, w, now, cov)
		if err != nil {
			return nil, err
		}
		m.ID = id + "@" + socSnapshotPeriod
		all = append(all, m)
	}
	var out []snapItem
	defs := map[string]MetricDefinition{}
	for _, m := range all {
		m.AsOf, m.Window, m.Source, m.SnapshotDate, m.Previous = nil, nil, "", "", nil
		c, err := igagov.CanonicalizeValue(m)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(c)
		out = append(out, snapItem{kind: SnapshotKindMetricValue, stableID: m.ID, body: c, hash: hex.EncodeToString(sum[:])})
		defs[m.Definition.ID] = m.Definition
	}
	for id, def := range defs {
		if id == "" {
			continue
		}
		c, err := igagov.CanonicalizeValue(def)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(c)
		out = append(out, snapItem{kind: SnapshotKindMetricDefinition, stableID: id, body: c, hash: hex.EncodeToString(sum[:])})
	}
	return out, nil
}

// metricFromSnapshotBody decodes a metric_value body.
func metricFromSnapshotBody(body []byte) (MetricResult, error) {
	var m MetricResult
	if err := json.Unmarshal(body, &m); err != nil {
		return m, fmt.Errorf("decode metric snapshot: %w", err)
	}
	return m, nil
}

/* ---------------------------------- writing --------------------------------- */

// SnapshotDayResult reports one day's snapshot.
type SnapshotDayResult struct {
	Date        string `json:"snapshot_date"`
	Skipped     bool   `json:"skipped"`
	RowsWritten int    `json:"rows_written"`
	Objects     int    `json:"objects"`
	ChainHash   string `json:"chain_hash"`
}

type snapKindCount struct {
	Objects   int  `json:"objects"`
	Written   int  `json:"written"`
	Absent    int  `json:"absent"`
	Truncated bool `json:"truncated"`
}

// TakeDaily writes today's (UTC) snapshot of ws, unless it exists.
func (s *HistoryService) TakeDaily(ctx context.Context, ws uuid.UUID) (*SnapshotDayResult, error) {
	now := s.now().UTC()
	day := dateOnly(now)
	res := &SnapshotDayResult{Date: day.Format("2006-01-02")}
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		// One writer per workspace and day.
		if err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext('iga_snapshot:' || ?::text))`, ws.String()).Error; err != nil {
			return err
		}
		var exists int64
		if err := tx.Raw(`SELECT count(*) FROM iga_snapshot_day WHERE workspace_id = ? AND snapshot_date = ?`, ws, day).Scan(&exists).Error; err != nil {
			return err
		}
		if exists > 0 {
			res.Skipped = true
			return nil
		}
		items, truncated, err := collectSnapshot(tx, ws, now)
		if err != nil {
			return err
		}
		var latest []struct {
			Kind, StableID, Hash, ChainHash string
			Absent                          bool
		}
		if err := tx.Raw(`SELECT DISTINCT ON (kind, stable_id) kind, stable_id, hash, chain_hash, absent
		                    FROM iga_snapshot WHERE workspace_id = ? AND snapshot_date < ?
		                   ORDER BY kind, stable_id, snapshot_date DESC`, ws, day).Scan(&latest).Error; err != nil {
			return err
		}
		type prevRow struct {
			hash, chain string
			absent      bool
		}
		prev := make(map[string]prevRow, len(latest))
		for _, l := range latest {
			prev[l.Kind+"\x00"+l.StableID] = prevRow{l.Hash, l.ChainHash, l.Absent}
		}
		counts := map[string]*snapKindCount{}
		for _, k := range SnapshotKinds {
			counts[k] = &snapKindCount{Truncated: truncated[k]}
		}
		seen := make(map[string]bool, len(items))
		var write []snapItem
		for _, it := range items {
			key := it.kind + "\x00" + it.stableID
			if seen[key] {
				continue
			}
			seen[key] = true
			counts[it.kind].Objects++
			if p, ok := prev[key]; ok && !p.absent && p.hash == it.hash {
				continue
			}
			write = append(write, it)
		}
		// Objects gone since their last row: an absent row, unless their
		// kind was truncated today (absence is then unknown).
		_, absentHash, _ := canonicalBody(absentBody)
		for _, l := range latest {
			key := l.Kind + "\x00" + l.StableID
			if seen[key] || l.Absent || truncated[l.Kind] {
				continue
			}
			write = append(write, snapItem{kind: l.Kind, stableID: l.StableID, body: absentBody, hash: absentHash, absent: true})
			counts[l.Kind].Absent++
		}
		sort.Slice(write, func(i, j int) bool {
			if write[i].kind != write[j].kind {
				return write[i].kind < write[j].kind
			}
			return write[i].stableID < write[j].stableID
		})
		held, err := liveHoldKinds(tx, ws, day)
		if err != nil {
			return err
		}
		content := make([][3]string, 0, len(write))
		const batch = 400
		for i := 0; i < len(write); i += batch {
			end := i + batch
			if end > len(write) {
				end = len(write)
			}
			var sb strings.Builder
			args := make([]any, 0, (end-i)*10)
			sb.WriteString(`INSERT INTO iga_snapshot (workspace_id, snapshot_date, kind, stable_id, hash, body, absent, legal_hold, prev_chain_hash, chain_hash) VALUES `)
			for j, it := range write[i:end] {
				if j > 0 {
					sb.WriteString(", ")
				}
				sb.WriteString("(?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?)")
				p := prev[it.kind+"\x00"+it.stableID]
				chain := snapshotRowChain(ws, p.chain, day, it.kind, it.stableID, it.hash)
				args = append(args, ws, day, it.kind, it.stableID, it.hash, string(it.body), it.absent, held[it.kind], p.chain, chain)
				counts[it.kind].Written++
				content = append(content, [3]string{it.kind, it.stableID, it.hash})
			}
			if err := tx.Exec(sb.String(), args...).Error; err != nil {
				return err
			}
		}
		kindsRaw, err := json.Marshal(counts)
		if err != nil {
			return err
		}
		kindsCanon, _, err := canonicalBody(kindsRaw)
		if err != nil {
			return err
		}
		var prevDay []string
		if err := tx.Raw(`SELECT chain_hash FROM iga_snapshot_day WHERE workspace_id = ? AND snapshot_date < ?
		                   ORDER BY snapshot_date DESC LIMIT 1`, ws, day).Scan(&prevDay).Error; err != nil {
			return err
		}
		prevChain := ""
		if len(prevDay) > 0 {
			prevChain = prevDay[0]
		}
		contentHash := snapshotContentHash(content)
		chain := snapshotDayChain(ws, prevChain, day, contentHash, len(write), string(kindsCanon))
		if err := tx.Exec(`INSERT INTO iga_snapshot_day (workspace_id, snapshot_date, kinds, rows_written, content_hash, prev_chain_hash, chain_hash)
		                   VALUES (?, ?, ?::jsonb, ?, ?, ?, ?)`, ws, day, string(kindsCanon), len(write), contentHash, prevChain, chain).Error; err != nil {
			return err
		}
		if err := refreshHoldFlags(tx, ws); err != nil {
			return err
		}
		res.RowsWritten, res.Objects, res.ChainHash = len(write), len(seen), chain
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !res.Skipped && config.AuditLogger != nil {
		// The daily anchor, outside the snapshot tables.
		config.AuditLogger.LogAdminAction("", ws.String(), "system", "history.day_anchored", "iga_snapshot_day", res.Date,
			"", "", "", "authsec-snapshot-job", 200, 0, nil,
			map[string]any{"chain_hash": res.ChainHash, "rows_written": res.RowsWritten, "objects": res.Objects}, "")
	}
	return res, nil
}

// liveHoldKinds is the kinds a live hold covers on day.
func liveHoldKinds(tx *gorm.DB, ws uuid.UUID, day time.Time) (map[string]bool, error) {
	var kinds []string
	if err := tx.Raw(`SELECT DISTINCT unnest(kinds) FROM iga_snapshot_hold
	                   WHERE workspace_id = ? AND released_at IS NULL AND from_date <= ? AND to_date >= ?`, ws, day, day).
		Scan(&kinds).Error; err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, k := range kinds {
		out[k] = true
	}
	return out, nil
}

// refreshHoldFlags sets legal_hold on every row whose effective period (its
// day until the next row of its stable id) meets a live hold of its kind,
// and clears it elsewhere.
func refreshHoldFlags(tx *gorm.DB, ws uuid.UUID) error {
	return tx.Exec(`WITH eff AS (
	        SELECT s.id, s.kind, s.snapshot_date AS d,
	               lead(s.snapshot_date) OVER (PARTITION BY s.kind, s.stable_id ORDER BY s.snapshot_date) AS nd
	          FROM iga_snapshot s WHERE s.workspace_id = ?),
	    want AS (
	        SELECT e.id, EXISTS (SELECT 1 FROM iga_snapshot_hold h
	                              WHERE h.workspace_id = ? AND h.released_at IS NULL AND e.kind = ANY (h.kinds)
	                                AND e.d <= h.to_date AND (e.nd IS NULL OR e.nd > h.from_date)) AS held
	          FROM eff e)
	    UPDATE iga_snapshot s SET legal_hold = w.held
	      FROM want w
	     WHERE s.workspace_id = ? AND s.id = w.id AND s.legal_hold IS DISTINCT FROM w.held`, ws, ws, ws).Error
}

/* --------------------------------- retention -------------------------------- */

// PurgeResult reports one retention pass.
type PurgeResult struct {
	Deleted        int64  `json:"deleted"`
	Cutoff         string `json:"cutoff"`
	ExportsExpired int64  `json:"exports_expired"`
}

// Purge applies snapshot retention in ws: a row older than the workspace's
// retention is deleted only when a newer row of its stable id is also older
// than the cutoff (so every as-of read after the cutoff still answers), and
// never while it is under a legal hold. Expired export bytes and pending
// requests are closed in the same pass.
func (s *HistoryService) Purge(ctx context.Context, ws uuid.UUID) (*PurgeResult, error) {
	now := s.now().UTC()
	out := &PurgeResult{}
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		days := DefaultSnapshotRetentionDays
		var set []int
		if err := tx.Raw(`SELECT retention_days FROM iga_snapshot_setting WHERE workspace_id = ?`, ws).Scan(&set).Error; err != nil {
			return err
		}
		if len(set) > 0 {
			days = set[0]
		}
		cutoff := dateOnly(now).AddDate(0, 0, -days)
		out.Cutoff = cutoff.Format("2006-01-02")
		if err := refreshHoldFlags(tx, ws); err != nil {
			return err
		}
		if err := tx.Exec(`SELECT set_config('authsec.snapshot_purge', 'on', true)`).Error; err != nil {
			return err
		}
		var goneDates []time.Time
		if err := tx.Raw(`WITH gone AS (
		        DELETE FROM iga_snapshot s
		         WHERE s.workspace_id = ? AND s.snapshot_date < ? AND NOT s.legal_hold
		           AND EXISTS (SELECT 1 FROM iga_snapshot n
		                        WHERE n.workspace_id = s.workspace_id AND n.kind = s.kind AND n.stable_id = s.stable_id
		                          AND n.snapshot_date > s.snapshot_date AND n.snapshot_date <= ?)
		        RETURNING s.snapshot_date)
		    SELECT snapshot_date FROM gone`, ws, cutoff, cutoff).Scan(&goneDates).Error; err != nil {
			return err
		}
		if err := tx.Exec(`SELECT set_config('authsec.snapshot_purge', 'off', true)`).Error; err != nil {
			return err
		}
		var purgedDays []time.Time
		dayseen := map[time.Time]bool{}
		for _, d := range goneDates {
			if !dayseen[d] {
				dayseen[d] = true
				purgedDays = append(purgedDays, d)
			}
		}
		if len(purgedDays) > 0 {
			if err := tx.Exec(`UPDATE iga_snapshot_day SET purged = true WHERE workspace_id = ? AND snapshot_date IN ? AND NOT purged`,
				ws, purgedDays).Error; err != nil {
				return err
			}
		}
		out.Deleted = int64(len(goneDates))
		r := tx.Exec(`UPDATE iga_export SET content = NULL WHERE workspace_id = ? AND content IS NOT NULL AND expires_at < ?`, ws, now)
		if r.Error != nil {
			return r.Error
		}
		out.ExportsExpired = r.RowsAffected
		return tx.Exec(`UPDATE iga_history_approval SET state = 'expired', decided_at = ?
		                 WHERE workspace_id = ? AND state = 'pending' AND expires_at < ?`, now, ws, now).Error
	})
	return out, err
}

/* ---------------------------------- worker ---------------------------------- */

// RunDaily snapshots and purges every workspace once.
func (s *HistoryService) RunDaily(ctx context.Context) error {
	var wss []uuid.UUID
	// TENANT-EXEMPT: the snapshot job runs across workspaces (no request tenant) and lists workspace ids only; each workspace is snapshotted and purged in its own workspace_id-bound transaction under RLS (tenancy.InWorkspace).
	if err := s.db.WithContext(ctx).Raw(`SELECT id FROM workspaces ORDER BY id`).Scan(&wss).Error; err != nil {
		return err
	}
	var first error
	for _, ws := range wss {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := s.TakeDaily(ctx, ws); err != nil {
			log.Printf("[history] snapshot workspace %s: %v", ws, err)
			if first == nil {
				first = err
			}
			continue
		}
		if _, err := s.Purge(ctx, ws); err != nil {
			log.Printf("[history] retention workspace %s: %v", ws, err)
			if first == nil {
				first = err
			}
		}
	}
	return first
}

// RunHistorySnapshotWorker takes the daily snapshots (and applies
// retention) on the replica holding the leader lock, checking hourly.
// AUTHSEC_DISABLE_SNAPSHOTS=true turns it off on a replica.
func RunHistorySnapshotWorker(ctx context.Context, db *gorm.DB) {
	if os.Getenv("AUTHSEC_DISABLE_SNAPSHOTS") == "true" {
		log.Printf("[history] snapshot worker not started: AUTHSEC_DISABLE_SNAPSHOTS=true")
		return
	}
	svc := NewHistoryService(db)
	for {
		RunAsLeader(ctx, db, "iga-snapshots", func() {
			if err := svc.RunDaily(ctx); err != nil && ctx.Err() == nil {
				log.Printf("[history] daily run: %v", err)
			}
		})
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

/* ---------------------------------- reads ----------------------------------- */

// latestSnapshots is the latest row at or before day of each stable id.
func latestSnapshots(tx *gorm.DB, ws uuid.UUID, kind string, ids []string, day time.Time) (map[string]HistorySnapshot, error) {
	var rows []HistorySnapshot
	if err := tx.Raw(`SELECT DISTINCT ON (stable_id) `+historySnapshotColumns+` FROM iga_snapshot
	                   WHERE workspace_id = ? AND kind = ? AND stable_id IN ? AND snapshot_date <= ?
	                   ORDER BY stable_id, snapshot_date DESC`, ws, kind, ids, day).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]HistorySnapshot, len(rows))
	for _, r := range rows {
		r.fill()
		out[r.StableID] = r
	}
	return out, nil
}

// SnapshotPage is GET /snapshots.
type SnapshotPage struct {
	AsOf       string            `json:"as_of"`
	Kind       string            `json:"kind"`
	Items      []HistorySnapshot `json:"items"`
	NextCursor *string           `json:"next_cursor"`
}

// SnapshotsAsOf returns the latest snapshot at or before asOf: of one stable
// id (absent rows included, so a deletion is visible), or a page of every
// stable id of the kind present on that day.
func (s *HistoryService) SnapshotsAsOf(ctx context.Context, ws uuid.UUID, kind, stableID string, asOf time.Time, cursor string, limit int) (*SnapshotPage, error) {
	if !validSnapshotKind(kind) {
		return nil, GovBadParam("kind", "kind must be one of "+strings.Join(SnapshotKinds, ", ")+".")
	}
	if limit <= 0 || limit > MaxGovPage {
		limit = 100
	}
	day := dateOnly(asOf)
	out := &SnapshotPage{AsOf: day.Format("2006-01-02"), Kind: kind, Items: []HistorySnapshot{}}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		if stableID != "" {
			m, err := latestSnapshots(tx, ws, kind, []string{stableID}, day)
			if err != nil {
				return err
			}
			r, ok := m[stableID]
			if !ok {
				return GovNotFound()
			}
			out.Items = append(out.Items, r)
			return nil
		}
		var rows []HistorySnapshot
		if err := tx.Raw(`SELECT `+historySnapshotColumns+` FROM (
		        SELECT DISTINCT ON (stable_id) `+historySnapshotColumns+` FROM iga_snapshot
		         WHERE workspace_id = ? AND kind = ? AND snapshot_date <= ? AND stable_id > ?
		         ORDER BY stable_id, snapshot_date DESC) x
		     WHERE NOT x.absent ORDER BY stable_id LIMIT ?`, ws, kind, day, cursor, limit+1).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			next := rows[limit-1].StableID
			out.NextCursor = &next
		}
		for i := range rows {
			rows[i].fill()
		}
		out.Items = append(out.Items, rows...)
		return nil
	})
	return out, err
}

// SnapshotDays lists the day rows in [from, to].
func (s *HistoryService) SnapshotDays(ctx context.Context, ws uuid.UUID, from, to time.Time) ([]SnapshotDay, error) {
	var rows []SnapshotDay
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT snapshot_date, kinds, rows_written, content_hash, prev_chain_hash, chain_hash, purged, created_at
		                 FROM iga_snapshot_day WHERE workspace_id = ? AND snapshot_date >= ? AND snapshot_date <= ?
		                ORDER BY snapshot_date LIMIT 1000`, ws, dateOnly(from), dateOnly(to)).Scan(&rows).Error
	})
	for i := range rows {
		rows[i].Date = rows[i].SnapshotDate.Format("2006-01-02")
	}
	if rows == nil {
		rows = []SnapshotDay{}
	}
	return rows, err
}

// ChainVerification is GET /snapshots/verify.
type ChainVerification struct {
	OK          bool     `json:"ok"`
	DaysChecked int      `json:"days_checked"`
	RowsChecked int      `json:"rows_checked"`
	Head        string   `json:"head"`
	Problems    []string `json:"problems"`
}

// VerifyChain recomputes the workspace's day chain up to to, each day's
// content hash where retention left its rows, and every row's chain and
// body hash from from to to (a redacted row's body is a tombstone: only its
// chain is checked).
func (s *HistoryService) VerifyChain(ctx context.Context, ws uuid.UUID, from, to time.Time) (*ChainVerification, error) {
	out := &ChainVerification{OK: true, Problems: []string{}}
	add := func(p string) {
		out.OK = false
		if len(out.Problems) < 50 {
			out.Problems = append(out.Problems, p)
		}
	}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var days []SnapshotDay
		if err := tx.Raw(`SELECT snapshot_date, kinds, rows_written, content_hash, prev_chain_hash, chain_hash, purged, created_at
		                    FROM iga_snapshot_day WHERE workspace_id = ? AND snapshot_date <= ? ORDER BY snapshot_date`, ws, dateOnly(to)).
			Scan(&days).Error; err != nil {
			return err
		}
		prev := ""
		for _, d := range days {
			date := d.SnapshotDate.Format("2006-01-02")
			out.DaysChecked++
			if d.PrevChainHash != prev {
				add(date + ": prev_chain_hash does not match the previous day's chain_hash")
			}
			kc, _, err := canonicalBody(d.Kinds)
			if err != nil {
				return err
			}
			if snapshotDayChain(ws, d.PrevChainHash, d.SnapshotDate, d.ContentHash, d.RowsWritten, string(kc)) != d.ChainHash {
				add(date + ": chain_hash does not match its contents")
			}
			if !d.Purged && !d.SnapshotDate.Before(dateOnly(from)) {
				var rows []struct{ Kind, StableID, Hash string }
				if err := tx.Raw(`SELECT kind, stable_id, hash FROM iga_snapshot WHERE workspace_id = ? AND snapshot_date = ?`, ws, d.SnapshotDate).
					Scan(&rows).Error; err != nil {
					return err
				}
				lines := make([][3]string, len(rows))
				for i, r := range rows {
					lines[i] = [3]string{r.Kind, r.StableID, r.Hash}
				}
				if len(rows) != d.RowsWritten || snapshotContentHash(lines) != d.ContentHash {
					add(date + ": the day's rows do not match its content hash")
				}
			}
			prev = d.ChainHash
		}
		out.Head = prev
		var rows []HistorySnapshot
		if err := tx.Raw(`SELECT `+historySnapshotColumns+` FROM iga_snapshot
		                   WHERE workspace_id = ? AND snapshot_date >= ? AND snapshot_date <= ?
		                   ORDER BY kind, stable_id, snapshot_date LIMIT 200000`, ws, dateOnly(from), dateOnly(to)).Scan(&rows).Error; err != nil {
			return err
		}
		for _, r := range rows {
			out.RowsChecked++
			date := r.SnapshotDate.Format("2006-01-02")
			if snapshotRowChain(ws, r.PrevChainHash, r.SnapshotDate, r.Kind, r.StableID, r.Hash) != r.ChainHash {
				add(fmt.Sprintf("%s %s %s: chain_hash does not match", date, r.Kind, r.StableID))
			}
			if r.Redacted {
				continue
			}
			_, h, err := canonicalBody(r.Body)
			if err != nil || h != r.Hash {
				add(fmt.Sprintf("%s %s %s: body does not match its hash", date, r.Kind, r.StableID))
			}
		}
		return nil
	})
	return out, err
}
