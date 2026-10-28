package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// recordCandidate stores the filter result and, when the logical key already
// belongs to a different fingerprint, links this sighting onto that agent.
// A nil linked agent with hold false means the caller should upsert this
// fingerprint as its own discovered_agents row. Metadata on in is updated
// with the logical key and filter before that upsert.
func (m *discoveryManager) recordCandidate(workspaceID uuid.UUID, in *SightingInput, observedAt time.Time) (*models.DiscoveredAgent, bool, error) {
	db := m.repo.DB()
	if db == nil {
		return nil, false, errors.New("discovery candidate store is unavailable")
	}

	obs := observationFromSighting(*in)
	decision := Classify(obs)
	present, conf := reportedConfidence(in.Metadata)
	hold := present && (conf == "" || conf == confidenceNone || conf == confidenceLow)
	if present {
		if conf == "" {
			conf = confidenceNone
		}
		decision.Confidence = conf
	}
	if hold {
		decision.Decision = decisionHold
	} else {
		decision.Decision = decisionPromote
	}
	if decision.LogicalKey == "" && !hold {
		if fws := reportedFrameworks(in.Metadata); len(fws) > 0 {
			if name := chooseName(obs); name != "" {
				decision.LogicalKey = logicalKey(fws[0], name)
			}
		}
	}

	if in.Metadata == nil {
		in.Metadata = map[string]interface{}{}
	}
	if err := upsertCandidate(db, candidateWrite{
		WorkspaceID: workspaceID,
		Source:      in.Source,
		Fingerprint: in.Fingerprint,
		LogicalKey:  decision.LogicalKey,
		Kind:        decision.Kind,
		DisplayName: in.DisplayName,
		Signals:     decision.Signals,
		Frameworks:  decision.Frameworks,
		Confidence:  decision.Confidence,
		Decision:    decision.Decision,
		Reasons:     decision.Reasons,
		Metadata:    in.Metadata,
		ObservedAt:  observedAt,
	}); err != nil {
		return nil, false, err
	}
	if hold {
		return nil, true, nil
	}

	if decision.LogicalKey != "" {
		in.Metadata["logical_key"] = decision.LogicalKey
	}
	in.Metadata["filter"] = map[string]interface{}{
		"confidence":  decision.Confidence,
		"decision":    decision.Decision,
		"reasons":     decision.Reasons,
		"frameworks":  decision.Frameworks,
		"logical_key": decision.LogicalKey,
		"kind":        decision.Kind,
	}

	other, err := findAgentByLogicalKey(db, workspaceID, decision.LogicalKey, in.Source, in.Fingerprint)
	if err != nil {
		return nil, false, err
	}
	if other != nil {
		if err := appendCandidateSource(db, other.ID, map[string]string{
			"source":       in.Source,
			"kind":         decision.Kind,
			"display_name": in.DisplayName,
			"fingerprint":  in.Fingerprint,
		}); err != nil {
			return nil, false, err
		}
		if err := linkCandidate(db, workspaceID, in.Source, in.Fingerprint, other.ID); err != nil {
			return nil, false, err
		}
		return other, false, nil
	}
	if err := preserveSources(db, workspaceID, in.Source, in.Fingerprint, in.Metadata); err != nil {
		return nil, false, err
	}
	return nil, false, nil
}

func (m *discoveryManager) ListCandidates(workspaceID uuid.UUID, decision string, limit, offset int) ([]models.DiscoveryCandidate, int64, error) {
	if decision == "" {
		decision = decisionHold
	}
	if decision != decisionHold && decision != decisionPromote && decision != "all" {
		return nil, 0, fmt.Errorf("unknown decision %q", decision)
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	db := m.repo.DB()
	if db == nil {
		return nil, 0, errors.New("discovery candidate store is unavailable")
	}

	filter := db.Model(&models.DiscoveryCandidate{}).Where("workspace_id = ?", workspaceID)
	if decision != "all" {
		filter = filter.Where("decision = ?", decision)
	}
	var total int64
	if err := filter.Session(&gorm.Session{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []models.DiscoveryCandidate
	err := filter.Session(&gorm.Session{}).Order("observed_at DESC").Limit(limit).Offset(offset).Find(&rows).Error
	if err != nil {
		return nil, 0, err
	}
	return rows, total, nil
}

type candidateWrite struct {
	WorkspaceID uuid.UUID
	Source      string
	Fingerprint string
	LogicalKey  string
	Kind        string
	DisplayName string
	Signals     []string
	Frameworks  []string
	Confidence  string
	Decision    string
	Reasons     []string
	AgentID     *uuid.UUID
	Metadata    map[string]interface{}
	ObservedAt  time.Time
}

func upsertCandidate(db *gorm.DB, c candidateWrite) error {
	meta, err := json.Marshal(c.Metadata)
	if err != nil {
		return fmt.Errorf("candidate metadata: %w", err)
	}
	if len(meta) == 0 {
		meta = []byte("{}")
	}
	return db.Exec(`INSERT INTO discovery_candidates (
		id, workspace_id, source, fingerprint, logical_key, kind, display_name,
		signals, frameworks, confidence, decision, reasons, discovered_agent_id,
		metadata, observed_at, created_at, updated_at
	) VALUES (
		?, ?, ?, ?, ?, ?, ?,
		CAST(? AS jsonb), CAST(? AS jsonb), ?, ?, CAST(? AS jsonb), ?,
		CAST(? AS jsonb), ?, now(), now()
	)
	ON CONFLICT (workspace_id, source, fingerprint) DO UPDATE SET
		logical_key = EXCLUDED.logical_key,
		kind = EXCLUDED.kind,
		display_name = EXCLUDED.display_name,
		signals = EXCLUDED.signals,
		frameworks = EXCLUDED.frameworks,
		confidence = EXCLUDED.confidence,
		decision = EXCLUDED.decision,
		reasons = EXCLUDED.reasons,
		discovered_agent_id = COALESCE(EXCLUDED.discovered_agent_id, discovery_candidates.discovered_agent_id),
		metadata = EXCLUDED.metadata,
		observed_at = EXCLUDED.observed_at,
		updated_at = now()`,
		uuid.New(), c.WorkspaceID, c.Source, c.Fingerprint, c.LogicalKey, c.Kind, c.DisplayName,
		string(jsonArray(c.Signals)), string(jsonArray(c.Frameworks)), c.Confidence, c.Decision,
		string(jsonArray(c.Reasons)), c.AgentID, string(meta), c.ObservedAt,
	).Error
}

func linkCandidate(db *gorm.DB, workspaceID uuid.UUID, source, fingerprint string, agentID uuid.UUID) error {
	return db.Exec(`UPDATE discovery_candidates
		SET discovered_agent_id = ?, updated_at = now()
		WHERE workspace_id = ? AND source = ? AND fingerprint = ?`,
		agentID, workspaceID, source, fingerprint).Error
}

func findAgentByLogicalKey(db *gorm.DB, workspaceID uuid.UUID, key, source, fingerprint string) (*models.DiscoveredAgent, error) {
	if key == "" {
		return nil, nil
	}
	var agent models.DiscoveredAgent
	err := db.Where(
		"workspace_id = ? AND metadata->>'logical_key' = ? AND NOT (source = ? AND fingerprint = ?)",
		workspaceID, key, source, fingerprint,
	).First(&agent).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &agent, nil
}

// appendCandidateSource records another sighting of the same logical agent.
// The rest of the primary row's metadata is left as it was.
func appendCandidateSource(db *gorm.DB, agentID uuid.UUID, ref map[string]string) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var raw string
		err := tx.Raw(`SELECT COALESCE(metadata::text, '{}') FROM discovered_agents WHERE id = ? FOR UPDATE`, agentID).Scan(&raw).Error
		if err != nil {
			return err
		}
		if strings.TrimSpace(raw) == "" {
			raw = "{}"
		}
		var md map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &md); err != nil {
			return err
		}
		if md == nil {
			md = map[string]interface{}{}
		}
		var sources []interface{}
		if existing, ok := md["sources"].([]interface{}); ok {
			sources = existing
		}
		for _, item := range sources {
			cur, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if asString(cur["source"]) == ref["source"] && asString(cur["fingerprint"]) == ref["fingerprint"] {
				return nil
			}
		}
		sources = append(sources, map[string]interface{}{
			"source":       ref["source"],
			"kind":         ref["kind"],
			"display_name": ref["display_name"],
			"fingerprint":  ref["fingerprint"],
		})
		md["sources"] = sources
		buf, err := json.Marshal(md)
		if err != nil {
			return err
		}
		return tx.Exec(`UPDATE discovered_agents SET metadata = CAST(? AS jsonb), updated_at = now() WHERE id = ?`, string(buf), agentID).Error
	})
}

func preserveSources(db *gorm.DB, workspaceID uuid.UUID, source, fingerprint string, md map[string]interface{}) error {
	if md == nil || md["sources"] != nil {
		return nil
	}
	var raw string
	err := db.Raw(`SELECT COALESCE(metadata::text, '') FROM discovered_agents
		WHERE workspace_id = ? AND source = ? AND fingerprint = ?`,
		workspaceID, source, fingerprint).Scan(&raw).Error
	if err != nil {
		return err
	}
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var existing map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &existing); err != nil {
		return nil
	}
	if existing["sources"] != nil {
		md["sources"] = existing["sources"]
	}
	return nil
}

func observationFromSighting(in SightingInput) Observation {
	o := Observation{Source: in.Source, DisplayName: in.DisplayName}
	md := in.Metadata
	if md == nil {
		return o
	}
	if img, ok := asMap(md["image"]); ok {
		o.Image = firstString(img, "full", "repository")
	}
	if k, ok := asMap(md["kubernetes"]); ok {
		o.WorkloadName = asString(k["workload_name"])
		o.Namespace = asString(k["namespace"])
		if labels, ok := asMap(k["labels"]); ok {
			o.Labels = map[string]string{}
			for key, val := range labels {
				o.Labels[key] = asString(val)
			}
		}
	}
	if host, ok := asMap(md["host"]); ok {
		o.Exe = asString(host["exe"])
		o.Unit = asString(host["unit"])
		o.Path = asString(host["path"])
		o.ContainerID = asString(host["container_id"])
		o.Command = asString(host["command"])
		o.Argv = stringList(host["argv"])
		if strings.TrimSpace(o.Command) == "" && len(o.Argv) > 0 {
			o.Command = strings.Join(o.Argv, " ")
		}
	}
	if det, ok := asMap(md["detection"]); ok {
		o.EnvKeys = stringList(det["env_marker_keys"])
	}
	return o
}

func hasActivity(md map[string]interface{}) bool {
	if md == nil {
		return false
	}
	switch rows := md["activity"].(type) {
	case []interface{}:
		return len(rows) > 0
	default:
		return false
	}
}

func jsonArray(items []string) []byte {
	if items == nil {
		items = []string{}
	}
	buf, err := json.Marshal(items)
	if err != nil {
		return []byte("[]")
	}
	return buf
}

func asMap(v interface{}) (map[string]interface{}, bool) {
	m, ok := v.(map[string]interface{})
	return m, ok
}

func asString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	case json.Number:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}

func firstString(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if s := strings.TrimSpace(asString(m[key])); s != "" {
			return s
		}
	}
	return ""
}

func stringList(v interface{}) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s := strings.TrimSpace(asString(item))
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// RunDiscoveryProjector classifies recent host-collector objects and feeds
// them through the same sighting path as cluster workloads. It is not gated
// on policy publication.
func RunDiscoveryProjector(ctx context.Context, db *gorm.DB, interval time.Duration) {
	if db == nil {
		return
	}
	if interval <= 0 {
		interval = time.Minute
	}
	mgr := NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	run := func() {
		n, err := projectHostCandidates(db, mgr)
		if err != nil {
			log.Printf("[discovery] host projector: %v", err)
			return
		}
		log.Printf("[discovery] host projector classified %d objects", n)
	}
	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

type hostObject struct {
	WorkspaceID uuid.UUID `gorm:"column:workspace_id"`
	ObjectType  string    `gorm:"column:object_type"`
	Payload     string    `gorm:"column:payload"`
	LastSeen    time.Time `gorm:"column:last_seen_at"`
}

// projectHostCandidates reads linux process, systemd, and file rows from
// iga_source_objects. Accounts, groups, and secret references are not
// candidates. The fingerprint ignores pid and start ticks so a process
// restart does not mint a new row.
func projectHostCandidates(db *gorm.DB, mgr DiscoveryManager) (int, error) {
	var rows []hostObject
	err := db.Raw(`SELECT workspace_id, object_type, normalized_payload::text AS payload, last_seen_at
		FROM iga_source_objects
		WHERE lifecycle = 'active'
		  AND object_type IN ('linux.process_group', 'linux.systemd_workload', 'linux.file')
		  AND last_seen_at >= NOW() - INTERVAL '15 minutes'
		ORDER BY last_seen_at DESC
		LIMIT 2000`).Scan(&rows).Error
	if err != nil {
		return 0, err
	}
	seen := map[string]struct{}{}
	n := 0
	for _, row := range rows {
		in, ok := hostSighting(row)
		if !ok {
			continue
		}
		key := row.WorkspaceID.String() + "|" + in.Source + "|" + in.Fingerprint
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		observed := row.LastSeen
		in.ObservedAt = &observed
		if _, _, err := mgr.ReportSighting(row.WorkspaceID, "projector:vm_sensor", in); err != nil {
			log.Printf("[discovery] host candidate %s: %v", in.DisplayName, err)
			continue
		}
		n++
	}
	return n, nil
}

func hostSighting(row hostObject) (SightingInput, bool) {
	var body map[string]interface{}
	if err := json.Unmarshal([]byte(row.Payload), &body); err != nil {
		return SightingInput{}, false
	}
	native, ok := asMap(body["native"])
	if !ok {
		return SightingInput{}, false
	}
	exe := asString(native["exe"])
	unit := firstString(native, "systemd_unit", "unit")
	path := asString(native["path"])
	containerID := asString(native["container_id"])
	argv := stringList(native["argv"])
	execStart := stringify(native["exec_start"])
	if strings.TrimSpace(exe) == "" && strings.TrimSpace(unit) == "" && strings.TrimSpace(path) == "" && strings.TrimSpace(execStart) == "" {
		return SightingInput{}, false
	}

	obs := Observation{
		Source:      models.DiscoverySourceVMSensor,
		Exe:         exe,
		Unit:        unit,
		Path:        path,
		ContainerID: containerID,
		Argv:        argv,
		Command:     strings.Join(argv, " "),
	}
	if obs.Command == "" {
		obs.Command = execStart
	}
	decision := Classify(obs)
	fp := hostFingerprint(decision.Kind, chooseName(obs), exe, strings.Join(argv, "\x00"), unit, path, containerID, "", "")
	display := hostDisplay(decision.Kind, exe, unit, path, argv, execStart)
	signals := decision.Signals
	if signals == nil {
		signals = []string{}
	}
	meta := map[string]interface{}{
		"schema_version": "1",
		"detection": map[string]interface{}{
			"confidence": decision.Confidence,
			"frameworks": decision.Frameworks,
			"signals":    signals,
		},
		"host": map[string]interface{}{
			"kind":         decision.Kind,
			"exe":          exe,
			"argv":         argv,
			"unit":         unit,
			"path":         path,
			"container_id": containerID,
			"command":      obs.Command,
		},
	}
	return SightingInput{
		Source:      models.DiscoverySourceVMSensor,
		Fingerprint: fp,
		DisplayName: display,
		Metadata:    meta,
	}, true
}

func hostFingerprint(kind, name, exe, argv, unit, path, containerID, namespace, workload string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		kind, name, exe, argv, unit, path, containerID, namespace, workload,
	}, "\n")))
	return hex.EncodeToString(sum[:])
}

func hostDisplay(kind, exe, unit, path string, argv []string, execStart string) string {
	switch kind {
	case "linux.systemd":
		if unit != "" {
			return unit
		}
	case "python.file", "linux.file":
		if path != "" {
			return path
		}
	case "python.process":
		if len(argv) > 0 {
			return strings.Join(argv, " ")
		}
		return "python"
	case "docker.container":
		if exe != "" {
			return "container " + candidateName(exe)
		}
	}
	if path != "" {
		return path
	}
	if unit != "" {
		return unit
	}
	if exe != "" {
		return exe
	}
	if execStart != "" {
		return execStart
	}
	if len(argv) > 0 {
		return strings.Join(argv, " ")
	}
	return kind
}

func stringify(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		buf, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprint(t)
		}
		if string(buf) == "null" {
			return ""
		}
		return string(buf)
	}
}
