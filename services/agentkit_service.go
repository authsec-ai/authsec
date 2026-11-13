package services

// AuthSec Agent Kit (authsec-cli) control plane: the events a machine's
// daemon reports and the agent policies machines pull. A machine is a
// discovery source of kind vm_sensor; its agents arrive as ordinary
// sightings, and quarantine reuses provisioning instructions
// (EnforceQuarantine). Every statement here runs under row-level security
// for one workspace (tenancy.InWorkspace / InWorkspaceRead).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

// Limits on what a machine may send at once.
const (
	AgentKitMaxEventsPerBatch = 500
	AgentKitMaxRecordBytes    = 16 * 1024
	AgentKitMaxPolicyBytes    = 256 * 1024
	agentKitMaxCommentLen     = 500
	// A record stamped further ahead than this is stamped with the arrival
	// time: a machine's clock is not trusted to order the console's logs
	// into the future.
	agentKitMaxClockSkew = 5 * time.Minute
)

var (
	// ErrAgentKitSourceNotFound: the call names no vm_sensor source of the
	// workspace. The caller answers 404.
	ErrAgentKitSourceNotFound = errors.New("discovery source not found")
	// ErrAgentKitPolicyInvalid wraps a policy document the service refuses.
	ErrAgentKitPolicyInvalid = errors.New("invalid policy")
	// ErrAgentKitPolicyConflict: the base version given is not the latest.
	ErrAgentKitPolicyConflict = errors.New("policy changed since it was read")
)

// agentKitAgentIDRe is the agent id a policy names (the table's check).
var agentKitAgentIDRe = regexp.MustCompile(`^(\*|[a-z0-9][a-z0-9._-]{0,99})$`)

// ValidAgentKitAgentID reports whether id may name a policy's agent.
func ValidAgentKitAgentID(id string) bool { return agentKitAgentIDRe.MatchString(id) }

// AgentKit is the control plane service.
type AgentKit struct{ db *gorm.DB }

// NewAgentKit constructs the service.
func NewAgentKit(db *gorm.DB) *AgentKit { return &AgentKit{db: db} }

/* --------------------------------- sources -------------------------------- */

// MachineSource returns the workspace's vm_sensor source id, or
// ErrAgentKitSourceNotFound. A source of another kind or another workspace
// is not found.
func (s *AgentKit) MachineSource(ctx context.Context, ws, sourceID uuid.UUID) (*models.DiscoverySource, error) {
	var src models.DiscoverySource
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Where("workspace_id = ? AND id = ? AND kind = ?", ws, sourceID, models.DiscoverySourceVMSensor).
			First(&src).Error
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrAgentKitSourceNotFound
	}
	if err != nil {
		return nil, err
	}
	return &src, nil
}

/* --------------------------------- events --------------------------------- */

// agentKitRecord is the part of a daemon record (authsec-cli events.Record)
// copied into columns.
type agentKitRecord struct {
	Time  time.Time `json:"ts"`
	Type  string    `json:"type"`
	Agent *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		PID  int    `json:"pid"`
	} `json:"agent"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Action   string `json:"action"`
	Kind     string `json:"kind"`
	Enforced bool   `json:"enforced"`
}

// AgentKitIngestResult says what happened to a batch.
type AgentKitIngestResult struct {
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
	// Errors is the first few reasons, by index in the batch.
	Errors []AgentKitRecordError `json:"errors,omitempty"`
}

// AgentKitRecordError is why one record was refused.
type AgentKitRecordError struct {
	Index int    `json:"index"`
	Error string `json:"error"`
}

func clip(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary.
	for n > 0 && !utf8RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// parseAgentKitEvent turns one record into a row, or says why not.
func parseAgentKitEvent(ws, sourceID uuid.UUID, raw json.RawMessage, now time.Time) (*models.AgentKitEvent, error) {
	if len(raw) > AgentKitMaxRecordBytes {
		return nil, fmt.Errorf("record is larger than %d bytes", AgentKitMaxRecordBytes)
	}
	var rec agentKitRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("record is not a JSON object: %v", err)
	}
	// Re-encode through a map: the stored record is an object, whatever the
	// machine sent, and Postgres sees valid JSON only.
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, errors.New("record is not a JSON object")
	}
	valid := false
	for _, t := range models.ValidAgentKitEventTypes() {
		if rec.Type == t {
			valid = true
		}
	}
	if !valid {
		return nil, fmt.Errorf("type %q is not one of %s", rec.Type, strings.Join(models.ValidAgentKitEventTypes(), ", "))
	}
	if rec.Time.IsZero() {
		return nil, errors.New("ts is required")
	}
	observed := rec.Time
	if observed.After(now.Add(agentKitMaxClockSkew)) {
		observed = now
	}
	sev := strings.ToLower(strings.TrimSpace(rec.Severity))
	switch sev {
	case "", "high", "medium", "low":
	case "critical":
		sev = "high"
	default:
		sev = ""
	}
	body, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	// Postgres stores no NUL in text or jsonb: one such record would fail
	// the whole batch, so it is refused on its own.
	if strings.Contains(string(body), `\u0000`) {
		return nil, errors.New("record contains a NUL character")
	}
	ev := &models.AgentKitEvent{
		ID:                uuid.New(),
		WorkspaceID:       ws,
		DiscoverySourceID: sourceID,
		ObservedAt:        observed.UTC(),
		ReceivedAt:        now,
		Type:              rec.Type,
		Kind:              clip(rec.Kind, 40),
		Action:            clip(rec.Action, 40),
		Rule:              clip(rec.Rule, 200),
		Severity:          sev,
		Enforced:          rec.Enforced,
		Record:            body,
	}
	if rec.Agent != nil {
		ev.AgentID = clip(rec.Agent.ID, 100)
		ev.AgentName = clip(rec.Agent.Name, 200)
		if rec.Agent.PID > 0 && rec.Agent.PID <= 1<<31-1 {
			ev.AgentPID = rec.Agent.PID
		}
	}
	return ev, nil
}

// IngestEvents stores a batch of a machine's records. Records that fail
// validation are counted and skipped; the rest are stored together.
func (s *AgentKit) IngestEvents(ctx context.Context, ws, sourceID uuid.UUID, records []json.RawMessage) (AgentKitIngestResult, error) {
	var res AgentKitIngestResult
	now := time.Now().UTC()
	rows := make([]models.AgentKitEvent, 0, len(records))
	for i, raw := range records {
		ev, err := parseAgentKitEvent(ws, sourceID, raw, now)
		if err != nil {
			res.Rejected++
			if len(res.Errors) < 10 {
				res.Errors = append(res.Errors, AgentKitRecordError{Index: i, Error: err.Error()})
			}
			continue
		}
		rows = append(rows, *ev)
	}
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		// The source is checked in the same transaction as the insert, under
		// the workspace's row-level security; the composite foreign key pins
		// it to the workspace as well.
		var n int64
		if err := tx.Model(&models.DiscoverySource{}).
			Where("workspace_id = ? AND id = ? AND kind = ?", ws, sourceID, models.DiscoverySourceVMSensor).
			Count(&n).Error; err != nil {
			return err
		}
		if n == 0 {
			return ErrAgentKitSourceNotFound
		}
		if len(rows) == 0 {
			return nil
		}
		return tx.CreateInBatches(rows, 100).Error
	})
	if err != nil {
		return AgentKitIngestResult{}, err
	}
	res.Accepted = len(rows)
	return res, nil
}

// AgentKitEventFilter narrows ListEvents.
type AgentKitEventFilter struct {
	SourceID *uuid.UUID
	Types    []string
	AgentID  string
	Severity string
	Action   string
	// Tag matches a compliance tag in the record's "tags" list (an OWASP
	// id such as LLM06, or a free tag the daemon added).
	Tag string
	// EnforcedOnly keeps records whose action was blocked.
	EnforcedOnly bool
	Since, Until *time.Time
	// Before is the id of the last row of the previous page.
	Before *uuid.UUID
	Limit  int
}

// ListEvents returns the workspace's events, newest first, and the cursor
// for the next page (nil at the end).
func (s *AgentKit) ListEvents(ctx context.Context, ws uuid.UUID, f AgentKitEventFilter) ([]models.AgentKitEvent, *uuid.UUID, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []models.AgentKitEvent
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		q := tx.Model(&models.AgentKitEvent{}).Where("workspace_id = ?", ws)
		if f.SourceID != nil {
			q = q.Where("discovery_source_id = ?", *f.SourceID)
		}
		if len(f.Types) > 0 {
			q = q.Where("type IN ?", f.Types)
		}
		if f.AgentID != "" {
			q = q.Where("agent_id = ?", f.AgentID)
		}
		if f.Severity != "" {
			q = q.Where("severity = ?", f.Severity)
		}
		if f.Action != "" {
			q = q.Where("action = ?", f.Action)
		}
		if f.EnforcedOnly {
			q = q.Where("enforced")
		}
		if f.Tag != "" {
			// @> rather than the ? operator, which GORM would read as a
			// placeholder.
			q = q.Where("record->'tags' @> jsonb_build_array(?::text)", f.Tag)
		}
		if f.Since != nil {
			q = q.Where("observed_at >= ?", *f.Since)
		}
		if f.Until != nil {
			q = q.Where("observed_at < ?", *f.Until)
		}
		if f.Before != nil {
			// Keyset page: rows strictly after the cursor row in
			// (observed_at DESC, id DESC) order. A cursor of another
			// workspace is not visible here, so it matches nothing.
			q = q.Where(`(observed_at, id) < (SELECT c.observed_at, c.id FROM agentkit_events c
				WHERE c.workspace_id = ? AND c.id = ?)`, ws, *f.Before)
		}
		return q.Order("observed_at DESC, id DESC").Limit(limit + 1).Find(&out).Error
	})
	if err != nil {
		return nil, nil, err
	}
	var next *uuid.UUID
	if len(out) > limit {
		out = out[:limit]
		id := out[limit-1].ID
		next = &id
	}
	return out, next, nil
}

// AgentKitAccess is the latest access summary of one agent on one machine.
type AgentKitAccess struct {
	DiscoverySourceID uuid.UUID       `json:"discovery_source_id"`
	AgentID           string          `json:"agent_id"`
	AgentName         string          `json:"agent_name"`
	ObservedAt        time.Time       `json:"observed_at"`
	Record            json.RawMessage `json:"record"`
}

// LatestAccess returns, per machine and agent, the newest access summary.
func (s *AgentKit) LatestAccess(ctx context.Context, ws uuid.UUID, sourceID *uuid.UUID, agentID string) ([]AgentKitAccess, error) {
	var out []AgentKitAccess
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		q := tx.Table("agentkit_events").
			Select("DISTINCT ON (discovery_source_id, agent_id) discovery_source_id, agent_id, agent_name, observed_at, record").
			Where("workspace_id = ? AND type = ?", ws, models.AgentKitEventAccess)
		if sourceID != nil {
			q = q.Where("discovery_source_id = ?", *sourceID)
		}
		if agentID != "" {
			q = q.Where("agent_id = ?", agentID)
		}
		return q.Order("discovery_source_id, agent_id, observed_at DESC").Limit(1000).Scan(&out).Error
	})
	return out, err
}

/* -------------------------------- policies -------------------------------- */

// agentKitPolicyHead is the part of a policy document the service checks.
// The full validation (rules, paths, commands) is the machine's: a machine
// keeps its previous policy when a pulled one does not pass `policy check`.
type agentKitPolicyHead struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Agent      struct {
		ID string `yaml:"id"`
	} `yaml:"agent"`
	Mode string `yaml:"mode"`
}

// CheckAgentKitPolicy checks a document's head: authsec.ai/v1 AgentPolicy,
// for agentID, in mode monitor or enforce.
func CheckAgentKitPolicy(agentID, doc string) error {
	if strings.TrimSpace(doc) == "" {
		return fmt.Errorf("%w: document is empty", ErrAgentKitPolicyInvalid)
	}
	if len(doc) > AgentKitMaxPolicyBytes {
		return fmt.Errorf("%w: document is larger than %d bytes", ErrAgentKitPolicyInvalid, AgentKitMaxPolicyBytes)
	}
	var head agentKitPolicyHead
	if err := yaml.Unmarshal([]byte(doc), &head); err != nil {
		return fmt.Errorf("%w: not YAML: %v", ErrAgentKitPolicyInvalid, err)
	}
	switch {
	case head.APIVersion != "authsec.ai/v1":
		return fmt.Errorf("%w: apiVersion must be authsec.ai/v1", ErrAgentKitPolicyInvalid)
	case head.Kind != "AgentPolicy":
		return fmt.Errorf("%w: kind must be AgentPolicy", ErrAgentKitPolicyInvalid)
	case head.Agent.ID != agentID:
		return fmt.Errorf("%w: agent.id %q does not match the policy's agent %q", ErrAgentKitPolicyInvalid, head.Agent.ID, agentID)
	case head.Mode != "monitor" && head.Mode != "enforce":
		return fmt.Errorf("%w: mode must be monitor or enforce", ErrAgentKitPolicyInvalid)
	}
	return nil
}

// LatestPolicies returns the newest version of every agent's policy.
func (s *AgentKit) LatestPolicies(ctx context.Context, ws uuid.UUID) ([]models.AgentKitPolicy, error) {
	var out []models.AgentKitPolicy
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT DISTINCT ON (agent_id) * FROM agentkit_policies
			WHERE workspace_id = ? ORDER BY agent_id, version DESC`, ws).Scan(&out).Error
	})
	return out, err
}

// PolicyVersions returns one agent's versions, newest first.
func (s *AgentKit) PolicyVersions(ctx context.Context, ws uuid.UUID, agentID string) ([]models.AgentKitPolicy, error) {
	var out []models.AgentKitPolicy
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Where("workspace_id = ? AND agent_id = ?", ws, agentID).
			Order("version DESC").Limit(200).Find(&out).Error
	})
	return out, err
}

// PutPolicy stores a new version of an agent's policy. baseVersion, when
// set, must be the latest version (0: the agent has none yet), so two
// editors do not overwrite each other. A document equal to the latest is
// not stored again; the latest is returned with created=false.
func (s *AgentKit) PutPolicy(ctx context.Context, ws uuid.UUID, agentID, doc, comment string,
	baseVersion *int, by *uuid.UUID) (row *models.AgentKitPolicy, created bool, err error) {

	if !ValidAgentKitAgentID(agentID) {
		return nil, false, fmt.Errorf("%w: agent id must be * or lower-case letters, digits, '.', '_' or '-'", ErrAgentKitPolicyInvalid)
	}
	if err := CheckAgentKitPolicy(agentID, doc); err != nil {
		return nil, false, err
	}
	if len(comment) > agentKitMaxCommentLen {
		return nil, false, fmt.Errorf("%w: comment is longer than %d characters", ErrAgentKitPolicyInvalid, agentKitMaxCommentLen)
	}
	sum := sha256.Sum256([]byte(doc))
	digest := hex.EncodeToString(sum[:])

	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		// One writer per agent at a time: the advisory lock is held to the
		// end of the transaction and keyed by workspace and agent.
		if err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended(?, 0))`,
			"agentkit_policy:"+ws.String()+":"+agentID).Error; err != nil {
			return err
		}
		var latest []models.AgentKitPolicy
		if err := tx.Where("workspace_id = ? AND agent_id = ?", ws, agentID).
			Order("version DESC").Limit(1).Find(&latest).Error; err != nil {
			return err
		}
		current := 0
		if len(latest) > 0 {
			current = latest[0].Version
		}
		if baseVersion != nil && *baseVersion != current {
			return ErrAgentKitPolicyConflict
		}
		if len(latest) > 0 && latest[0].SHA256 == digest {
			row = &latest[0]
			return nil
		}
		row = &models.AgentKitPolicy{
			ID:          uuid.New(),
			WorkspaceID: ws,
			AgentID:     agentID,
			Version:     current + 1,
			Document:    doc,
			SHA256:      digest,
			Comment:     comment,
			CreatedBy:   by,
			CreatedAt:   time.Now().UTC(),
		}
		created = true
		return tx.Create(row).Error
	})
	if err != nil {
		return nil, false, err
	}
	return row, created, nil
}
