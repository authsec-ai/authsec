package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// ---------------------------------------------------------------------------
// IGA audit event types — the canonical taxonomy for the agentic IGA surface.
// ---------------------------------------------------------------------------

// Discovery events.
const (
	IGAAuditEventDiscoveryEnrollment = "discovery.enrollment"
	IGAAuditEventObjectCreated       = "discovery.object.created"
	IGAAuditEventObjectChanged       = "discovery.object.changed"
	IGAAuditEventObjectRetired       = "discovery.object.retired"
)

// Identity events.
const (
	IGAAuditEventIdentityAssignment  = "identity.assignment"
	IGAAuditEventIdentityAttestation = "identity.attestation"
	IGAAuditEventIdentityRotation    = "identity.rotation"
	IGAAuditEventIdentityDisable     = "identity.disable"
)

// Policy events.
const (
	IGAAuditEventPolicyCreation    = "policy.creation"
	IGAAuditEventPolicyEdit        = "policy.edit"
	IGAAuditEventPolicyValidation  = "policy.validation"
	IGAAuditEventPolicySimulation  = "policy.simulation"
	IGAAuditEventPolicyApproval    = "policy.approval"
	IGAAuditEventPolicyPublication = "policy.publication"
)

// Enforcement events.
const (
	IGAAuditEventEnforcementRollout = "enforcement.rollout"
	IGAAuditEventEnforcementReceipt = "enforcement.receipt"
	IGAAuditEventEnforcementDrift   = "enforcement.drift"
)

// Access events.
const (
	IGAAuditEventAccessRequest    = "access.request"
	IGAAuditEventAccessMFA        = "access.mfa"
	IGAAuditEventAccessLease      = "access.lease"
	IGAAuditEventAccessRevocation = "access.revocation"
)

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

// IGAAuditEvent is a single normalised audit record for the IGA lifecycle.
// It links observation -> graph -> policy -> approval -> binary -> receipt ->
// operation into a continuous chain.
type IGAAuditEvent struct {
	ID          uuid.UUID `json:"event_id"        gorm:"column:id;type:uuid;primaryKey"`
	WorkspaceID uuid.UUID `json:"workspace_id"    gorm:"column:workspace_id;type:uuid;not null;index:idx_iga_audit_ws_time,priority:1"`
	EventType   string    `json:"event_type"      gorm:"column:event_type;type:text;not null;index:idx_iga_audit_event_type"`

	// Temporal.
	OccurredAt time.Time `json:"occurred_at"     gorm:"column:occurred_at;not null;index:idx_iga_audit_ws_time,priority:2"`
	ReceivedAt time.Time `json:"received_at"     gorm:"column:received_at;not null"`

	// Actor.
	Actor           string     `json:"actor"             gorm:"column:actor;type:text"`
	VerifiedActorID *uuid.UUID `json:"verified_actor_id" gorm:"column:verified_actor_id;type:uuid;index:idx_iga_audit_actor"`
	SpiffeID        string     `json:"spiffe_id"         gorm:"column:spiffe_id;type:text;index:idx_iga_audit_spiffe"`

	// Subject references.
	AgentID     *uuid.UUID `json:"agent_id"     gorm:"column:agent_id;type:uuid;index:idx_iga_audit_agent"`
	WorkloadID  *uuid.UUID `json:"workload_id"  gorm:"column:workload_id;type:uuid"`
	ExecutionID *uuid.UUID `json:"execution_id" gorm:"column:execution_id;type:uuid"`

	// Policy references.
	PolicyID       *uuid.UUID `json:"policy_id"        gorm:"column:policy_id;type:uuid;index:idx_iga_audit_policy"`
	PolicyRevision *int       `json:"policy_revision"  gorm:"column:policy_revision"`
	PolicyHash     string     `json:"policy_hash"      gorm:"column:policy_hash;type:text"`

	// Rule / primitive.
	RuleID      string `json:"rule_id"      gorm:"column:rule_id;type:text;index:idx_iga_audit_rule"`
	PrimitiveID string `json:"primitive_id"  gorm:"column:primitive_id;type:text;index:idx_iga_audit_primitive"`
	Resource    string `json:"resource"      gorm:"column:resource;type:text"`

	// Outcome.
	Outcome string `json:"outcome"  gorm:"column:outcome;type:text;index:idx_iga_audit_outcome"`
	Reason  string `json:"reason"   gorm:"column:reason;type:text"`

	// Correlation.
	CorrelationID string `json:"correlation_id" gorm:"column:correlation_id;type:text;index:idx_iga_audit_correlation"`

	// Evidence and delivery references.
	EvidenceRefs pq.StringArray `json:"evidence_refs"  gorm:"column:evidence_refs;type:text[]"`
	Backend      string         `json:"backend"        gorm:"column:backend;type:text;index:idx_iga_audit_backend"`
	PublicationID *uuid.UUID    `json:"publication_id" gorm:"column:publication_id;type:uuid"`
	BinaryDigest string         `json:"binary_digest"  gorm:"column:binary_digest;type:text"`

	// Metadata stored as JSONB for extensibility.
	Metadata json.RawMessage `json:"metadata,omitempty" gorm:"column:metadata;type:jsonb"`

	CreatedAt time.Time `json:"created_at" gorm:"column:created_at"`
}

// TableName sets the GORM table name.
func (IGAAuditEvent) TableName() string { return "iga_audit_events" }

// ---------------------------------------------------------------------------
// Filter & pagination
// ---------------------------------------------------------------------------

// IGAAuditFilter selects audit events for the query endpoint.
type IGAAuditFilter struct {
	AgentID        *uuid.UUID `form:"agent_id"`
	SpiffeID       string     `form:"spiffe_id"`
	PolicyRevision *int       `form:"policy_revision"`
	PolicyID       *uuid.UUID `form:"policy_id"`
	RuleID         string     `form:"rule_id"`
	PrimitiveID    string     `form:"primitive_id"`
	Backend        string     `form:"backend"`
	ActorID        *uuid.UUID `form:"actor_id"`
	EventType      string     `form:"event_type"`
	Outcome        string     `form:"outcome"`
	CorrelationID  string     `form:"correlation_id"`
	TimeFrom       *time.Time `form:"time_from"`
	TimeTo         *time.Time `form:"time_to"`
	Cursor         string     `form:"cursor"`
	Limit          int        `form:"limit"`
}

// IGAAuditPage is the paginated response envelope.
type IGAAuditPage struct {
	Data       []IGAAuditEvent `json:"data"`
	TotalCount int64           `json:"total_count"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// IGAAuditService records and queries normalised IGA audit events.
type IGAAuditService struct {
	db *gorm.DB
}

// NewIGAAuditService constructs the service.
func NewIGAAuditService(db *gorm.DB) *IGAAuditService {
	return &IGAAuditService{db: db}
}

// RecordEvent persists an audit event atomically. When called inside an
// existing GORM transaction the event is committed with the mutation it
// records — satisfying the "atomic with the mutation" requirement.
func (s *IGAAuditService) RecordEvent(ctx context.Context, event *IGAAuditEvent) error {
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	if event.ReceivedAt.IsZero() {
		event.ReceivedAt = time.Now().UTC()
	}
	if event.EvidenceRefs == nil {
		event.EvidenceRefs = pq.StringArray{}
	}
	return s.db.WithContext(ctx).Create(event).Error
}

// RecordEventTx persists an audit event inside the caller's transaction.
// This is the preferred path for mutation-paired audit: the event either
// commits with the mutation or rolls back with it.
func (s *IGAAuditService) RecordEventTx(tx *gorm.DB, event *IGAAuditEvent) error {
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	if event.ReceivedAt.IsZero() {
		event.ReceivedAt = time.Now().UTC()
	}
	if event.EvidenceRefs == nil {
		event.EvidenceRefs = pq.StringArray{}
	}
	return tx.Create(event).Error
}

// QueryEvents returns a cursor-paginated, filtered list of audit events for a
// workspace. The cursor is an opaque base64-encoded timestamp+ID pair.
func (s *IGAAuditService) QueryEvents(ctx context.Context, workspaceID uuid.UUID, f IGAAuditFilter) (*IGAAuditPage, error) {
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	q := s.db.WithContext(ctx).Model(&IGAAuditEvent{}).Where("workspace_id = ?", workspaceID)

	// Apply optional filters.
	if f.AgentID != nil {
		q = q.Where("agent_id = ?", *f.AgentID)
	}
	if f.SpiffeID != "" {
		q = q.Where("spiffe_id = ?", f.SpiffeID)
	}
	if f.PolicyID != nil {
		q = q.Where("policy_id = ?", *f.PolicyID)
	}
	if f.PolicyRevision != nil {
		q = q.Where("policy_revision = ?", *f.PolicyRevision)
	}
	if f.RuleID != "" {
		q = q.Where("rule_id = ?", f.RuleID)
	}
	if f.PrimitiveID != "" {
		q = q.Where("primitive_id = ?", f.PrimitiveID)
	}
	if f.Backend != "" {
		q = q.Where("backend = ?", f.Backend)
	}
	if f.ActorID != nil {
		q = q.Where("verified_actor_id = ?", *f.ActorID)
	}
	if f.EventType != "" {
		q = q.Where("event_type = ?", f.EventType)
	}
	if f.Outcome != "" {
		q = q.Where("outcome = ?", f.Outcome)
	}
	if f.CorrelationID != "" {
		q = q.Where("correlation_id = ?", f.CorrelationID)
	}
	if f.TimeFrom != nil {
		q = q.Where("occurred_at >= ?", *f.TimeFrom)
	}
	if f.TimeTo != nil {
		q = q.Where("occurred_at <= ?", *f.TimeTo)
	}

	// Total count (before cursor filter).
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, err
	}

	// Decode cursor: "occurred_at|id" base64-encoded.
	if f.Cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(f.Cursor)
		if err == nil {
			var ct time.Time
			var cid uuid.UUID
			if _, err := fmt.Sscanf(string(raw), "%s|%s", &ct, &cid); err == nil {
				q = q.Where("(occurred_at, id) < (?, ?)", ct, cid)
			} else {
				// Try simpler parse.
				parts := splitCursor(string(raw))
				if len(parts) == 2 {
					if pt, err := time.Parse(time.RFC3339Nano, parts[0]); err == nil {
						if pid, err := uuid.Parse(parts[1]); err == nil {
							q = q.Where("(occurred_at, id) < (?, ?)", pt, pid)
						}
					}
				}
			}
		}
	}

	var events []IGAAuditEvent
	if err := q.Order("occurred_at DESC, id DESC").Limit(limit + 1).Find(&events).Error; err != nil {
		return nil, err
	}

	var nextCursor string
	if len(events) > limit {
		last := events[limit-1]
		cursorRaw := last.OccurredAt.Format(time.RFC3339Nano) + "|" + last.ID.String()
		nextCursor = base64.RawURLEncoding.EncodeToString([]byte(cursorRaw))
		events = events[:limit]
	}

	return &IGAAuditPage{
		Data:       events,
		TotalCount: total,
		NextCursor: nextCursor,
	}, nil
}

// splitCursor splits "timestamp|uuid" on the first "|".
func splitCursor(s string) []string {
	for i := 0; i < len(s); i++ {
		if s[i] == '|' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Convenience helpers for recording typed IGA audit events.
// ---------------------------------------------------------------------------

// RecordPolicyMutationEvent is a helper for policy lifecycle audit. It builds
// a full IGAAuditEvent from the common fields of a runtime-policy mutation and
// writes it inside the provided transaction.
func (s *IGAAuditService) RecordPolicyMutationEvent(
	tx *gorm.DB,
	workspaceID uuid.UUID,
	actorID uuid.UUID,
	policyID uuid.UUID,
	eventType string,
	revision int,
	contentHash string,
	outcome string,
	reason string,
	correlationID string,
	metadata map[string]any,
) error {
	var md json.RawMessage
	if metadata != nil {
		md, _ = json.Marshal(metadata)
	}
	rev := revision
	event := &IGAAuditEvent{
		ID:              uuid.New(),
		WorkspaceID:     workspaceID,
		EventType:       eventType,
		OccurredAt:      time.Now().UTC(),
		ReceivedAt:      time.Now().UTC(),
		VerifiedActorID: &actorID,
		PolicyID:        &policyID,
		PolicyRevision:  &rev,
		PolicyHash:      contentHash,
		Outcome:         outcome,
		Reason:          reason,
		CorrelationID:   correlationID,
		EvidenceRefs:    pq.StringArray{},
		Metadata:        md,
	}
	return s.RecordEventTx(tx, event)
}

// ---------------------------------------------------------------------------
// BG06 — Structured rule diff types and provenance audit helpers
// ---------------------------------------------------------------------------

// RuleDiffEntry describes a single rule change between two policy revisions.
type RuleDiffEntry struct {
	RuleID      string         `json:"rule_id"`
	Change      string         `json:"change"` // "added", "removed", "changed"
	Operation   string         `json:"operation,omitempty"`
	Target      string         `json:"target,omitempty"`
	Constraints map[string]any `json:"constraints,omitempty"`
	Effect      string         `json:"effect,omitempty"`
}

// StructuredRuleDiff is the structured diff between two policy revision
// documents. It records added/removed/changed rule IDs and before/after
// revision hashes for provenance.
type StructuredRuleDiff struct {
	FromRevision int             `json:"from_revision"`
	ToRevision   int             `json:"to_revision"`
	BeforeHash   string          `json:"before_hash,omitempty"`
	AfterHash    string          `json:"after_hash,omitempty"`
	Added        []RuleDiffEntry `json:"added"`
	Removed      []RuleDiffEntry `json:"removed"`
	Changed      []RuleDiffEntry `json:"changed"`
	Summary      string          `json:"summary,omitempty"`
}

// BuildStructuredRuleDiff compares two V1 policy documents (as JSON strings)
// and produces a structured diff suitable for the rule_diff audit column.
func BuildStructuredRuleDiff(prevDoc string, nextDoc string, fromRev, toRev int, beforeHash, afterHash string) *StructuredRuleDiff {
	type ruleShape struct {
		ID         string `json:"id"`
		Action     string `json:"action"`
		ResourceID string `json:"resource_id"`
		Path       string `json:"path"`
		Effect     string `json:"effect"`
	}
	type docShape struct {
		Name  string      `json:"name"`
		Rules []ruleShape `json:"rules"`
	}

	var old, next docShape
	_ = json.Unmarshal([]byte(prevDoc), &old)
	_ = json.Unmarshal([]byte(nextDoc), &next)

	oldByID := map[string]ruleShape{}
	for _, r := range old.Rules {
		oldByID[r.ID] = r
	}
	newByID := map[string]ruleShape{}
	for _, r := range next.Rules {
		newByID[r.ID] = r
	}

	diff := &StructuredRuleDiff{
		FromRevision: fromRev,
		ToRevision:   toRev,
		BeforeHash:   beforeHash,
		AfterHash:    afterHash,
		Added:        []RuleDiffEntry{},
		Removed:      []RuleDiffEntry{},
		Changed:      []RuleDiffEntry{},
	}

	// Detect added and changed rules.
	for _, r := range next.Rules {
		prev, existed := oldByID[r.ID]
		if !existed {
			diff.Added = append(diff.Added, RuleDiffEntry{
				RuleID:    r.ID,
				Change:    "added",
				Operation: r.Action,
				Target:    ruleTarget(r.ResourceID, r.Path),
				Effect:    r.Effect,
			})
		} else if prev.Action != r.Action || prev.Effect != r.Effect || prev.ResourceID != r.ResourceID || prev.Path != r.Path {
			diff.Changed = append(diff.Changed, RuleDiffEntry{
				RuleID:    r.ID,
				Change:    "changed",
				Operation: r.Action,
				Target:    ruleTarget(r.ResourceID, r.Path),
				Effect:    r.Effect,
			})
		}
	}

	// Detect removed rules.
	for _, r := range old.Rules {
		if _, exists := newByID[r.ID]; !exists {
			diff.Removed = append(diff.Removed, RuleDiffEntry{
				RuleID:    r.ID,
				Change:    "removed",
				Operation: r.Action,
				Target:    ruleTarget(r.ResourceID, r.Path),
				Effect:    r.Effect,
			})
		}
	}

	// Build human-readable summary sentence.
	diff.Summary = buildDiffSummary(diff, next.Name)

	return diff
}

// ruleTarget returns the most specific target identifier for a rule.
func ruleTarget(resourceID, path string) string {
	if path != "" {
		return path
	}
	return resourceID
}

// buildDiffSummary creates a human-readable sentence from the diff.
// Example: "Denied file.write to /srv/output for invoice-worker"
func buildDiffSummary(diff *StructuredRuleDiff, policyName string) string {
	parts := []string{}
	for _, e := range diff.Added {
		verb := effectVerb(e.Effect)
		target := e.Target
		if target == "" {
			target = "*"
		}
		parts = append(parts, fmt.Sprintf("%s %s to %s", verb, e.Operation, target))
	}
	for _, e := range diff.Removed {
		target := e.Target
		if target == "" {
			target = "*"
		}
		parts = append(parts, fmt.Sprintf("Removed %s on %s", e.Operation, target))
	}
	for _, e := range diff.Changed {
		verb := effectVerb(e.Effect)
		target := e.Target
		if target == "" {
			target = "*"
		}
		parts = append(parts, fmt.Sprintf("Changed to %s %s to %s", verb, e.Operation, target))
	}
	if len(parts) == 0 {
		return ""
	}
	suffix := ""
	if policyName != "" {
		suffix = " for " + policyName
	}
	if len(parts) == 1 {
		return parts[0] + suffix
	}
	return fmt.Sprintf("%d rule changes%s", len(parts), suffix)
}

// effectVerb returns the past-tense verb for a policy effect.
func effectVerb(effect string) string {
	switch effect {
	case "deny":
		return "Denied"
	case "allow":
		return "Allowed"
	case "require_approval":
		return "Required approval for"
	default:
		return "Set " + effect + " on"
	}
}
