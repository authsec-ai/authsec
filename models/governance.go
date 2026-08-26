package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// Entitlement kinds that provenance can describe.
//
// These are the grant shapes that exist as rows today. A scope is deliberately NOT
// one of them: scopes are derived by the ScopeResolver from the role chain rather
// than granted per-subject, so there is no row to point at and recording one would
// invent a grant that does not exist.
const (
	EntitlementRoleBinding        = "role_binding"
	EntitlementClientRegistration = "client_registration"
	EntitlementSecretAccess       = "secret_access"
)

// Subject kinds that can hold an entitlement.
//
// oauth_client appears here even though role_bindings cannot bind one (its
// check_principal allows only user/group/service_account) — a client registration is
// held by the client itself, so provenance has to be able to name it.
const (
	ProvenanceSubjectUser           = "user"
	ProvenanceSubjectServiceAccount = "service_account"
	ProvenanceSubjectOAuthClient    = "oauth_client"
	ProvenanceSubjectGroup          = "group"
)

// How a grant came to be. This is the "one pipeline, several origins" idea: the
// approval path is identical, and origin records which door the request came through.
const (
	GrantOriginDiscoveryClaim     = "discovery_claim"
	GrantOriginSelfService        = "self_service"
	GrantOriginBirthright         = "birthright"
	GrantOriginAdmin              = "admin"
	GrantOriginEscalation         = "escalation"
	GrantOriginConnectionApproval = "connection_approval"
	GrantOriginMigration          = "migration"
)

// Which mechanism closed a grant. All of them funnel through one de-provision path;
// this records the caller, so "why did this access disappear?" is answerable.
const (
	RevokedViaExpiry         = "expiry"
	RevokedViaCertification  = "certification"
	RevokedViaLeaver         = "leaver"
	RevokedViaQuarantine     = "quarantine"
	RevokedViaAdmin          = "admin"
	RevokedViaSoDRemediation = "sod_remediation"
)

// Governance status of an agent identity. Deliberately orthogonal to
// DiscoveredAgent.RuntimeStatus: this is what a human decided about the agent's
// authority, that is what we observed about its workload. An agent can legitimately
// be governance-active and runtime-gone (deleted but still governed, pending review),
// or governance-deprovisioned and runtime-running (revoked, but the workload has not
// noticed yet — which is exactly the state token revocation exists to close).
const (
	GovernanceStatusUngoverned    = "ungoverned"
	GovernanceStatusActive        = "active"
	GovernanceStatusSuspended     = "suspended"
	GovernanceStatusDeprovisioned = "deprovisioned"
)

// Risk tiers for a resource server, driving certification frequency and ordering.
const (
	RiskTierLow      = "low"
	RiskTierMedium   = "medium"
	RiskTierHigh     = "high"
	RiskTierCritical = "critical"
)

// ValidEntitlementTypes returns the allowed entitlement kinds.
func ValidEntitlementTypes() []string {
	return []string{EntitlementRoleBinding, EntitlementClientRegistration, EntitlementSecretAccess}
}

// ValidProvenanceSubjectTypes returns the allowed subject kinds.
func ValidProvenanceSubjectTypes() []string {
	return []string{ProvenanceSubjectUser, ProvenanceSubjectServiceAccount,
		ProvenanceSubjectOAuthClient, ProvenanceSubjectGroup}
}

// ValidGrantOrigins returns the allowed grant origins.
func ValidGrantOrigins() []string {
	return []string{GrantOriginDiscoveryClaim, GrantOriginSelfService, GrantOriginBirthright,
		GrantOriginAdmin, GrantOriginEscalation, GrantOriginConnectionApproval, GrantOriginMigration}
}

// ValidRevokedVia returns the allowed revocation mechanisms.
func ValidRevokedVia() []string {
	return []string{RevokedViaExpiry, RevokedViaCertification, RevokedViaLeaver,
		RevokedViaQuarantine, RevokedViaAdmin, RevokedViaSoDRemediation}
}

// ValidGovernanceStatuses returns the allowed agent governance statuses.
func ValidGovernanceStatuses() []string {
	return []string{GovernanceStatusUngoverned, GovernanceStatusActive,
		GovernanceStatusSuspended, GovernanceStatusDeprovisioned}
}

// ValidRiskTiers returns the allowed resource-server risk tiers.
func ValidRiskTiers() []string {
	return []string{RiskTierLow, RiskTierMedium, RiskTierHigh, RiskTierCritical}
}

// EntitlementProvenance is one grant decision: what was granted, to whom, why, by
// whom, and for how long.
//
// WHAT THIS EXISTS FOR
// The platform can already answer "what does this subject have?" — the ScopeResolver
// walks the role chain and honours expiry at read time. It cannot answer "WHY does
// this subject have it?": who asked, who approved, on what justification, for what
// purpose, and whether it was meant to be temporary. That question is the whole of
// certification, and it is unanswerable without this table.
//
// Rows are OPENED on grant and CLOSED on revoke. Nothing is deleted, because this is
// evidence. The live pointers are ON DELETE SET NULL so a row survives the grant it
// describes — an expired binding is deleted, and that is exactly when the record of
// it starts to matter — which is why Snapshot carries a denormalised copy.
type EntitlementProvenance struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`

	EntitlementType string `json:"entitlement_type" gorm:"not null"`
	// Exactly one of these is set, matching EntitlementType. Nulled when the
	// underlying grant is deleted; Snapshot is what survives.
	RoleBindingID         *uuid.UUID `json:"role_binding_id,omitempty" gorm:"type:uuid"`
	ClientRegistrationID  *uuid.UUID `json:"client_registration_id,omitempty" gorm:"type:uuid"`
	ConnectorAssignmentID *uuid.UUID `json:"connector_assignment_id,omitempty" gorm:"type:uuid"`
	// Snapshot is the denormalised copy of the grant, readable after the pointer is
	// nulled. Schemaless because the shape differs per entitlement type and nothing
	// makes a decision from it — it is read by humans and by report rendering.
	Snapshot json.RawMessage `json:"entitlement_snapshot" gorm:"column:entitlement_snapshot;type:jsonb;not null;default:'{}'"`
	// Label is the one-liner shown in a review queue, so a reviewer never has to read
	// jsonb to know what they are deciding on.
	Label string `json:"entitlement_label" gorm:"column:entitlement_label;not null;default:''"`

	// Subject is polymorphic and therefore not an FK — see ValidProvenanceSubjectTypes.
	SubjectType  string    `json:"subject_type" gorm:"not null"`
	SubjectID    uuid.UUID `json:"subject_id" gorm:"type:uuid;not null"`
	SubjectLabel string    `json:"subject_label" gorm:"not null;default:''"`

	Origin            string     `json:"origin" gorm:"not null"`
	Justification     string     `json:"justification" gorm:"not null;default:''"`
	Purpose           string     `json:"purpose" gorm:"not null;default:''"`
	AccessRequestID   *uuid.UUID `json:"access_request_id,omitempty" gorm:"type:uuid"`
	DiscoveredAgentID *uuid.UUID `json:"discovered_agent_id,omitempty" gorm:"type:uuid"`

	GrantedBy *uuid.UUID `json:"granted_by,omitempty" gorm:"type:uuid"`
	// GrantedByLabel is denormalised deliberately: a deactivated user's row can be
	// removed, and "granted by <null>" is useless in an audit six months later.
	GrantedByLabel string    `json:"granted_by_label" gorm:"not null;default:''"`
	GrantedAt      time.Time `json:"granted_at" gorm:"not null;default:now()"`

	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// IsStanding marks a deliberate permanent grant. The DB requires a justification
	// for one, which is the mechanism behind "ephemeral by default, permanent is the
	// audited exception".
	IsStanding bool `json:"is_standing" gorm:"not null;default:false"`

	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokedBy     *uuid.UUID `json:"revoked_by,omitempty" gorm:"type:uuid"`
	RevokedReason string     `json:"revoked_reason" gorm:"not null;default:''"`
	RevokedVia    string     `json:"revoked_via" gorm:"not null;default:''"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Lapsed is derived at read time: the grant has passed its expiry but nothing has
	// closed it yet. Surfacing it is what makes the expiry worker's backlog visible
	// instead of silent.
	Lapsed bool `json:"lapsed" gorm:"-"`
}

func (EntitlementProvenance) TableName() string { return "entitlement_provenance" }

// IsOpen reports whether the grant is still in force as far as governance knows.
func (p *EntitlementProvenance) IsOpen() bool { return p.RevokedAt == nil }

// AfterFind derives Lapsed on every read.
//
// A hook rather than a call in each service method, for the same reason
// DiscoverySource.AfterFind exists: a derived field is only trustworthy if it is
// populated on every path that returns the row, and "remember to compute it" is the
// kind of invariant a later read path forgets.
func (p *EntitlementProvenance) AfterFind(*gorm.DB) error {
	p.Lapsed = p.RevokedAt == nil && p.ExpiresAt != nil && p.ExpiresAt.Before(time.Now())
	return nil
}

// SoD rule shapes.
//
// 'conflict' is the textbook shape: holding capabilities from BOTH sides at once is
// the violation. 'prohibition' has one side only — holding ANY of these is the
// violation for the subjects the rule applies to.
//
// The second shape exists because the agentic controls are not all conflicts. "No
// agent principal may hold role-management authority" is not two duties that must stay
// apart; it is a capability an agent must never have. Forcing it into the two-set
// shape would mean inventing a fake second side.
const (
	SoDKindConflict    = "conflict"
	SoDKindProhibition = "prohibition"
)

// Which population a rule applies to. 'agents' resolves to a service account that is
// an agent's entitlement anchor (service_accounts.oauth_client_id IS NOT NULL), so a
// rule never has to know how agents are modelled.
const (
	SoDScopeAny    = "any"
	SoDScopeAgents = "agents"
	SoDScopeHumans = "humans"
)

// Enforcement. 'warn' exists so a rule can be rolled out in observation mode before it
// starts refusing real requests.
const (
	SoDEnforcementBlock = "block"
	SoDEnforcementWarn  = "warn"
)

// Violation lifecycle. 'accepted' is a documented risk acceptance, not a fix, and the
// DB requires a note for it.
const (
	SoDViolationOpen       = "open"
	SoDViolationAccepted   = "accepted"
	SoDViolationRemediated = "remediated"
)

// How a violation was found. A preventive row is evidence that a grant was ATTEMPTED
// and refused, which is worth keeping distinct from one a scan merely noticed.
const (
	SoDDetectedPreventive = "preventive"
	SoDDetectedDetective  = "detective"
)

// SoDRule is one separation-of-duties rule.
//
// Capabilities are named in the platform's own vocabulary — role ids and
// `resource:action` permission strings — so a rule means exactly what enforcement
// means (PG-7). A parallel vocabulary is how an SoD engine drifts from the thing it
// polices, and a drifted engine gives false assurance, which is worse than none.
type SoDRule struct {
	ID uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	// WorkspaceID nil marks a GLOBAL rule that applies in every workspace, the same
	// convention permissions use.
	WorkspaceID *uuid.UUID `json:"workspace_id,omitempty" gorm:"type:uuid"`
	Name        string     `json:"name" gorm:"not null"`
	Description string     `json:"description" gorm:"not null;default:''"`
	Kind        string     `json:"kind" gorm:"not null;default:'conflict'"`
	Severity    string     `json:"severity" gorm:"not null;default:'high'"`
	Enabled     bool       `json:"enabled" gorm:"not null;default:true"`
	// IsSystem marks a seeded, immutable rule. The self-modification control has to be
	// un-editable, or an attacker who reaches the governance API turns it off before
	// escalating.
	IsSystem     bool   `json:"is_system" gorm:"not null;default:false"`
	SubjectScope string `json:"subject_scope" gorm:"not null;default:'any'"`

	LeftLabel       string         `json:"left_label" gorm:"not null;default:''"`
	LeftRoles       pq.StringArray `json:"left_roles" gorm:"type:text[]"`
	LeftPermissions pq.StringArray `json:"left_permissions" gorm:"type:text[]"`

	RightLabel       string         `json:"right_label" gorm:"not null;default:''"`
	RightRoles       pq.StringArray `json:"right_roles" gorm:"type:text[]"`
	RightPermissions pq.StringArray `json:"right_permissions" gorm:"type:text[]"`

	Enforcement string    `json:"enforcement" gorm:"not null;default:'block'"`
	CreatedBy   string    `json:"created_by" gorm:"not null;default:''"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (SoDRule) TableName() string { return "sod_rules" }

// SoDViolation is one rule matching one subject.
//
// It records the CONFLICTING PATHS, not just a flag: a reviewer told "this subject
// violates rule X" cannot act, one told "it holds governance:admin via role
// platform-admin" can.
type SoDViolation struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	RuleID      uuid.UUID `json:"rule_id" gorm:"type:uuid;not null"`
	RuleName    string    `json:"rule_name" gorm:"not null;default:''"`

	SubjectType  string    `json:"subject_type" gorm:"not null"`
	SubjectID    uuid.UUID `json:"subject_id" gorm:"type:uuid;not null"`
	SubjectLabel string    `json:"subject_label" gorm:"not null;default:''"`

	LeftEvidence  json.RawMessage `json:"left_evidence" gorm:"type:jsonb;not null;default:'[]'"`
	RightEvidence json.RawMessage `json:"right_evidence" gorm:"type:jsonb;not null;default:'[]'"`

	Status         string     `json:"status" gorm:"not null;default:'open'"`
	ResolutionNote string     `json:"resolution_note" gorm:"not null;default:''"`
	ResolvedBy     *uuid.UUID `json:"resolved_by,omitempty" gorm:"type:uuid"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`

	DetectedAt  time.Time `json:"detected_at" gorm:"not null;default:now()"`
	LastSeenAt  time.Time `json:"last_seen_at" gorm:"not null;default:now()"`
	DetectedVia string    `json:"detected_via" gorm:"not null;default:'detective'"`
}

func (SoDViolation) TableName() string { return "sod_violations" }

// ValidSoDKinds returns the allowed rule shapes.
func ValidSoDKinds() []string { return []string{SoDKindConflict, SoDKindProhibition} }

// ValidSoDSubjectScopes returns the allowed subject populations.
func ValidSoDSubjectScopes() []string { return []string{SoDScopeAny, SoDScopeAgents, SoDScopeHumans} }

// ValidSoDEnforcements returns the allowed enforcement modes.
func ValidSoDEnforcements() []string { return []string{SoDEnforcementBlock, SoDEnforcementWarn} }

// Campaign lifecycle. draft -> active (once generated) -> closed (export frozen).
const (
	CampaignStatusDraft  = "draft"
	CampaignStatusActive = "active"
	CampaignStatusClosed = "closed"
)

// Certification decisions. 'delegate' reassigns the item and leaves it pending, because
// passing an item to somebody else is not a decision about the access.
const (
	DecisionPending  = "pending"
	DecisionKeep     = "keep"
	DecisionRevoke   = "revoke"
	DecisionDelegate = "delegate"
)

// ValidCampaignStatuses returns the allowed campaign states.
func ValidCampaignStatuses() []string {
	return []string{CampaignStatusDraft, CampaignStatusActive, CampaignStatusClosed}
}

// ValidDecisions returns the allowed item decisions.
func ValidDecisions() []string {
	return []string{DecisionPending, DecisionKeep, DecisionRevoke, DecisionDelegate}
}

// CertificationCampaign is a scoped, scheduled access review.
//
// The queue is deliberately small: PG-4 makes grants expire by default, so most access
// lapses rather than needing review. What genuinely needs certifying is the STANDING
// grants, which is why CampaignScope.StandingOnly defaults to true.
type CertificationCampaign struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	Name        string    `json:"name" gorm:"not null"`
	Description string    `json:"description" gorm:"not null;default:''"`
	// Scope is a services.CampaignScope. Stored as jsonb so a new filter dimension does
	// not need a migration.
	Scope  json.RawMessage `json:"scope" gorm:"type:jsonb;not null;default:'{}'"`
	Status string          `json:"status" gorm:"not null;default:'draft'"`
	DueAt  *time.Time      `json:"due_at,omitempty"`

	// Export is the frozen audit artifact, written at close. Stored rather than
	// recomputed: recomputing later would reflect the world as it is then, not as the
	// reviewer found it.
	Export      json.RawMessage `json:"export,omitempty" gorm:"type:jsonb"`
	GeneratedAt *time.Time      `json:"generated_at,omitempty"`
	ClosedAt    *time.Time      `json:"closed_at,omitempty"`
	ClosedBy    *uuid.UUID      `json:"closed_by,omitempty" gorm:"type:uuid"`

	ItemsTotal   int `json:"items_total" gorm:"not null;default:0"`
	ItemsDecided int `json:"items_decided" gorm:"not null;default:0"`
	ItemsKept    int `json:"items_kept" gorm:"not null;default:0"`
	ItemsRevoked int `json:"items_revoked" gorm:"not null;default:0"`

	CreatedBy string    `json:"created_by" gorm:"not null;default:''"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Overdue is derived at read time: past due with decisions outstanding.
	Overdue bool `json:"overdue" gorm:"-"`
}

func (CertificationCampaign) TableName() string { return "certification_campaigns" }

// AfterFind derives Overdue on every read, for the same reason
// DiscoverySource.AfterFind exists: a derived field is only trustworthy if every path
// that returns the row populates it.
func (c *CertificationCampaign) AfterFind(*gorm.DB) error {
	c.Overdue = c.Status == CampaignStatusActive &&
		c.DueAt != nil && c.DueAt.Before(time.Now()) &&
		c.ItemsDecided < c.ItemsTotal
	return nil
}

// CertificationItem is one entitlement under review.
//
// A SNAPSHOT, not a live join. Certifying against live data means the thing you
// approved can change under you mid-review, and the export at close would not match
// what the reviewer actually saw.
type CertificationItem struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	CampaignID  uuid.UUID `json:"campaign_id" gorm:"type:uuid;not null;index"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	// Nullable so an item survives its provenance row being removed — otherwise closing
	// a campaign could lose the very record it certified.
	EntitlementProvenanceID *uuid.UUID `json:"entitlement_provenance_id,omitempty" gorm:"type:uuid"`

	SubjectType      string          `json:"subject_type" gorm:"not null"`
	SubjectID        uuid.UUID       `json:"subject_id" gorm:"type:uuid;not null"`
	SubjectLabel     string          `json:"subject_label" gorm:"not null;default:''"`
	EntitlementLabel string          `json:"entitlement_label" gorm:"not null;default:''"`
	EntitlementType  string          `json:"entitlement_type" gorm:"not null;default:''"`
	Snapshot         json.RawMessage `json:"snapshot" gorm:"type:jsonb;not null;default:'{}'"`
	// Evidence is what turns a review into a decision rather than a rubber stamp: why
	// it was granted, whether it has ever been used, whether the workload is still
	// running, and any open SoD violation.
	Evidence json.RawMessage `json:"evidence" gorm:"type:jsonb;not null;default:'{}'"`

	// Frozen at generation, so a later ownership change cannot silently move an
	// in-flight review to somebody who never saw it.
	ReviewerUserID *uuid.UUID `json:"reviewer_user_id,omitempty" gorm:"type:uuid"`
	ReviewerLabel  string     `json:"reviewer_label" gorm:"not null;default:''"`
	ReviewerSource string     `json:"reviewer_source" gorm:"not null;default:''"`

	Decision     string     `json:"decision" gorm:"not null;default:'pending'"`
	DecisionNote string     `json:"decision_note" gorm:"not null;default:''"`
	DecidedBy    *uuid.UUID `json:"decided_by,omitempty" gorm:"type:uuid"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
	// Set when a revoke was actually carried out, so a decision that failed to execute
	// is visibly distinct from one that succeeded.
	RevocationExecutedAt *time.Time `json:"revocation_executed_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

func (CertificationItem) TableName() string { return "certification_items" }

// Instruction kinds the in-cluster agent can be asked to apply.
//
// Deliberately NOT a credential-delivery kind: AuthSec's workload identity model is
// secretless (a workload authenticates with a `spiffe-svid` assertion using an SVID it
// already holds), so governance grants access to an identity the workload HAS rather
// than shipping one to it. Nothing needs delivering.
//
// What does need in-cluster action:
//   - quarantine   — `status='quarantined'` was advisory, enforced by nothing. A
//     NetworkPolicy makes it real.
//   - verify_uptake — confirm the workload actually runs as the ServiceAccount its
//     entitlements are anchored to. If not, the grant is bound to an identity it lacks.
const (
	InstructionQuarantine   = "quarantine"
	InstructionUnquarantine = "unquarantine"
	InstructionVerifyUptake = "verify_uptake"
)

// Instruction lifecycle. 'leased' is time-bounded, so a crashed agent's work returns to
// pending rather than being lost — which is why every kind must be idempotent.
const (
	InstructionPending = "pending"
	InstructionLeased  = "leased"
	InstructionApplied = "applied"
	InstructionFailed  = "failed"
	// InstructionSuperseded is an instruction overtaken by a newer, contradicting
	// decision before it was applied — a quarantine released before the cluster agent
	// polled, typically. Kept rather than deleted: an operator asking why enforcement
	// did or did not happen needs to see that a decision was overtaken, not find a
	// gap where a row used to be.
	InstructionSuperseded = "superseded"
)

// InstructionOpen reports whether an instruction is still awaiting or undergoing
// application. Only open instructions are constrained by the one-per-key unique index,
// so a superseded row never blocks a later enqueue.
func InstructionOpen(status string) bool {
	return status == InstructionPending || status == InstructionLeased
}

// ValidInstructionKinds returns the allowed instruction kinds.
func ValidInstructionKinds() []string {
	return []string{InstructionQuarantine, InstructionUnquarantine, InstructionVerifyUptake}
}

// ProvisioningInstruction is one unit of cluster-side work.
//
// Pull-based: the control plane cannot reach into a customer's cluster and should not
// want to — an inbound connection is a hole in their network, an outbound poll is not.
type ProvisioningInstruction struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	// Which cluster is responsible. NOT nullable: queuing work for a cluster with no
	// agent looks like enforcement is pending when nothing will ever pick it up.
	DiscoverySourceID uuid.UUID       `json:"discovery_source_id" gorm:"type:uuid;not null"`
	Kind              string          `json:"kind" gorm:"not null"`
	Payload           json.RawMessage `json:"payload" gorm:"type:jsonb;not null;default:'{}'"`
	DiscoveredAgentID *uuid.UUID      `json:"discovered_agent_id,omitempty" gorm:"type:uuid"`
	Fingerprint       string          `json:"fingerprint" gorm:"not null;default:''"`
	// IdempotencyKey collapses a re-issued instruction onto the row already queued, so
	// quarantining an already-quarantined agent is a no-op rather than a second write.
	IdempotencyKey string `json:"idempotency_key" gorm:"not null"`

	Status   string `json:"status" gorm:"not null;default:'pending'"`
	Attempts int    `json:"attempts" gorm:"not null;default:0"`

	LeaseExpiresAt *time.Time `json:"lease_expires_at,omitempty"`
	LeasedBy       string     `json:"leased_by" gorm:"not null;default:''"`
	AppliedAt      *time.Time `json:"applied_at,omitempty"`
	// Result is the agent's ANSWER for a verify_uptake, not merely an acknowledgement,
	// which is why it is structured rather than a status flag.
	Result json.RawMessage `json:"result,omitempty" gorm:"type:jsonb"`
	Error  string          `json:"error" gorm:"not null;default:''"`

	CreatedBy string    `json:"created_by" gorm:"not null;default:''"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (ProvisioningInstruction) TableName() string { return "provisioning_instructions" }

// Birthright match kinds. Group-based or workspace-wide only: `users` has no department
// or title column, and matching on a field nothing populates would be a policy that
// silently never fires.
const (
	BirthrightMatchGroup = "group"
	BirthrightMatchAll   = "all"
)

// What to do when a user stops matching a birthright policy (the mover case).
//
// 'flag' is the default because a group change is ambiguous — a correction, a temporary
// secondment, or a mistake — and auto-revoking would let one mistyped membership take
// somebody's access away with nobody in the loop. Revoking is opt-in per policy.
const (
	OnUnmatchFlag   = "flag"
	OnUnmatchRevoke = "revoke"
)

// ValidBirthrightMatchKinds returns the allowed match kinds.
func ValidBirthrightMatchKinds() []string {
	return []string{BirthrightMatchGroup, BirthrightMatchAll}
}

// ValidOnUnmatch returns the allowed unmatch behaviours.
func ValidOnUnmatch() []string { return []string{OnUnmatchFlag, OnUnmatchRevoke} }

// PGInterval carries a Postgres `interval` as a time.Duration.
//
// GORM has no native interval mapping, and the driver hands back a string. Reading it as
// microseconds via EXTRACT would work but would need every query to remember to do it;
// a Scanner keeps the conversion in one place.
type PGInterval time.Duration

// Scan implements sql.Scanner for a Postgres interval.
func (d *PGInterval) Scan(value interface{}) error {
	if value == nil {
		*d = 0
		return nil
	}
	switch v := value.(type) {
	case int64:
		// Postgres integer intervals arrive as microseconds.
		*d = PGInterval(time.Duration(v) * time.Microsecond)
		return nil
	case []byte:
		return d.parse(string(v))
	case string:
		return d.parse(v)
	default:
		return fmt.Errorf("cannot scan %T into PGInterval", value)
	}
}

// parse reads the `HH:MM:SS[.ffffff]` form the driver returns, optionally preceded by a
// day count ("2 days 03:00:00"). Only the forms Postgres actually emits for an interval
// built from a Go duration are handled — anything else is rejected rather than guessed.
func (d *PGInterval) parse(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		*d = 0
		return nil
	}
	var total time.Duration

	// Leading "<n> day[s]" segments.
	fields := strings.Fields(s)
	i := 0
	for i+1 < len(fields) && (strings.HasPrefix(fields[i+1], "day") || strings.HasPrefix(fields[i+1], "mon")) {
		var n int
		if _, err := fmt.Sscanf(fields[i], "%d", &n); err != nil {
			return fmt.Errorf("interval %q: %w", s, err)
		}
		unit := 24 * time.Hour
		if strings.HasPrefix(fields[i+1], "mon") {
			unit = 30 * 24 * time.Hour // Postgres months are calendar-relative; 30d is the honest approximation here
		}
		total += time.Duration(n) * unit
		i += 2
	}
	if i < len(fields) {
		var h, m int
		var sec float64
		if _, err := fmt.Sscanf(fields[i], "%d:%d:%f", &h, &m, &sec); err != nil {
			return fmt.Errorf("interval %q: %w", s, err)
		}
		total += time.Duration(h)*time.Hour + time.Duration(m)*time.Minute +
			time.Duration(sec*float64(time.Second))
	}
	*d = PGInterval(total)
	return nil
}

// Value implements driver.Valuer, writing the interval in a form Postgres accepts.
func (d PGInterval) Value() (driver.Value, error) {
	if d == 0 {
		return nil, nil
	}
	// Seconds is unambiguous and avoids Go's "1h0m0s" form, which Postgres cannot parse.
	return fmt.Sprintf("%d seconds", int64(time.Duration(d).Seconds())), nil
}

// BirthrightPolicy is "everyone in this group gets this role on this Application".
//
// The joiner half of JML, and the thing a mover diff is computed against.
type BirthrightPolicy struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	Name        string    `json:"name" gorm:"not null"`
	Description string    `json:"description" gorm:"not null;default:''"`

	MatchKind    string     `json:"match_kind" gorm:"not null;default:'group'"`
	MatchGroupID *uuid.UUID `json:"match_group_id,omitempty" gorm:"type:uuid"`

	ResourceServerID uuid.UUID `json:"resource_server_id" gorm:"type:uuid;not null"`
	RoleID           uuid.UUID `json:"role_id" gorm:"type:uuid;not null"`

	// Duration zero means a STANDING grant, which requires a justification — the same
	// rule as everywhere else, and it matters most here because a birthright applies to
	// an entire group.
	Duration      PGInterval `json:"duration,omitempty" gorm:"type:interval"`
	Justification string     `json:"justification" gorm:"not null;default:''"`
	OnUnmatch     string     `json:"on_unmatch" gorm:"not null;default:'flag'"`

	Enabled   bool      `json:"enabled" gorm:"not null;default:true"`
	CreatedBy string    `json:"created_by" gorm:"not null;default:''"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (BirthrightPolicy) TableName() string { return "birthright_policies" }
