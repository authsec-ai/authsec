package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Cloud discovery providers. One connector row per onboarded scope, and the
// provider is a value in a column rather than a separate table per cloud — the
// whole point of the shared cross-cloud schema.
const (
	CloudProviderAWS   = "aws"
	CloudProviderGCP   = "gcp"
	CloudProviderAzure = "azure"
)

// What kind of scope was onboarded. AWS onboards an account; GCP may onboard an
// org, a folder or a project; Azure onboards a subscription with its tenant in
// ParentScopeID.
const (
	CloudScopeAccount      = "account"
	CloudScopeProject      = "project"
	CloudScopeFolder       = "folder"
	CloudScopeOrg          = "org"
	CloudScopeSubscription = "subscription"
)

// Connector lifecycle.
//
//   - active  — assumable, and proven so at VerifiedAt
//   - error   — the last attempt to use it failed; LastError says how. NOT a
//     reason to delete anything the connector previously found: a broken
//     connection is "we cannot look right now", never "it is gone".
//   - revoked — the customer withdrew access, or an operator disconnected it
const (
	CloudConnectorActive  = "active"
	CloudConnectorRevoked = "revoked"
	CloudConnectorError   = "error"
)

// ValidCloudProviders returns the allowed providers.
func ValidCloudProviders() []string {
	return []string{CloudProviderAWS, CloudProviderGCP, CloudProviderAzure}
}

// ValidCloudScopeKinds returns the allowed scope kinds.
func ValidCloudScopeKinds() []string {
	return []string{
		CloudScopeAccount, CloudScopeProject, CloudScopeFolder,
		CloudScopeOrg, CloudScopeSubscription,
	}
}

// ValidCloudConnectorStatuses returns the allowed connector statuses.
func ValidCloudConnectorStatuses() []string {
	return []string{CloudConnectorActive, CloudConnectorRevoked, CloudConnectorError}
}

// CloudConnector is one onboarded cloud account, project or subscription.
// Every other cloud discovery row points at one of these, and reconciliation is
// driven by ScanGeneration.
//
// UNIQUE(workspace_id, provider, scope_id) makes re-onboarding an account an
// update rather than a second row. Two rows for one account would split its
// inventory in half and bill every scan twice.
//
// AuthRef is a HANDLE and nothing else. No column in the cloud discovery schema
// accepts a secret value; for AWS this is the secrets-store path holding the
// ExternalId, and the role ARN — which is not secret — lives in Attrs so it
// stays queryable without a round trip to the store.
type CloudConnector struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	Provider    string    `json:"provider" gorm:"not null"`
	ScopeKind   string    `json:"scope_kind" gorm:"not null"`
	ScopeID     string    `json:"scope_id" gorm:"not null"`
	// ParentScopeID is a pointer, not a string, because the shared schema says
	// null. A connector writing '' where another writes NULL breaks IS NULL for
	// every reader of the shared table.
	ParentScopeID *string `json:"parent_scope_id,omitempty"`

	// AuthRef is json:"-" deliberately. It is not itself a secret, but it is the
	// address of one, and an API response is the wrong place to publish where a
	// workspace's credentials live.
	AuthRef string `json:"-" gorm:"not null;default:''"`

	Status         string          `json:"status" gorm:"not null;default:'active'"`
	ScanGeneration int             `json:"scan_generation" gorm:"not null;default:0"`
	Coverage       json.RawMessage `json:"coverage" gorm:"type:jsonb;not null;default:'{}'"`
	Attrs          json.RawMessage `json:"attrs" gorm:"type:jsonb;not null;default:'{}'"`

	// VerifiedAt is when the connection was last PROVEN — the role actually
	// assumed and the identity read back — as opposed to merely edited. Nil
	// means never proven, which is not the same as broken.
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	LastError  string     `json:"last_error" gorm:"not null;default:''"`

	CreatedBy string    `json:"created_by" gorm:"not null;default:''"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName pins the singular name. GORM would pluralise to cloud_connectors,
// but the name is a contract with the Azure and GCP connectors, which are not
// built in this repository and are writing against `cloud_connector`.
func (CloudConnector) TableName() string { return "cloud_connector" }

// Per-surface coverage states, written into CloudConnector.Coverage.
//
// The whole reason this exists is that "could not read" and "found nothing" are
// different answers and neither one means "clean". A scan that was denied IAM
// and reports zero identities must never be rendered as an account with no
// identities.
const (
	CloudCoverageReached       = "reached"
	CloudCoverageDenied        = "denied"
	CloudCoverageThrottled     = "throttled"
	CloudCoverageNotConfigured = "not_configured"

	// CloudCoverageUnknown is the state a surface starts in, before any scan
	// has touched it. It exists so onboarding can pre-create the full surface
	// list rather than leaving coverage empty: an absent surface and a surface
	// that returned nothing look identical to a reader, and only one of them
	// means the estate is clean.
	CloudCoverageUnknown = "unknown"

	// CloudCoverageConstrained is a read that failed BY DESIGN -- an org
	// policy or a VPC Service Controls perimeter refused it. Distinct from
	// denied, which is a missing grant: denied is fixed by granting a role,
	// constrained is a deliberate decision by the customer and asking them to
	// grant something would be the wrong conversation.
	CloudCoverageConstrained = "constrained"

	// CloudCoverageStale is data carried over from an earlier generation
	// because this scan could not refresh it. Present so a partial scan can
	// keep prior findings visible without claiming it re-confirmed them.
	CloudCoverageStale = "stale"
)

// Overall scan outcome.
//
//   - running  — in flight
//   - complete — every surface reached; this is the ONLY state in which
//     reconciliation may age a row out
//   - partial  — finished, but at least one surface was denied or throttled
//   - failed   — could not start, or died before any surface completed
const (
	ScanStatusRunning  = "running"
	ScanStatusComplete = "complete"
	ScanStatusPartial  = "partial"
	ScanStatusFailed   = "failed"
)

// The AWS surfaces ticket [1] reads. Named per (region, surface) elsewhere;
// IAM is global, so these carry no region.
const (
	SurfaceIAMRoles      = "iam_roles"
	SurfaceIAMUsers      = "iam_users"
	SurfaceIAMAccessKeys = "iam_access_keys"
	SurfaceIAMPolicies   = "iam_policies"
)

// SurfaceCoverage is what one scan managed against one surface.
type SurfaceCoverage struct {
	State string `json:"state"`
	// Count is how many objects were read. Only meaningful when State is
	// reached — a count from a denied surface is a floor, not a total.
	Count int `json:"count"`
	// Error is the provider's own words when State is not reached.
	Error string `json:"error,omitempty"`
}

// ScanCoverage is the typed shape of CloudConnector.Coverage: the durable
// report of what a scan could and could not read.
//
// It lives in the connector's jsonb rather than a scan_runs table because the
// shared cross-cloud schema puts it there, and because the question it answers
// ("is the current inventory trustworthy?") is about the connector's present
// state, not about scan history.
type ScanCoverage struct {
	Generation int                        `json:"generation"`
	Status     string                     `json:"status"`
	StartedAt  *time.Time                 `json:"started_at,omitempty"`
	FinishedAt *time.Time                 `json:"finished_at,omitempty"`
	Surfaces   map[string]SurfaceCoverage `json:"surfaces,omitempty"`
	Counters   map[string]int             `json:"counters,omitempty"`
	// Error is set only when Status is failed.
	Error string `json:"error,omitempty"`
}

// Complete reports whether every surface was reached. Reconciliation is gated
// on this: a scan that could not look everywhere has not earned the right to
// conclude that anything is gone.
func (c ScanCoverage) Complete() bool {
	if len(c.Surfaces) == 0 {
		return false
	}
	for _, s := range c.Surfaces {
		if s.State != CloudCoverageReached {
			return false
		}
	}
	return true
}

// DecodeScanCoverage reads a connector's coverage blob. A malformed or absent
// blob decodes to a zero value rather than an error: coverage is a report, and
// an unreadable report must not stop a scan from producing a fresh one.
func DecodeScanCoverage(raw json.RawMessage) ScanCoverage {
	var c ScanCoverage
	if len(raw) == 0 {
		return c
	}
	_ = json.Unmarshal(raw, &c)
	return c
}

// Identity kinds. The real provider object name, never an AuthSec abstraction —
// an operator reading "iam_role" knows exactly what to go and look at.
const (
	CloudIdentityIAMRole = "iam_role"
	CloudIdentityIAMUser = "iam_user"
)

// Secret kinds.
const (
	CloudSecretAccessKey = "access_key"
)

// Secret status, in the provider's own words.
const (
	CloudSecretActive   = "active"
	CloudSecretInactive = "inactive"
)

// CloudIdentity is what code runs as: an IAM role, an IAM user, a GCP service
// account, an Azure service principal.
//
// It is the CANDIDATE POOL, not a list of agents — no cloud has a list-agents
// API. Nothing in this table asserts that anything is an agent; classification
// happens later and writes discovered_agents, which points here.
//
// UNIQUE(workspace_id, native_id) implements the shared schema's rule: one
// identity, one row, matched on native_id, so two connectors seeing the same
// principal update the same row rather than forking it.
type CloudIdentity struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	ConnectorID uuid.UUID `json:"connector_id" gorm:"type:uuid;not null"`

	Kind     string `json:"kind" gorm:"not null"`
	NativeID string `json:"native_id" gorm:"not null"`
	Name     string `json:"name" gorm:"not null;default:''"`

	// ProviderCreatedAt maps to the column `created_at`, which by the shared
	// schema's definition holds the PROVIDER's creation time.
	//
	// The Go field is deliberately NOT named CreatedAt: GORM auto-populates a
	// field with that name using the insert time, which would overwrite the
	// provider's value with today's date on every write — turning "this role is
	// five years old" into "this role is new", the exact inversion of the
	// finding this column exists to support.
	ProviderCreatedAt *time.Time `json:"created_at,omitempty" gorm:"column:created_at"`

	// LastUsedAt nil means UNKNOWN, never "never used".
	LastUsedAt *time.Time      `json:"last_used_at,omitempty"`
	Enabled    bool            `json:"enabled" gorm:"not null;default:true"`
	Attrs      json.RawMessage `json:"attrs" gorm:"type:jsonb;not null;default:'{}'"`

	LastSeenGeneration int       `json:"last_seen_generation" gorm:"not null;default:0"`
	FirstSeenAt        time.Time `json:"first_seen_at" gorm:"not null;default:now()"`
	LastSeenAt         time.Time `json:"last_seen_at" gorm:"not null;default:now()"`
	RowUpdatedAt       time.Time `json:"row_updated_at" gorm:"not null;default:now()"`
}

func (CloudIdentity) TableName() string { return "cloud_identity" }

// AWSIdentityAttrs is the AWS shape of CloudIdentity.Attrs.
type AWSIdentityAttrs struct {
	// UniqueID is the AWS-assigned immutable id: AROA... for a role, AIDA... for
	// a user. Not the join key — every policy document and every other connector
	// refers to the ARN — but kept because a role deleted and recreated under
	// the same name has the SAME ARN and a DIFFERENT unique id. Without this
	// there is no way to notice the principal is not the one we saw last week.
	UniqueID string `json:"unique_id,omitempty"`
	// Path is the IAM path, e.g. "/service-role/".
	Path string `json:"path,omitempty"`
	// Description is the role description, where one is set.
	Description string `json:"description,omitempty"`
	// MaxSessionDuration is seconds, roles only.
	MaxSessionDuration int32 `json:"max_session_duration,omitempty"`
	// Tags carry ownership hints. Names AND values are kept here: unlike an
	// environment variable, an IAM tag is metadata by construction — it is what
	// the ownership question in the AWS plan's section 10 reads.
	Tags map[string]string `json:"tags,omitempty"`
	// HasTrustPolicy records that a role carried an AssumeRolePolicyDocument.
	// The document itself is parsed in the next ticket into cloud_assume_edge;
	// this is only the flag that says there is something to parse.
	HasTrustPolicy bool `json:"has_trust_policy,omitempty"`
}

// AWSAttrs decodes Attrs as the AWS shape.
func (i *CloudIdentity) AWSAttrs() AWSIdentityAttrs {
	var a AWSIdentityAttrs
	if len(i.Attrs) == 0 {
		return a
	}
	_ = json.Unmarshal(i.Attrs, &a)
	return a
}

// SetAWSAttrs encodes the AWS shape into Attrs.
func (i *CloudIdentity) SetAWSAttrs(a AWSIdentityAttrs) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	i.Attrs = raw
	return nil
}

// CloudSecret is a long-lived secret that proves an identity. Metadata only —
// there is deliberately no column anywhere that accepts a value, so the
// guarantee is structural rather than a convention this code has to remember.
//
// NativeID holds a key IDENTIFIER (an AWS access key id), which appears in
// CloudTrail and in the credential report. It is not the key.
type CloudSecret struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	ConnectorID uuid.UUID `json:"connector_id" gorm:"type:uuid;not null"`
	IdentityID  uuid.UUID `json:"identity_id" gorm:"type:uuid;not null"`

	Kind     string `json:"kind" gorm:"not null"`
	NativeID string `json:"native_id" gorm:"not null"`

	// ProviderCreatedAt maps to `created_at` — the provider's creation time.
	// Age is the finding. See CloudIdentity.ProviderCreatedAt for why the Go
	// field is not called CreatedAt.
	ProviderCreatedAt *time.Time `json:"created_at,omitempty" gorm:"column:created_at"`
	// ExpiresAt is nil where the provider has no expiry. Every AWS access key is
	// in that case, which is precisely why its age matters.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// LastUsedAt nil means UNKNOWN. AWS reports a never-used key by omitting the
	// date, and the scanner must not turn that into a zero timestamp.
	LastUsedAt *time.Time      `json:"last_used_at,omitempty"`
	Status     string          `json:"status" gorm:"not null;default:'active'"`
	Attrs      json.RawMessage `json:"attrs" gorm:"type:jsonb;not null;default:'{}'"`

	LastSeenGeneration int       `json:"last_seen_generation" gorm:"not null;default:0"`
	FirstSeenAt        time.Time `json:"first_seen_at" gorm:"not null;default:now()"`
	LastSeenAt         time.Time `json:"last_seen_at" gorm:"not null;default:now()"`
	RowUpdatedAt       time.Time `json:"row_updated_at" gorm:"not null;default:now()"`
}

func (CloudSecret) TableName() string { return "cloud_secret" }

// AWSConnectorAttrs is the AWS shape of CloudConnector.Attrs.
//
// These are the three things AWS onboarding cannot work without and that the
// shared column list has nowhere for. Kept as a typed struct rather than loose
// map access so a misspelt key fails to compile instead of silently reading as
// empty on the next scan.
type AWSConnectorAttrs struct {
	// DisplayName is the operator's label for the account. Cosmetic; ScopeID is
	// the identity.
	DisplayName string `json:"display_name,omitempty"`

	// RoleARN is the read-only cross-account role AuthSec assumes. Not secret —
	// it is a public identifier printed in the CloudFormation output — so it is
	// stored here rather than behind AuthRef, where every scan would have to pay
	// a secrets-store read to learn which role to assume.
	RoleARN string `json:"role_arn,omitempty"`

	// Partition is aws | aws-us-gov | aws-cn, taken from the role ARN. It decides
	// which endpoints and which managed-policy ARNs apply.
	Partition string `json:"partition,omitempty"`

	// Regions in scope, operator-selected. Scan cost grows with regions x
	// services, so the selection has to be recorded with the connector that made
	// it — and a later scan must report coverage against THIS list, not against
	// every region AWS happens to have enabled.
	Regions []string `json:"regions,omitempty"`

	// CallerARN is what sts:GetCallerIdentity returned the last time the
	// connection was proven: the assumed-role ARN, not the role ARN. Evidence of
	// what we actually became, kept because it is the only thing that
	// distinguishes "the role exists" from "we can use it".
	CallerARN string `json:"caller_arn,omitempty"`

	// TemplateVersion is the CloudFormation template the customer deployed, as
	// last reported. When we add a permission for a new surface, this is how an
	// operator finds the accounts still on the older stack.
	TemplateVersion string `json:"template_version,omitempty"`
}

// AWSAttrs decodes Attrs as the AWS shape. A malformed or empty blob decodes to
// a zero struct rather than an error: Attrs is provider extras, and a connector
// must stay listable even if one key is unreadable.
func (c *CloudConnector) AWSAttrs() AWSConnectorAttrs {
	var a AWSConnectorAttrs
	if len(c.Attrs) == 0 {
		return a
	}
	_ = json.Unmarshal(c.Attrs, &a)
	return a
}

// SetAWSAttrs encodes the AWS shape into Attrs.
func (c *CloudConnector) SetAWSAttrs(a AWSConnectorAttrs) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	c.Attrs = raw
	return nil
}

// Capability limits recorded on a GCP connector: things this connector will
// never be able to do, as opposed to things that merely failed once.
//
// They exist so discovery reports a shortfall as a KNOWN BOUNDARY rather than
// as an absence of data. Without GCPLimitOAuthProjectScopeOnly, a
// project-scoped connector that reports no organization bindings is
// indistinguishable from an organization that genuinely has none.
const (
	// GCPLimitOAuthProjectScopeOnly: onboarded through Google Authentication,
	// which can only offer projects because Google’s project search returns
	// projects and not organizations or folders. Nothing above this project
	// was ever in scope.
	GCPLimitOAuthProjectScopeOnly = "oauth_project_scope_only"

	// GCPLimitKeyedCredential: authenticates with a stored service-account
	// key rather than federation. No new connector can be created this way;
	// the flag marks the ones that already exist.
	GCPLimitKeyedCredential = "keyed_credential"

	// GCPLimitQuotaProjectUnusable: the reader cannot use the quota project
	// every Cloud Asset call bills against, so the CAI-backed surfaces will
	// fail regardless of how readable the scope itself is.
	GCPLimitQuotaProjectUnusable = "quota_project_unusable"
)

// How a GCP connector was onboarded. Recorded explicitly rather than inferred
// from auth method and provisioning provenance, which between them could
// express manual_wif only as "neither of the other two" — an absence rather
// than a value, and one that reads identically to a field nobody set.
const (
	GCPOnboardingPathOAuthDefault = "oauth_default"
	GCPOnboardingPathManualWIF    = "manual_wif"
	GCPOnboardingPathManualKey    = "manual_key"
)

// Whether this connector is ready for discovery to scan it.
const (
	// GCPReadinessReady: every P1 surface probed reachable, the P1 APIs are
	// on, and the quota project is usable.
	GCPReadinessReady = "ready"
	// GCPReadinessPartial: it will scan, but some surfaces are closed. Which
	// ones is in the reasons and in the capability profile.
	GCPReadinessPartial = "partial"
	// GCPReadinessBlocked: nothing can scan. The credential does not resolve,
	// the scope is unreadable, or the quota project every Cloud Asset call
	// bills against is unusable.
	GCPReadinessBlocked = "blocked"
)

// GCPOnboardingHints is customer-declared context no GCP API returns.
//
// Every field is optional and none of it affects what gets scanned. It matters
// afterwards: ownership resolution has to attribute a finding to a team, and a
// naming convention is often the only signal left when labels are absent.
// Captured at onboarding because that is the one moment somebody who knows the
// answer is present — asking later means guessing.
type GCPOnboardingHints struct {
	// Environment is the customer's own word for this scope: prod, staging,
	// sandbox. Their vocabulary rather than a fixed enum — an estate that
	// calls it "live" should not be made to say "prod".
	Environment string `json:"environment,omitempty"`
	// EnvironmentLabels are the resource label KEYS that carry the
	// environment, so ownership resolution knows which label to read instead
	// of guessing between "env", "environment" and "stage".
	EnvironmentLabels []string `json:"environment_labels,omitempty"`
	// NamingConvention is free text describing how they name things.
	NamingConvention string `json:"naming_convention,omitempty"`
	// OwningTeam is the team accountable for this scope, as the fallback when
	// nothing more specific resolves.
	OwningTeam string `json:"owning_team,omitempty"`
	// OwnerContact is how to reach them — a group address or a channel.
	OwnerContact string `json:"owner_contact,omitempty"`
}

// GCPSurfaceCapability is what a live permission probe found for ONE
// discovery surface, recorded on the connector so a scan knows before it
// starts which surfaces it can read.
//
// Can and Unknown are deliberately separate booleans rather than a single
// tri-state string, because the difference is load-bearing: Can=false means
// the probe ran and the reader provably lacks a permission, while
// Unknown=true means the probe could not answer at all. Collapsing the second
// into the first would render "we could not check" as "there is nothing
// there", which is the exact failure the coverage rules exist to prevent.
type GCPSurfaceCapability struct {
	// Can is true only when every permission the surface needs was held.
	Can bool `json:"can"`
	// Missing lists the permissions the reader did NOT hold. Meaningful only
	// when Unknown is false.
	Missing []string `json:"missing,omitempty"`
	// Unknown is set when the probe itself could not answer — the API refused
	// the check, or rejected a permission name it does not recognise at this
	// resource type. Never treat this as "no access".
	Unknown bool `json:"unknown,omitempty"`
	// Reason is a short, sanitized explanation when Unknown is set.
	Reason string `json:"reason,omitempty"`
}

// GCPConnectorAttrs is the GCP shape of CloudConnector.Attrs — the WIF analog
// of AWSConnectorAttrs, per prompt.md's GCP-D9 design. Everything here is
// non-secret: a project id, a service-account email, a GCP resource name, or
// AuthSec's own deterministic derivation of one. No column or field anywhere
// in this struct accepts key material — the json_key path's key bytes never
// reach this struct, only a reference to where they live in Vault
// (CloudConnector.AuthRef, not Attrs).
type GCPConnectorAttrs struct {
	// DisplayName is the operator's label for the connector. Cosmetic; ScopeID
	// is the identity.
	DisplayName string `json:"display_name,omitempty"`

	// AuthMethod is "json_key" or "wif" — see GCPAuthMethodJSONKey/
	// GCPAuthMethodWIF in services/gcp_auth_service.go. Recorded here (not just
	// inferable from AuthRef's prefix) so a reader never has to parse AuthRef
	// to answer "how is this connector authenticated".
	AuthMethod string `json:"auth_method,omitempty"`

	// ReaderProjectID is the reader service account's home project — distinct
	// from ScopeID, since a service account always has a home project even
	// when its IAM grants are at org/folder scope (GCP-D9, point 2).
	ReaderProjectID string `json:"reader_project_id,omitempty"`

	// ReaderSAEmail is the reader service account's email, as the customer
	// pasted it back (json_key: parsed from the uploaded key's client_email;
	// wif: the second of the two values GCP-D9's flow has the customer paste).
	ReaderSAEmail string `json:"reader_sa_email,omitempty"`

	// WIFProviderResource is the full WIF provider resource name the customer
	// pasted back. Empty for a json_key connector. The one fact AuthSec cannot
	// derive itself (it embeds the GCP project NUMBER) — see GCP-D9's naming/
	// pool-ownership note.
	WIFProviderResource string `json:"wif_provider_resource,omitempty"`

	// WIFSubject is the deterministic subject internal/gcp.DeriveWIFParams
	// computed for this (workspace, scope) pair — durable so every later
	// scan/verify call can re-derive the same value without re-deriving it
	// from scratch or storing it twice inconsistently.
	WIFSubject string `json:"wif_subject,omitempty"`

	// PoolID and ProviderID are internal/gcp.DeriveWIFParams's other two
	// outputs, stored for the same reason as WIFSubject: so a later read never
	// has to re-derive what was already derived once at CreateConnector time.
	PoolID     string `json:"pool_id,omitempty"`
	ProviderID string `json:"provider_id,omitempty"`

	// CAIQuotaProject is the project Cloud Asset Inventory calls bill against.
	// Per authsec/docs/gcp/feasibility-validation.md's STEP 4 finding, this is
	// ReaderProjectID by default — recorded explicitly rather than re-derived
	// by every later scan call, mirroring why WIFSubject/PoolID/ProviderID are
	// stored rather than recomputed.
	CAIQuotaProject string `json:"cai_quota_project,omitempty"`

	// RoleSetStatus records which reader role set this connector was set up
	// against: "confirmed" once GCP-01's feasibility ledger reaches COMPLETE,
	// "candidate_pending_GCP-01" until then (see internal/gcp.RoleSetStatus).
	// Recorded per connector so an operator can find connectors set up
	// against an earlier, still-candidate role set once GCP-01 closes.
	RoleSetStatus string `json:"role_set_status,omitempty"`

	// RoleSetVersion is the internal/gcp.ReaderRoleSetVersion this connector's
	// reader roles were granted from -- a stable hand-bumped label, not a
	// derived value. Distinct from RoleSetStatus, which says how confident we
	// are in the set, and from SetupScriptVersion, which versions the script
	// rather than the roles: two connectors can share a script version and
	// hold different roles if the script was re-rendered for a different scope
	// kind. This is the field that answers "which roles does this connector
	// actually have", which is what decides whether a discovery phase can run.
	RoleSetVersion string `json:"role_set_version,omitempty"`

	// CapabilityProfile is the per-surface result of the last live permission
	// probe, keyed by surface name. This is what E4.1/E4.2 ask for: what the
	// reader was PROVED to reach, rather than what the setup script was
	// supposed to grant. Empty means never probed — not "reaches nothing".
	CapabilityProfile map[string]GCPSurfaceCapability `json:"capability_profile,omitempty"`

	// ProbedPermissions is every permission the last probe found the reader
	// actually holds, flattened across surfaces. Kept alongside the profile
	// because the profile answers "can this phase run" while this answers
	// "what exactly is granted", and an operator investigating a surprise
	// needs the second.
	ProbedPermissions []string `json:"probed_permissions,omitempty"`

	// WritePermissionsHeld is the zero-write assurance, inverted: it must be
	// empty. Anything here means the reader identity holds a permission that
	// can change customer state, which is a finding, not a configuration
	// detail. Recorded rather than merely logged so it is auditable after the
	// fact.
	WritePermissionsHeld []string `json:"write_permissions_held,omitempty"`

	// APIEnablement is the state of every API discovery reads, keyed by API
	// host name: "enabled", "not_enabled" or "unknown". Recorded so coverage
	// accounting can start before the first call, and so "the API is off" is
	// distinguishable from "we were denied" — two different conversations to
	// have with a customer, only one of which is anybody's fault.
	//
	// "unknown" is a real value, not a gap to be tidied up: a reader without
	// serviceusage.services.list cannot tell, and recording that as
	// "not_enabled" would read identically to the truth while being invented.
	APIEnablement map[string]string `json:"api_enablement,omitempty"`

	// APIEnablementRepaired records whether this onboarding path was able to
	// ENABLE what was missing, or could only report it. The manual federation
	// path holds no credential that can write, so it always reports; the
	// Google Authentication path repairs. Without this, an operator cannot
	// tell "nothing needed fixing" from "we could not fix anything".
	APIEnablementRepaired bool `json:"api_enablement_repaired,omitempty"`

	// CapabilityLimits are the GCPLimit* constants that apply to this
	// connector — permanent boundaries, not transient failures. Discovery
	// reads these to describe a shortfall honestly instead of reporting an
	// empty result as an empty estate.
	CapabilityLimits []string `json:"capability_limits,omitempty"`

	// ScopeEnumeration is whether, and how, the reader can walk the tree
	// below the onboarded scope. Load-bearing for an org or folder connector:
	// one whose reader cannot enumerate can read exactly one resource, and a
	// scan on it would report a nearly empty estate with nothing actually
	// wrong. Shaped as internal/gcp.ScopeEnumeration.
	ScopeEnumeration json.RawMessage `json:"scope_enumeration,omitempty"`

	// OnboardingPath is one of the GCPOnboardingPath* constants. Reporting has
	// to tell the three apart: they differ in what they were able to
	// configure, and therefore in what a shortfall on this connector means.
	OnboardingPath string `json:"onboarding_path,omitempty"`

	// Hints are what the customer told us at onboarding that no API reports.
	Hints *GCPOnboardingHints `json:"hints,omitempty"`

	// DiscoveryReadiness is one of the GCPReadiness* constants, DERIVED from
	// the probe evidence above rather than maintained independently. It exists
	// so a scheduler can skip a blocked connector by reading one field, rather
	// than re-deriving the judgement from four others and possibly disagreeing
	// with the console about what it found.
	DiscoveryReadiness string `json:"discovery_readiness,omitempty"`

	// DiscoveryReadinessReasons names what pushed readiness below ready, and
	// is empty when ready. Without it the value is a verdict with no argument
	// attached, which gives an operator nothing to act on.
	DiscoveryReadinessReasons []string `json:"discovery_readiness_reasons,omitempty"`

	// ProbedAt is when the capability profile was last refreshed. Nil means
	// never probed. Distinct from VerifiedAt on the row, which says the
	// credential worked, not what it can reach.
	ProbedAt *time.Time `json:"probed_at,omitempty"`

	// SetupScriptVersion is the internal/gcp.Version the customer's script was
	// rendered from — the WIF/json_key analog of AWS's TemplateVersion, same
	// reason: lets an operator find connectors still on an older script once
	// the role set or binding shape changes.
	SetupScriptVersion string `json:"setup_script_version,omitempty"`

	// ProvisionedVia and ProvisionedBy are additive provenance metadata for
	// the Google Authentication onboarding option (services/gcp_oauth_
	// provision_service.go): they record HOW a WIF connector's GCP-side
	// resources were configured, never a second auth method — AuthMethod
	// above still reads "wif" for a connector provisioned this way, and its
	// persistent credential is still the ordinary ResolveWIFCredential path.
	// Both fields are omitted (empty string, indistinguishable from a
	// manually-onboarded connector on every other field) unless a connector
	// was actually created through that option. ProvisionedBy deliberately
	// reuses the same AuthSec actor identifier already recorded on
	// CloudConnector.CreatedBy — never a Google account email or any other
	// Google identity detail, per this option's minimum-necessary-
	// persistence design: the transient Google identity used for the
	// one-time OAuth consent lives only in a short-lived Redis session and
	// the audit trail, never here.
	ProvisionedVia string `json:"provisioned_via,omitempty"`
	ProvisionedBy  string `json:"provisioned_by,omitempty"`
}

// GCPAttrs decodes Attrs as the GCP shape. A malformed or empty blob decodes
// to a zero struct rather than an error, for the same reason AWSAttrs does:
// Attrs is provider extras, and a connector must stay listable even if one
// key is unreadable.
func (c *CloudConnector) GCPAttrs() GCPConnectorAttrs {
	var a GCPConnectorAttrs
	if len(c.Attrs) == 0 {
		return a
	}
	_ = json.Unmarshal(c.Attrs, &a)
	return a
}

// SetGCPAttrs encodes the GCP shape into Attrs.
func (c *CloudConnector) SetGCPAttrs(a GCPConnectorAttrs) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	c.Attrs = raw
	return nil
}

/* ============================================================================
   Ticket [2]: cloud_assume_edge, cloud_permission, cloud_resource.
   ========================================================================= */

// Who may assume an identity. These are the five values AWS writes today --
// the shared cross-cloud note splits "another account" into a SPECIFIC known
// principal (identity) and an unnamed one (external_account, including a bare
// account id, an account root ARN, or "*"), a distinction collapsed by ticket
// [2]'s own summary text but not by the schema it points at.
//
// NOT a closed set. cloud_assume_edge.subject_kind has no CHECK enumerating
// these -- see the migration's header -- because GCP and Azure both have
// federation and impersonation shapes that do not fit AWS's five. These
// constants exist so AWS's own code never hand-types the string, not to
// declare every value another connector may write.
const (
	AssumeSubjectCloudService = "cloud_service"
	AssumeSubjectIdentity     = "identity"
	AssumeSubjectK8sSA        = "k8s_service_account"
	AssumeSubjectCIPipeline   = "ci_pipeline"
	AssumeSubjectExternal     = "external_account"
)

// How the assumption happens, not who is assuming. Two come from a trust
// policy: a static principal (sts:AssumeRole), and a Federated principal
// (sts:AssumeRoleWithWebIdentity) -- which covers BOTH k8s_service_account and
// ci_pipeline, told apart by subject_kind and issuer rather than by mechanism.
//
// The third is not in any trust policy. EKS Pod Identity binds a service
// account to a role through an EKS association resource, and the role's trust
// policy names only the pods.eks.amazonaws.com service principal -- so the
// service account is invisible to a trust-policy read and the mechanism has to
// be recorded distinctly. See internal/awsdiscovery/eks.go.
//
// Also not a closed set -- see AssumeSubject* above. GCP service-account
// impersonation, for one, is none of these three.
const (
	AssumeMechanismSTSAssumeRole  = "sts_assume_role"
	AssumeMechanismOIDCFederation = "oidc_federation"
	AssumeMechanismEKSPodIdentity = "eks_pod_identity"
)

// KnownAWSAssumeSubjectKinds returns the subject kinds AWS's own scanner
// writes. Not an exhaustive list of legal values -- see the constants' own
// comment -- useful for a console filter or a validation warning, not for a
// database constraint.
func KnownAWSAssumeSubjectKinds() []string {
	return []string{
		AssumeSubjectCloudService, AssumeSubjectIdentity, AssumeSubjectK8sSA,
		AssumeSubjectCIPipeline, AssumeSubjectExternal,
	}
}

// CloudAssumeEdge is one principal in an identity's trust policy: who may
// become it, and how.
//
// UNIQUE(identity_id, subject_kind, subject) is the upsert's conflict target --
// a trust policy re-read on every scan updates the same row rather than
// duplicating a principal that has not changed.
type CloudAssumeEdge struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	ConnectorID uuid.UUID `json:"connector_id" gorm:"type:uuid;not null"`
	IdentityID  uuid.UUID `json:"identity_id" gorm:"type:uuid;not null"`

	SubjectKind string `json:"subject_kind" gorm:"not null"`
	// Subject is the provider's own string, stored verbatim: a service
	// principal, a principal ARN, an account id/root ARN/"*", or an OIDC
	// subject claim.
	Subject string `json:"subject" gorm:"not null"`
	// Issuer is the OIDC issuer host, no scheme. Nil for an sts_assume_role
	// edge, which has no issuer.
	Issuer    *string `json:"issuer,omitempty"`
	Mechanism string  `json:"mechanism" gorm:"not null"`
	// K8sRef is set only for AssumeSubjectK8sSA, format
	// system:serviceaccount:<ns>:<sa> -- the exact string the Kubernetes
	// connector already records for the same pod.
	K8sRef *string         `json:"k8s_ref,omitempty"`
	Attrs  json.RawMessage `json:"attrs" gorm:"type:jsonb;not null;default:'{}'"`

	LastSeenGeneration int       `json:"last_seen_generation" gorm:"not null;default:0"`
	FirstSeenAt        time.Time `json:"first_seen_at" gorm:"not null;default:now()"`
	LastSeenAt         time.Time `json:"last_seen_at" gorm:"not null;default:now()"`
	RowUpdatedAt       time.Time `json:"row_updated_at" gorm:"not null;default:now()"`
}

func (CloudAssumeEdge) TableName() string { return "cloud_assume_edge" }

// Resource and permission sensitivity. A starting heuristic per the AWS plan's
// section 5: Secrets Manager, KMS and IAM are high; everything else is low.
// 'med' exists for a later ticket that refines this from tags or activity.
const (
	SensitivityLow    = "low"
	SensitivityMedium = "med"
	SensitivityHigh   = "high"
)

// CloudResource is the thing a grant points at. A row exists only because a
// cloud_permission statement named it -- nothing here scans an account for
// resources on its own.
type CloudResource struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	ConnectorID uuid.UUID `json:"connector_id" gorm:"type:uuid;not null"`

	// Kind is typed by service, e.g. "s3_bucket", "dynamodb_table". Text, not an
	// enum -- a schema-wide enum of every AWS resource type would need a
	// migration for every new service AWS ships.
	Kind        string `json:"kind" gorm:"not null"`
	NativeID    string `json:"native_id" gorm:"not null"`
	Name        string `json:"name" gorm:"not null;default:''"`
	Sensitivity string `json:"sensitivity" gorm:"not null;default:'low'"`

	LastSeenGeneration int       `json:"last_seen_generation" gorm:"not null;default:0"`
	FirstSeenAt        time.Time `json:"first_seen_at" gorm:"not null;default:now()"`
	LastSeenAt         time.Time `json:"last_seen_at" gorm:"not null;default:now()"`
	RowUpdatedAt       time.Time `json:"row_updated_at" gorm:"not null;default:now()"`
}

func (CloudResource) TableName() string { return "cloud_resource" }

// Permission scope. Never expand a broad scope into the children it might
// cover -- scope_kind IS the record of the breadth, not an invitation to
// enumerate it.
const (
	PermissionScopeResource     = "resource"
	PermissionScopePrefix       = "prefix"
	PermissionScopeAccountWide  = "account_wide"
	PermissionEffectAllow       = "allow"
	PermissionEffectDeny        = "deny"
	PermissionPlaneCloud        = "cloud"
	PermissionPlaneAPI          = "api"
	PermissionDerivationGranted = "granted"
	// PermissionDerivationEffective is not written by ticket [2]. Computing
	// effective access needs service control policies, permission boundaries
	// and session policies evaluated together, which the AWS plan's section 2
	// puts out of scope. The value exists so a later ticket can add effective
	// rows without a schema change.
	PermissionDerivationEffective = "effective"
)

// CloudPermission is one grant: an identity may take these actions against
// that resource (or scope, when ResourceID is nil).
//
// UNIQUE(identity_id, native_id, resource_id) is the conflict target. NativeID
// already identifies the source statement; ResourceID completes the key for a
// statement naming more than one resource, which becomes one row per resource
// sharing the same NativeID.
type CloudPermission struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	ConnectorID uuid.UUID `json:"connector_id" gorm:"type:uuid;not null"`
	IdentityID  uuid.UUID `json:"identity_id" gorm:"type:uuid;not null"`
	// ResourceID is nil on a wildcard or prefix grant. Never set to fill in a
	// resource that was not independently named.
	ResourceID *uuid.UUID `json:"resource_id,omitempty" gorm:"type:uuid"`

	Plane  string `json:"plane" gorm:"not null;default:'cloud'"`
	Effect string `json:"effect" gorm:"not null"`
	// RoleName is always nil for AWS. The shared schema names the column for
	// Azure's RBAC role assignments, which have one; an IAM policy statement
	// does not.
	RoleName   *string        `json:"role_name,omitempty"`
	Actions    pq.StringArray `json:"actions" gorm:"type:text[];not null"`
	ScopeKind  string         `json:"scope_kind" gorm:"not null"`
	Derivation string         `json:"derivation" gorm:"not null;default:'granted'"`

	Sensitivity string `json:"sensitivity" gorm:"not null;default:'low'"`
	// LastExercisedAt is aggregated from cloud_usage by a later ticket. Always
	// nil as written by ticket [2].
	LastExercisedAt *time.Time `json:"last_exercised_at,omitempty"`
	// NativeID is where the grant came from: a managed policy ARN, or
	// "inline:<policy name>" for one defined on the identity directly, suffixed
	// with the statement's position so two statements in one document do not
	// collide.
	NativeID string `json:"native_id" gorm:"not null"`

	LastSeenGeneration int       `json:"last_seen_generation" gorm:"not null;default:0"`
	FirstSeenAt        time.Time `json:"first_seen_at" gorm:"not null;default:now()"`
	LastSeenAt         time.Time `json:"last_seen_at" gorm:"not null;default:now()"`
	RowUpdatedAt       time.Time `json:"row_updated_at" gorm:"not null;default:now()"`
}

func (CloudPermission) TableName() string { return "cloud_permission" }

/* ------------------------------ cloud_workload ---------------------------- */

// Runtime kinds AWS discovery writes. Text in the schema, not an enum -- see
// migration 015's header on why a new AWS compute service must not need a
// migration.
const (
	WorkloadLambdaFunction     = "lambda_function"
	WorkloadECSTaskDefinition  = "ecs_task_definition"
	WorkloadEC2Instance        = "ec2_instance"
	WorkloadBedrockAgent       = "bedrock_agent"
	WorkloadBedrockAgentCoreRT = "bedrock_agentcore_runtime"
)

// CloudWorkload is compute that RUNS AS a cloud identity: a Lambda function, an
// ECS task definition, an EC2 instance, a Bedrock agent.
//
// It is not an identity and not an agent. It is the observation that this
// compute exists and runs as this role; whether it constitutes an agent is a
// later judgement, and migration 015's header explains why that judgement is
// deliberately not encoded here.
type CloudWorkload struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	ConnectorID uuid.UUID `json:"connector_id" gorm:"type:uuid;not null"`

	// IdentityID is the role this compute runs as, nil when the workload could
	// not be attributed to a role this scan discovered. Nil is a finding --
	// compute nobody can tie to an identity -- not a broken row.
	IdentityID *uuid.UUID `json:"identity_id,omitempty" gorm:"type:uuid"`

	RuntimeKind string `json:"runtime_kind" gorm:"not null"`
	NativeID    string `json:"native_id" gorm:"not null"`
	Name        string `json:"name" gorm:"not null;default:''"`
	// Region matters here in a way it never did for IAM: every service in this
	// table is regional, and one name can be two workloads in two regions.
	Region string          `json:"region" gorm:"not null;default:''"`
	Attrs  json.RawMessage `json:"attrs" gorm:"type:jsonb;not null;default:'{}'"`

	LastSeenGeneration int       `json:"last_seen_generation" gorm:"not null;default:0"`
	FirstSeenAt        time.Time `json:"first_seen_at" gorm:"not null;default:now()"`
	LastSeenAt         time.Time `json:"last_seen_at" gorm:"not null;default:now()"`
	RowUpdatedAt       time.Time `json:"row_updated_at" gorm:"not null;default:now()"`
}

func (CloudWorkload) TableName() string { return "cloud_workload" }

// AWSWorkloadAttrs is the AWS shape of CloudWorkload.Attrs.
//
// Never holds a secret value. EnvVarNames exists because AWS returns Lambda
// environment variable VALUES with the function and offers no way to ask for
// names only -- the values are dropped at parse time and only the names reach
// this struct.
type AWSWorkloadAttrs struct {
	// ExecutionRoleARN is ECS's executionRoleArn or a Lambda's role as reported
	// by the service. For ECS this is deliberately NOT the identity: the task
	// role is what the application acts as, and attributing container
	// permissions to the execution role would report the wrong permissions.
	ExecutionRoleARN string `json:"execution_role_arn,omitempty"`
	// InstanceProfileARN is EC2 only. EC2 names an instance profile, a thin
	// wrapper holding exactly one role, so resolving it costs an extra call.
	InstanceProfileARN string `json:"instance_profile_arn,omitempty"`
	// EnvVarNames are Lambda environment variable names. NEVER values.
	EnvVarNames []string `json:"env_var_names,omitempty"`
	// FoundationModel is the Bedrock agent's model id.
	FoundationModel string `json:"foundation_model,omitempty"`
	// Status is the provider's own lifecycle string, verbatim.
	Status string `json:"status,omitempty"`
	// UnresolvedRoleARN records a role the workload names that this scan could
	// not find in inventory, so an unattributed row still says which role it
	// was looking for.
	UnresolvedRoleARN string `json:"unresolved_role_arn,omitempty"`
}

// AWSAttrs decodes the AWS attrs, returning the zero value on anything
// unparseable rather than failing a read.
func (w *CloudWorkload) AWSAttrs() AWSWorkloadAttrs {
	var a AWSWorkloadAttrs
	if len(w.Attrs) == 0 {
		return a
	}
	_ = json.Unmarshal(w.Attrs, &a)
	return a
}

// SetAWSAttrs encodes the AWS attrs.
func (w *CloudWorkload) SetAWSAttrs(a AWSWorkloadAttrs) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	w.Attrs = raw
	return nil
}

/* -------------------------------- cloud_usage ----------------------------- */

// Where a usage row's evidence came from. The two support different claims:
// service-last-accessed is per service, CloudTrail is per call.
const (
	UsageSourceServiceLastAccessed = "service_last_accessed"
	UsageSourceCloudTrail          = "cloudtrail"
)

// CloudUsage is evidence that an identity actually exercised a service, as
// opposed to merely being permitted to.
//
// The grain is (identity, service, source) because that is the grain AWS
// reports -- see migration 016's header on why a per-action grain would be
// invented precision.
type CloudUsage struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	ConnectorID uuid.UUID `json:"connector_id" gorm:"type:uuid;not null"`
	IdentityID  uuid.UUID `json:"identity_id" gorm:"type:uuid;not null"`

	// Service is the AWS namespace as AWS reports it: "s3", "dynamodb".
	Service string `json:"service" gorm:"not null"`
	// LastUsedAt nil means AWS reports the service was NEVER accessed in the
	// tracking window. That is the most actionable row in the table, not
	// missing data -- a service that could not be read produces no row at all.
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	Source     string     `json:"source" gorm:"not null;default:'service_last_accessed'"`
	// GeneratedAt is when AWS produced the report, which can be materially
	// older than the scan that stored it.
	GeneratedAt *time.Time      `json:"generated_at,omitempty"`
	Attrs       json.RawMessage `json:"attrs" gorm:"type:jsonb;not null;default:'{}'"`

	LastSeenGeneration int       `json:"last_seen_generation" gorm:"not null;default:0"`
	FirstSeenAt        time.Time `json:"first_seen_at" gorm:"not null;default:now()"`
	LastSeenAt         time.Time `json:"last_seen_at" gorm:"not null;default:now()"`
	RowUpdatedAt       time.Time `json:"row_updated_at" gorm:"not null;default:now()"`
}

func (CloudUsage) TableName() string { return "cloud_usage" }

/* --------------------------- cloud_scan_checkpoint ------------------------ */

// Resumable scan phases. Free text in the schema -- see migration 017's header
// on why an unrecognised phase must be inert rather than an error.
const (
	// ScanPhaseIdentityPolicies is the per-identity policy fetch: the phase
	// that costs roughly seven calls per identity and dominates a large scan.
	ScanPhaseIdentityPolicies = "identity_policies"
	// ScanPhaseActivity is the per-identity service-last-accessed report job.
	ScanPhaseActivity = "activity"
)

// ScanPhaseWorkloads names the per-region workload phase for one region.
func ScanPhaseWorkloads(region string) string { return "workloads:" + region }

// CloudScanCheckpoint records how far one phase of one scan attempt got, so an
// interrupted scan resumes instead of repeating thousands of AWS calls.
//
// Cursor is the last item the phase finished, in that phase's deterministic
// sort order. Resuming skips everything at or before it -- safe because those
// items' rows were already written and stamped with this same generation.
type CloudScanCheckpoint struct {
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	ConnectorID uuid.UUID `json:"connector_id" gorm:"type:uuid;primaryKey"`
	Generation  int       `json:"generation" gorm:"primaryKey"`
	Phase       string    `json:"phase" gorm:"primaryKey"`

	Cursor    string    `json:"cursor" gorm:"not null;default:''"`
	DoneCount int       `json:"done_count" gorm:"not null;default:0"`
	UpdatedAt time.Time `json:"updated_at" gorm:"not null;default:now()"`
}

func (CloudScanCheckpoint) TableName() string { return "cloud_scan_checkpoint" }
