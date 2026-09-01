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

/* ============================================================================
   Ticket [2]: cloud_assume_edge, cloud_permission, cloud_resource.
   ========================================================================= */

// Who may assume an identity. Five values because the shared cross-cloud note
// splits "another account" into a SPECIFIC known principal (identity) and an
// unnamed one (external_account, including a bare account id, an account root
// ARN, or "*") -- a distinction collapsed by ticket [2]'s own summary text but
// not by the schema it points at.
const (
	AssumeSubjectCloudService = "cloud_service"
	AssumeSubjectIdentity     = "identity"
	AssumeSubjectK8sSA        = "k8s_service_account"
	AssumeSubjectCIPipeline   = "ci_pipeline"
	AssumeSubjectExternal     = "external_account"
)

// How the assumption happens, not who is assuming. AWS has exactly two: a
// static trust-policy principal (sts:AssumeRole), and a Federated principal
// (sts:AssumeRoleWithWebIdentity) -- which covers BOTH k8s_service_account and
// ci_pipeline, told apart by subject_kind and issuer rather than by mechanism.
const (
	AssumeMechanismSTSAssumeRole  = "sts_assume_role"
	AssumeMechanismOIDCFederation = "oidc_federation"
)

// ValidAssumeSubjectKinds returns the allowed subject kinds.
func ValidAssumeSubjectKinds() []string {
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
