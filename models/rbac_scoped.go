package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// RBACRole represents a role in the RBAC system
type RBACRole struct {
	ID          uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID *uuid.UUID `json:"workspace_id" gorm:"type:uuid;uniqueIndex:idx_roles_workspace_name;index"`
	Name        string     `json:"name" gorm:"type:text;not null;uniqueIndex:idx_roles_workspace_name"`
	Description string     `json:"description" gorm:"type:text"`
	IsSystem    bool       `json:"is_system" gorm:"default:false"`
	CreatedAt   time.Time  `json:"created_at"`

	// Relations
	Permissions []RBACPermission `json:"permissions" gorm:"many2many:role_permissions;joinForeignKey:RoleID;joinReferences:PermissionID"`
}

func (RBACRole) TableName() string {
	return "roles"
}

// BeforeCreate hook ensures ID is set before inserting into database
func (r *RBACRole) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}

// RBACPermission represents an atomic resource-action capability
type RBACPermission struct {
	ID          uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID *uuid.UUID `json:"workspace_id" gorm:"type:uuid;uniqueIndex:idx_permissions_workspace_resource_action;index"`
	Resource    string     `json:"resource" gorm:"type:text;not null;uniqueIndex:idx_permissions_workspace_resource_action"`
	Action      string     `json:"action" gorm:"type:text;not null;uniqueIndex:idx_permissions_workspace_resource_action"`
	Description string     `json:"description" gorm:"type:text"`
	CreatedAt   time.Time  `json:"created_at"`
}

func (RBACPermission) TableName() string {
	return "permissions"
}

// BeforeCreate hook ensures ID is set before inserting into database
func (p *RBACPermission) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}

// RolePermission represents the many-to-many link between Roles and Permissions
type RolePermission struct {
	RoleID       uuid.UUID `json:"role_id" gorm:"type:uuid;primaryKey"`
	PermissionID uuid.UUID `json:"permission_id" gorm:"type:uuid;primaryKey"`
}

func (RolePermission) TableName() string {
	return "role_permissions"
}

// ServiceAccount represents a non-human machine principal.
// PK is (workspace_id, id) — workspace_id is non-null.
// Status starts 'disabled' and flips to 'active' once a confidential credential is attached.
type ServiceAccount struct {
	ID            uuid.UUID  `json:"id"             gorm:"type:uuid;not null;primaryKey;default:gen_random_uuid()"`
	WorkspaceID   uuid.UUID  `json:"workspace_id"   gorm:"type:uuid;not null;primaryKey"`
	Name          string     `json:"name"           gorm:"type:text;not null"`
	Description   string     `json:"description"    gorm:"type:text"`
	Status        string     `json:"status"         gorm:"type:text;not null;default:'disabled'"`
	OAuthClientID   *uuid.UUID `json:"oauth_client_id" gorm:"type:uuid;column:oauth_client_id"`
	SpiffeID        *string    `json:"spiffe_id"      gorm:"type:text"`
	ExternalSubject *string    `json:"external_subject,omitempty" gorm:"type:text"`
	OwnerEmail      *string    `json:"owner_email,omitempty"      gorm:"type:text"`
	OwnerTeam       *string    `json:"owner_team,omitempty"       gorm:"type:text"`
	LastSeenAt      *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func (ServiceAccount) TableName() string { return "service_accounts" }

// WorkloadIdentityProvider is a registered external token issuer that workloads
// authenticate with (kind 'spiffe' = a SPIRE trust domain; kind 'oidc' = a
// generic OIDC issuer such as GitHub Actions). Replaces the single global
// SPIFFE_OIDC_ISSUER env. Backing table: public.workload_identity_providers.
type WorkloadIdentityProvider struct {
	ID               uuid.UUID      `json:"id"            gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID      uuid.UUID      `json:"workspace_id"  gorm:"type:uuid;not null"`
	Name             string         `json:"name"          gorm:"type:text;not null"`
	Kind             string         `json:"kind"          gorm:"type:text;not null;default:'spiffe'"`
	Issuer           string         `json:"issuer"        gorm:"type:text;not null"`
	JWKSUri          *string        `json:"jwks_uri,omitempty"     gorm:"type:text"`
	TrustDomain      *string        `json:"trust_domain,omitempty" gorm:"type:text"`
	AllowedAudiences pq.StringArray `json:"allowed_audiences" gorm:"type:text[];default:'{}'"`
	SubjectClaim     string         `json:"subject_claim" gorm:"type:text;not null;default:'sub'"`
	Status           string         `json:"status"        gorm:"type:text;not null;default:'active'"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

func (WorkloadIdentityProvider) TableName() string { return "workload_identity_providers" }

// RoleBinding represents an assignment of a Role to a Principal
// (User, Group, or Service Account). Migration 111 added group_id; exactly one
// of UserID / GroupID / ServiceAccountID must be set, enforced by the
// check_principal CHECK constraint on the table.
type RoleBinding struct {
	ID                 uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID        *uuid.UUID      `json:"workspace_id" gorm:"type:uuid;index"`
	UserID             *uuid.UUID      `json:"user_id" gorm:"type:uuid"`
	Username           string          `json:"username" gorm:"type:text"`
	GroupID            *uuid.UUID      `json:"group_id" gorm:"type:uuid"`
	ServiceAccountID   *uuid.UUID      `json:"service_account_id" gorm:"type:uuid"`
	RoleID             uuid.UUID       `json:"role_id" gorm:"type:uuid;not null"`
	RoleName           string          `json:"role_name" gorm:"type:text"`
	ScopeType          *string         `json:"scope_type" gorm:"type:text"`
	ScopeID            *uuid.UUID      `json:"scope_id" gorm:"type:uuid"`
	Conditions         json.RawMessage `json:"conditions" gorm:"type:jsonb;default:'{}'"`
	AssignmentSource   string          `json:"assignment_source" gorm:"type:text;not null;default:'manual'"`
	AssignmentMetadata json.RawMessage `json:"assignment_metadata" gorm:"type:jsonb;default:'{}'"`
	ExpiresAt          *time.Time      `json:"expires_at"`
	CreatedBy          *uuid.UUID      `json:"created_by" gorm:"type:uuid"`
	CreatedAt          time.Time       `json:"created_at"`

	// Relations
	// We need to be careful with GORM relationships and composite keys.
	// Since the DB enforces composite keys, we should reflect that here if we want GORM to handle preloading correctly.
	// However, for simple referencing, standard ID referencing works if the DB constraint handles the integrity.
	Role           *RBACRole       `json:"role,omitempty" gorm:"foreignKey:RoleID;references:ID"`
	User           *ExtendedUser   `json:"user,omitempty" gorm:"foreignKey:UserID;references:ID"`
	Group          *Group          `json:"group,omitempty" gorm:"foreignKey:GroupID;references:ID"`
	ServiceAccount *ServiceAccount `json:"service_account,omitempty" gorm:"foreignKey:ServiceAccountID;references:ID"`
}

// SubjectType returns "user" | "group" | "service_account" based on which
// principal column is set. Returns empty string if the row is malformed.
func (rb *RoleBinding) SubjectType() string {
	switch {
	case rb.UserID != nil:
		return "user"
	case rb.GroupID != nil:
		return "group"
	case rb.ServiceAccountID != nil:
		return "service_account"
	default:
		return ""
	}
}

// SubjectID returns the non-nil principal id corresponding to SubjectType.
func (rb *RoleBinding) SubjectID() *uuid.UUID {
	switch {
	case rb.UserID != nil:
		return rb.UserID
	case rb.GroupID != nil:
		return rb.GroupID
	case rb.ServiceAccountID != nil:
		return rb.ServiceAccountID
	default:
		return nil
	}
}

func (RoleBinding) TableName() string {
	return "role_bindings"
}

// GrantAudit represents the audit log for role assignments
// Note: This table was removed in the migration to ensure strict schema adherence to the prompt.
// If it's not in the prompt, I should probably remove it or keep it separate.
// The prompt didn't ask for it, but didn't forbid it. I dropped it in the migration.
// So I will remove the struct to avoid confusion.
