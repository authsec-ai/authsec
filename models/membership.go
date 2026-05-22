// Package models — tenant membership and end-user state.
//
// Two distinct kinds of users coexist in AuthSec; this file models both:
//
//  1. TenantMembership — operators with operational rights inside the tenant
//     (Owner, Admin, Member, Contractor, Service Operator, Readonly Auditor).
//     One row per (tenant, user). Members are managed under Settings → Team
//     in the admin UI and are the subject of admin-tier role bindings.
//
//  2. TenantEndUserState — consumers of a tenant's published Applications.
//     End users have a global identity (currently the per-tenant users row;
//     Phase D migrates this to a global identities table) and a tenant-scoped
//     state object that captures plan tier, status, and rate-limit overrides.
//     End users are NOT modeled as members.
//
// Backed by migrations 108 and 109.
package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Membership status enum values.
const (
	MembershipStatusActive    = "active"
	MembershipStatusInvited   = "invited"
	MembershipStatusSuspended = "suspended"
	MembershipStatusLeft      = "left"
)

// Membership type enum values. These describe the lifecycle/relationship of an
// operator to a tenant. They are NOT the same thing as RBAC roles — a member
// of type "admin" still needs a role binding to actually receive permissions.
const (
	MembershipTypeOwner           = "owner"
	MembershipTypeAdmin           = "admin"
	MembershipTypeMember          = "member"
	MembershipTypeContractor      = "contractor"
	MembershipTypeServiceOperator = "service_operator"
	MembershipTypeReadonlyAuditor = "readonly_auditor"
)

// Membership source enum values — how the membership was created.
const (
	MembershipSourceSignup    = "signup"
	MembershipSourceInvite    = "invite"
	MembershipSourceSCIM      = "scim"
	MembershipSourceOIDCJIT   = "oidc_jit"
	MembershipSourceSAMLJIT   = "saml_jit"
	MembershipSourceAPI       = "api"
	MembershipSourceMigration = "migration"
)

// TenantMembership models a user's operational relationship with a tenant.
// One row per (tenant_id, user_id).
type TenantMembership struct {
	ID             uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	TenantID       uuid.UUID  `json:"tenant_id" gorm:"type:uuid;not null;uniqueIndex:idx_tm_tenant_user"`
	UserID         uuid.UUID  `json:"user_id" gorm:"type:uuid;not null;uniqueIndex:idx_tm_tenant_user"`
	Status         string     `json:"status" gorm:"type:text;not null;default:'active'"`
	MembershipType string     `json:"membership_type" gorm:"type:text;not null;default:'member'"`
	Source         string     `json:"source" gorm:"type:text;not null;default:'manual'"`
	ExternalID     *string    `json:"external_id,omitempty" gorm:"type:text"`
	InvitedBy      *uuid.UUID `json:"invited_by,omitempty" gorm:"type:uuid"`
	JoinedAt       *time.Time `json:"joined_at,omitempty"`
	SuspendedAt    *time.Time `json:"suspended_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt      time.Time  `json:"updated_at" gorm:"autoUpdateTime"`
}

// TableName overrides the default GORM table name (would otherwise pluralize to "tenant_memberships" anyway).
func (TenantMembership) TableName() string {
	return "tenant_memberships"
}

// IsActive returns true when the membership is in a state that should pass
// the membership-status precheck during scope resolution.
func (m *TenantMembership) IsActive() bool {
	return m.Status == MembershipStatusActive
}

// End-user state status enum values.
const (
	EndUserStatusActive    = "active"
	EndUserStatusSuspended = "suspended"
)

// Plan tier helpers. Values are tenant-defined; these are the conventional
// defaults Phase E uses for plan-based role assignment.
const (
	EndUserPlanFree   = "free"
	EndUserPlanPro    = "pro"
	EndUserPlanCustom = "custom"
)

// TenantEndUserState models the per-(tenant, user) state of an end user
// (a consumer who has consented to one of the tenant's published Applications).
// Created lazily on first consent. Primary key is (tenant_id, user_id).
type TenantEndUserState struct {
	TenantID          uuid.UUID       `json:"tenant_id" gorm:"type:uuid;primaryKey"`
	UserID            uuid.UUID       `json:"user_id" gorm:"type:uuid;primaryKey"`
	Status            string          `json:"status" gorm:"type:text;not null;default:'active'"`
	PlanTier          *string         `json:"plan_tier,omitempty" gorm:"type:text"`
	RateLimitOverride json.RawMessage `json:"rate_limit_override,omitempty" gorm:"type:jsonb"`
	FirstConsentAt    time.Time       `json:"first_consent_at" gorm:"autoCreateTime"`
	LastSeenAt        *time.Time      `json:"last_seen_at,omitempty"`
	SuspendedAt       *time.Time      `json:"suspended_at,omitempty"`
	SuspendedBy       *uuid.UUID      `json:"suspended_by,omitempty" gorm:"type:uuid"`
	SuspendedReason   *string         `json:"suspended_reason,omitempty" gorm:"type:text"`
	CreatedAt         time.Time       `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt         time.Time       `json:"updated_at" gorm:"autoUpdateTime"`
}

func (TenantEndUserState) TableName() string {
	return "tenant_end_user_states"
}

// IsActive returns true when the end user is not suspended for this tenant.
func (s *TenantEndUserState) IsActive() bool {
	return s.Status == EndUserStatusActive
}
