// Package models — workspace membership and end-user state.
//
// Two distinct kinds of users coexist in AuthSec:
//
//  1. Workspace members (operators) — modeled via workspace_memberships table
//     with a role_id FK. Managed by the membership controller + RequireWorkspaceRole
//     middleware. See models/workspace.go for the WorkspaceMembership struct.
//
//  2. TenantEndUserState — consumers of a workspace's published Applications.
//     Created lazily on first OAuth consent. Governs suspension, plan tier,
//     and rate-limit overrides. Checked by ScopeResolver at consent time.
package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Membership status enum values (shared by workspace_memberships and end-user states).
const (
	MembershipStatusActive    = "active"
	MembershipStatusInvited   = "invited"
	MembershipStatusSuspended = "suspended"
	MembershipStatusLeft      = "left"
)

// Membership type values — used by the membership controller to resolve role names.
// These map to roles.name in the workspace's roles table.
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
	MembershipSourceSignup  = "signup"
	MembershipSourceInvite  = "invite"
	MembershipSourceSCIM    = "scim"
	MembershipSourceOIDCJIT = "oidc_jit"
	MembershipSourceSAMLJIT = "saml_jit"
	MembershipSourceAPI     = "api"
	MembershipSourceManual  = "manual"
)

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
// Created lazily on first consent. Primary key is (workspace_id, user_id).
type TenantEndUserState struct {
	WorkspaceID          uuid.UUID       `json:"workspace_id" gorm:"type:uuid;primaryKey"`
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
	return "workspace_end_user_states"
}

// IsActive returns true when the end user is not suspended for this tenant.
func (s *TenantEndUserState) IsActive() bool {
	return s.Status == EndUserStatusActive
}
