package sharedmodels

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// RoleCreateRequest captures role metadata plus permission mapping for creation.
type RoleCreateRequest struct {
	Name          string      `json:"name" binding:"required"`
	Description   string      `json:"description"`
	IsSystem      bool        `json:"is_system"`
	PermissionIDs []uuid.UUID `json:"permission_ids"`
}

// RoleUpdateRequest mirrors RoleCreateRequest for updates.
type RoleUpdateRequest struct {
	Name          string      `json:"name"`
	Description   string      `json:"description"`
	IsSystem      bool        `json:"is_system"`
	PermissionIDs []uuid.UUID `json:"permission_ids"`
}

// RoleBindingCreateRequest represents a set of bindings to create in bulk.
type RoleBindingCreateRequest struct {
	PrincipalIDs  []uuid.UUID    `json:"principal_ids" binding:"required"`
	PrincipalType string         `json:"principal_type" binding:"required,oneof=user service_account"`
	RoleID        uuid.UUID      `json:"role_id" binding:"required"`
	ScopeType     *string        `json:"scope_type"`
	ScopeID       *uuid.UUID     `json:"scope_id"`
	ExpiresAt     *time.Time     `json:"expires_at"`
	Conditions    datatypes.JSON `json:"conditions"`
}

// ScopeCreateRequest captures scope metadata and mapped permission IDs.
type ScopeCreateRequest struct {
	Name                string      `json:"name" binding:"required"`
	Description         string      `json:"description"`
	MappedPermissionIDs []uuid.UUID `json:"mapped_permission_ids" binding:"required"`
}

// PolicyCheckRequest defines the payload for scoped policy checks.
type PolicyCheckRequest struct {
	PrincipalID uuid.UUID  `json:"principal_id" binding:"required"`
	Resource    string     `json:"resource" binding:"required"`
	Action      string     `json:"action" binding:"required"`
	ScopeID     *uuid.UUID `json:"scope_id"`
}
