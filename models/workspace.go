package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	WorkspaceTypePersonal = "personal"
	WorkspaceTypeTeam     = "team"
)

type Workspace struct {
	ID            uuid.UUID `json:"id" gorm:"type:uuid;primaryKey"`
	Name          string    `json:"name" gorm:"type:text;not null"`
	Slug          string    `json:"slug" gorm:"type:text;uniqueIndex"`
	OwnerUserID   uuid.UUID `json:"owner_user_id" gorm:"type:uuid;not null"`
	WorkspaceType string    `json:"workspace_type" gorm:"type:text;not null;default:'personal'"`
	CreatedAt     time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt     time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

func (Workspace) TableName() string {
	return "workspaces"
}

func (w *Workspace) BeforeCreate(tx *gorm.DB) error {
	if w.ID == uuid.Nil {
		w.ID = uuid.New()
	}
	if w.WorkspaceType == "" {
		w.WorkspaceType = WorkspaceTypePersonal
	}
	return nil
}

type WorkspaceMembership struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;uniqueIndex:idx_workspace_memberships_workspace_user"`
	UserID      uuid.UUID `json:"user_id" gorm:"type:uuid;not null;uniqueIndex:idx_workspace_memberships_workspace_user"`
	RoleID      uuid.UUID `json:"role_id" gorm:"type:uuid;not null"`
	Status      string    `json:"status" gorm:"type:text;not null;default:'active'"`
	CreatedAt   time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

func (WorkspaceMembership) TableName() string {
	return "workspace_memberships"
}

func (m *WorkspaceMembership) BeforeCreate(tx *gorm.DB) error {
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	if m.Status == "" {
		m.Status = MembershipStatusActive
	}
	return nil
}
