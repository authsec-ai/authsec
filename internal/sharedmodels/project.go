package sharedmodels

import (
	"time"

	"github.com/google/uuid"
)

type Project struct {
	ID          uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty" gorm:"index"`
	Name        string         `gorm:"not null"`
	Description string
	UserID      uuid.UUID `gorm:"type:uuid"`
	TenantID    uuid.UUID `gorm:"type:uuid"`
	Active      bool      `gorm:"default:true"`
}

// ProjectInput represents the input for creating a new project
type ProjectInput struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
}

type ProjectResponse struct {
	ID          uuid.UUID  `json:"id"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	UserID      uuid.UUID  `json:"user_id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	Active      bool       `json:"active"`
	User        struct {
		ID    uuid.UUID `json:"id"`
		Email string    `json:"email"`
		Name  string    `json:"name"`
	} `json:"user"`
}
