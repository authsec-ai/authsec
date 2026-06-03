package models

import (
	"time"

	"github.com/google/uuid"
)

// ResourceServerTenantIndex maps a public resource_uri to the tenant that owns
// the Application row in its tenant DB. The DCR handler consults this index
// before it can route the rest of the request to the right tenant DB.
type ResourceServerTenantIndex struct {
	ResourceURI      string    `json:"resource_uri" gorm:"primaryKey;type:text"`
	TenantID         uuid.UUID `json:"tenant_id" gorm:"type:uuid;not null;index"`
	ResourceServerID uuid.UUID `json:"resource_server_id" gorm:"type:uuid;not null"`
	Active           bool      `json:"active" gorm:"not null;default:true;index"`
	CreatedAt        time.Time `json:"created_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
	UpdatedAt        time.Time `json:"updated_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
}

func (ResourceServerTenantIndex) TableName() string { return "resource_server_tenant_index" }
