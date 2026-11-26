package models

import "time"

// Tenant is a workspace row as the embedded SPIRE control plane sees it.
type Tenant struct {
	ID         string    `json:"id" db:"id"`
	Name       string    `json:"name" db:"name"`
	VaultMount string    `json:"vault_mount" db:"vault_mount"`
	Domain     string    `json:"workspace_domain" db:"workspace_domain"`
	Status     string    `json:"status" db:"status"` // active, suspended, deleted
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`
}

// IsActive checks if the tenant is active
func (t *Tenant) IsActive() bool {
	return t.Status == "active"
}
