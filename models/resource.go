package models

import "time"

// ResourceRecord represents a resource row with UUID identifiers.
type ResourceRecord struct {
	ID          string     `json:"id"`
	WorkspaceID    *string    `json:"workspace_id,omitempty"`
	Name        string     `json:"name"`
	Description *string    `json:"description,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}
