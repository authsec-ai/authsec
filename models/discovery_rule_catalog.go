package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// DiscoveryRuleCatalog is a workspace's overlay on the built-in detection
// patterns.
//
// It stores DELTAS, never a copy of the shipped catalogue. A workspace that
// adds one action marker keeps receiving every marker shipped in later
// releases; had the full list been stored, customising once would freeze that
// workspace on that day's vocabulary and it would quietly stop benefiting from
// the catalogue improving. See 009_discovery_rule_catalogs.sql.
type DiscoveryRuleCatalog struct {
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;primaryKey"`

	// Overlay is the add/remove configuration. Its shape is validated in Go
	// before write; see services/iga_rule_catalog_config.go.
	Overlay json.RawMessage `json:"overlay" gorm:"type:jsonb;not null;default:'{}'"`

	// BasedOn records which built-in catalogue version the overlay was authored
	// against, so a later built-in change that conflicts can be reported rather
	// than silently resolved.
	BasedOn string `json:"based_on" gorm:"not null;default:''"`

	// OverlayHash is the content fingerprint. Combined with the built-in
	// version it forms the effective catalogue version stamped on findings.
	OverlayHash string `json:"overlay_hash" gorm:"not null;default:''"`

	UpdatedBy string    `json:"updated_by" gorm:"not null;default:''"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName pins the table; GORM's pluraliser would otherwise guess.
func (DiscoveryRuleCatalog) TableName() string { return "discovery_rule_catalogs" }
