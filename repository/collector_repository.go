package repositories

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrCollectorNotFound is returned when a credential or enrollment does not exist.
var ErrCollectorNotFound = errors.New("collector record not found")

// CollectorRepository reads and writes the M1 collector tables.
type CollectorRepository struct {
	db *gorm.DB
}

// NewCollectorRepository constructs a repository on db.
func NewCollectorRepository(db *gorm.DB) *CollectorRepository {
	return &CollectorRepository{db: db}
}

// DB returns the underlying handle, which may be a transaction.
func (r *CollectorRepository) DB() *gorm.DB { return r.db }

// With returns a repository bound to tx.
func (r *CollectorRepository) With(tx *gorm.DB) *CollectorRepository {
	return &CollectorRepository{db: tx}
}

func collectorNotFound(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrCollectorNotFound
	}
	return err
}

// FindEnrollmentByTokenHash loads an enrollment by the stored hash.
func (r *CollectorRepository) FindEnrollmentByTokenHash(hash string) (*models.CollectorEnrollment, error) {
	var row models.CollectorEnrollment
	err := r.db.Where("token_hash = ?", hash).First(&row).Error
	if err != nil {
		return nil, collectorNotFound(err)
	}
	return &row, nil
}

// LockEnrollmentByID locks an enrollment by its primary key. The token hash
// already proved which row it is; the lock closes the use-versus-retry race.
func (r *CollectorRepository) LockEnrollmentByID(id uuid.UUID) (*models.CollectorEnrollment, error) {
	var row models.CollectorEnrollment
	err := r.db.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ?", id).
		First(&row).Error
	if err != nil {
		return nil, collectorNotFound(err)
	}
	return &row, nil
}

// LockEnrollment loads and locks one enrollment row inside a workspace.
func (r *CollectorRepository) LockEnrollment(workspaceID, id uuid.UUID) (*models.CollectorEnrollment, error) {
	var row models.CollectorEnrollment
	err := r.db.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("workspace_id = ? AND id = ?", workspaceID, id).
		First(&row).Error
	if err != nil {
		return nil, collectorNotFound(err)
	}
	return &row, nil
}

// FindRecovery loads the encrypted response for one key+nonce pair.
func (r *CollectorRepository) FindRecovery(enrollmentID uuid.UUID, keyHash string) (*models.CollectorEnrollmentRecovery, error) {
	var row models.CollectorEnrollmentRecovery
	err := r.db.Where("enrollment_id = ? AND key_hash = ?", enrollmentID, keyHash).First(&row).Error
	if err != nil {
		return nil, collectorNotFound(err)
	}
	return &row, nil
}

// AuthenticatedCollector is a live credential and its instance.
type AuthenticatedCollector struct {
	Credential models.CollectorCredential
	Instance   models.CollectorInstance
}

// AuthenticateCredential resolves a credential hash. Expired, revoked and
// unknown credentials all fail. The caller maps every failure to 401.
func (r *CollectorRepository) AuthenticateCredential(hash string, now time.Time) (*AuthenticatedCollector, error) {
	var cred models.CollectorCredential
	err := r.db.Where("credential_hash = ?", hash).First(&cred).Error
	if err != nil {
		return nil, collectorNotFound(err)
	}
	if cred.RevokedAt != nil || !cred.ExpiresAt.After(now) {
		return nil, ErrCollectorNotFound
	}
	var inst models.CollectorInstance
	err = r.db.Where("id = ? AND workspace_id = ?", cred.CollectorID, cred.WorkspaceID).First(&inst).Error
	if err != nil {
		return nil, collectorNotFound(err)
	}
	if inst.Status != models.CollectorStatusActive || inst.RevokedAt != nil {
		return nil, ErrCollectorNotFound
	}
	return &AuthenticatedCollector{Credential: cred, Instance: inst}, nil
}

// GetInstance loads one collector in a workspace.
func (r *CollectorRepository) GetInstance(workspaceID, id uuid.UUID) (*models.CollectorInstance, error) {
	var row models.CollectorInstance
	err := r.db.Where("workspace_id = ? AND id = ?", workspaceID, id).First(&row).Error
	if err != nil {
		return nil, collectorNotFound(err)
	}
	return &row, nil
}

// LockInstance locks one collector row for revoke or rotation.
func (r *CollectorRepository) LockInstance(workspaceID, id uuid.UUID) (*models.CollectorInstance, error) {
	var row models.CollectorInstance
	err := r.db.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("workspace_id = ? AND id = ?", workspaceID, id).
		First(&row).Error
	if err != nil {
		return nil, collectorNotFound(err)
	}
	return &row, nil
}

// LegacyIngressDisabled reports the per-workspace switch. A missing row is off.
// Undefined-table (migration 038 not applied) is also off, so a database that
// has not migrated keeps the legacy routes working.
func (r *CollectorRepository) LegacyIngressDisabled(workspaceID uuid.UUID) (bool, error) {
	var disabled bool
	err := r.db.Raw(`SELECT legacy_discovery_ingress_disabled
		FROM workspace_collector_settings WHERE workspace_id = ?`, workspaceID).Row().Scan(&disabled)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		if isUndefinedTable(err) {
			return false, nil
		}
		return false, err
	}
	return disabled, nil
}

// SetLegacyIngress upserts the per-workspace switch.
func (r *CollectorRepository) SetLegacyIngress(workspaceID uuid.UUID, disabled bool, updatedBy string, now time.Time) error {
	row := models.WorkspaceCollectorSettings{
		WorkspaceID:                    workspaceID,
		LegacyDiscoveryIngressDisabled: disabled,
		UpdatedAt:                      now,
		UpdatedBy:                      updatedBy,
	}
	return r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "workspace_id"}},
		DoUpdates: clause.Assignments(map[string]any{
			"legacy_discovery_ingress_disabled": disabled,
			"updated_at":                        now,
			"updated_by":                        updatedBy,
		}),
	}).Create(&row).Error
}

// DiscoveryTrust is the trust label of one discovered_agents row.
type DiscoveryTrust struct {
	Name  string
	Trust string
}

// PolicyEvidenceFromDiscovery reads discovered_agents trust labels. The caller
// must pass the result through services.SelectPolicyInputs before using it.
func (r *CollectorRepository) PolicyEvidenceFromDiscovery(workspaceID uuid.UUID) ([]DiscoveryTrust, error) {
	rows, err := r.db.Raw(`SELECT display_name, evidence_trust
		FROM discovered_agents WHERE workspace_id = ?`, workspaceID).Rows()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []DiscoveryTrust
	for rows.Next() {
		var item DiscoveryTrust
		if err := rows.Scan(&item.Name, &item.Trust); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// CountByWorkspace counts rows in a known table for one workspace.
// table must be one of the collector tables this package owns; it is checked
// against an allowlist so it cannot be used as a SQL injection sink.
func (r *CollectorRepository) CountByWorkspace(table string, workspaceID uuid.UUID) (int64, error) {
	switch table {
	case "collector_enrollments", "collector_instances", "collector_credentials",
		"collector_integrations", "collector_batches", "discovered_agents",
		"iga_relationship", "iga_agents", "discovery_sources":
	default:
		return 0, errors.New("refusing to count unknown table")
	}
	var n int64
	err := r.db.Raw(`SELECT count(*) FROM `+table+` WHERE workspace_id = ?`, workspaceID).Scan(&n).Error
	return n, err
}

func isUndefinedTable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "42P01") || strings.Contains(msg, "does not exist")
}
