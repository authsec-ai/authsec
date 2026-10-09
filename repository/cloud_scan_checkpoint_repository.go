package repositories

import (
	"errors"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// CloudScanCheckpointRepository stores how far each phase of a scan attempt
// got, so an interrupted scan resumes instead of repeating its AWS calls.
//
// Every method is workspace-scoped, same as the rest of the cloud discovery
// repositories.
type CloudScanCheckpointRepository interface {
	// Advance records that a phase finished everything up to and including
	// cursor. Called after the work is durably written, never before -- a
	// cursor ahead of the data would make a resumed scan skip work that was
	// never done.
	Advance(workspaceID, connectorID uuid.UUID, generation int, phase, cursor string, doneCount int) error

	// Cursor returns how far a phase got, and false when it has no checkpoint.
	Cursor(workspaceID, connectorID uuid.UUID, generation int, phase string) (string, bool, error)

	// HasAny reports whether any checkpoint exists for this generation, which
	// is how a scan tells "resume the attempt that was interrupted" from
	// "start a new attempt".
	HasAny(workspaceID, connectorID uuid.UUID, generation int) (bool, error)

	// Clear removes every checkpoint for a generation. Called once a scan
	// completes: the checkpoints have served their purpose, and leaving them
	// would make the next scan think an attempt was interrupted.
	Clear(workspaceID, connectorID uuid.UUID, generation int) error
}

type cloudScanCheckpointRepository struct{ db *gorm.DB }

// NewCloudScanCheckpointRepository constructs the repository.
func NewCloudScanCheckpointRepository(db *gorm.DB) CloudScanCheckpointRepository {
	return &cloudScanCheckpointRepository{db: db}
}

func (r *cloudScanCheckpointRepository) Advance(
	workspaceID, connectorID uuid.UUID, generation int, phase, cursor string, doneCount int,
) error {
	if workspaceID == uuid.Nil || connectorID == uuid.Nil {
		return errors.New("workspace_id and connector_id are required")
	}
	if phase == "" {
		return errors.New("phase is required")
	}

	checkpoint := &models.CloudScanCheckpoint{
		WorkspaceID: workspaceID,
		ConnectorID: connectorID,
		Generation:  generation,
		Phase:       phase,
		Cursor:      cursor,
		DoneCount:   doneCount,
		UpdatedAt:   time.Now(),
	}
	return r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "workspace_id"}, {Name: "connector_id"},
			{Name: "generation"}, {Name: "phase"},
		},
		DoUpdates: clause.AssignmentColumns([]string{"cursor", "done_count", "updated_at"}),
	}).Create(checkpoint).Error
}

func (r *cloudScanCheckpointRepository) Cursor(
	workspaceID, connectorID uuid.UUID, generation int, phase string,
) (string, bool, error) {
	var checkpoint models.CloudScanCheckpoint
	err := r.db.Where(
		`workspace_id = ? AND connector_id = ? AND generation = ? AND phase = ?`,
		workspaceID, connectorID, generation, phase,
	).First(&checkpoint).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return checkpoint.Cursor, true, nil
}

func (r *cloudScanCheckpointRepository) HasAny(
	workspaceID, connectorID uuid.UUID, generation int,
) (bool, error) {
	var count int64
	err := r.db.Model(&models.CloudScanCheckpoint{}).
		Where(`workspace_id = ? AND connector_id = ? AND generation = ?`,
			workspaceID, connectorID, generation).
		Count(&count).Error
	return count > 0, err
}

func (r *cloudScanCheckpointRepository) Clear(
	workspaceID, connectorID uuid.UUID, generation int,
) error {
	return r.db.Where(
		`workspace_id = ? AND connector_id = ? AND generation = ?`,
		workspaceID, connectorID, generation,
	).Delete(&models.CloudScanCheckpoint{}).Error
}
