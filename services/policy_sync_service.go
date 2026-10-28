package services

import (
	"context"
	"encoding/json"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type PolicySyncService struct {
	db *gorm.DB
}

func NewPolicySyncService(db *gorm.DB) *PolicySyncService {
	return &PolicySyncService{db: db}
}

type PolicySyncRequest struct {
	Cursor int64 `json:"cursor"`
	Inline bool  `json:"inline"`
}

type PolicySyncBinding struct {
	WorkloadID     uuid.UUID       `json:"workload_id"`
	PolicyID       uuid.UUID       `json:"policy_id"`
	Revision       int             `json:"revision"`
	State          string          `json:"state"`
	ArtifactSHA256 string          `json:"artifact_sha256,omitempty"`
	SignedManifest string          `json:"signed_manifest,omitempty"`
	ArtifactData   json.RawMessage `json:"artifact_data,omitempty"`
	DeliveryCursor int64           `json:"delivery_cursor"`
}

type PolicySyncResponse struct {
	Bindings []PolicySyncBinding `json:"bindings"`
	Cursor   int64               `json:"cursor"`
	HasMore  bool                `json:"has_more"`
}

func (s *PolicySyncService) Sync(ctx context.Context, principal *models.CollectorPrincipal, req PolicySyncRequest) (*PolicySyncResponse, error) {
	wsID := principal.WorkspaceID

	var bindings []models.WorkloadPolicyBinding
	query := s.db.WithContext(ctx).
		Where("workspace_id = ? AND state IN ?", wsID,
			[]string{models.WPBStateActive, models.WPBStateRevoked}).
		Order("delivery_cursor ASC")

	if req.Cursor > 0 {
		query = query.Where("delivery_cursor > ?", req.Cursor)
	}

	const pageSize = 100
	if err := query.Limit(pageSize + 1).Find(&bindings).Error; err != nil {
		return nil, err
	}

	hasMore := len(bindings) > pageSize
	if hasMore {
		bindings = bindings[:pageSize]
	}

	syncBindings := make([]PolicySyncBinding, 0, len(bindings))
	var maxCursor int64
	for _, b := range bindings {
		sb := PolicySyncBinding{
			WorkloadID:     b.WorkloadID,
			PolicyID:       b.PolicyID,
			Revision:       b.Revision,
			State:          b.State,
			DeliveryCursor: b.DeliveryCursor,
		}

		if b.State == models.WPBStateActive && req.Inline {
			var artifact PolicyArtifact
			err := s.db.WithContext(ctx).
				Where("workspace_id = ? AND policy_id = ? AND revision = ?",
					wsID, b.PolicyID, b.Revision).
				First(&artifact).Error
			if err == nil {
				sb.ArtifactSHA256 = artifact.ArtifactSHA256
				sb.SignedManifest = artifact.SignedManifest
				sb.ArtifactData = json.RawMessage(artifact.ArtifactData)
			}
		}

		syncBindings = append(syncBindings, sb)
		if b.DeliveryCursor > maxCursor {
			maxCursor = b.DeliveryCursor
		}
	}

	if maxCursor == 0 {
		maxCursor = req.Cursor
	}

	return &PolicySyncResponse{
		Bindings: syncBindings,
		Cursor:   maxCursor,
		HasMore:  hasMore,
	}, nil
}
