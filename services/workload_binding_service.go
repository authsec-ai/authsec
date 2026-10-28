package services

import (
	"context"
	"errors"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var ErrWorkloadBindingNotFound = errors.New("workload policy binding not found")

type WorkloadBindingService struct {
	db *gorm.DB
}

func NewWorkloadBindingService(db *gorm.DB) *WorkloadBindingService {
	return &WorkloadBindingService{db: db}
}

type PutWorkloadBindingRequest struct {
	PolicyID uuid.UUID `json:"policy_id"`
	Revision int       `json:"revision"`
}

func (s *WorkloadBindingService) GetForWorkload(ctx context.Context, wsID, workloadID uuid.UUID) ([]models.WorkloadPolicyBinding, error) {
	var bindings []models.WorkloadPolicyBinding
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND workload_id = ? AND state IN ?", wsID, workloadID,
			[]string{models.WPBStatePending, models.WPBStateActive}).
		Order("created_at DESC").
		Find(&bindings).Error
	return bindings, err
}

func (s *WorkloadBindingService) PutBinding(ctx context.Context, wsID, workloadID uuid.UUID, req PutWorkloadBindingRequest) (*models.WorkloadPolicyBinding, error) {
	var binding models.WorkloadPolicyBinding
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Where("workspace_id = ? AND workload_id = ? AND policy_id = ?",
			wsID, workloadID, req.PolicyID).First(&binding)
		if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return result.Error
		}
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			binding = models.WorkloadPolicyBinding{
				ID:          uuid.New(),
				WorkspaceID: wsID,
				WorkloadID:  workloadID,
				PolicyID:    req.PolicyID,
				Revision:    req.Revision,
				State:       models.WPBStateActive,
			}
			return tx.Create(&binding).Error
		}
		binding.Revision = req.Revision
		binding.State = models.WPBStateActive
		binding.UpdatedAt = time.Now()
		return tx.Save(&binding).Error
	})
	if err != nil {
		return nil, err
	}
	return &binding, nil
}

func (s *WorkloadBindingService) ListForPolicy(ctx context.Context, wsID, policyID uuid.UUID) ([]models.WorkloadPolicyBinding, error) {
	var bindings []models.WorkloadPolicyBinding
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND policy_id = ?", wsID, policyID).
		Order("created_at DESC").
		Find(&bindings).Error
	return bindings, err
}

func (s *WorkloadBindingService) Supersede(ctx context.Context, wsID, workloadID, policyID uuid.UUID) error {
	return s.db.WithContext(ctx).
		Model(&models.WorkloadPolicyBinding{}).
		Where("workspace_id = ? AND workload_id = ? AND policy_id = ? AND state = ?",
			wsID, workloadID, policyID, models.WPBStateActive).
		Updates(map[string]any{"state": models.WPBStateSuperseded, "updated_at": time.Now()}).Error
}

func (s *WorkloadBindingService) UpdateCursor(ctx context.Context, wsID, workloadID uuid.UUID, cursor int64) error {
	return s.db.WithContext(ctx).
		Model(&models.WorkloadPolicyBinding{}).
		Where("workspace_id = ? AND workload_id = ? AND state = ?",
			wsID, workloadID, models.WPBStateActive).
		Update("delivery_cursor", cursor).Error
}
