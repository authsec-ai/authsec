package services

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/infrastructure/database"
	infrarepos "github.com/authsec-ai/authsec/internal/spire/infrastructure/repositories"

	"github.com/sirupsen/logrus"
)

// WorkloadEntryService handles workload entry management operations
type WorkloadEntryService struct {
	connManager *database.ConnectionManager
	logger      *logrus.Entry
}

// NewWorkloadEntryService creates a new workload entry service
func NewWorkloadEntryService(
	connManager *database.ConnectionManager,
	logger *logrus.Entry,
) *WorkloadEntryService {
	return &WorkloadEntryService{
		connManager: connManager,
		logger:      logger,
	}
}

// CreateEntry creates a new workload entry
func (s *WorkloadEntryService) CreateEntry(ctx context.Context, entry *models.WorkloadEntry) (*models.WorkloadEntry, error) {
	s.logger.WithFields(logrus.Fields{
		"workspace_id": entry.WorkspaceID,
		"spiffe_id": entry.SpiffeID,
		"parent_id": entry.ParentID,
	}).Info("Creating workload entry")

	// Validate entry
	if err := entry.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Get tenant-specific database connection
	tenantDB, err := s.connManager.GetWorkspaceDB(ctx, entry.WorkspaceID)
	if err != nil {
		s.logger.WithField("workspace_id", entry.WorkspaceID).WithError(err).Error("Failed to connect to tenant database")
		return nil, fmt.Errorf("failed to connect to tenant database: %w", err)
	}

	// Create repository for tenant database
	repo := infrarepos.NewPostgresWorkloadEntryRepository(tenantDB, s.logger)

	// Check if entry with same SPIFFE ID already exists
	existing, err := repo.GetBySpiffeID(ctx, entry.WorkspaceID, entry.SpiffeID)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing entry: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("workload entry with SPIFFE ID %s already exists", entry.SpiffeID)
	}

	// Create entry
	if err := repo.Create(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to create workload entry: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"id":        entry.ID,
		"spiffe_id": entry.SpiffeID,
	}).Info("Workload entry created successfully")

	return entry, nil
}

// GetEntry retrieves a workload entry by ID
func (s *WorkloadEntryService) GetEntry(ctx context.Context, workspaceID, entryID string) (*models.WorkloadEntry, error) {
	// Get tenant-specific database connection
	tenantDB, err := s.connManager.GetWorkspaceDB(ctx, workspaceID)
	if err != nil {
		s.logger.WithField("workspace_id", workspaceID).WithError(err).Error("Failed to connect to tenant database")
		return nil, fmt.Errorf("failed to connect to tenant database: %w", err)
	}

	// Create repository for tenant database
	repo := infrarepos.NewPostgresWorkloadEntryRepository(tenantDB, s.logger)

	// Get entry
	entry, err := repo.GetByID(ctx, entryID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workload entry: %w", err)
	}

	if entry == nil {
		return nil, fmt.Errorf("workload entry not found: %s", entryID)
	}

	// Verify entry belongs to tenant
	if entry.WorkspaceID != workspaceID {
		return nil, fmt.Errorf("workload entry does not belong to tenant")
	}

	return entry, nil
}

// ListEntries retrieves workload entries based on filter
func (s *WorkloadEntryService) ListEntries(ctx context.Context, filter *models.WorkloadEntryFilter) ([]*models.WorkloadEntry, error) {
	s.logger.WithFields(logrus.Fields{
		"workspace_id": filter.WorkspaceID,
		"parent_id": filter.ParentID,
	}).Info("Listing workload entries")

	// Get tenant-specific database connection
	tenantDB, err := s.connManager.GetWorkspaceDB(ctx, filter.WorkspaceID)
	if err != nil {
		s.logger.WithField("workspace_id", filter.WorkspaceID).WithError(err).Error("Failed to connect to tenant database")
		return nil, fmt.Errorf("failed to connect to tenant database: %w", err)
	}

	// Create repository for tenant database
	repo := infrarepos.NewPostgresWorkloadEntryRepository(tenantDB, s.logger)

	// List entries
	entries, err := repo.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list workload entries: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"workspace_id": filter.WorkspaceID,
		"count":     len(entries),
	}).Info("Workload entries retrieved")

	return entries, nil
}

// ListEntriesByParent retrieves all workload entries for a specific parent (agent)
func (s *WorkloadEntryService) ListEntriesByParent(ctx context.Context, workspaceID, parentID string) ([]*models.WorkloadEntry, error) {
	s.logger.WithFields(logrus.Fields{
		"workspace_id": workspaceID,
		"parent_id": parentID,
	}).Info("Listing workload entries by parent")

	// Get tenant-specific database connection
	tenantDB, err := s.connManager.GetWorkspaceDB(ctx, workspaceID)
	if err != nil {
		s.logger.WithField("workspace_id", workspaceID).WithError(err).Error("Failed to connect to tenant database")
		return nil, fmt.Errorf("failed to connect to tenant database: %w", err)
	}

	// Create repository for tenant database
	repo := infrarepos.NewPostgresWorkloadEntryRepository(tenantDB, s.logger)

	// List entries matching this agent's parent_id OR entries with empty parent_id
	// (unassigned entries are shared across all agents in the tenant)
	entries, err := repo.ListByParent(ctx, workspaceID, parentID)
	if err != nil {
		return nil, fmt.Errorf("failed to list workload entries by parent: %w", err)
	}

	return entries, nil
}

// UpdateEntry updates an existing workload entry
func (s *WorkloadEntryService) UpdateEntry(ctx context.Context, entry *models.WorkloadEntry) (*models.WorkloadEntry, error) {
	s.logger.WithFields(logrus.Fields{
		"id":        entry.ID,
		"workspace_id": entry.WorkspaceID,
	}).Info("Updating workload entry")

	// Validate entry
	if err := entry.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Get tenant-specific database connection
	tenantDB, err := s.connManager.GetWorkspaceDB(ctx, entry.WorkspaceID)
	if err != nil {
		s.logger.WithField("workspace_id", entry.WorkspaceID).WithError(err).Error("Failed to connect to tenant database")
		return nil, fmt.Errorf("failed to connect to tenant database: %w", err)
	}

	// Create repository for tenant database
	repo := infrarepos.NewPostgresWorkloadEntryRepository(tenantDB, s.logger)

	// Verify entry exists and belongs to tenant
	existing, err := repo.GetByID(ctx, entry.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing entry: %w", err)
	}
	if existing == nil {
		return nil, fmt.Errorf("workload entry not found: %s", entry.ID)
	}
	if existing.WorkspaceID != entry.WorkspaceID {
		return nil, fmt.Errorf("workload entry does not belong to tenant")
	}

	// Update entry
	if err := repo.Update(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to update workload entry: %w", err)
	}

	s.logger.WithField("id", entry.ID).Info("Workload entry updated successfully")

	return entry, nil
}

// DeleteEntry deletes a workload entry
func (s *WorkloadEntryService) DeleteEntry(ctx context.Context, workspaceID, entryID string) error {
	s.logger.WithFields(logrus.Fields{
		"id":        entryID,
		"workspace_id": workspaceID,
	}).Info("Deleting workload entry")

	// Get tenant-specific database connection
	tenantDB, err := s.connManager.GetWorkspaceDB(ctx, workspaceID)
	if err != nil {
		s.logger.WithField("workspace_id", workspaceID).WithError(err).Error("Failed to connect to tenant database")
		return fmt.Errorf("failed to connect to tenant database: %w", err)
	}

	// Create repository for tenant database
	repo := infrarepos.NewPostgresWorkloadEntryRepository(tenantDB, s.logger)

	// Verify entry exists and belongs to tenant
	existing, err := repo.GetByID(ctx, entryID)
	if err != nil {
		return fmt.Errorf("failed to get existing entry: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("workload entry not found: %s", entryID)
	}
	if existing.WorkspaceID != workspaceID {
		return fmt.Errorf("workload entry does not belong to tenant")
	}

	// Delete entry
	if err := repo.Delete(ctx, entryID); err != nil {
		return fmt.Errorf("failed to delete workload entry: %w", err)
	}

	s.logger.WithField("id", entryID).Info("Workload entry deleted successfully")

	return nil
}

// CountEntries returns the total count of workload entries matching the filter
// This is used for pagination to show accurate total count
func (s *WorkloadEntryService) CountEntries(ctx context.Context, filter *models.WorkloadEntryFilter) (int, error) {
	s.logger.WithField("workspace_id", filter.WorkspaceID).Debug("Counting workload entries")

	// Get tenant-specific database connection
	tenantDB, err := s.connManager.GetWorkspaceDB(ctx, filter.WorkspaceID)
	if err != nil {
		s.logger.WithField("workspace_id", filter.WorkspaceID).WithError(err).Error("Failed to connect to tenant database")
		return 0, fmt.Errorf("failed to connect to tenant database: %w", err)
	}

	// Create repository for tenant database
	repo := infrarepos.NewPostgresWorkloadEntryRepository(tenantDB, s.logger)

	// Count entries (without limit/offset)
	count, err := repo.Count(ctx, filter)
	if err != nil {
		return 0, fmt.Errorf("failed to count workload entries: %w", err)
	}

	return count, nil
}

// FindMatchingEntries finds workload entries matching the given selectors
// Used during workload attestation to determine which SPIFFE ID to issue
func (s *WorkloadEntryService) FindMatchingEntries(ctx context.Context, workspaceID string, selectors map[string]string) ([]*models.WorkloadEntry, error) {
	s.logger.WithFields(logrus.Fields{
		"workspace_id": workspaceID,
		"selectors": selectors,
	}).Info("Finding matching workload entries")

	// Get tenant-specific database connection
	tenantDB, err := s.connManager.GetWorkspaceDB(ctx, workspaceID)
	if err != nil {
		s.logger.WithField("workspace_id", workspaceID).WithError(err).Error("Failed to connect to tenant database")
		return nil, fmt.Errorf("failed to connect to tenant database: %w", err)
	}

	// Create repository for tenant database
	repo := infrarepos.NewPostgresWorkloadEntryRepository(tenantDB, s.logger)

	// Find matching entries
	entries, err := repo.FindMatchingEntries(ctx, workspaceID, selectors)
	if err != nil {
		return nil, fmt.Errorf("failed to find matching entries: %w", err)
	}

	return entries, nil
}

// MatchSelectorsWithWildcard matches workload selectors against entry selectors with wildcard support
// Entry selectors must be a SUBSET of collected selectors
// Supports wildcard matching for values containing '*'
func (s *WorkloadEntryService) MatchSelectorsWithWildcard(
	collectedSelectors map[string]string,
	entrySelectors map[string]string,
) bool {
	// Entry selectors must be a SUBSET of collected selectors
	for entryKey, entryValue := range entrySelectors {
		// Check if selector exists in collected
		collectedValue, exists := collectedSelectors[entryKey]
		if !exists {
			return false
		}

		// Support wildcard matching for certain selectors
		if strings.Contains(entryValue, "*") {
			matched, err := filepath.Match(entryValue, collectedValue)
			if err != nil || !matched {
				return false
			}
		} else {
			// Exact match
			if collectedValue != entryValue {
				return false
			}
		}
	}

	return true
}

// FilterEntriesWithWildcard filters entries using wildcard selector matching
// This can be used as a post-processing step after FindMatchingEntries
func (s *WorkloadEntryService) FilterEntriesWithWildcard(
	entries []*models.WorkloadEntry,
	collectedSelectors map[string]string,
) []*models.WorkloadEntry {
	var matchedEntries []*models.WorkloadEntry

	for _, entry := range entries {
		if s.MatchSelectorsWithWildcard(collectedSelectors, entry.Selectors) {
			matchedEntries = append(matchedEntries, entry)
		}
	}

	return matchedEntries
}
