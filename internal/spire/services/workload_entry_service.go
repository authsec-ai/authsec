package services

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/spire/utils"
)

// WorkloadEntryService manages registration entries of the workspace carried
// by ctx.
type WorkloadEntryService struct {
	repo          repositories.WorkloadEntryRepository
	workspaceRepo repositories.WorkspaceRepository
	logger        *logrus.Entry
}

// NewWorkloadEntryService creates the workload entry service.
func NewWorkloadEntryService(repo repositories.WorkloadEntryRepository, workspaceRepo repositories.WorkspaceRepository, logger *logrus.Entry) *WorkloadEntryService {
	return &WorkloadEntryService{repo: repo, workspaceRepo: workspaceRepo, logger: logger}
}

// validateEntrySpiffeID requires a well-formed SPIFFE ID inside one of the
// workspace's trust domains (its id, or its domain), so an entry cannot name
// another workspace's identities.
func (s *WorkloadEntryService) validateEntrySpiffeID(ctx context.Context, workspaceID, spiffeID string) error {
	if err := utils.ValidateSpiffeID(spiffeID); err != nil {
		return errors.NewBadRequestError("Invalid spiffe_id: "+err.Error(), err)
	}
	if TrustDomainOf(spiffeID) == workspaceID {
		return nil
	}
	if s.workspaceRepo != nil {
		if ws, err := s.workspaceRepo.GetByID(ctx, workspaceID); err == nil && ws.Domain != "" &&
			strings.EqualFold(TrustDomainOf(spiffeID), ws.Domain) {
			return nil
		}
	}
	return errors.NewBadRequestError("spiffe_id must be in the workspace's trust domain (spiffe://"+workspaceID+"/...)", nil)
}

// TrustDomainOf returns the trust domain of a SPIFFE ID, or "".
func TrustDomainOf(spiffeID string) string { return utils.TrustDomainOf(spiffeID) }

// CreateEntry creates an entry in ctx's workspace.
func (s *WorkloadEntryService) CreateEntry(ctx context.Context, entry *models.WorkloadEntry) (*models.WorkloadEntry, error) {
	ws, err := workspaceFromContext(ctx)
	if err != nil {
		return nil, err
	}
	entry.WorkspaceID = ws
	if err := entry.Validate(); err != nil {
		return nil, errors.NewBadRequestError(err.Error(), err)
	}
	if err := s.validateEntrySpiffeID(ctx, ws, entry.SpiffeID); err != nil {
		return nil, err
	}
	existing, err := s.repo.GetBySpiffeID(ctx, entry.SpiffeID)
	if err != nil {
		return nil, errors.NewInternalError("Failed to check existing entry", err)
	}
	if existing != nil {
		return nil, errors.NewConflictError("A workload entry with this SPIFFE ID already exists", nil)
	}
	if err := s.repo.Create(ctx, entry); err != nil {
		return nil, asAppError(err, "Failed to create workload entry")
	}
	return entry, nil
}

// GetEntry returns an entry of ctx's workspace; another workspace's is 404.
func (s *WorkloadEntryService) GetEntry(ctx context.Context, entryID string) (*models.WorkloadEntry, error) {
	entry, err := s.repo.GetByID(ctx, entryID)
	if err != nil {
		return nil, errors.NewInternalError("Failed to get workload entry", err)
	}
	if entry == nil {
		return nil, errors.NewNotFoundError("Workload entry not found", nil)
	}
	return entry, nil
}

// GetBySpiffeID returns the entry of ctx's workspace with this SPIFFE ID, or
// (nil, nil).
func (s *WorkloadEntryService) GetBySpiffeID(ctx context.Context, spiffeID string) (*models.WorkloadEntry, error) {
	return s.repo.GetBySpiffeID(ctx, spiffeID)
}

// ListEntries lists ctx's workspace's entries.
func (s *WorkloadEntryService) ListEntries(ctx context.Context, filter *models.WorkloadEntryFilter) ([]*models.WorkloadEntry, error) {
	entries, err := s.repo.List(ctx, filter)
	if err != nil {
		return nil, errors.NewInternalError("Failed to list workload entries", err)
	}
	return entries, nil
}

// CountEntries counts ctx's workspace's entries (for paging).
func (s *WorkloadEntryService) CountEntries(ctx context.Context, filter *models.WorkloadEntryFilter) (int, error) {
	return s.repo.Count(ctx, filter)
}

// ListEntriesByParent lists the entries an agent of ctx's workspace serves.
func (s *WorkloadEntryService) ListEntriesByParent(ctx context.Context, parentID string) ([]*models.WorkloadEntry, error) {
	entries, err := s.repo.ListByParent(ctx, parentID)
	if err != nil {
		return nil, errors.NewInternalError("Failed to list workload entries", err)
	}
	return entries, nil
}

// UpdateEntry rewrites an entry of ctx's workspace.
func (s *WorkloadEntryService) UpdateEntry(ctx context.Context, entry *models.WorkloadEntry) (*models.WorkloadEntry, error) {
	ws, err := workspaceFromContext(ctx)
	if err != nil {
		return nil, err
	}
	entry.WorkspaceID = ws
	if err := entry.Validate(); err != nil {
		return nil, errors.NewBadRequestError(err.Error(), err)
	}
	if err := s.validateEntrySpiffeID(ctx, ws, entry.SpiffeID); err != nil {
		return nil, err
	}
	if err := s.repo.Update(ctx, entry); err != nil {
		return nil, asAppError(err, "Failed to update workload entry")
	}
	return s.GetEntry(ctx, entry.ID)
}

// DeleteEntry deletes an entry of ctx's workspace.
func (s *WorkloadEntryService) DeleteEntry(ctx context.Context, entryID string) error {
	if err := s.repo.Delete(ctx, entryID); err != nil {
		return asAppError(err, "Failed to delete workload entry")
	}
	return nil
}

// FindMatchingEntries returns entries of ctx's workspace whose selectors the
// given ones satisfy.
func (s *WorkloadEntryService) FindMatchingEntries(ctx context.Context, selectors map[string]string) ([]*models.WorkloadEntry, error) {
	return s.repo.FindMatchingEntries(ctx, selectors)
}

// MatchSelectorsWithWildcard reports whether every entry selector is among
// the collected ones; values containing '*' match as a glob.
func (s *WorkloadEntryService) MatchSelectorsWithWildcard(collected, entrySelectors map[string]string) bool {
	for k, v := range entrySelectors {
		got, ok := collected[k]
		if !ok {
			return false
		}
		if strings.Contains(v, "*") {
			if matched, err := filepath.Match(v, got); err != nil || !matched {
				return false
			}
		} else if got != v {
			return false
		}
	}
	return true
}

// FilterEntriesWithWildcard keeps the entries whose selectors match.
func (s *WorkloadEntryService) FilterEntriesWithWildcard(entries []*models.WorkloadEntry, collected map[string]string) []*models.WorkloadEntry {
	var out []*models.WorkloadEntry
	for _, e := range entries {
		if s.MatchSelectorsWithWildcard(collected, e.Selectors) {
			out = append(out, e)
		}
	}
	return out
}

// asAppError keeps an *errors.AppError and wraps anything else as 500.
func asAppError(err error, message string) error {
	if appErr, ok := err.(*errors.AppError); ok {
		return appErr
	}
	if _, ok := err.(*models.ValidationError); ok {
		return errors.NewBadRequestError(err.Error(), err)
	}
	return errors.NewInternalError(message, err)
}
