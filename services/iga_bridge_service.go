package services

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrStaleLinkVersion is returned when a decision carries a version that is no
// longer current, meaning someone else decided first.
var ErrStaleLinkVersion = errors.New("this link was changed by someone else; re-read it and decide again")

// IGABridgeManager correlates the k8s runtime inventory with the canonical IGA
// estate.
//
// The two models have NO shared identifier — iga_agents is canonical with no
// fingerprint, and native keys live in iga_source_objects behind
// iga_correlations. So this proposes and never concludes: every automatic link
// is 'weak' + 'proposed', and only a recorded human decision makes it
// authoritative. The database enforces that rather than trusting this code.
type IGABridgeManager interface {
	// ProposeForAgent looks for a canonical agent this sighting plausibly is, and
	// records a proposal. Returns nil (no error) when nothing matched or the match
	// was ambiguous — neither is a failure.
	ProposeForAgent(workspaceID, discoveredAgentID uuid.UUID) (*models.DiscoveredAgentIGALink, error)

	// GetLink returns the link for one discovered agent, or nil when unlinked.
	GetLink(workspaceID, discoveredAgentID uuid.UUID) (*models.DiscoveredAgentIGALink, error)

	// ListProposals is the reviewer queue: links still awaiting a decision.
	ListProposals(workspaceID uuid.UUID, limit, offset int) ([]models.DiscoveredAgentIGALink, int64, error)

	// Decide accepts or rejects a proposed link. ExpectedVersion guards against a
	// stale decision winning.
	Decide(workspaceID, discoveredAgentID uuid.UUID, decision string,
		by *uuid.UUID, expectedVersion int64) (*models.DiscoveredAgentIGALink, error)
}

type igaBridgeManager struct{ db *gorm.DB }

// NewIGABridgeManager constructs an IGABridgeManager.
func NewIGABridgeManager(db *gorm.DB) IGABridgeManager { return &igaBridgeManager{db: db} }

// nonAlnum collapses everything that is not a letter or digit, so
// "Research Agent", "research-agent" and "research_agent" correlate.
var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

func normalizeName(s string) string {
	return strings.Trim(nonAlnum.ReplaceAllString(strings.ToLower(s), "-"), "-")
}

func (m *igaBridgeManager) ProposeForAgent(workspaceID,
	discoveredAgentID uuid.UUID) (*models.DiscoveredAgentIGALink, error) {

	// An already-DECIDED link is never revisited. Without this, a rejected link
	// would be re-proposed on every sighting and the reviewer would be asked the
	// same question forever.
	existing, err := m.GetLink(workspaceID, discoveredAgentID)
	if err != nil {
		return nil, err
	}
	if existing != nil && existing.State != models.IGALinkProposed {
		return existing, nil
	}

	var agent models.DiscoveredAgent
	if err := m.db.First(&agent, "id = ? AND workspace_id = ?",
		discoveredAgentID, workspaceID).Error; err != nil {
		return nil, err
	}

	key := normalizeName(agent.DisplayName)
	if key == "" {
		// Nothing to match on. Not an error: plenty of sightings have no useful
		// display name, and inventing a correlation would be worse than none.
		return nil, nil
	}

	// Candidates whose normalized display name equals this one. Only ACTIVE
	// canonical agents: proposing a link to a retired or tombstoned agent would
	// send a reviewer to resurrect something deliberately closed.
	var candidates []struct {
		ID          uuid.UUID
		DisplayName string
	}
	if err := m.db.Raw(`
		SELECT id, display_name FROM iga_agents
		 WHERE workspace_id = ? AND lifecycle = 'active'
		   -- btrim mirrors the Trim in normalizeName. Without it the two
		   -- normalisations disagree on any name with leading or trailing
		   -- punctuation -- " research-agent " would never match "research-agent"
		   -- and the correlation would silently just not happen.
		   AND btrim(regexp_replace(lower(display_name), '[^a-z0-9]+', '-', 'g'), '-') = ?
		 LIMIT 5`, workspaceID, key).Scan(&candidates).Error; err != nil {
		return nil, err
	}

	switch len(candidates) {
	case 0:
		return nil, nil
	case 1:
		// The only case worth proposing.
	default:
		// AMBIGUOUS. Two canonical agents share this name, so a proposal would be
		// a coin flip dressed as evidence. Proposing nothing leaves the sighting
		// visibly unlinked, which is the honest state and still actionable.
		return nil, nil
	}

	link := &models.DiscoveredAgentIGALink{
		WorkspaceID:       workspaceID,
		DiscoveredAgentID: discoveredAgentID,
		IGAAgentID:        candidates[0].ID,
		JoinKey:           "display_name:" + key,
		// Weak by construction: a name match is not an identifier. The DB CHECK
		// makes this un-acceptable without a human, so mislabelling it 'strong'
		// here would be the only way to bypass review — hence it is hardcoded.
		Strength: models.IGALinkWeak,
		State:    models.IGALinkProposed,
	}

	// Upsert on the one-link-per-agent key, but only ever over a row that is
	// still 'proposed'. TargetWhere repeats the predicate so Postgres can infer
	// the partial-free unique constraint, and the WHERE on the update is what
	// protects a decided link.
	res := m.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "workspace_id"}, {Name: "discovered_agent_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"iga_agent_id": candidates[0].ID,
			"join_key":     link.JoinKey,
			"strength":     models.IGALinkWeak,
			"updated_at":   time.Now(),
		}),
		Where: clause.Where{Exprs: []clause.Expression{
			gorm.Expr("discovered_agent_iga_links.state = ?", models.IGALinkProposed),
		}},
	}).Create(link)
	if res.Error != nil {
		return nil, res.Error
	}
	return m.GetLink(workspaceID, discoveredAgentID)
}

func (m *igaBridgeManager) GetLink(workspaceID,
	discoveredAgentID uuid.UUID) (*models.DiscoveredAgentIGALink, error) {

	var out models.DiscoveredAgentIGALink
	err := m.db.First(&out, "workspace_id = ? AND discovered_agent_id = ?",
		workspaceID, discoveredAgentID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil // unlinked is a normal state, not an error
	}
	if err != nil {
		return nil, err
	}
	out.Decided = out.State != models.IGALinkProposed
	return &out, nil
}

func (m *igaBridgeManager) ListProposals(workspaceID uuid.UUID,
	limit, offset int) ([]models.DiscoveredAgentIGALink, int64, error) {

	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := m.db.Model(&models.DiscoveredAgentIGALink{}).
		Where("workspace_id = ? AND state = ?", workspaceID, models.IGALinkProposed)

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []models.DiscoveredAgentIGALink
	if err := q.Order("created_at ASC").Limit(limit).Offset(offset).Find(&out).Error; err != nil {
		return nil, 0, err
	}
	for i := range out {
		out[i].Decided = out[i].State != models.IGALinkProposed
	}
	return out, total, nil
}

func (m *igaBridgeManager) Decide(workspaceID, discoveredAgentID uuid.UUID,
	decision string, by *uuid.UUID, expectedVersion int64) (*models.DiscoveredAgentIGALink, error) {

	if !containsString(models.ValidIGALinkDecisions(), decision) {
		return nil, fmt.Errorf("decision must be one of %v, got %q",
			models.ValidIGALinkDecisions(), decision)
	}
	if by == nil {
		// The DB CHECK would catch an accept, but not a reject. Requiring an
		// attributable decider for both keeps the audit trail whole: "who decided
		// these are not the same agent" is as much a governance question as the
		// affirmative.
		return nil, errors.New("a link decision must be attributable to a user")
	}

	now := time.Now()
	// Conditional on BOTH the state and the version: deciding twice, or deciding
	// against a stale read, both fail rather than silently overwriting.
	res := m.db.Model(&models.DiscoveredAgentIGALink{}).
		Where(`workspace_id = ? AND discovered_agent_id = ? AND state = ? AND version = ?`,
			workspaceID, discoveredAgentID, models.IGALinkProposed, expectedVersion).
		Updates(map[string]interface{}{
			"state":      decision,
			"decided_by": by,
			"decided_at": now,
			"version":    gorm.Expr("version + 1"),
			"updated_at": now,
		})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		// Say which it was, so the caller can pick the right status code.
		current, err := m.GetLink(workspaceID, discoveredAgentID)
		if err != nil {
			return nil, err
		}
		if current == nil {
			return nil, gorm.ErrRecordNotFound
		}
		if current.State != models.IGALinkProposed {
			return nil, fmt.Errorf("this link was already %s", current.State)
		}
		return nil, fmt.Errorf("%w (expected version %d, current %d)",
			ErrStaleLinkVersion, expectedVersion, current.Version)
	}
	return m.GetLink(workspaceID, discoveredAgentID)
}
