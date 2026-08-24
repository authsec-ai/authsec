package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// CertifyManager runs access certification: campaigns, items, decisions, and the
// frozen export an auditor reads.
//
// WHAT MAKES A REVIEW REAL RATHER THAN A RUBBER STAMP
// The evidence on each item. A reviewer shown only "agent-reader on payments" is
// guessing; one shown "granted 90 days ago by alice for nightly reconciliation, marked
// standing with no expiry, has never issued a token, agent last seen 40 days ago,
// runtime says gone" is deciding. Mass approval is the normal failure mode of access
// review, and thin evidence is what causes it.
//
// ITEMS ARE SNAPSHOTS. Certifying against live data means the thing you approved can
// change under you mid-review, and the export at close would not match what the
// reviewer actually saw.
type CertifyManager interface {
	CreateCampaign(workspaceID uuid.UUID, createdBy string, in CampaignInput) (*models.CertificationCampaign, error)
	GetCampaign(workspaceID, id uuid.UUID) (*models.CertificationCampaign, error)
	ListCampaigns(workspaceID uuid.UUID) ([]models.CertificationCampaign, error)

	// Generate materialises a draft campaign's items, with evidence, and activates it.
	// Idempotent: re-generating adds only entitlements not already under review.
	Generate(workspaceID, campaignID uuid.UUID) (*GenerateResult, error)

	// ListItems returns a campaign's items, optionally only those a given reviewer owes
	// a decision on.
	ListItems(workspaceID, campaignID uuid.UUID, f ItemFilter) ([]models.CertificationItem, int64, error)

	// Decide records a reviewer's decision. A 'revoke' executes the standard
	// de-provision path; nothing else revokes.
	Decide(workspaceID, itemID uuid.UUID, in DecisionInput) (*models.CertificationItem, error)

	// Close freezes the export. Refuses while decisions are outstanding unless forced.
	Close(workspaceID, campaignID uuid.UUID, by *uuid.UUID, force bool) (*models.CertificationCampaign, error)
}

// CampaignScope decides what a campaign reviews.
//
// StandingOnly defaults to TRUE, which is the whole point: expiring grants lapse on
// their own, so reviewing them wastes the reviewer's attention on access that is about
// to disappear anyway.
type CampaignScope struct {
	// StandingOnly restricts to non-expiring grants. Pointer so an explicit false is
	// distinguishable from an absent field.
	StandingOnly      *bool       `json:"standing_only,omitempty"`
	EntitlementTypes  []string    `json:"entitlement_types,omitempty"`
	SubjectTypes      []string    `json:"subject_types,omitempty"`
	Origins           []string    `json:"origins,omitempty"`
	ResourceServerIDs []uuid.UUID `json:"resource_server_ids,omitempty"`
	// DormantDays restricts to entitlements whose subject has issued no token in this
	// many days. The highest-signal filter there is: unused standing access.
	DormantDays int `json:"dormant_days,omitempty"`
	// AgentsOnly restricts to agent anchors, for an agent-specific review.
	AgentsOnly bool `json:"agents_only,omitempty"`
}

func (s CampaignScope) standing() bool {
	if s.StandingOnly == nil {
		return true
	}
	return *s.StandingOnly
}

// CampaignInput creates a campaign.
type CampaignInput struct {
	Name        string
	Description string
	Scope       CampaignScope
	DueAt       *time.Time
}

// GenerateResult reports what generation produced.
type GenerateResult struct {
	CampaignID   uuid.UUID `json:"campaign_id"`
	ItemsCreated int       `json:"items_created"`
	ItemsSkipped int       `json:"items_skipped"`
	// Unassigned is items where no reviewer could be resolved. Surfaced rather than
	// hidden: an item nobody owns is one nobody will decide.
	Unassigned int `json:"unassigned"`
}

// ItemFilter narrows an item listing.
type ItemFilter struct {
	ReviewerUserID *uuid.UUID
	PendingOnly    bool
	Limit          int
	Offset         int
}

// DecisionInput is a reviewer's decision.
type DecisionInput struct {
	Decision string
	Note     string
	By       *uuid.UUID
	// DelegateTo is required for a 'delegate' decision.
	DelegateTo *uuid.UUID
}

// itemEvidence is what a reviewer is shown. Assembled at generation and frozen.
type itemEvidence struct {
	// Why it exists.
	Origin        string     `json:"origin"`
	Justification string     `json:"justification"`
	Purpose       string     `json:"purpose"`
	GrantedBy     string     `json:"granted_by"`
	GrantedAt     time.Time  `json:"granted_at"`
	IsStanding    bool       `json:"is_standing"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	AgeDays       int        `json:"age_days"`

	// Whether it has ever been used. The single most useful fact on the item.
	TokensIssued      int64      `json:"tokens_issued"`
	LastTokenIssuedAt *time.Time `json:"last_token_issued_at,omitempty"`
	NeverUsed         bool       `json:"never_used"`
	DormantDays       *int       `json:"dormant_days,omitempty"`

	// Whether the workload is even running, straight from discovery.
	RuntimeStatus string     `json:"runtime_status,omitempty"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`

	// Open conflicts on this subject, so a reviewer sees the risk alongside the grant.
	OpenSoDViolations []string `json:"open_sod_violations,omitempty"`

	// Recommendation is a computed hint, never a decision. Stated as a suggestion with
	// its reason so the reviewer can disagree — an automatic revoke on this signal
	// would let a quiet-but-needed agent be killed by a heuristic.
	Recommendation       string `json:"recommendation"`
	RecommendationReason string `json:"recommendation_reason"`
}

type certifyManager struct {
	db         *gorm.DB
	repo       repositories.GovernanceRepository
	provenance ProvenanceManager
	prov       ProvisioningManager
}

// NewCertifyManager constructs a CertifyManager.
func NewCertifyManager(db *gorm.DB, oauth *OAuthASService) CertifyManager {
	repo := repositories.NewGovernanceRepository(db)
	return &certifyManager{
		db:         db,
		repo:       repo,
		provenance: NewProvenanceManager(repo),
		prov:       NewProvisioningManager(db, oauth),
	}
}

/* ------------------------------- campaigns ------------------------------- */

func (m *certifyManager) CreateCampaign(workspaceID uuid.UUID, createdBy string,
	in CampaignInput) (*models.CertificationCampaign, error) {

	if strings.TrimSpace(in.Name) == "" {
		return nil, errors.New("name is required")
	}
	for _, t := range in.Scope.EntitlementTypes {
		if !containsString(models.ValidEntitlementTypes(), t) {
			return nil, fmt.Errorf("unknown entitlement type %q in scope", t)
		}
	}
	for _, t := range in.Scope.SubjectTypes {
		if !containsString(models.ValidProvenanceSubjectTypes(), t) {
			return nil, fmt.Errorf("unknown subject type %q in scope", t)
		}
	}
	for _, o := range in.Scope.Origins {
		if !containsString(models.ValidGrantOrigins(), o) {
			return nil, fmt.Errorf("unknown origin %q in scope", o)
		}
	}
	if in.DueAt != nil && !in.DueAt.After(time.Now()) {
		return nil, errors.New("due_at must be in the future: a campaign that is already overdue cannot be reviewed")
	}

	scopeJSON, err := json.Marshal(in.Scope)
	if err != nil {
		return nil, fmt.Errorf("invalid scope: %w", err)
	}

	c := &models.CertificationCampaign{
		ID:          uuid.New(),
		WorkspaceID: workspaceID,
		Name:        strings.TrimSpace(in.Name),
		Description: in.Description,
		Scope:       scopeJSON,
		Status:      models.CampaignStatusDraft,
		DueAt:       in.DueAt,
		CreatedBy:   createdBy,
	}
	if err := m.db.Create(c).Error; err != nil {
		return nil, err
	}
	return c, nil
}

func (m *certifyManager) GetCampaign(workspaceID, id uuid.UUID) (*models.CertificationCampaign, error) {
	var c models.CertificationCampaign
	if err := m.db.First(&c, "id = ? AND workspace_id = ?", id, workspaceID).Error; err != nil {
		return nil, err
	}
	return &c, nil
}

func (m *certifyManager) ListCampaigns(workspaceID uuid.UUID) ([]models.CertificationCampaign, error) {
	var out []models.CertificationCampaign
	// Active first, then drafts, then closed — a reviewer's attention belongs on what
	// is in flight.
	err := m.db.Where("workspace_id = ?", workspaceID).
		Order(`CASE status WHEN 'active' THEN 0 WHEN 'draft' THEN 1 ELSE 2 END`).
		Order("created_at DESC").Find(&out).Error
	return out, err
}

/* ------------------------------- generation ------------------------------ */

func (m *certifyManager) Generate(workspaceID, campaignID uuid.UUID) (*GenerateResult, error) {
	campaign, err := m.GetCampaign(workspaceID, campaignID)
	if err != nil {
		return nil, err
	}
	if campaign.Status == models.CampaignStatusClosed {
		return nil, errors.New("a closed campaign cannot be regenerated: its export is frozen evidence")
	}

	var scope CampaignScope
	if len(campaign.Scope) > 0 {
		if err := json.Unmarshal(campaign.Scope, &scope); err != nil {
			return nil, fmt.Errorf("invalid campaign scope: %w", err)
		}
	}

	candidates, err := m.selectCandidates(workspaceID, scope)
	if err != nil {
		return nil, err
	}

	res := &GenerateResult{CampaignID: campaignID}
	now := time.Now()

	for i := range candidates {
		p := &candidates[i]

		// Idempotent: skip anything already under review in this campaign.
		var exists int64
		if err := m.db.Model(&models.CertificationItem{}).
			Where("campaign_id = ? AND entitlement_provenance_id = ?", campaignID, p.ID).
			Count(&exists).Error; err != nil {
			return nil, err
		}
		if exists > 0 {
			res.ItemsSkipped++
			continue
		}

		evidence, err := m.assembleEvidence(workspaceID, p)
		if err != nil {
			return nil, fmt.Errorf("assemble evidence for %s: %w", p.ID, err)
		}
		evidenceJSON, _ := json.Marshal(evidence)

		reviewer, reviewerLabel, reviewerSource := m.resolveReviewer(workspaceID, p)
		if reviewer == nil {
			res.Unassigned++
		}

		item := models.CertificationItem{
			ID:                      uuid.New(),
			CampaignID:              campaignID,
			WorkspaceID:             workspaceID,
			EntitlementProvenanceID: &p.ID,
			SubjectType:             p.SubjectType,
			SubjectID:               p.SubjectID,
			SubjectLabel:            p.SubjectLabel,
			EntitlementLabel:        p.Label,
			EntitlementType:         p.EntitlementType,
			Snapshot:                p.Snapshot,
			Evidence:                evidenceJSON,
			ReviewerUserID:          reviewer,
			ReviewerLabel:           reviewerLabel,
			ReviewerSource:          reviewerSource,
			Decision:                models.DecisionPending,
			CreatedAt:               now,
		}
		if err := m.db.Create(&item).Error; err != nil {
			return nil, fmt.Errorf("create item: %w", err)
		}
		res.ItemsCreated++
	}

	updates := map[string]interface{}{
		"items_total":  gorm.Expr("items_total + ?", res.ItemsCreated),
		"generated_at": now,
		"updated_at":   now,
	}
	// Only activate once there is something to review. An active campaign with no items
	// is a review nobody can perform, and the DB check enforces the generated_at half
	// of that.
	if campaign.Status == models.CampaignStatusDraft && (res.ItemsCreated > 0 || campaign.ItemsTotal > 0) {
		updates["status"] = models.CampaignStatusActive
	}
	if err := m.db.Model(&models.CertificationCampaign{}).
		Where("id = ?", campaignID).Updates(updates).Error; err != nil {
		return nil, err
	}
	return res, nil
}

// selectCandidates finds the open provenance rows a campaign's scope covers.
func (m *certifyManager) selectCandidates(workspaceID uuid.UUID, scope CampaignScope) ([]models.EntitlementProvenance, error) {
	q := m.db.Model(&models.EntitlementProvenance{}).
		Where("workspace_id = ? AND revoked_at IS NULL", workspaceID)

	if scope.standing() {
		q = q.Where("is_standing")
	}
	if len(scope.EntitlementTypes) > 0 {
		q = q.Where("entitlement_type IN ?", scope.EntitlementTypes)
	}
	if len(scope.SubjectTypes) > 0 {
		q = q.Where("subject_type IN ?", scope.SubjectTypes)
	}
	if len(scope.Origins) > 0 {
		q = q.Where("origin IN ?", scope.Origins)
	}
	if len(scope.ResourceServerIDs) > 0 {
		ids := make([]string, 0, len(scope.ResourceServerIDs))
		for _, id := range scope.ResourceServerIDs {
			ids = append(ids, id.String())
		}
		// The RS lives in the snapshot, which is where it stays readable after the grant
		// row is gone.
		q = q.Where("entitlement_snapshot #>> '{resource_server_id}' IN ?", ids)
	}
	if scope.AgentsOnly {
		// An agent anchor is a service account paired to an oauth client.
		q = q.Where(`subject_type = ? AND EXISTS (
		               SELECT 1 FROM service_accounts sa
		                WHERE sa.id = entitlement_provenance.subject_id
		                  AND sa.oauth_client_id IS NOT NULL)`,
			models.ProvenanceSubjectServiceAccount)
	}
	if scope.DormantDays > 0 {
		// No token issued for the subject within the window. The highest-signal filter
		// available: standing access nobody uses.
		cutoff := time.Now().AddDate(0, 0, -scope.DormantDays)
		q = q.Where(`NOT EXISTS (
		               SELECT 1 FROM native_tokens nt
		                WHERE nt.subject_id = entitlement_provenance.subject_id
		                  AND nt.issued_at >= ?)`, cutoff)
	}

	var out []models.EntitlementProvenance
	// Standing first, then oldest — the grants most likely to be stale lead the queue.
	err := q.Order("is_standing DESC").Order("granted_at ASC").Find(&out).Error
	return out, err
}

// assembleEvidence gathers everything the reviewer needs, and computes a suggestion.
func (m *certifyManager) assembleEvidence(workspaceID uuid.UUID,
	p *models.EntitlementProvenance) (*itemEvidence, error) {

	ev := &itemEvidence{
		Origin:        p.Origin,
		Justification: p.Justification,
		Purpose:       p.Purpose,
		GrantedBy:     p.GrantedByLabel,
		GrantedAt:     p.GrantedAt,
		IsStanding:    p.IsStanding,
		ExpiresAt:     p.ExpiresAt,
		AgeDays:       int(time.Since(p.GrantedAt).Hours() / 24),
	}

	// Usage. subject_type in native_tokens only ever holds user/service_account, so
	// anything else has no token history to report rather than an empty one.
	if p.SubjectType == models.ProvenanceSubjectUser ||
		p.SubjectType == models.ProvenanceSubjectServiceAccount {
		var usage struct {
			Count int64
			Last  *time.Time
		}
		if err := m.db.Raw(`
			SELECT count(*) AS count, max(issued_at) AS last
			  FROM native_tokens
			 WHERE subject_id = ? AND subject_type = ?`,
			p.SubjectID, p.SubjectType).Scan(&usage).Error; err != nil {
			return nil, fmt.Errorf("token usage: %w", err)
		}
		ev.TokensIssued = usage.Count
		ev.LastTokenIssuedAt = usage.Last
		ev.NeverUsed = usage.Count == 0
		if usage.Last != nil {
			d := int(time.Since(*usage.Last).Hours() / 24)
			ev.DormantDays = &d
		}
	}

	// Runtime state, straight from discovery. This is evidence no traditional IGA has:
	// whether the workload behind the entitlement is even running.
	if p.DiscoveredAgentID != nil {
		var agent struct {
			RuntimeStatus string
			LastSeenAt    *time.Time
		}
		if err := m.db.Raw(`SELECT runtime_status, last_seen_at FROM discovered_agents WHERE id = ?`,
			*p.DiscoveredAgentID).Scan(&agent).Error; err == nil {
			ev.RuntimeStatus = agent.RuntimeStatus
			ev.LastSeenAt = agent.LastSeenAt
		}
	}

	// Open conflicts, so risk sits next to the grant rather than in another report.
	var violations []string
	if err := m.db.Raw(`
		SELECT rule_name FROM sod_violations
		 WHERE workspace_id = ? AND subject_type = ? AND subject_id = ? AND status = 'open'`,
		workspaceID, p.SubjectType, p.SubjectID).Scan(&violations).Error; err == nil {
		ev.OpenSoDViolations = violations
	}

	ev.Recommendation, ev.RecommendationReason = recommend(ev)
	return ev, nil
}

// recommend computes a SUGGESTION, never a decision.
//
// Deliberately advisory: an automatic revoke on these signals would let a heuristic
// kill a quiet-but-needed agent, and a reviewer who cannot disagree is not reviewing.
// It exists because an unranked queue of hundreds gets rubber-stamped.
func recommend(ev *itemEvidence) (string, string) {
	switch {
	case len(ev.OpenSoDViolations) > 0:
		return "revoke", fmt.Sprintf("open separation-of-duties violation: %s",
			strings.Join(ev.OpenSoDViolations, ", "))
	case ev.RuntimeStatus == models.RuntimeStatusGone:
		return "revoke", "the workload behind this entitlement is no longer running"
	case ev.NeverUsed && ev.AgeDays >= 30:
		return "revoke", fmt.Sprintf("granted %d days ago and never used", ev.AgeDays)
	case ev.DormantDays != nil && *ev.DormantDays >= 90:
		return "revoke", fmt.Sprintf("unused for %d days", *ev.DormantDays)
	case ev.IsStanding && strings.Contains(ev.Justification, legacyStandingJustification):
		return "review", "permanent access with no stated business reason — set an expiry or justify it"
	case ev.IsStanding:
		return "review", "permanent access: confirm it still needs to be permanent"
	default:
		return "keep", "in active use"
	}
}

// resolveReviewer picks who has to decide: resource-server owner -> the human who
// granted it -> workspace owner.
//
// Frozen onto the item at generation, so a later ownership change cannot silently move
// an in-flight review to somebody who never saw it.
func (m *certifyManager) resolveReviewer(workspaceID uuid.UUID,
	p *models.EntitlementProvenance) (*uuid.UUID, string, string) {

	// 1. The owner of the Application the entitlement grants access to. The most
	// defensible reviewer: they are accountable for what it protects.
	var snap struct {
		ResourceServerID string `json:"resource_server_id"`
	}
	if len(p.Snapshot) > 0 {
		_ = json.Unmarshal(p.Snapshot, &snap)
	}
	if snap.ResourceServerID != "" {
		if rsID, err := uuid.Parse(snap.ResourceServerID); err == nil {
			var owner struct {
				ID    *uuid.UUID
				Email string
			}
			if err := m.db.Raw(`
				SELECT u.id, COALESCE(u.email,'') AS email
				  FROM resource_servers rs JOIN users u ON u.id = rs.owner_user_id
				 WHERE rs.id = ? AND rs.workspace_id = ?`, rsID, workspaceID).
				Scan(&owner).Error; err == nil && owner.ID != nil {
				return owner.ID, owner.Email, "resource_server_owner"
			}
		}
	}

	// 2. Whoever granted it. They made the call, so they can defend or withdraw it.
	if p.GrantedBy != nil {
		var email string
		if err := m.db.Raw(`SELECT COALESCE(email,'') FROM users WHERE id = ? AND workspace_id = ?`,
			*p.GrantedBy, workspaceID).Scan(&email).Error; err == nil && email != "" {
			return p.GrantedBy, email, "granted_by"
		}
	}

	// 3. The workspace owner. Not a good reviewer for volume, but better than nobody —
	// an unassigned item is one nobody will decide.
	var wsOwner struct {
		ID    *uuid.UUID
		Email string
	}
	if err := m.db.Raw(`
		SELECT u.id, COALESCE(u.email,'') AS email
		  FROM workspaces w JOIN users u ON u.id = w.owner_user_id
		 WHERE w.id = ?`, workspaceID).Scan(&wsOwner).Error; err == nil && wsOwner.ID != nil {
		return wsOwner.ID, wsOwner.Email, "workspace_owner"
	}
	return nil, "", ""
}

/* -------------------------------- decisions ------------------------------ */

func (m *certifyManager) ListItems(workspaceID, campaignID uuid.UUID,
	f ItemFilter) ([]models.CertificationItem, int64, error) {

	q := m.db.Model(&models.CertificationItem{}).
		Where("workspace_id = ? AND campaign_id = ?", workspaceID, campaignID)
	if f.ReviewerUserID != nil {
		q = q.Where("reviewer_user_id = ?", *f.ReviewerUserID)
	}
	if f.PendingOnly {
		q = q.Where("decision = ?", models.DecisionPending)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	var out []models.CertificationItem
	// Pending first, then the ones the evidence says to revoke, so a reviewer working
	// top-down handles the riskiest items while their attention is freshest.
	err := q.Order(`CASE decision WHEN 'pending' THEN 0 ELSE 1 END`).
		Order(`CASE evidence #>> '{recommendation}' WHEN 'revoke' THEN 0 WHEN 'review' THEN 1 ELSE 2 END`).
		Order("created_at ASC").
		Limit(limit).Offset(offset).Find(&out).Error
	return out, total, err
}

func (m *certifyManager) Decide(workspaceID, itemID uuid.UUID, in DecisionInput) (*models.CertificationItem, error) {
	if !containsString(models.ValidDecisions(), in.Decision) || in.Decision == models.DecisionPending {
		return nil, fmt.Errorf("decision must be one of keep, revoke, delegate (got %q)", in.Decision)
	}
	note := strings.TrimSpace(in.Note)
	// Keeping needs a reason as much as revoking does. "Keep" with no justification is
	// exactly the rubber stamp certification exists to prevent, and the DB enforces it
	// too.
	if in.Decision == models.DecisionKeep && note == "" {
		return nil, errors.New("a 'keep' decision requires a note: confirming access without " +
			"stating why is the rubber stamp certification exists to prevent")
	}
	if in.Decision == models.DecisionDelegate && in.DelegateTo == nil {
		return nil, errors.New("delegate requires delegate_to")
	}

	var item models.CertificationItem
	if err := m.db.First(&item, "id = ? AND workspace_id = ?", itemID, workspaceID).Error; err != nil {
		return nil, err
	}
	if item.Decision != models.DecisionPending {
		return nil, fmt.Errorf("this item was already decided (%s)", item.Decision)
	}

	var campaign models.CertificationCampaign
	if err := m.db.First(&campaign, "id = ?", item.CampaignID).Error; err != nil {
		return nil, err
	}
	if campaign.Status != models.CampaignStatusActive {
		return nil, fmt.Errorf("campaign is %s, not active", campaign.Status)
	}

	now := time.Now()

	// Delegation reassigns rather than decides: the item stays pending for its new
	// reviewer, because passing an item on is not a decision about the access.
	if in.Decision == models.DecisionDelegate {
		var email string
		_ = m.db.Raw(`SELECT COALESCE(email,'') FROM users WHERE id = ? AND workspace_id = ?`,
			*in.DelegateTo, workspaceID).Scan(&email).Error
		if err := m.db.Model(&models.CertificationItem{}).Where("id = ?", itemID).
			Updates(map[string]interface{}{
				"reviewer_user_id": *in.DelegateTo,
				"reviewer_label":   email,
				"reviewer_source":  "delegated",
				"decision_note":    note,
			}).Error; err != nil {
			return nil, err
		}
		return m.getItem(workspaceID, itemID)
	}

	updates := map[string]interface{}{
		"decision":      in.Decision,
		"decision_note": note,
		"decided_by":    in.By,
		"decided_at":    now,
	}

	// A revoke executes the standard de-provision path — nothing else in this package
	// revokes anything (PG-6). Done BEFORE recording the decision so a failed
	// revocation does not leave an item claiming access was removed when it was not.
	if in.Decision == models.DecisionRevoke {
		if err := m.executeRevocation(workspaceID, &item, in.By, note); err != nil {
			return nil, fmt.Errorf("revoke: %w", err)
		}
		updates["revocation_executed_at"] = now
	}

	if err := m.db.Model(&models.CertificationItem{}).Where("id = ?", itemID).
		Updates(updates).Error; err != nil {
		return nil, err
	}

	// Campaign counters.
	counter := map[string]interface{}{
		"items_decided": gorm.Expr("items_decided + 1"),
		"updated_at":    now,
	}
	if in.Decision == models.DecisionKeep {
		counter["items_kept"] = gorm.Expr("items_kept + 1")
	} else {
		counter["items_revoked"] = gorm.Expr("items_revoked + 1")
	}
	if err := m.db.Model(&models.CertificationCampaign{}).
		Where("id = ?", item.CampaignID).Updates(counter).Error; err != nil {
		return nil, err
	}

	return m.getItem(workspaceID, itemID)
}

// executeRevocation revokes the certified entitlement through the one de-provision
// path, so a certification revoke produces the same effect and audit shape as an
// expiry, a leaver, or an admin revoke.
func (m *certifyManager) executeRevocation(workspaceID uuid.UUID, item *models.CertificationItem,
	by *uuid.UUID, note string) error {

	if item.EntitlementProvenanceID == nil {
		// The provenance row is gone, so the grant it described is gone too. Nothing to
		// revoke, and reporting failure would block a reviewer from closing out an item
		// about access that no longer exists.
		return nil
	}
	var p models.EntitlementProvenance
	if err := m.db.First(&p, "id = ?", *item.EntitlementProvenanceID).Error; err != nil {
		return err
	}
	if !p.IsOpen() {
		// Already revoked by something else — an expiry, or a de-provision. Fine.
		return nil
	}

	reason := "revoked at certification"
	if note != "" {
		reason = "revoked at certification: " + note
	}

	// A role binding is revoked directly; an agent's whole identity is not torn down
	// just because one of its entitlements failed review.
	if p.EntitlementType == models.EntitlementRoleBinding && p.RoleBindingID != nil {
		bindingID := *p.RoleBindingID
		return m.db.Transaction(func(tx *gorm.DB) error {
			if _, err := m.provenance.CloseGrant(tx, workspaceID, CloseGrantInput{
				RoleBindingID: &bindingID,
				Via:           models.RevokedViaCertification,
				Reason:        reason,
				By:            by,
				At:            time.Now(),
			}); err != nil {
				return err
			}
			// Kill live tokens too: leaving them would keep the revoked access working
			// for up to their remaining lifetime.
			tokens, err := m.repo.LiveTokenJTIsForSubject(p.SubjectID, p.SubjectType)
			if err != nil {
				return err
			}
			if len(tokens) > 0 {
				if err := m.repo.RevokeTokensTx(tx, tokens, reason); err != nil {
					return err
				}
			}
			return m.repo.DeleteRoleBindingTx(tx, bindingID)
		})
	}

	// A client registration failing review means the agent should not be connected at
	// all, which is a full de-provision.
	if p.EntitlementType == models.EntitlementClientRegistration && p.SubjectType == models.ProvenanceSubjectOAuthClient {
		clientID := p.SubjectID
		_, err := m.prov.Deprovision(workspaceID, DeprovisionInput{
			OAuthClientID: &clientID,
			Via:           models.RevokedViaCertification,
			Reason:        reason,
			By:            by,
		})
		return err
	}

	// Anything else: close the record so the inventory is honest, and say so rather
	// than pretending the underlying grant was removed.
	_, err := m.provenance.CloseGrant(nil, workspaceID, CloseGrantInput{
		RoleBindingID:         p.RoleBindingID,
		ClientRegistrationID:  p.ClientRegistrationID,
		ConnectorAssignmentID: p.ConnectorAssignmentID,
		Via:                   models.RevokedViaCertification,
		Reason:                reason,
		By:                    by,
		At:                    time.Now(),
	})
	return err
}

func (m *certifyManager) getItem(workspaceID, itemID uuid.UUID) (*models.CertificationItem, error) {
	var out models.CertificationItem
	err := m.db.First(&out, "id = ? AND workspace_id = ?", itemID, workspaceID).Error
	return &out, err
}

/* ---------------------------------- close -------------------------------- */

func (m *certifyManager) Close(workspaceID, campaignID uuid.UUID, by *uuid.UUID,
	force bool) (*models.CertificationCampaign, error) {

	campaign, err := m.GetCampaign(workspaceID, campaignID)
	if err != nil {
		return nil, err
	}
	if campaign.Status == models.CampaignStatusClosed {
		return campaign, nil // idempotent
	}

	var pending int64
	if err := m.db.Model(&models.CertificationItem{}).
		Where("campaign_id = ? AND decision = ?", campaignID, models.DecisionPending).
		Count(&pending).Error; err != nil {
		return nil, err
	}
	if pending > 0 && !force {
		// Closing with undecided items produces an export that claims a review happened
		// where it did not. Allowed with force, and the export records how many were
		// left undecided so the gap is in the artifact rather than hidden by it.
		return nil, fmt.Errorf("%d item(s) still undecided; decide them or close with force=true "+
			"(the export will record them as undecided)", pending)
	}

	var items []models.CertificationItem
	if err := m.db.Where("campaign_id = ?", campaignID).Order("created_at").
		Find(&items).Error; err != nil {
		return nil, err
	}

	// The frozen export. Stored rather than recomputed: recomputing later would reflect
	// the world as it is then, not as the reviewer found it.
	export := map[string]interface{}{
		"campaign_id":       campaign.ID,
		"campaign_name":     campaign.Name,
		"workspace_id":      workspaceID,
		"scope":             json.RawMessage(campaign.Scope),
		"generated_at":      campaign.GeneratedAt,
		"closed_at":         time.Now().UTC(),
		"due_at":            campaign.DueAt,
		"items_total":       len(items),
		"items_undecided":   pending,
		"closed_with_force": force && pending > 0,
		"items":             items,
	}
	exportJSON, err := json.Marshal(export)
	if err != nil {
		return nil, fmt.Errorf("build export: %w", err)
	}

	now := time.Now()
	if err := m.db.Model(&models.CertificationCampaign{}).Where("id = ?", campaignID).
		Updates(map[string]interface{}{
			"status":     models.CampaignStatusClosed,
			"export":     exportJSON,
			"closed_at":  now,
			"closed_by":  by,
			"updated_at": now,
		}).Error; err != nil {
		return nil, err
	}
	return m.GetCampaign(workspaceID, campaignID)
}
