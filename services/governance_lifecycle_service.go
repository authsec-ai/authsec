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

// LifecycleManager reconciles human access against birthright policy.
//
// RECONCILED, NOT EVENT-DRIVEN. ARCHITECTURE.md §4.5 proposed consuming `scim_events`;
// that table is an HTTP audit log (method, path, status_code) with no semantic payload,
// so a `PATCH /Users/123` could be a rename, a deactivation, or a group edit and the
// before/after state is recorded nowhere. Joiner/mover/leaver simply cannot be derived
// from it.
//
// Reconciling is better than the event stream would have been: it catches changes made
// through ANY path, it is idempotent and self-healing, and it needs no cursor — the
// desired state is computable from birthright policies and the actual state is already
// in entitlement_provenance (origin='birthright').
//
// THE ASYMMETRY THAT MATTERS. Joiner grants and leaver revocations are automatic,
// because both are unambiguous: a matching policy means the access is intended, and a
// deactivated user must lose access immediately. A MOVER is not unambiguous — a group
// change may be a correction, a temporary secondment, or a mistake — so by default it is
// flagged, not revoked. Auto-revoking on a group edit would let one mistyped membership
// take somebody's access away with nobody in the loop.
type LifecycleManager interface {
	CreatePolicy(workspaceID uuid.UUID, createdBy string, in BirthrightInput) (*models.BirthrightPolicy, error)
	ListPolicies(workspaceID uuid.UUID) ([]models.BirthrightPolicy, error)
	DeletePolicy(workspaceID, id uuid.UUID) error

	// Reconcile brings a workspace's human access into line with policy. Safe to run on
	// a timer forever: everything it does is idempotent.
	Reconcile(workspaceID uuid.UUID, opts ReconcileOptions) (*ReconcileResult, error)

	// ReconcileUser reconciles one user, for an admin acting on a single joiner or
	// leaver without waiting for the next sweep.
	ReconcileUser(workspaceID, userID uuid.UUID, opts ReconcileOptions) (*ReconcileResult, error)

	// StaleBirthrights lists grants whose policy no longer matches the holder — the
	// mover queue a human decides on.
	StaleBirthrights(workspaceID uuid.UUID) ([]StaleBirthright, error)

	// OrphanedAgents lists agents whose accountable owner has been deactivated.
	OrphanedAgents(workspaceID uuid.UUID) ([]OrphanedAgent, error)
}

// BirthrightInput creates a policy.
type BirthrightInput struct {
	Name             string
	Description      string
	MatchKind        string
	MatchGroupID     *uuid.UUID
	ResourceServerID uuid.UUID
	RoleID           uuid.UUID
	// Duration nil means a STANDING grant, which requires a justification — the same
	// rule as everywhere else, and it matters most here because a birthright applies to
	// a whole group.
	Duration      *time.Duration
	Justification string
	OnUnmatch     string
}

// ReconcileOptions tunes one pass.
type ReconcileOptions struct {
	// DryRun computes everything and changes nothing. The first thing to run against a
	// real workspace, because a birthright policy's blast radius is an entire group.
	DryRun bool
	// Actor is recorded as the grantor on birthright provenance.
	Actor      *uuid.UUID
	ActorLabel string
}

// ReconcileResult reports what a pass did or would do.
type ReconcileResult struct {
	DryRun         bool `json:"dry_run"`
	UsersScanned   int  `json:"users_scanned"`
	PoliciesActive int  `json:"policies_active"`

	// Joiner.
	GrantsCreated int `json:"grants_created"`
	// Mover.
	StaleFlagged int `json:"stale_flagged"`
	StaleRevoked int `json:"stale_revoked"`
	// Leaver.
	LeaversProcessed int `json:"leavers_processed"`
	BindingsRevoked  int `json:"bindings_revoked"`
	TokensRevoked    int `json:"tokens_revoked"`
	// Agents whose owner left. Reported, never killed — see the comment on
	// processLeaver.
	OrphanedAgents int `json:"orphaned_agents"`

	Errors []string `json:"errors,omitempty"`
}

// StaleBirthright is a grant whose policy no longer matches its holder.
type StaleBirthright struct {
	ProvenanceID     uuid.UUID `json:"provenance_id"`
	UserID           uuid.UUID `json:"user_id"`
	UserLabel        string    `json:"user_label"`
	EntitlementLabel string    `json:"entitlement_label"`
	GrantedAt        time.Time `json:"granted_at"`
	// Reason is written for a human deciding what to do.
	Reason string `json:"reason"`
}

// OrphanedAgent is an agent whose accountable owner has been deactivated.
type OrphanedAgent struct {
	DiscoveredAgentID *uuid.UUID `json:"discovered_agent_id,omitempty"`
	OAuthClientID     uuid.UUID  `json:"oauth_client_id"`
	ClientID          string     `json:"client_id"`
	DisplayName       string     `json:"display_name"`
	OwnerUserID       uuid.UUID  `json:"owner_user_id"`
	OwnerEmail        string     `json:"owner_email"`
	RuntimeStatus     string     `json:"runtime_status,omitempty"`
	GovernanceStatus  string     `json:"governance_status"`
}

type lifecycleManager struct {
	db         *gorm.DB
	repo       repositories.GovernanceRepository
	provenance ProvenanceManager
	prov       ProvisioningManager
	sod        SoDManager
}

// NewLifecycleManager constructs a LifecycleManager.
func NewLifecycleManager(db *gorm.DB, oauth *OAuthASService) LifecycleManager {
	repo := repositories.NewGovernanceRepository(db)
	return &lifecycleManager{
		db:         db,
		repo:       repo,
		provenance: NewProvenanceManager(repo),
		prov:       NewProvisioningManager(db, oauth),
		sod:        NewSoDManager(db),
	}
}

/* -------------------------------- policies ------------------------------- */

func (m *lifecycleManager) CreatePolicy(workspaceID uuid.UUID, createdBy string,
	in BirthrightInput) (*models.BirthrightPolicy, error) {

	if strings.TrimSpace(in.Name) == "" {
		return nil, errors.New("name is required")
	}
	if in.ResourceServerID == uuid.Nil || in.RoleID == uuid.Nil {
		return nil, errors.New("resource_server_id and role_id are required")
	}
	kind := in.MatchKind
	if kind == "" {
		kind = models.BirthrightMatchGroup
	}
	if !containsString(models.ValidBirthrightMatchKinds(), kind) {
		return nil, fmt.Errorf("match_kind must be group or all (got %q)", kind)
	}
	if kind == models.BirthrightMatchGroup && in.MatchGroupID == nil {
		return nil, errors.New("match_group_id is required for a group policy")
	}
	if kind == models.BirthrightMatchAll && in.MatchGroupID != nil {
		return nil, errors.New("an 'all' policy must not name a group: it would look " +
			"scoped while applying to everyone")
	}
	onUnmatch := in.OnUnmatch
	if onUnmatch == "" {
		onUnmatch = models.OnUnmatchFlag
	}
	if !containsString(models.ValidOnUnmatch(), onUnmatch) {
		return nil, fmt.Errorf("on_unmatch must be flag or revoke (got %q)", onUnmatch)
	}
	justification := strings.TrimSpace(in.Justification)
	if in.Duration == nil && justification == "" {
		// A standing birthright is the widest blast radius in the system: permanent
		// access for an entire group. Somebody has to say why on the record.
		return nil, errors.New("a birthright with no duration is a STANDING grant for " +
			"everyone it matches, and requires a justification")
	}
	if in.Duration != nil && *in.Duration <= 0 {
		return nil, errors.New("duration must be positive")
	}

	// The role must live in this workspace, and the RS too — otherwise a policy could
	// graft a foreign-workspace role onto every member of a group.
	if err := m.validateTarget(workspaceID, in.ResourceServerID, in.RoleID); err != nil {
		return nil, err
	}

	p := &models.BirthrightPolicy{
		ID:               uuid.New(),
		WorkspaceID:      workspaceID,
		Name:             strings.TrimSpace(in.Name),
		Description:      in.Description,
		MatchKind:        kind,
		MatchGroupID:     in.MatchGroupID,
		ResourceServerID: in.ResourceServerID,
		RoleID:           in.RoleID,
		Justification:    justification,
		OnUnmatch:        onUnmatch,
		Enabled:          true,
		CreatedBy:        createdBy,
	}
	if in.Duration != nil {
		p.Duration = models.PGInterval(*in.Duration)
	}
	if err := m.db.Create(p).Error; err != nil {
		return nil, err
	}
	return p, nil
}

func (m *lifecycleManager) validateTarget(workspaceID, rsID, roleID uuid.UUID) error {
	var n int64
	if err := m.db.Table("resource_servers").
		Where("id = ? AND workspace_id = ?", rsID, workspaceID).Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return errors.New("resource_server not found in this workspace")
	}
	if err := m.db.Table("roles").
		Where("id = ? AND (workspace_id = ? OR workspace_id IS NULL)", roleID, workspaceID).
		Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return errors.New("role not found in this workspace")
	}
	return nil
}

func (m *lifecycleManager) ListPolicies(workspaceID uuid.UUID) ([]models.BirthrightPolicy, error) {
	var out []models.BirthrightPolicy
	err := m.db.Where("workspace_id = ?", workspaceID).
		Order("enabled DESC, name").Find(&out).Error
	return out, err
}

func (m *lifecycleManager) DeletePolicy(workspaceID, id uuid.UUID) error {
	// Grants already made are NOT revoked: deleting a policy stops future grants, it is
	// not a mass-revocation instruction. The existing grants become stale birthrights,
	// which surface in the mover queue for a human to decide on.
	res := m.db.Delete(&models.BirthrightPolicy{}, "id = ? AND workspace_id = ?", id, workspaceID)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

/* ------------------------------- reconcile ------------------------------- */

// userState is everything the reconcile needs about one person.
type userState struct {
	ID        uuid.UUID
	Email     string
	Active    bool
	DeletedAt *time.Time
	GroupIDs  []uuid.UUID
}

func (m *lifecycleManager) Reconcile(workspaceID uuid.UUID, opts ReconcileOptions) (*ReconcileResult, error) {
	users, err := m.loadUsers(workspaceID, nil)
	if err != nil {
		return nil, err
	}
	return m.reconcileUsers(workspaceID, users, opts)
}

func (m *lifecycleManager) ReconcileUser(workspaceID, userID uuid.UUID,
	opts ReconcileOptions) (*ReconcileResult, error) {

	users, err := m.loadUsers(workspaceID, &userID)
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return m.reconcileUsers(workspaceID, users, opts)
}

// loadUsers reads users and their group memberships.
//
// Reads `active`, NOT `is_active`: `active` is what models.User maps and what the SCIM
// controller writes on deactivation. `is_active` is a vestigial duplicate column with no
// writer, and reading it would make every leaver invisible.
func (m *lifecycleManager) loadUsers(workspaceID uuid.UUID, only *uuid.UUID) ([]userState, error) {
	type row struct {
		ID        uuid.UUID
		Email     string
		Active    bool
		DeletedAt *time.Time
	}
	q := m.db.Table("users").
		Select("id, COALESCE(email,'') AS email, COALESCE(active,true) AS active, deleted_at").
		Where("workspace_id = ?", workspaceID)
	if only != nil {
		q = q.Where("id = ?", *only)
	}
	var rows []row
	if err := q.Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("load users: %w", err)
	}

	out := make([]userState, 0, len(rows))
	for _, r := range rows {
		var groups []uuid.UUID
		if err := m.db.Table("user_groups").Where("user_id = ? AND workspace_id = ?",
			r.ID, workspaceID).Pluck("group_id", &groups).Error; err != nil {
			return nil, fmt.Errorf("load groups for %s: %w", r.ID, err)
		}
		out = append(out, userState{
			ID: r.ID, Email: r.Email, Active: r.Active, DeletedAt: r.DeletedAt, GroupIDs: groups,
		})
	}
	return out, nil
}

func (m *lifecycleManager) reconcileUsers(workspaceID uuid.UUID, users []userState,
	opts ReconcileOptions) (*ReconcileResult, error) {

	var policies []models.BirthrightPolicy
	if err := m.db.Where("workspace_id = ? AND enabled", workspaceID).
		Find(&policies).Error; err != nil {
		return nil, err
	}

	res := &ReconcileResult{
		DryRun:         opts.DryRun,
		UsersScanned:   len(users),
		PoliciesActive: len(policies),
	}

	for i := range users {
		u := &users[i]

		// LEAVER first. A deactivated user's desired birthright set is empty regardless
		// of what groups they are still in, so computing joiner grants for them would be
		// actively wrong.
		if !u.Active || u.DeletedAt != nil {
			if err := m.processLeaver(workspaceID, u, opts, res); err != nil {
				res.Errors = append(res.Errors,
					fmt.Sprintf("leaver %s: %v", u.Email, err))
			}
			continue
		}

		if err := m.processActiveUser(workspaceID, u, policies, opts, res); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("user %s: %v", u.Email, err))
		}
	}
	return res, nil
}

// matches reports whether a policy applies to a user.
func matchesPolicy(p *models.BirthrightPolicy, u *userState) bool {
	if p.MatchKind == models.BirthrightMatchAll {
		return true
	}
	if p.MatchGroupID == nil {
		return false
	}
	for _, g := range u.GroupIDs {
		if g == *p.MatchGroupID {
			return true
		}
	}
	return false
}

// processActiveUser handles the joiner and mover halves for one active user.
func (m *lifecycleManager) processActiveUser(workspaceID uuid.UUID, u *userState,
	policies []models.BirthrightPolicy, opts ReconcileOptions, res *ReconcileResult) error {

	// What this user's birthright grants currently are.
	var existing []models.EntitlementProvenance
	if err := m.db.Where(`workspace_id = ? AND subject_type = ? AND subject_id = ?
	                      AND origin = ? AND revoked_at IS NULL`,
		workspaceID, models.ProvenanceSubjectUser, u.ID, models.GrantOriginBirthright).
		Find(&existing).Error; err != nil {
		return err
	}
	// Keyed by the policy that produced them, which is why the policy id goes into the
	// snapshot at grant time.
	held := map[uuid.UUID]*models.EntitlementProvenance{}
	for i := range existing {
		if pid := birthrightPolicyID(&existing[i]); pid != uuid.Nil {
			held[pid] = &existing[i]
		}
	}

	// JOINER: a matching policy with no grant yet.
	for i := range policies {
		p := &policies[i]
		if !matchesPolicy(p, u) {
			continue
		}
		if _, ok := held[p.ID]; ok {
			continue
		}
		if opts.DryRun {
			res.GrantsCreated++
			continue
		}
		if err := m.grantBirthright(workspaceID, u, p, opts); err != nil {
			return fmt.Errorf("grant %s: %w", p.Name, err)
		}
		res.GrantsCreated++
	}

	// MOVER: a grant whose policy no longer matches.
	for pid, prov := range held {
		var p *models.BirthrightPolicy
		for i := range policies {
			if policies[i].ID == pid {
				p = &policies[i]
				break
			}
		}
		// Either the policy is gone/disabled, or the user stopped matching it.
		if p != nil && matchesPolicy(p, u) {
			continue
		}

		// Default is FLAG, not revoke. A group change may be a correction, a temporary
		// secondment, or a mistake; auto-revoking would let one mistyped membership take
		// somebody's access away with nobody in the loop.
		if p == nil || p.OnUnmatch == models.OnUnmatchFlag {
			res.StaleFlagged++
			continue
		}
		if opts.DryRun {
			res.StaleRevoked++
			continue
		}
		if err := m.revokeBirthright(workspaceID, prov, opts,
			"birthright no longer matches: "+p.Name); err != nil {
			return fmt.Errorf("revoke stale %s: %w", p.Name, err)
		}
		res.StaleRevoked++
	}
	return nil
}

// birthrightPolicyID pulls the originating policy out of a grant's snapshot.
func birthrightPolicyID(p *models.EntitlementProvenance) uuid.UUID {
	var snap struct {
		BirthrightPolicyID string `json:"birthright_policy_id"`
	}
	if len(p.Snapshot) == 0 {
		return uuid.Nil
	}
	if err := json.Unmarshal(p.Snapshot, &snap); err != nil {
		return uuid.Nil
	}
	id, err := uuid.Parse(snap.BirthrightPolicyID)
	if err != nil {
		return uuid.Nil
	}
	return id
}

// grantBirthright creates one birthright entitlement, atomically with its provenance.
func (m *lifecycleManager) grantBirthright(workspaceID uuid.UUID, u *userState,
	p *models.BirthrightPolicy, opts ReconcileOptions) error {

	var expiresAt *time.Time
	standing := true
	if d := time.Duration(p.Duration); d > 0 {
		t := time.Now().Add(d)
		expiresAt = &t
		standing = false
	}

	// SoD applies to birthrights too. A policy that would create a conflict for one
	// member of a group must not silently grant it — the preventive check has to guard
	// every entry point or it is not a control.
	decision, err := m.sod.Check(nil, workspaceID, SoDCheckInput{
		SubjectType:  models.ProvenanceSubjectUser,
		SubjectID:    u.ID,
		SubjectLabel: u.Email,
		AddingRoleID: p.RoleID,
	})
	if err != nil {
		return fmt.Errorf("separation-of-duties check: %w", err)
	}
	if !decision.Allowed {
		return fmt.Errorf("refused by %s: %s",
			decision.Blocking[0].RuleName, decision.Blocking[0].Explanation)
	}

	justification := p.Justification
	if justification == "" {
		justification = "birthright policy " + p.Name
	}

	return m.db.Transaction(func(tx *gorm.DB) error {
		var rsName string
		_ = tx.Raw(`SELECT name FROM resource_servers WHERE id = ?`, p.ResourceServerID).
			Scan(&rsName).Error
		var roleName string
		_ = tx.Raw(`SELECT name FROM roles WHERE id = ?`, p.RoleID).Scan(&roleName).Error

		scopeType := "resource_server"
		rb := models.RoleBinding{
			WorkspaceID:      &workspaceID,
			RoleID:           p.RoleID,
			RoleName:         roleName,
			UserID:           &u.ID,
			ScopeType:        &scopeType,
			ScopeID:          &p.ResourceServerID,
			AssignmentSource: "birthright",
			Conditions:       []byte("{}"),
			ExpiresAt:        expiresAt,
			CreatedAt:        time.Now().UTC(),
		}
		if err := tx.Create(&rb).Error; err != nil {
			return fmt.Errorf("create binding: %w", err)
		}

		policyID := p.ID
		_, err := m.provenance.OpenGrant(tx, workspaceID, OpenGrantInput{
			EntitlementType: models.EntitlementRoleBinding,
			RoleBindingID:   &rb.ID,
			Snapshot: map[string]interface{}{
				// The policy id is what makes the mover diff possible: without it a later
				// pass cannot tell which policy produced this grant.
				"birthright_policy_id":   policyID.String(),
				"birthright_policy_name": p.Name,
				"role_id":                p.RoleID.String(),
				"role_name":              roleName,
				"scope_type":             scopeType,
				"resource_server_id":     p.ResourceServerID.String(),
				"resource_server":        rsName,
			},
			Label:          fmt.Sprintf("%s on %s (birthright)", roleName, rsName),
			SubjectType:    models.ProvenanceSubjectUser,
			SubjectID:      u.ID,
			SubjectLabel:   u.Email,
			Origin:         models.GrantOriginBirthright,
			Justification:  justification,
			Purpose:        p.Description,
			GrantedBy:      opts.Actor,
			GrantedByLabel: defaultString(opts.ActorLabel, "birthright reconcile"),
			ExpiresAt:      expiresAt,
			IsStanding:     standing,
		})
		return err
	})
}

// revokeBirthright removes one birthright grant through the standard path.
func (m *lifecycleManager) revokeBirthright(workspaceID uuid.UUID,
	prov *models.EntitlementProvenance, opts ReconcileOptions, reason string) error {

	if prov.RoleBindingID == nil {
		// Nothing to remove; just close the record so the inventory is honest.
		_, err := m.provenance.CloseGrant(nil, workspaceID, CloseGrantInput{
			ClientRegistrationID: prov.ClientRegistrationID,
			Via:                  models.RevokedViaLeaver,
			Reason:               reason,
			By:                   opts.Actor,
			At:                   time.Now(),
		})
		return err
	}
	bindingID := *prov.RoleBindingID

	return m.db.Transaction(func(tx *gorm.DB) error {
		if _, err := m.provenance.CloseGrant(tx, workspaceID, CloseGrantInput{
			RoleBindingID: &bindingID,
			Via:           models.RevokedViaLeaver,
			Reason:        reason,
			By:            opts.Actor,
			At:            time.Now(),
		}); err != nil {
			return err
		}
		tokens, err := m.repo.LiveTokenJTIsForSubject(prov.SubjectID, prov.SubjectType)
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

/* --------------------------------- leaver -------------------------------- */

// processLeaver revokes a deactivated user's access.
//
// AGENTS THEY OWNED ARE REPORTED, NOT KILLED. This is the one place I deliberately stop
// short of full automation. An agent is a running production workload; taking it down
// because a person changed jobs is its own incident, and the person leaving says nothing
// about whether the workload should keep running. So the human's access goes
// immediately, and their agents surface as orphaned for somebody to re-own or
// deprovision. Note the agent's OWN entitlements are untouched — they belong to the
// agent's service-account anchor, not to the departing user.
func (m *lifecycleManager) processLeaver(workspaceID uuid.UUID, u *userState,
	opts ReconcileOptions, res *ReconcileResult) error {

	// Every live binding held by this user, birthright or otherwise. A leaver loses all
	// access, not only what policy gave them.
	var bindings []models.RoleBinding
	if err := m.db.Where(`workspace_id = ? AND user_id = ?
	                      AND (expires_at IS NULL OR expires_at > NOW())`,
		workspaceID, u.ID).Find(&bindings).Error; err != nil {
		return err
	}

	// Agents this person owned. Counted, never killed — see the doc comment above.
	var orphanCount int64
	if err := m.db.Table("mcp_oauth_clients").
		Where("owner_user_id = ? AND governance_status <> ?",
			u.ID, models.GovernanceStatusDeprovisioned).
		Count(&orphanCount).Error; err != nil {
		return err
	}
	orphans := int(orphanCount)

	if opts.DryRun {
		if len(bindings) > 0 || orphans > 0 {
			res.LeaversProcessed++
		}
		res.BindingsRevoked += len(bindings)
		res.OrphanedAgents += orphans
		return nil
	}

	// Already processed and nothing new to do. Checked AFTER the dry-run branch so a
	// dry run still reports the true picture.
	if len(bindings) == 0 && orphans == 0 {
		return nil
	}
	res.LeaversProcessed++
	res.OrphanedAgents += orphans

	reason := "user deactivated"
	for i := range bindings {
		b := &bindings[i]
		bindingID := b.ID
		err := m.db.Transaction(func(tx *gorm.DB) error {
			// Close provenance if there is any; a grant predating provenance has none, and
			// that must not stop the revocation.
			if _, cerr := m.provenance.CloseGrant(tx, workspaceID, CloseGrantInput{
				RoleBindingID: &bindingID,
				Via:           models.RevokedViaLeaver,
				Reason:        reason,
				By:            opts.Actor,
				At:            time.Now(),
			}); cerr != nil {
				return cerr
			}
			return m.repo.DeleteRoleBindingTx(tx, bindingID)
		})
		if err != nil {
			return fmt.Errorf("revoke binding %s: %w", bindingID, err)
		}
		res.BindingsRevoked++
	}

	// Kill live tokens once, after the bindings are gone. Introspection treats
	// revoked_tokens as authoritative, so this is what makes the revocation immediate
	// rather than "when their current token expires".
	tokens, err := m.repo.LiveTokenJTIsForSubject(u.ID, models.ProvenanceSubjectUser)
	if err != nil {
		return err
	}
	if len(tokens) > 0 {
		if err := m.db.Transaction(func(tx *gorm.DB) error {
			return m.repo.RevokeTokensTx(tx, tokens, reason)
		}); err != nil {
			return err
		}
		res.TokensRevoked += len(tokens)
	}

	// Bookkeeping, so an operator can see the leaver was handled without reading the
	// audit log.
	summary := fmt.Sprintf("%d binding(s) revoked, %d token(s) killed, %d owned agent(s) orphaned",
		len(bindings), len(tokens), orphans)
	return m.db.Table("users").Where("id = ?", u.ID).Updates(map[string]interface{}{
		"access_revoked_at":      time.Now(),
		"access_revoked_summary": summary,
	}).Error
}

/* --------------------------------- reports ------------------------------- */

func (m *lifecycleManager) StaleBirthrights(workspaceID uuid.UUID) ([]StaleBirthright, error) {
	users, err := m.loadUsers(workspaceID, nil)
	if err != nil {
		return nil, err
	}
	byID := make(map[uuid.UUID]*userState, len(users))
	for i := range users {
		byID[users[i].ID] = &users[i]
	}

	var policies []models.BirthrightPolicy
	if err := m.db.Where("workspace_id = ? AND enabled", workspaceID).Find(&policies).Error; err != nil {
		return nil, err
	}
	byPolicy := make(map[uuid.UUID]*models.BirthrightPolicy, len(policies))
	for i := range policies {
		byPolicy[policies[i].ID] = &policies[i]
	}

	var grants []models.EntitlementProvenance
	if err := m.db.Where(`workspace_id = ? AND origin = ? AND revoked_at IS NULL`,
		workspaceID, models.GrantOriginBirthright).Find(&grants).Error; err != nil {
		return nil, err
	}

	var out []StaleBirthright
	for i := range grants {
		g := &grants[i]
		u := byID[g.SubjectID]
		pid := birthrightPolicyID(g)
		p := byPolicy[pid]

		switch {
		case u == nil:
			out = append(out, staleFrom(g, "", "the holder no longer exists in this workspace"))
		case !u.Active || u.DeletedAt != nil:
			out = append(out, staleFrom(g, u.Email, "the holder is deactivated"))
		case p == nil:
			out = append(out, staleFrom(g, u.Email,
				"the birthright policy that granted this has been deleted or disabled"))
		case !matchesPolicy(p, u):
			out = append(out, staleFrom(g, u.Email,
				fmt.Sprintf("the holder no longer matches policy %q", p.Name)))
		}
	}
	return out, nil
}

func staleFrom(g *models.EntitlementProvenance, email, reason string) StaleBirthright {
	return StaleBirthright{
		ProvenanceID:     g.ID,
		UserID:           g.SubjectID,
		UserLabel:        defaultString(email, g.SubjectLabel),
		EntitlementLabel: g.Label,
		GrantedAt:        g.GrantedAt,
		Reason:           reason,
	}
}

// OrphanedAgents lists agents whose accountable owner is deactivated.
//
// Its own report rather than an auto-revocation, because the two facts are independent:
// a person leaving says nothing about whether the workload they registered should keep
// running. Somebody has to re-own it or deprovision it deliberately.
func (m *lifecycleManager) OrphanedAgents(workspaceID uuid.UUID) ([]OrphanedAgent, error) {
	var out []OrphanedAgent
	err := m.db.Raw(`
		SELECT da.id AS discovered_agent_id,
		       c.id AS oauth_client_id,
		       c.client_id,
		       COALESCE(c.client_name, c.client_id) AS display_name,
		       c.owner_user_id,
		       COALESCE(u.email,'') AS owner_email,
		       COALESCE(da.runtime_status,'') AS runtime_status,
		       c.governance_status
		  FROM mcp_oauth_clients c
		  JOIN users u ON u.id = c.owner_user_id
		  LEFT JOIN discovered_agents da
		         ON da.matched_client_id = c.id AND da.workspace_id = ?
		 WHERE u.workspace_id = ?
		   AND (COALESCE(u.active, true) = false OR u.deleted_at IS NOT NULL)
		   AND c.governance_status <> ?
		 ORDER BY c.client_name`,
		workspaceID, workspaceID, models.GovernanceStatusDeprovisioned).Scan(&out).Error
	return out, err
}
