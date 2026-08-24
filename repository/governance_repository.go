package repositories

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ErrProvenanceAlreadyOpen is returned when a second open provenance row is opened
// for an entitlement that already has one. The database enforces this with a partial
// unique index; this is the friendly translation.
var ErrProvenanceAlreadyOpen = errors.New("this entitlement already has an open provenance record")

// GovernanceRepository owns entitlement provenance and the expiry sweep.
type GovernanceRepository interface {
	// OpenProvenance records a grant decision. Fails with ErrProvenanceAlreadyOpen
	// if the entitlement already has an open record.
	OpenProvenance(p *models.EntitlementProvenance) error

	// OpenProvenanceTx is OpenProvenance inside a caller-supplied transaction, so a
	// provisioning transaction can write provenance atomically with the grant itself.
	OpenProvenanceTx(tx *gorm.DB, p *models.EntitlementProvenance) error

	GetProvenance(workspaceID, id uuid.UUID) (*models.EntitlementProvenance, error)
	ListProvenance(workspaceID uuid.UUID, f ProvenanceFilter) ([]models.EntitlementProvenance, int64, error)

	// CloseProvenance closes the open record for an entitlement, reporting whether
	// there was one. Idempotent, and a missing record is NOT an error: every
	// revocation path may be retried, and a grant made before provenance existed has
	// no record to close — the caller must still revoke the grant itself.
	CloseProvenance(in CloseProvenanceInput) (closed bool, err error)
	CloseProvenanceTx(tx *gorm.DB, in CloseProvenanceInput) (closed bool, err error)

	// FindLapsedGrants returns open provenance rows whose expiry has passed, oldest
	// first, for the expiry worker. Standing grants are excluded — they have no
	// expiry by definition.
	FindLapsedGrants(limit int) ([]models.EntitlementProvenance, error)

	// FindOrphanedExpiredBindings returns role_bindings past expires_at that have no
	// open provenance row, i.e. grants made before provenance existed. They still
	// need cleaning up, but there is no "why" to close.
	FindOrphanedExpiredBindings(limit int) ([]ExpiredBinding, error)

	// DeleteRoleBindingTx removes an expired binding inside a transaction. Safe only
	// because provenance keeps the evidence — see the comment on the method.
	DeleteRoleBindingTx(tx *gorm.DB, bindingID uuid.UUID) error

	// LiveTokenJTIsForSubject returns unexpired, unrevoked native-token JTIs for a
	// subject, so revocation can close the window in which a token issued under a
	// now-lapsed grant still works.
	LiveTokenJTIsForSubject(subjectID uuid.UUID, subjectType string) ([]LiveToken, error)

	// RevokeTokensTx bulk-inserts revoked_tokens rows.
	RevokeTokensTx(tx *gorm.DB, tokens []LiveToken, reason string) error

	// DB exposes the handle so a service can open the transaction that spans a grant
	// and its provenance.
	DB() *gorm.DB
}

// ProvenanceFilter narrows a provenance listing. Empty fields are ignored.
type ProvenanceFilter struct {
	SubjectType       string
	SubjectID         *uuid.UUID
	EntitlementType   string
	Origin            string
	DiscoveredAgentID *uuid.UUID
	// OpenOnly restricts to grants still in force. Default false returns history too,
	// because "what happened to this?" is as common a question as "what is live?".
	OpenOnly bool
	// StandingOnly restricts to permanent grants — the first page of any campaign.
	StandingOnly bool
	// LapsedOnly restricts to open grants past their expiry: the expiry worker's
	// backlog, and a useful alarm on its own.
	LapsedOnly bool
	Limit      int
	Offset     int
}

// CloseProvenanceInput identifies the entitlement to close and records why.
//
// Exactly one of the three pointers must be set. The caller identifies the
// entitlement, not the provenance row, because every revocation path starts from the
// grant it is revoking rather than from its paperwork.
type CloseProvenanceInput struct {
	WorkspaceID           uuid.UUID
	RoleBindingID         *uuid.UUID
	ClientRegistrationID  *uuid.UUID
	ConnectorAssignmentID *uuid.UUID
	Via                   string
	Reason                string
	By                    *uuid.UUID
	At                    time.Time
}

// ExpiredBinding is a lapsed role binding the worker has to clean up.
type ExpiredBinding struct {
	ID          uuid.UUID
	WorkspaceID uuid.UUID
	RoleID      uuid.UUID
	RoleName    string
	ExpiresAt   time.Time
	// Exactly one of these is set, mirroring role_bindings.check_principal.
	UserID           *uuid.UUID
	GroupID          *uuid.UUID
	ServiceAccountID *uuid.UUID
}

// SubjectID returns the bound principal and its provenance subject type.
func (b ExpiredBinding) SubjectID() (uuid.UUID, string) {
	switch {
	case b.ServiceAccountID != nil:
		return *b.ServiceAccountID, models.ProvenanceSubjectServiceAccount
	case b.UserID != nil:
		return *b.UserID, models.ProvenanceSubjectUser
	case b.GroupID != nil:
		return *b.GroupID, models.ProvenanceSubjectGroup
	default:
		return uuid.Nil, ""
	}
}

// LiveToken is an unexpired, unrevoked native token.
//
// Kind matches revoked_tokens.kind, whose CHECK allows only 'id_jag' or
// 'access_token' — not an arbitrary token_type string.
type LiveToken struct {
	JTI       string
	Issuer    string
	Kind      string
	ExpiresAt time.Time
}

type governanceRepository struct{ db *gorm.DB }

// NewGovernanceRepository constructs a GovernanceRepository.
func NewGovernanceRepository(db *gorm.DB) GovernanceRepository {
	return &governanceRepository{db}
}

func (r *governanceRepository) DB() *gorm.DB { return r.db }

/* ------------------------------ provenance ------------------------------ */

func (r *governanceRepository) OpenProvenance(p *models.EntitlementProvenance) error {
	return r.OpenProvenanceTx(r.db, p)
}

func (r *governanceRepository) OpenProvenanceTx(tx *gorm.DB, p *models.EntitlementProvenance) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	if p.GrantedAt.IsZero() {
		p.GrantedAt = time.Now()
	}
	if len(p.Snapshot) == 0 {
		p.Snapshot = []byte("{}")
	}
	err := tx.Create(p).Error
	if err != nil && isDuplicateOpenProvenance(err) {
		return fmt.Errorf("%w (%s)", ErrProvenanceAlreadyOpen, p.EntitlementType)
	}
	return err
}

// isDuplicateOpenProvenance recognises a collision on any of the three partial
// unique indexes that enforce one-open-row-per-entitlement.
func isDuplicateOpenProvenance(err error) bool {
	msg := err.Error()
	for _, idx := range []string{
		"entitlement_provenance_open_role_binding_key",
		"entitlement_provenance_open_client_reg_key",
		"entitlement_provenance_open_connector_key",
	} {
		if strings.Contains(msg, idx) {
			return true
		}
	}
	return false
}

func (r *governanceRepository) GetProvenance(workspaceID, id uuid.UUID) (*models.EntitlementProvenance, error) {
	var p models.EntitlementProvenance
	if err := r.db.First(&p, "id = ? AND workspace_id = ?", id, workspaceID).Error; err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *governanceRepository) ListProvenance(workspaceID uuid.UUID, f ProvenanceFilter) ([]models.EntitlementProvenance, int64, error) {
	q := r.db.Model(&models.EntitlementProvenance{}).Where("workspace_id = ?", workspaceID)

	if f.SubjectType != "" {
		q = q.Where("subject_type = ?", f.SubjectType)
	}
	if f.SubjectID != nil {
		q = q.Where("subject_id = ?", *f.SubjectID)
	}
	if f.EntitlementType != "" {
		q = q.Where("entitlement_type = ?", f.EntitlementType)
	}
	if f.Origin != "" {
		q = q.Where("origin = ?", f.Origin)
	}
	if f.DiscoveredAgentID != nil {
		q = q.Where("discovered_agent_id = ?", *f.DiscoveredAgentID)
	}
	if f.OpenOnly || f.LapsedOnly || f.StandingOnly {
		// All three imply "currently in force"; a closed grant is not standing and
		// cannot be lapsed.
		q = q.Where("revoked_at IS NULL")
	}
	if f.StandingOnly {
		q = q.Where("is_standing")
	}
	if f.LapsedOnly {
		q = q.Where("expires_at IS NOT NULL AND expires_at <= ?", time.Now())
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

	var rows []models.EntitlementProvenance
	// Standing grants first — they are the ones that never expire on their own and so
	// need a human to look at them — then most recently granted.
	err := q.Order("is_standing DESC").Order("granted_at DESC").
		Limit(limit).Offset(offset).Find(&rows).Error
	return rows, total, err
}

func (r *governanceRepository) CloseProvenance(in CloseProvenanceInput) (bool, error) {
	return r.CloseProvenanceTx(r.db, in)
}

func (r *governanceRepository) CloseProvenanceTx(tx *gorm.DB, in CloseProvenanceInput) (bool, error) {
	if in.Via == "" {
		return false, errors.New("revoked_via is required: a closed grant must record which mechanism closed it")
	}
	if in.At.IsZero() {
		in.At = time.Now()
	}

	q := tx.Model(&models.EntitlementProvenance{}).
		Where("workspace_id = ? AND revoked_at IS NULL", in.WorkspaceID)

	switch {
	case in.RoleBindingID != nil:
		q = q.Where("role_binding_id = ?", *in.RoleBindingID)
	case in.ClientRegistrationID != nil:
		q = q.Where("client_registration_id = ?", *in.ClientRegistrationID)
	case in.ConnectorAssignmentID != nil:
		q = q.Where("connector_assignment_id = ?", *in.ConnectorAssignmentID)
	default:
		return false, errors.New("one of role_binding_id, client_registration_id, or connector_assignment_id is required")
	}

	res := q.Updates(map[string]interface{}{
		"revoked_at":     in.At,
		"revoked_by":     in.By,
		"revoked_reason": in.Reason,
		"revoked_via":    in.Via,
		"updated_at":     time.Now(),
	})
	if res.Error != nil {
		return false, res.Error
	}
	// RowsAffected == 0 means there was nothing open to close. Deliberately not an
	// error: the sweep may be retried, and a grant predating provenance has no record
	// to close — the caller still has to revoke the grant itself.
	return res.RowsAffected > 0, nil
}

/* ------------------------------ expiry sweep ---------------------------- */

func (r *governanceRepository) FindLapsedGrants(limit int) ([]models.EntitlementProvenance, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var rows []models.EntitlementProvenance
	err := r.db.
		Where("revoked_at IS NULL AND NOT is_standing AND expires_at IS NOT NULL AND expires_at <= ?", time.Now()).
		Order("expires_at ASC").
		Limit(limit).
		Find(&rows).Error
	return rows, err
}

func (r *governanceRepository) FindOrphanedExpiredBindings(limit int) ([]ExpiredBinding, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var out []ExpiredBinding
	// LEFT JOIN rather than NOT IN: the provenance table will be large and a
	// semi-join over an indexed column is the cheaper plan.
	err := r.db.Raw(`
		SELECT rb.id, rb.workspace_id, rb.role_id, COALESCE(rb.role_name,'') AS role_name,
		       rb.expires_at, rb.user_id, rb.group_id, rb.service_account_id
		  FROM role_bindings rb
		  LEFT JOIN entitlement_provenance ep
		         ON ep.role_binding_id = rb.id AND ep.revoked_at IS NULL
		 WHERE rb.expires_at IS NOT NULL
		   AND rb.expires_at <= NOW()
		   AND ep.id IS NULL
		 ORDER BY rb.expires_at ASC
		 LIMIT ?`, limit).Scan(&out).Error
	return out, err
}

// DeleteRoleBindingTx removes an expired binding.
//
// Deleting rather than flagging is deliberate. role_bindings is on the hot path of
// every token issuance and the ScopeResolver already filters
// `expires_at IS NULL OR expires_at > NOW()`, so adding a revoked_at column would
// mean a second predicate on the most-read table in the system for no gain. The
// audit trail lives in entitlement_provenance, which is exactly why provenance had
// to land before an expiry worker could safely delete anything.
func (r *governanceRepository) DeleteRoleBindingTx(tx *gorm.DB, bindingID uuid.UUID) error {
	return tx.Exec(`DELETE FROM role_bindings WHERE id = ?`, bindingID).Error
}

func (r *governanceRepository) LiveTokenJTIsForSubject(subjectID uuid.UUID, subjectType string) ([]LiveToken, error) {
	var out []LiveToken
	// Only tokens that are still valid and not already revoked matter: revoking an
	// expired token is a no-op row, and revoking twice is noise in the kill list.
	// Only tokens still valid and not already revoked: revoking an expired token
	// writes a useless row, and revoking twice is noise in the kill list.
	//
	// 'access_token' is hardcoded because native_tokens holds access tokens; the
	// other revoked_tokens kind ('id_jag') is an inbound assertion, revoked by the
	// trusted-issuer path, not by an entitlement lapsing.
	err := r.db.Raw(`
		SELECT nt.jti::text AS jti, nt.iss AS issuer,
		       'access_token' AS kind, nt.expires_at
		  FROM native_tokens nt
		 WHERE nt.subject_id = ?
		   AND nt.subject_type = ?
		   AND nt.expires_at > NOW()
		   AND NOT EXISTS (
		         SELECT 1 FROM revoked_tokens rt
		          WHERE rt.jti = nt.jti::text AND rt.iss = nt.iss AND rt.kind = 'access_token')`,
		subjectID, subjectType).Scan(&out).Error
	return out, err
}

func (r *governanceRepository) RevokeTokensTx(tx *gorm.DB, tokens []LiveToken, reason string) error {
	if len(tokens) == 0 {
		return nil
	}
	for _, t := range tokens {
		// ON CONFLICT DO NOTHING so a retried sweep is idempotent.
		// Column is `kind`, PK is (iss, kind, jti) — there is no `token_type` column,
		// which is what broke RevokeNativeTokenByJTI before this landed. ON CONFLICT
		// against the real PK so a retried sweep is idempotent.
		err := tx.Exec(`
			INSERT INTO revoked_tokens (iss, kind, jti, revoked_at, reason, expires_at)
			VALUES (?, ?, ?, NOW(), ?, ?)
			ON CONFLICT (iss, kind, jti) DO NOTHING`,
			t.Issuer, t.Kind, t.JTI, reason, t.ExpiresAt).Error
		if err != nil {
			return fmt.Errorf("revoke token %s: %w", t.JTI, err)
		}
	}
	return nil
}
