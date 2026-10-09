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

// ProvenanceManager owns the record of WHY every entitlement exists.
//
// It is the ONLY writer to entitlement_provenance. Concentrating writes here is what
// keeps the invariants enforceable in one place: a standing grant always carries a
// justification, an expiring grant always carries an expiry, and a closed grant
// always names the mechanism that closed it.
//
// It never grants or revokes anything itself. Provisioning writes the grant and calls
// OpenGrant in the same transaction; the de-provision path revokes and calls
// CloseGrant. Provenance is the paperwork, deliberately separate from the authority.
type ProvenanceManager interface {
	// OpenGrant records a grant decision. Call it inside the transaction that creates
	// the grant, so a grant can never exist without its justification.
	OpenGrant(tx *gorm.DB, workspaceID uuid.UUID, in OpenGrantInput) (*models.EntitlementProvenance, error)

	// CloseGrant closes the open record for an entitlement, reporting whether one was
	// found. A missing record is not an error — see the repository comment.
	CloseGrant(tx *gorm.DB, workspaceID uuid.UUID, in CloseGrantInput) (bool, error)

	Get(workspaceID, id uuid.UUID) (*models.EntitlementProvenance, error)
	List(workspaceID uuid.UUID, f repositories.ProvenanceFilter) ([]models.EntitlementProvenance, int64, error)
}

// OpenGrantInput is one grant decision being recorded.
type OpenGrantInput struct {
	EntitlementType string
	// Exactly one pointer, matching EntitlementType.
	RoleBindingID         *uuid.UUID
	ClientRegistrationID  *uuid.UUID
	ConnectorAssignmentID *uuid.UUID
	// Snapshot is the denormalised copy that outlives the grant. Provisioning should
	// put whatever a reviewer would need if the grant row were gone: role name, scope,
	// resource server, namespace.
	Snapshot map[string]interface{}
	Label    string

	SubjectType  string
	SubjectID    uuid.UUID
	SubjectLabel string

	Origin            string
	Justification     string
	Purpose           string
	AccessRequestID   *uuid.UUID
	DiscoveredAgentID *uuid.UUID

	GrantedBy      *uuid.UUID
	GrantedByLabel string

	// ExpiresAt is the grant's expiry. Leave nil ONLY with IsStanding, which requires
	// a justification — that pairing is what makes "ephemeral by default" real rather
	// than aspirational.
	ExpiresAt  *time.Time
	IsStanding bool
}

// CloseGrantInput identifies the entitlement to close and records why.
type CloseGrantInput struct {
	RoleBindingID         *uuid.UUID
	ClientRegistrationID  *uuid.UUID
	ConnectorAssignmentID *uuid.UUID
	Via                   string
	Reason                string
	By                    *uuid.UUID
	At                    time.Time
}

type provenanceManager struct {
	repo repositories.GovernanceRepository
}

// NewProvenanceManager constructs a ProvenanceManager.
func NewProvenanceManager(repo repositories.GovernanceRepository) ProvenanceManager {
	return &provenanceManager{repo: repo}
}

func (m *provenanceManager) OpenGrant(tx *gorm.DB, workspaceID uuid.UUID, in OpenGrantInput) (*models.EntitlementProvenance, error) {
	if workspaceID == uuid.Nil {
		return nil, errors.New("workspace is required")
	}
	if !containsString(models.ValidEntitlementTypes(), in.EntitlementType) {
		return nil, fmt.Errorf("unknown entitlement type %q", in.EntitlementType)
	}
	if !containsString(models.ValidProvenanceSubjectTypes(), in.SubjectType) {
		return nil, fmt.Errorf("unknown subject type %q", in.SubjectType)
	}
	if in.SubjectID == uuid.Nil {
		return nil, errors.New("subject_id is required: provenance with no subject explains nothing")
	}
	if !containsString(models.ValidGrantOrigins(), in.Origin) {
		return nil, fmt.Errorf("unknown grant origin %q", in.Origin)
	}

	// Exactly one pointer, and it must match the declared type. The DB enforces this
	// too; catching it here turns a constraint violation into a usable message.
	ptrs := 0
	if in.RoleBindingID != nil {
		ptrs++
		if in.EntitlementType != models.EntitlementRoleBinding {
			return nil, fmt.Errorf("role_binding_id set but entitlement_type is %q", in.EntitlementType)
		}
	}
	if in.ClientRegistrationID != nil {
		ptrs++
		if in.EntitlementType != models.EntitlementClientRegistration {
			return nil, fmt.Errorf("client_registration_id set but entitlement_type is %q", in.EntitlementType)
		}
	}
	if in.ConnectorAssignmentID != nil {
		ptrs++
		if in.EntitlementType != models.EntitlementSecretAccess {
			return nil, fmt.Errorf("connector_assignment_id set but entitlement_type is %q", in.EntitlementType)
		}
	}
	if ptrs != 1 {
		return nil, fmt.Errorf("exactly one entitlement pointer is required, got %d", ptrs)
	}

	justification := strings.TrimSpace(in.Justification)

	// The rule behind PG-4. A permanent grant is allowed, but somebody has to say why
	// on the record — otherwise "standing" becomes the silent default it is everywhere
	// else, and certification has nothing to push back on.
	if in.IsStanding && justification == "" {
		return nil, errors.New("a standing (non-expiring) grant requires a justification: " +
			"permanent access is the audited exception, not the default")
	}
	if in.IsStanding && in.ExpiresAt != nil {
		return nil, errors.New("a standing grant cannot also have an expiry")
	}
	if !in.IsStanding && in.ExpiresAt == nil {
		return nil, errors.New("a grant must either expire or be explicitly marked standing with a justification")
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(time.Now()) {
		// Recording an already-lapsed grant would hand the expiry worker a row to
		// revoke on its very next tick, which is never what the caller meant.
		return nil, fmt.Errorf("expires_at %s is not in the future", in.ExpiresAt.Format(time.RFC3339))
	}

	snapshot, err := marshalDiscoveryConfig(in.Snapshot)
	if err != nil {
		return nil, fmt.Errorf("invalid snapshot: %w", err)
	}

	p := &models.EntitlementProvenance{
		ID:                    uuid.New(),
		WorkspaceID:           workspaceID,
		EntitlementType:       in.EntitlementType,
		RoleBindingID:         in.RoleBindingID,
		ClientRegistrationID:  in.ClientRegistrationID,
		ConnectorAssignmentID: in.ConnectorAssignmentID,
		Snapshot:              json.RawMessage(snapshot),
		Label:                 in.Label,
		SubjectType:           in.SubjectType,
		SubjectID:             in.SubjectID,
		SubjectLabel:          in.SubjectLabel,
		Origin:                in.Origin,
		Justification:         justification,
		Purpose:               strings.TrimSpace(in.Purpose),
		AccessRequestID:       in.AccessRequestID,
		DiscoveredAgentID:     in.DiscoveredAgentID,
		GrantedBy:             in.GrantedBy,
		GrantedByLabel:        in.GrantedByLabel,
		GrantedAt:             time.Now(),
		ExpiresAt:             in.ExpiresAt,
		IsStanding:            in.IsStanding,
	}

	if tx == nil {
		if err := m.repo.OpenProvenance(p); err != nil {
			return nil, err
		}
		return p, nil
	}
	if err := m.repo.OpenProvenanceTx(tx, p); err != nil {
		return nil, err
	}
	return p, nil
}

func (m *provenanceManager) CloseGrant(tx *gorm.DB, workspaceID uuid.UUID, in CloseGrantInput) (bool, error) {
	if !containsString(models.ValidRevokedVia(), in.Via) {
		return false, fmt.Errorf("unknown revocation mechanism %q", in.Via)
	}
	input := repositories.CloseProvenanceInput{
		WorkspaceID:           workspaceID,
		RoleBindingID:         in.RoleBindingID,
		ClientRegistrationID:  in.ClientRegistrationID,
		ConnectorAssignmentID: in.ConnectorAssignmentID,
		Via:                   in.Via,
		Reason:                in.Reason,
		By:                    in.By,
		At:                    in.At,
	}
	if tx == nil {
		return m.repo.CloseProvenance(input)
	}
	return m.repo.CloseProvenanceTx(tx, input)
}

func (m *provenanceManager) Get(workspaceID, id uuid.UUID) (*models.EntitlementProvenance, error) {
	return m.repo.GetProvenance(workspaceID, id)
}

func (m *provenanceManager) List(workspaceID uuid.UUID, f repositories.ProvenanceFilter) ([]models.EntitlementProvenance, int64, error) {
	if f.SubjectType != "" && !containsString(models.ValidProvenanceSubjectTypes(), f.SubjectType) {
		return nil, 0, fmt.Errorf("unknown subject type %q", f.SubjectType)
	}
	if f.EntitlementType != "" && !containsString(models.ValidEntitlementTypes(), f.EntitlementType) {
		return nil, 0, fmt.Errorf("unknown entitlement type %q", f.EntitlementType)
	}
	if f.Origin != "" && !containsString(models.ValidGrantOrigins(), f.Origin) {
		return nil, 0, fmt.Errorf("unknown grant origin %q", f.Origin)
	}
	return m.repo.ListProvenance(workspaceID, f)
}
