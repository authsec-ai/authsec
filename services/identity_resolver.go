package services

import (
	"errors"
	"fmt"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Sentinel errors for identity resolution.
var (
	ErrIdentityNotFound    = errors.New("identity binding not found")
	ErrIdentityModeUnknown = errors.New("unknown identity mode")
	ErrIdentityRevoked     = errors.New("identity binding is revoked or disabled")
)

// IdentityResolution is the result of resolving a verified principal from a
// TLS certificate or SPIFFE URI. It carries enough context for the caller to
// authorise the request without further DB lookups.
type IdentityResolution struct {
	WorkspaceID       uuid.UUID `json:"workspace_id"`
	PrincipalKind     string    `json:"principal_kind"`     // "agent", "collector", "workload"
	PrincipalID       uuid.UUID `json:"principal_id"`       // agent or collector id
	IdentityMode      string    `json:"identity_mode"`      // spiffe, enrolled_mtls
	BindingGeneration int       `json:"binding_generation"`
	BindingID         uuid.UUID `json:"binding_id"`
	Assurance         string    `json:"assurance"`
}

// IdentityResolver resolves verified principals from TLS certificates and
// SPIFFE URIs. It is the single point where identity mode dispatch happens.
type IdentityResolver struct {
	db *gorm.DB
}

// NewIdentityResolver constructs a resolver.
func NewIdentityResolver(db *gorm.DB) *IdentityResolver {
	return &IdentityResolver{db: db}
}

// ResolveVerifiedPrincipal resolves a verified principal from the presented
// TLS peer credentials.
//
//   - SPIFFE mode: exact URI match against machine_identity_bindings.primary_spiffe_id.
//   - enrolled_mtls mode: issuer profile + registered cert serial match.
//
// Returns the workspace, principal kind/id, identity mode, and binding
// generation so the caller can authorise the request.
func (r *IdentityResolver) ResolveVerifiedPrincipal(spiffeURI string, certSerial string, issuerProfile string) (*IdentityResolution, error) {
	// Try SPIFFE mode first if a SPIFFE URI is presented.
	if spiffeURI != "" {
		res, err := r.resolveSPIFFE(spiffeURI)
		if err == nil {
			return res, nil
		}
		if !errors.Is(err, ErrIdentityNotFound) {
			return nil, err
		}
	}

	// Try enrolled_mtls mode if a certificate serial is presented.
	if certSerial != "" {
		res, err := r.resolveEnrolledMTLS(certSerial, issuerProfile)
		if err == nil {
			return res, nil
		}
		if !errors.Is(err, ErrIdentityNotFound) {
			return nil, err
		}
	}

	return nil, ErrIdentityNotFound
}

// resolveSPIFFE resolves a machine identity binding by exact SPIFFE URI match.
func (r *IdentityResolver) resolveSPIFFE(spiffeURI string) (*IdentityResolution, error) {
	var binding models.MachineIdentityBinding
	err := r.db.Where(
		"identity_mode = ? AND primary_spiffe_id = ? AND state NOT IN ?",
		models.IdentityModeSPIFFE,
		spiffeURI,
		[]string{models.IdentityBindingDisabled, models.IdentityBindingRevoked},
	).First(&binding).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrIdentityNotFound
		}
		return nil, fmt.Errorf("spiffe resolution: %w", err)
	}
	return r.bindingToResolution(&binding, "agent"), nil
}

// resolveEnrolledMTLS resolves a machine identity binding by certificate
// serial and issuer profile. The cert serial is stored when the enrollment
// service issues or rotates a client certificate.
func (r *IdentityResolver) resolveEnrolledMTLS(certSerial string, issuerProfile string) (*IdentityResolution, error) {
	var binding models.MachineIdentityBinding
	q := r.db.Where(
		"identity_mode = ? AND cert_serial = ? AND state NOT IN ?",
		models.IdentityModeEnrolledMTLS,
		certSerial,
		[]string{models.IdentityBindingDisabled, models.IdentityBindingRevoked},
	)
	// When an issuer profile is presented, further narrow the match by
	// checking the assurance field carries the expected profile tag.
	if issuerProfile != "" {
		q = q.Where("assurance = ?", issuerProfile)
	}
	err := q.First(&binding).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrIdentityNotFound
		}
		return nil, fmt.Errorf("enrolled_mtls resolution: %w", err)
	}
	return r.bindingToResolution(&binding, "agent"), nil
}

// bindingToResolution converts a MachineIdentityBinding into an
// IdentityResolution suitable for authorisation checks.
func (r *IdentityResolver) bindingToResolution(b *models.MachineIdentityBinding, principalKind string) *IdentityResolution {
	return &IdentityResolution{
		WorkspaceID:       b.WorkspaceID,
		PrincipalKind:     principalKind,
		PrincipalID:       b.AgentID,
		IdentityMode:      b.IdentityMode,
		BindingGeneration: b.BindingGeneration,
		BindingID:         b.ID,
		Assurance:         b.Assurance,
	}
}

// ResolveExecutionBinding resolves an execution-scoped identity binding by
// execution ID under a given parent machine binding.
func (r *IdentityResolver) ResolveExecutionBinding(parentBindingID uuid.UUID, executionID string) (*models.ExecutionIdentityBinding, error) {
	var binding models.ExecutionIdentityBinding
	err := r.db.Where(
		"parent_binding_id = ? AND execution_id = ? AND state NOT IN ?",
		parentBindingID,
		executionID,
		[]string{models.IdentityBindingDisabled, models.IdentityBindingRevoked},
	).First(&binding).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrIdentityNotFound
		}
		return nil, fmt.Errorf("execution binding resolution: %w", err)
	}
	return &binding, nil
}
