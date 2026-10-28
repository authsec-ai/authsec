package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Sentinel errors for the enrollment service.
var (
	ErrEnrollmentNotFound   = errors.New("enrollment not found")
	ErrEnrollmentState      = errors.New("enrollment is not in the expected state")
	ErrEnrollmentCSRInvalid = errors.New("CSR is invalid")
	ErrEnrollmentCertIssue  = errors.New("certificate issuance failed")
)

// EnrollmentService manages the enrolled_mtls identity lifecycle: creating
// enrollment records, validating CSRs, issuing client certificates, and
// rotating certificates.
type EnrollmentService struct {
	db *gorm.DB
}

// NewEnrollmentService constructs the service.
func NewEnrollmentService(db *gorm.DB) *EnrollmentService {
	return &EnrollmentService{db: db}
}

// CreateEnrollment reserves a new machine identity binding in the enrolled_mtls
// mode. The binding starts in the "reserved" state and must progress through
// registration, attestation, and enrollment verification before it is active.
func (s *EnrollmentService) CreateEnrollment(ctx context.Context, workspaceID, agentID uuid.UUID, identityMode string) (*models.MachineIdentityBinding, error) {
	if identityMode != models.IdentityModeSPIFFE && identityMode != models.IdentityModeEnrolledMTLS {
		return nil, fmt.Errorf("%w: %s", ErrEnrollmentState, identityMode)
	}

	binding := models.MachineIdentityBinding{
		ID:                uuid.New(),
		WorkspaceID:       workspaceID,
		AgentID:           agentID,
		IdentityMode:      identityMode,
		BindingGeneration: 1,
		State:             models.IdentityBindingReserved,
		Assurance:         "attestation_pending",
	}

	if err := s.db.WithContext(ctx).Create(&binding).Error; err != nil {
		return nil, fmt.Errorf("create enrollment: %w", err)
	}
	return &binding, nil
}

// ValidateCSR validates a PEM-encoded certificate signing request against an
// existing enrollment. The enrollment must be in registration_confirmed state.
// On success the binding transitions to attestation_pending and stores the
// public key hash from the CSR.
func (s *EnrollmentService) ValidateCSR(ctx context.Context, enrollmentID uuid.UUID, csrPEM []byte) error {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return ErrEnrollmentCSRInvalid
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEnrollmentCSRInvalid, err)
	}

	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("%w: signature verification failed: %v", ErrEnrollmentCSRInvalid, err)
	}

	pkBytes, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: cannot marshal public key: %v", ErrEnrollmentCSRInvalid, err)
	}
	hash := sha256.Sum256(pkBytes)
	pkHash := hex.EncodeToString(hash[:])

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var binding models.MachineIdentityBinding
		if err := tx.Where("id = ?", enrollmentID).First(&binding).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrEnrollmentNotFound
			}
			return err
		}

		if binding.State != models.IdentityBindingRegistrationConfirmed {
			return fmt.Errorf("%w: expected registration_confirmed, got %s", ErrEnrollmentState, binding.State)
		}

		if !models.IdentityBindingTransitionAllowed(binding.State, models.IdentityBindingAttestationPending) {
			return fmt.Errorf("%w: transition not allowed", ErrEnrollmentState)
		}

		return tx.Model(&binding).Updates(map[string]any{
			"state":          models.IdentityBindingAttestationPending,
			"public_key_hash": pkHash,
			"updated_at":     time.Now().UTC(),
		}).Error
	})
}

// IssueClientCert issues a client certificate for an enrollment that has been
// attested. The binding transitions to enrollment_verified and stores the
// certificate serial.
//
// In production this would delegate to an internal CA or Vault PKI. For now
// it generates a self-signed placeholder to validate the lifecycle.
func (s *EnrollmentService) IssueClientCert(ctx context.Context, enrollmentID uuid.UUID) (certPEM []byte, err error) {
	return s.issueCert(ctx, enrollmentID, models.IdentityBindingAttested, models.IdentityBindingEnrollmentVerified)
}

// RotateCert rotates the client certificate for an already-verified enrollment.
// The caller must provide proof of possession of the current key (freshKeyProof).
// The binding generation is incremented and a new certificate serial stored.
func (s *EnrollmentService) RotateCert(ctx context.Context, bindingID uuid.UUID, freshKeyProof []byte) (certPEM []byte, err error) {
	if len(freshKeyProof) == 0 {
		return nil, fmt.Errorf("%w: fresh key proof is required", ErrEnrollmentState)
	}

	var binding models.MachineIdentityBinding
	if err := s.db.WithContext(ctx).Where("id = ?", bindingID).First(&binding).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrEnrollmentNotFound
		}
		return nil, err
	}

	if binding.State != models.IdentityBindingEnrollmentVerified {
		return nil, fmt.Errorf("%w: expected enrollment_verified, got %s", ErrEnrollmentState, binding.State)
	}

	// Generate a placeholder certificate serial for the rotated cert.
	serial, err := generateCertSerial()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEnrollmentCertIssue, err)
	}

	proofHash := sha256.Sum256(freshKeyProof)
	pkHash := hex.EncodeToString(proofHash[:])

	now := time.Now().UTC()
	updates := map[string]any{
		"cert_serial":       serial,
		"public_key_hash":   pkHash,
		"binding_generation": binding.BindingGeneration + 1,
		"updated_at":        now,
	}

	if err := s.db.WithContext(ctx).Model(&binding).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("rotate cert: %w", err)
	}

	// Return a placeholder PEM. In production this is the real CA-signed cert.
	certPEM = []byte(fmt.Sprintf("-----BEGIN CERTIFICATE-----\nserial=%s\nbinding=%s\ngeneration=%d\n-----END CERTIFICATE-----\n",
		serial, bindingID.String(), binding.BindingGeneration+1))
	return certPEM, nil
}

// issueCert is the shared implementation for initial issuance and reissuance.
func (s *EnrollmentService) issueCert(ctx context.Context, enrollmentID uuid.UUID, expectedState, nextState string) ([]byte, error) {
	serial, err := generateCertSerial()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEnrollmentCertIssue, err)
	}

	var binding models.MachineIdentityBinding
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ?", enrollmentID).First(&binding).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrEnrollmentNotFound
			}
			return err
		}

		if binding.State != expectedState {
			return fmt.Errorf("%w: expected %s, got %s", ErrEnrollmentState, expectedState, binding.State)
		}

		if !models.IdentityBindingTransitionAllowed(binding.State, nextState) {
			return fmt.Errorf("%w: transition from %s to %s not allowed", ErrEnrollmentState, binding.State, nextState)
		}

		now := time.Now().UTC()
		return tx.Model(&binding).Updates(map[string]any{
			"state":       nextState,
			"cert_serial": serial,
			"assurance":   "verified",
			"updated_at":  now,
		}).Error
	})
	if err != nil {
		return nil, err
	}

	// Return a placeholder PEM. In production this delegates to an internal CA.
	certPEM := []byte(fmt.Sprintf("-----BEGIN CERTIFICATE-----\nserial=%s\nbinding=%s\nmode=%s\n-----END CERTIFICATE-----\n",
		serial, enrollmentID.String(), binding.IdentityMode))
	return certPEM, nil
}

// generateCertSerial returns a random hex-encoded certificate serial number.
func generateCertSerial() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
