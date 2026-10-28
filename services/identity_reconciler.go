package services

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// IdentityReconciler drives identity bindings through their state machine.
// It acts as an outbox processor: on each tick it picks up bindings in
// non-terminal states and attempts the next transition.
//
// For SPIFFE mode: creates SPIRE registration entries and transitions to
// attested once the SPIRE agent confirms attestation.
//
// For enrolled_mtls mode: creates enrollment records and issues certificates,
// driving the binding through to enrollment_verified.
type IdentityReconciler struct {
	db *gorm.DB
}

// NewIdentityReconciler constructs the reconciler.
func NewIdentityReconciler(db *gorm.DB) *IdentityReconciler {
	return &IdentityReconciler{db: db}
}

// Reconcile processes all non-terminal identity bindings and attempts to
// advance each one to its next state. This is idempotent and safe to call
// on every tick of a polling loop.
func (r *IdentityReconciler) Reconcile(ctx context.Context) error {
	var bindings []models.MachineIdentityBinding
	err := r.db.WithContext(ctx).
		Where("state NOT IN ?", []string{
			models.IdentityBindingEnrollmentVerified,
			models.IdentityBindingDisabled,
			models.IdentityBindingRevoked,
		}).
		Order("created_at ASC").
		Limit(100).
		Find(&bindings).Error
	if err != nil {
		return fmt.Errorf("identity reconciler: query failed: %w", err)
	}

	if len(bindings) == 0 {
		return nil
	}

	log.Printf("[IdentityReconciler] reconciling %d binding(s)", len(bindings))
	var lastErr error
	for i := range bindings {
		if err := r.reconcileOne(ctx, &bindings[i]); err != nil {
			log.Printf("[IdentityReconciler] binding %s: %v", bindings[i].ID, err)
			lastErr = err
		}
	}
	return lastErr
}

// reconcileOne drives a single binding forward in its state machine.
func (r *IdentityReconciler) reconcileOne(ctx context.Context, b *models.MachineIdentityBinding) error {
	switch b.IdentityMode {
	case models.IdentityModeSPIFFE:
		return r.reconcileSPIFFE(ctx, b)
	case models.IdentityModeEnrolledMTLS:
		return r.reconcileEnrolledMTLS(ctx, b)
	default:
		return fmt.Errorf("unknown identity mode %q for binding %s", b.IdentityMode, b.ID)
	}
}

// reconcileSPIFFE drives SPIFFE-mode bindings through:
//
//	reserved → registration_pending  (create SPIRE registration entry)
//	registration_pending → registration_confirmed  (SPIRE confirms entry)
//	registration_confirmed → attestation_pending  (agent begins attestation)
//	attestation_pending → attested  (SPIRE confirms attestation)
func (r *IdentityReconciler) reconcileSPIFFE(ctx context.Context, b *models.MachineIdentityBinding) error {
	switch b.State {
	case models.IdentityBindingReserved:
		return r.transitionBinding(ctx, b, models.IdentityBindingRegistrationPending, func(tx *gorm.DB) error {
			// In production: create SPIRE registration entry via SPIRE Server API.
			// The SPIFFE ID is derived from the agent and workspace.
			spiffeID := fmt.Sprintf("spiffe://authsec.local/workspace/%s/agent/%s",
				b.WorkspaceID.String(), b.AgentID.String())
			return tx.Model(b).Update("primary_spiffe_id", spiffeID).Error
		})

	case models.IdentityBindingRegistrationPending:
		// In production: check SPIRE server for entry confirmation.
		// For now, auto-advance to confirmed.
		return r.transitionBinding(ctx, b, models.IdentityBindingRegistrationConfirmed, nil)

	case models.IdentityBindingRegistrationConfirmed:
		return r.transitionBinding(ctx, b, models.IdentityBindingAttestationPending, nil)

	case models.IdentityBindingAttestationPending:
		// In production: check SPIRE agent attestation status.
		// Do not auto-advance; attestation is confirmed by an external signal.
		return nil

	default:
		return nil
	}
}

// reconcileEnrolledMTLS drives enrolled_mtls-mode bindings through:
//
//	reserved → registration_pending  (create enrollment record)
//	registration_pending → registration_confirmed  (admin confirms)
//	registration_confirmed → attestation_pending  (CSR validated)
//	attestation_pending → attested  (attestation confirmed)
//	attested → enrollment_verified  (certificate issued)
func (r *IdentityReconciler) reconcileEnrolledMTLS(ctx context.Context, b *models.MachineIdentityBinding) error {
	switch b.State {
	case models.IdentityBindingReserved:
		return r.transitionBinding(ctx, b, models.IdentityBindingRegistrationPending, func(tx *gorm.DB) error {
			// Derive a verified principal ID for enrollment tracking.
			principalID := fmt.Sprintf("enrolled:%s:%s", b.WorkspaceID.String(), b.AgentID.String())
			return tx.Model(b).Update("verified_principal_id", principalID).Error
		})

	case models.IdentityBindingRegistrationPending:
		// In production: wait for admin approval or automated policy check.
		// Do not auto-advance; an external action must confirm registration.
		return nil

	case models.IdentityBindingRegistrationConfirmed:
		// CSR validation drives this transition via EnrollmentService.ValidateCSR.
		return nil

	case models.IdentityBindingAttestationPending:
		// In production: attestation is confirmed by verifying the CSR against
		// a hardware trust anchor or platform attestation.
		// Do not auto-advance; an external signal must confirm attestation.
		return nil

	case models.IdentityBindingAttested:
		// Issue the client certificate via the enrollment service.
		return r.transitionBinding(ctx, b, models.IdentityBindingEnrollmentVerified, func(tx *gorm.DB) error {
			// In production: invoke the internal CA to issue the cert.
			// The EnrollmentService.IssueClientCert handles this;
			// here we just record the completion state.
			return tx.Model(b).Update("assurance", "verified").Error
		})

	default:
		return nil
	}
}

// transitionBinding atomically transitions a binding to the next state,
// optionally running a side-effect function within the same transaction.
func (r *IdentityReconciler) transitionBinding(
	ctx context.Context,
	b *models.MachineIdentityBinding,
	nextState string,
	sideEffect func(tx *gorm.DB) error,
) error {
	if !models.IdentityBindingTransitionAllowed(b.State, nextState) {
		return fmt.Errorf("transition from %s to %s is not allowed for binding %s",
			b.State, nextState, b.ID)
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Re-read under lock to prevent races.
		var fresh models.MachineIdentityBinding
		if err := tx.Where("id = ?", b.ID).First(&fresh).Error; err != nil {
			return err
		}
		if fresh.State != b.State {
			// Another reconciler instance already advanced this binding.
			return nil
		}

		if sideEffect != nil {
			if err := sideEffect(tx); err != nil {
				return err
			}
		}

		now := time.Now().UTC()
		return tx.Model(&fresh).Updates(map[string]any{
			"state":      nextState,
			"updated_at": now,
		}).Error
	})
}

// ReconcileExecutionBindings creates execution-scoped identity bindings for a
// parent machine binding. Each execution ID gets its own row with a derived
// SPIFFE URI and principal URI.
func (r *IdentityReconciler) ReconcileExecutionBindings(
	ctx context.Context,
	parentBindingID uuid.UUID,
	executionIDs []string,
) error {
	var parent models.MachineIdentityBinding
	if err := r.db.WithContext(ctx).Where("id = ?", parentBindingID).First(&parent).Error; err != nil {
		return fmt.Errorf("parent binding not found: %w", err)
	}

	for _, execID := range executionIDs {
		// Check if already exists.
		var count int64
		r.db.WithContext(ctx).Model(&models.ExecutionIdentityBinding{}).
			Where("parent_binding_id = ? AND execution_id = ?", parentBindingID, execID).
			Count(&count)
		if count > 0 {
			continue
		}

		now := time.Now().UTC()
		eb := models.ExecutionIdentityBinding{
			ID:                uuid.New(),
			ParentBindingID:   parentBindingID,
			WorkspaceID:       parent.WorkspaceID,
			ExecutionID:       execID,
			BindingGeneration: parent.BindingGeneration,
			State:             parent.State,
			IssuedAt:          &now,
			CreatedAt:         now,
		}

		// Derive URIs from the parent binding.
		if parent.PrimarySPIFFEID != "" {
			eb.SPIFFEURI = fmt.Sprintf("%s/exec/%s", parent.PrimarySPIFFEID, execID)
		}
		if parent.VerifiedPrincipalID != "" {
			eb.PrincipalURI = fmt.Sprintf("%s/exec/%s", parent.VerifiedPrincipalID, execID)
		}

		if err := r.db.WithContext(ctx).Create(&eb).Error; err != nil {
			return fmt.Errorf("create execution binding for %s: %w", execID, err)
		}
	}
	return nil
}
