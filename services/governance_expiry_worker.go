package services

import (
	"log"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ExpiryWorker revokes entitlements whose expiry has passed.
//
// WHAT WAS AND WAS NOT ALREADY WORKING
// Expiry is already honoured at READ time: the ScopeResolver and every RBAC query
// filter `expires_at IS NULL OR expires_at > NOW()`, so a lapsed binding grants no
// new scope. Three things were still missing, and this worker supplies them.
//
//  1. A TOKEN ALREADY ISSUED under a now-lapsed binding keeps working until it
//     expires on its own. Native M2M access tokens live an hour, so a 15-minute JIT
//     grant could in practice yield up to 75 minutes of access. Introspection treats
//     revoked_tokens as authoritative, so inserting there closes the window
//     immediately.
//  2. NOTHING RECORDED THE LAPSE. The grant simply stopped resolving. Certification
//     and any "what happened to this access?" question had no answer.
//  3. NOTHING CLEANED UP. Lapsed bindings accumulate forever in the table every token
//     issuance reads, and make "what does this subject have?" queries misleading.
//
// FAILURE POSTURE
// The worker only ever REMOVES access (PG-5). A bug here fails toward less access,
// never more. Each entitlement is processed in its own transaction, so one bad row
// cannot block the rest of the sweep, and every step is idempotent so a retry after a
// crash is safe.
type ExpiryWorker struct {
	repo       repositories.GovernanceRepository
	provenance ProvenanceManager
	interval   time.Duration
	// batch bounds one sweep. A cluster-wide expiry storm (a campaign revoking
	// thousands of grants at once) should be drained over several ticks rather than
	// held in one enormous transaction.
	batch int
}

// NewExpiryWorker constructs an ExpiryWorker.
func NewExpiryWorker(db *gorm.DB, interval time.Duration, batch int) *ExpiryWorker {
	if interval <= 0 {
		interval = time.Minute
	}
	if batch <= 0 || batch > 1000 {
		batch = 200
	}
	repo := repositories.NewGovernanceRepository(db)
	return &ExpiryWorker{
		repo:       repo,
		provenance: NewProvenanceManager(repo),
		interval:   interval,
		batch:      batch,
	}
}

// ExpirySweepResult reports what one sweep did, so the caller can log or test it.
type ExpirySweepResult struct {
	LapsedFound      int
	BindingsRemoved  int
	TokensRevoked    int
	ProvenanceClosed int
	OrphansRemoved   int
	Errors           int
}

// Start launches the sweep loop.
func (w *ExpiryWorker) Start() {
	go func() {
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for range ticker.C {
			if res := w.RunOnce(); res.LapsedFound > 0 || res.OrphansRemoved > 0 || res.Errors > 0 {
				log.Printf("governance expiry sweep: lapsed=%d bindings_removed=%d tokens_revoked=%d "+
					"provenance_closed=%d orphans_removed=%d errors=%d",
					res.LapsedFound, res.BindingsRemoved, res.TokensRevoked,
					res.ProvenanceClosed, res.OrphansRemoved, res.Errors)
			}
		}
	}()
}

// RunOnce performs a single sweep. Exported so an operator can trigger one and so
// tests do not have to wait on a ticker.
func (w *ExpiryWorker) RunOnce() ExpirySweepResult {
	var res ExpirySweepResult

	// Pass 1: grants WITH provenance. These are the ones we can fully account for.
	lapsed, err := w.repo.FindLapsedGrants(w.batch)
	if err != nil {
		log.Printf("governance expiry sweep: could not list lapsed grants: %v", err)
		res.Errors++
		return res
	}
	res.LapsedFound = len(lapsed)

	for i := range lapsed {
		if err := w.revokeLapsed(&lapsed[i], &res); err != nil {
			// Per-row, so one undeletable binding cannot stall every other expiry.
			log.Printf("governance expiry sweep: provenance %s: %v", lapsed[i].ID, err)
			res.Errors++
		}
	}

	// Pass 2: expired bindings with NO provenance — grants made before provenance
	// existed. There is no "why" to close, but they still need cleaning up and their
	// tokens still need killing. Skipping them would leave the pre-existing installed
	// base permanently un-swept.
	orphans, err := w.repo.FindOrphanedExpiredBindings(w.batch)
	if err != nil {
		log.Printf("governance expiry sweep: could not list orphaned expired bindings: %v", err)
		res.Errors++
		return res
	}
	for _, b := range orphans {
		if err := w.revokeOrphan(b, &res); err != nil {
			log.Printf("governance expiry sweep: orphaned binding %s: %v", b.ID, err)
			res.Errors++
		}
	}

	return res
}

// revokeLapsed handles one lapsed grant that has a provenance record.
func (w *ExpiryWorker) revokeLapsed(p *models.EntitlementProvenance, res *ExpirySweepResult) error {
	// Only role bindings are actioned today. A lapsed client registration or secret
	// grant is recorded but not yet revoked, because the de-provision path for those
	// arrives with provisioning (phase 2) — and silently half-revoking one would be
	// worse than leaving it for the phase that owns it.
	if p.EntitlementType != models.EntitlementRoleBinding || p.RoleBindingID == nil {
		return nil
	}
	bindingID := *p.RoleBindingID

	return w.repo.DB().Transaction(func(tx *gorm.DB) error {
		// Close the paperwork FIRST. If the transaction fails after this point nothing
		// commits, and if it succeeds the record and the removal are consistent.
		closed, err := w.provenance.CloseGrant(tx, p.WorkspaceID, CloseGrantInput{
			RoleBindingID: &bindingID,
			Via:           models.RevokedViaExpiry,
			Reason:        expiryReason(p.ExpiresAt),
			At:            time.Now(),
		})
		if err != nil {
			return err
		}
		if closed {
			res.ProvenanceClosed++
		}

		// Kill live tokens riding the lapsed grant. This is the window that read-time
		// expiry filtering cannot close on its own.
		n, err := w.revokeSubjectTokens(tx, p.SubjectID, p.SubjectType, "entitlement expired")
		if err != nil {
			return err
		}
		res.TokensRevoked += n

		if err := w.repo.DeleteRoleBindingTx(tx, bindingID); err != nil {
			return err
		}
		res.BindingsRemoved++
		return nil
	})
}

// revokeOrphan handles an expired binding with no provenance record.
func (w *ExpiryWorker) revokeOrphan(b repositories.ExpiredBinding, res *ExpirySweepResult) error {
	subjectID, subjectType := b.SubjectID()
	if subjectID == uuid.Nil {
		// role_bindings.check_principal guarantees exactly one principal, so this
		// should be unreachable. Skip rather than guess at whose tokens to revoke.
		return nil
	}

	return w.repo.DB().Transaction(func(tx *gorm.DB) error {
		n, err := w.revokeSubjectTokens(tx, subjectID, subjectType, "entitlement expired")
		if err != nil {
			return err
		}
		res.TokensRevoked += n

		if err := w.repo.DeleteRoleBindingTx(tx, b.ID); err != nil {
			return err
		}
		res.OrphansRemoved++
		return nil
	})
}

// revokeSubjectTokens revokes a subject's live tokens, returning how many.
//
// DELIBERATELY BROAD, AND WHY
// native_tokens records the subject a token was issued for, not the binding that
// authorised it, so there is no way to revoke "only the tokens that relied on this
// one binding". Revoking all of the subject's live tokens is therefore the only
// correct choice available: leaving them would keep the lapsed access alive, which is
// the whole failure this closes. The cost is that a subject holding several grants
// re-authenticates when any one of them lapses — acceptable for tokens with a
// one-hour life, and it errs toward less access (PG-5).
func (w *ExpiryWorker) revokeSubjectTokens(tx *gorm.DB, subjectID uuid.UUID, subjectType, reason string) (int, error) {
	// native_tokens.subject_type only ever holds 'user' or 'service_account'. A group
	// is not a token subject, so there is nothing to revoke for one.
	if subjectType != models.ProvenanceSubjectUser && subjectType != models.ProvenanceSubjectServiceAccount {
		return 0, nil
	}
	tokens, err := w.repo.LiveTokenJTIsForSubject(subjectID, subjectType)
	if err != nil {
		return 0, err
	}
	if len(tokens) == 0 {
		return 0, nil
	}
	if err := w.repo.RevokeTokensTx(tx, tokens, reason); err != nil {
		return 0, err
	}
	return len(tokens), nil
}

func expiryReason(expiresAt *time.Time) string {
	if expiresAt == nil {
		return "grant lapsed"
	}
	return "grant lapsed at " + expiresAt.UTC().Format(time.RFC3339)
}
