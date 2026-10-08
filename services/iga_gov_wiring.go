package services

import (
	"log"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/vault"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Integration wiring (p3-wire): T3.12's owner review behind T3.11/T3.13's
// authoring hooks, and T3.11's RetainVersionTx behind T3.12's review hook.
// cmd/main.go installs both with InstallGovOwnerReviewWiring once the Phase 3
// schema has verified (IGA_POLICY=on); tests install the same function.
//
//	OnProposed      -> OpenReviewTx (create, or resync/reopen on a re-propose)
//	OwnerGate       -> CheckGate (409 review_incomplete / age_unconfirmed /
//	                   route_unconfirmed refuse the approval)
//	OnVersionClosed -> CancelReviewTx (withdrawn, rejected, superseded)
//	OnImpactChanged -> OpenReviewTx: the resync reopens the review, adds rows
//	                   ONLY for owners who are new and notifies only them
//	OnApproved      -> nil (DECISION W3: no "approved" notice kind exists in
//	                   iga_gov_notification's vocabulary -- approval_request
//	                   asks approvers, it does not announce a decision -- so
//	                   approval notices are left to T3.14/T3.15)
//
// Every hook runs in the caller's transaction; an error rolls it back.

// GovOwnerReviewAuthoringHooks are the authoring hooks backed by the owner
// review service over db.
func GovOwnerReviewAuthoringHooks(db *gorm.DB) GovAuthoringHooks {
	svc := NewIGAGovOwnerReviewService(db)
	return GovAuthoringHooks{
		OnProposed: func(tx *gorm.DB, p GovProposedVersion) error {
			_, err := svc.OpenReviewTx(tx, p.WorkspaceID, p.VersionID, p.ActorID)
			return err
		},
		OwnerGate: func(tx *gorm.DB, c GovApprovalCheck) error {
			return svc.CheckGate(tx, c.WorkspaceID, c.VersionID)
		},
		OnVersionClosed: func(tx *gorm.DB, ws, versionID uuid.UUID, status string) error {
			return svc.CancelReviewTx(tx, ws, versionID, uuid.Nil, "version "+status)
		},
		OnImpactChanged: func(tx *gorm.DB, c GovImpactChange) error {
			// DECISION W1: the resync is the reopen (OpenReviewTx compares the
			// current forward plans' impact_hash set and the live owners with
			// the review). Called once per changed target; the second and
			// later calls find nothing new. The system is the actor.
			_, err := svc.OpenReviewTx(tx, c.WorkspaceID, c.VersionID, uuid.Nil)
			return err
		},
	}
}

// govReviewAuthoringAdapter is T3.12's GovReviewAuthoringHook over T3.11's
// authoring service.
type govReviewAuthoringAdapter struct {
	authoring *GovAuthoring
}

// NewGovReviewAuthoringAdapter builds the review hook over db. The authoring
// service it uses reads the process-wide authoring hooks at call time, so
// the new version's creation withdraws the reviewed one through
// OnVersionClosed (its review cancelled) like any other edit.
func NewGovReviewAuthoringAdapter(db *gorm.DB) GovReviewAuthoringHook {
	return &govReviewAuthoringAdapter{authoring: NewGovAuthoring(db, nil)}
}

// OwnerResponseTx: retain creates the next version with the retained
// services moved to retain (basis owner, reason, review_by) and returns its
// id; object returns nil.
//
// DECISION W2 (object): the objection is recorded by the review itself --
// the owner's response row (response = object, comment) and the
// review.responded event written in the same transaction -- and it blocks
// the version through the owner gate (409 review_incomplete, blocker
// objection) until the owner changes their answer, an approver excepts, or
// the author edits the version. The version stays in_review: 049's
// status machine has no in_review -> draft step, and a withdrawal would
// discard every other owner's answers for one objection.
func (a *govReviewAuthoringAdapter) OwnerResponseTx(tx *gorm.DB, r GovOwnerResponseEvent) (*uuid.UUID, error) {
	if r.Response != GovResponseRetain {
		return nil, nil
	}
	items := make([]igagov.RetainEntry, 0, len(r.RetainItems))
	for _, it := range r.RetainItems {
		items = append(items, igagov.RetainEntry{Service: strings.ToLower(strings.TrimSpace(it.Service)),
			Basis: igagov.RetainOwner, Reason: strings.TrimSpace(it.Reason), ReviewBy: strings.TrimSpace(it.ReviewBy)})
	}
	v, err := a.authoring.RetainVersionTx(tx, r.WorkspaceID, r.UserID, r.VersionID, items)
	if err != nil {
		return nil, err
	}
	id := v.ID
	return &id, nil
}

// InstallGovOwnerReviewWiring installs both directions process-wide and
// returns a function restoring what was installed before (tests).
func InstallGovOwnerReviewWiring(db *gorm.DB) (restore func()) {
	prevHooks := SetGovAuthoringHooks(GovOwnerReviewAuthoringHooks(db))
	restoreReview := SetGovReviewAuthoringHook(NewGovReviewAuthoringAdapter(db))
	return func() {
		restoreReview()
		SetGovAuthoringHooks(prevHooks)
	}
}

// InstallGovPolicyRuntime installs everything the Phase 3 policy product
// needs at runtime beyond its routes and worker (cmd/main.go calls it from
// the IGA_POLICY gate's ready hook, i.e. only once the Phase 3 schema has
// verified, before the job worker starts):
//
//   - the owner review wiring (InstallGovOwnerReviewWiring);
//   - the notification channel store (GovDBChannelStore over vc; vc nil:
//     channels are stored but a webhook secret cannot be);
//   - the compiler's discovery-role live reader (GovAWSLiveReader over
//     AWSEnforcementAccess), only with Vault: the discovery session needs the
//     connector's ExternalId from it. Without Vault no reader is installed
//     and compilation answers 503 discovery_unavailable.
func InstallGovPolicyRuntime(db *gorm.DB, vc vault.VaultClient, discoveryPrincipal string) {
	InstallGovOwnerReviewWiring(db)
	SetGovNotificationChannelStore(NewGovDBChannelStore(vc))
	if vc == nil {
		SetGovLiveReader(nil)
		log.Printf("[policy] live reads not configured: VAULT_ADDR/VAULT_TOKEN not set; compilation answers discovery_unavailable")
		return
	}
	cb, err := LoadAWSCallbackConfig()
	if err != nil {
		// The binding service is only the enforcement half of the access;
		// live reads use the discovery half. Its config error is logged.
		log.Printf("[policy] enforcement callback config: %v", err)
	}
	access := NewAWSEnforcementAccess(repositories.NewCloudConnectorRepository(db), NewAWSOnboardingService(db, vc),
		NewEnforcementBindingService(db, vc, cb, discoveryPrincipal))
	SetGovLiveReader(NewGovAWSLiveReader(access))
	log.Printf("[policy] owner review wiring, notification channels and discovery-role live reads installed")
}
