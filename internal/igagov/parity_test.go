package igagov

import (
	"testing"

	"github.com/authsec-ai/authsec/models"
)

// The package keeps its own vocabulary so it stays free of the models
// package at run time; this test pins it to the model constants, which in
// turn mirror the 047–056 CHECKs (the migration is the authority).
func TestVocabularyMatchesModels(t *testing.T) {
	pairs := [][2]string{
		{KindUnusedService, models.GovFindingUnusedService},
		{KindBroadGrant, models.GovFindingBroadGrant},
		{KindSharedRole, models.GovFindingSharedRole},
		{KindMissingOwner, models.GovFindingMissingOwner},
		{KindMissingReviewDate, models.GovFindingMissingReviewDate},
		{KindActivityNotRead, models.GovFindingActivityNotRead},
		{StatusOpen, models.GovFindingOpen},
		{StatusUnderReview, models.GovFindingUnderReview},
		{StatusExcepted, models.GovFindingExcepted},
		{StatusMitigated, models.GovFindingMitigated},
		{StatusResolved, models.GovFindingResolved},
		{StatusCleared, models.GovFindingCleared},
		{StatusSuperseded, models.GovFindingSuperseded},
		{StatusReopened, models.GovFindingReopened},
		{ConfidenceQualified, models.GovConfidenceQualified},
		{ConfidenceAgeUnverified, models.GovConfidenceAgeUnverified},
		{ConfidenceNotApplicable, models.GovConfidenceNotApplicable},
		{GrantAgeObservedSinceChange, models.GovGrantAgeObservedSinceChange},
		{GrantAgePredatesObservation, models.GovGrantAgePredatesObservation},
		{GrantAgeUnknown, models.GovGrantAgeUnknown},
		{FamilyGovernance, models.GovFamilyGovernance},
		{FamilyCloudAccess, models.GovFamilyCloudAccess},
		{TrustTrusted, models.GovTrustTrusted},
		{TrustPartial, models.GovTrustPartial},
		{TrustUntrusted, models.GovTrustUntrusted},
		{DeliveryDirect, models.GovDeliveryDirect},
		{DeliveryIaCPR, models.GovDeliveryIaCPR},
		{DeliveryExport, models.GovDeliveryExport},
		{RouteStateNoneObserved, models.GovRouteNoneObserved},
		{RouteStateBypassKnown, models.GovRouteBypassKnown},
		{RouteStateEffectUnknown, models.GovRouteEffectUnknown},
		{RouteStateNotAnalysed, models.GovRouteNotAnalysed},
		{OutcomePending, models.GovOutcomePending},
		{OutcomeRemoved, models.GovOutcomeRemoved},
		{OutcomeExcludedRoutesRemain, models.GovOutcomeExcludedRoutesRemain},
		{OutcomeExcludedRoutesUnknown, models.GovOutcomeExcludedRoutesUnknown},
		{OutcomeNotRemoved, models.GovOutcomeNotRemoved},
	}
	for _, p := range pairs {
		if p[0] != p[1] {
			t.Errorf("igagov %q != models %q", p[0], p[1])
		}
	}
}
