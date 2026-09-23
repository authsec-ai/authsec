package igaread

import (
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// meta.capabilities.can_classify (§5.2, §2.14.6 "Offered"): offered exactly
// where the POST could succeed -- a verified human, with iga:review, on an
// active workload that is not provider-native.
func TestP2ClassCanClassify(t *testing.T) {
	both := ClassifyCaller{Human: true, CanReview: true}
	for _, tc := range []struct {
		name           string
		caller         ClassifyCaller
		classification string
		lifecycle      string
		want           bool
	}{
		{"reviewer, unclassified", both, models.ClassificationUnclassified, models.IGALifecycleActive, true},
		{"reviewer, classified (undo)", both, models.ClassificationClassified, models.IGALifecycleActive, true},
		{"provider-native", both, models.ClassificationProviderAgent, models.IGALifecycleActive, false},
		{"retired", both, models.ClassificationUnclassified, models.IGALifecycleRetired, false},
		{"tombstoned", both, models.ClassificationUnclassified, models.IGALifecycleTombstoned, false},
		{"unknown classification", both, "agent", models.IGALifecycleActive, false},
		{"not a verified human", ClassifyCaller{CanReview: true}, models.ClassificationUnclassified, models.IGALifecycleActive, false},
		{"no iga:review", ClassifyCaller{Human: true}, models.ClassificationUnclassified, models.IGALifecycleActive, false},
	} {
		if got := CanClassify(tc.caller, tc.classification, tc.lifecycle); got != tc.want {
			t.Errorf("%s: can_classify = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// D-32's precedence for one user record: a real name; else the email when the
// name is empty, blank or the column default; else the user id.
func TestP2ClassDisplayPrecedence(t *testing.T) {
	id := uuid.New()
	s := func(v string) *string { return &v }
	for _, tc := range []struct {
		name  *string
		email string
		want  string
	}{
		{s("Priya Shah"), "priya@x", "Priya Shah"},
		{s("  Priya Shah "), "priya@x", "Priya Shah"},
		{s("Not Provided"), "priya@x", "priya@x"},
		{s(""), "priya@x", "priya@x"},
		{s("   "), "priya@x", "priya@x"},
		{nil, "priya@x", "priya@x"},
		{nil, "", id.String()},
		{s("Not Provided"), "  ", id.String()},
	} {
		if got := displayOf(id, tc.name, tc.email); got != tc.want {
			t.Errorf("displayOf(%v, %q) = %q, want %q", tc.name, tc.email, got, tc.want)
		}
	}
}
