package igagov

import (
	"errors"
	"strings"
	"testing"
)

// fix/p3-tidy item 2: an owner retain scoped to subjects applies to those
// subjects only (ForSubject), and validation keeps the scoped form honest.
func TestScopedOwnerRetain(t *testing.T) {
	const a, b = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	base := func() RightSizeIntent {
		return RightSizeIntent{Kind: IntentRightSizeServices,
			Subjects: []Subject{{IdentityAccountID: a, RoleID: "AROAAAAAAAAAAAA", AccountID: "429418377036"},
				{IdentityAccountID: b, RoleID: "AROABBBBBBBBBBB", AccountID: "429418377036"}},
			Retain: []RetainEntry{{Service: "s3", Basis: RetainObserved, LastAttempt: "2026-10-01"},
				{Service: "sqs", Basis: RetainOwner, Reason: "dlq", ReviewBy: "2027-06-30", Subjects: []string{a}}},
			Remove: []RemoveEntry{{Service: "sqs", Basis: RemoveNoAttempt, QualifiedDays: 90, GrantAgeBasis: GrantAgePredatesObservation},
				{Service: "sns", Basis: RemoveNoAttempt, QualifiedDays: 90, GrantAgeBasis: GrantAgePredatesObservation}},
			ObservationDays: 7, Delivery: DeliveryDirect, EvidenceRev: 1}
	}
	in := base()
	if err := ValidateIntent(Intent{Kind: IntentRightSizeServices, RightSize: &in}); err != nil {
		t.Fatalf("a scoped owner retain of a removed service: %v", err)
	}
	removed := func(r RightSizeIntent) string {
		var s []string
		for _, e := range r.Remove {
			s = append(s, e.Service)
		}
		return strings.Join(s, ",")
	}
	retained := func(r RightSizeIntent) string {
		var s []string
		for _, e := range r.Retain {
			if len(e.Subjects) > 0 {
				t.Fatalf("ForSubject left a scoped entry: %+v", e)
			}
			s = append(s, e.Service)
		}
		return strings.Join(s, ",")
	}
	if fa := in.ForSubject(a); removed(fa) != "sns" || retained(fa) != "s3,sqs" {
		t.Fatalf("subject A: removes %q retains %q, want sns / s3,sqs", removed(fa), retained(fa))
	}
	if fb := in.ForSubject(b); removed(fb) != "sqs,sns" || retained(fb) != "s3" {
		t.Fatalf("subject B: removes %q retains %q, want sqs,sns / s3", removed(fb), retained(fb))
	}
	if removed(in) != "sqs,sns" || len(in.Retain[1].Subjects) != 1 {
		t.Fatal("ForSubject modified the intent")
	}

	bad := map[string]func(r *RightSizeIntent){
		"retain[1].subjects":    func(r *RightSizeIntent) { r.Retain[1].Basis = RetainUnreviewed },
		"retain[1].subjects[0]": func(r *RightSizeIntent) { r.Retain[1].Subjects = []string{"33333333-3333-3333-3333-333333333333"} },
		"subjects[0]": func(r *RightSizeIntent) {
			r.Retain = append(r.Retain, RetainEntry{Service: "sns", Basis: RetainOwner, Reason: "x", ReviewBy: "2027-06-30", Subjects: []string{a}})
		},
		"retain": func(r *RightSizeIntent) {
			r.Retain = append(r.Retain, RetainEntry{Service: "sqs", Basis: RetainOwner, Reason: "x", ReviewBy: "2027-06-30"})
		},
	}
	for field, mutate := range bad {
		r := base()
		mutate(&r)
		err := ValidateIntent(Intent{Kind: IntentRightSizeServices, RightSize: &r})
		var ie IntentErrors
		if !errors.As(err, &ie) {
			t.Fatalf("%s: %v, want IntentErrors", field, err)
		}
		found := false
		for _, e := range ie {
			found = found || e.Field == field
		}
		if !found {
			t.Fatalf("%s: errors %v do not name it", field, ie)
		}
	}
	// An unscoped retain still conflicts with a removal of the same service.
	r := base()
	r.Retain[1].Subjects = nil
	if err := ValidateIntent(Intent{Kind: IntentRightSizeServices, RightSize: &r}); err == nil || !strings.Contains(err.Error(), "both retained and removed") {
		t.Fatalf("unscoped retain of a removed service: %v", err)
	}
}
