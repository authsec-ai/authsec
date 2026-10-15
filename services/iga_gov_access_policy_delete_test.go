package services

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

var deleteTestNow = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

// deleteBundle is a policy with one applied version ending at `ends` and one
// deployment row in `rowState`.
func deleteBundle(t *testing.T, lifecycle string, ends time.Time, rowState, endReason string) *accessBundle {
	t.Helper()
	intent, err := json.Marshal(igagov.AccessIntent{Effect: "allow", EndsAt: &ends})
	if err != nil {
		t.Fatal(err)
	}
	pid, vid := uuid.New(), uuid.New()
	row := models.IGAGovTempGrant{PolicyID: &pid, VersionID: &vid, RoleID: "r1", State: rowState, EndReason: endReason}
	if endReason != "" {
		row.EndedAt = &ends
	}
	return &accessBundle{
		pol:      models.IGAGovPolicy{ID: pid, Lifecycle: lifecycle},
		versions: []models.IGAGovAccessPolicyVersion{{ID: vid, PolicyID: pid, Status: models.AccessVersionApplied, Intent: intent}},
		rows:     []models.IGAGovTempGrant{row},
	}
}

// An access policy that expires on its own reads "ended" while its stored
// lifecycle is still "active" (only End archives it). Delete must accept it.
func TestAccessEnded(t *testing.T) {
	past := deleteTestNow.Add(-time.Hour)
	future := deleteTestNow.Add(time.Hour)
	cases := []struct {
		name string
		b    *accessBundle
		want bool
	}{
		{"expired on its own, lifecycle active", deleteBundle(t, "active", past, models.R2StateExpired, r2EndReasonExpired), true},
		{"end time passed, still coming out of AWS", deleteBundle(t, "active", past, models.R2StateExpiring, ""), true},
		{"ended by the user (archived)", deleteBundle(t, "archived", future, models.R2StateRevoked, "ended"), true},
		{"running, ends later", deleteBundle(t, "active", future, models.R2StateActive, ""), false},
		{"paused", deleteBundle(t, "paused", future, models.R2StateRevoked, "paused"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := accessEnded(c.b, deleteTestNow); got != c.want {
				status, reason, _, _ := accessStatus(c.b, deleteTestNow)
				t.Fatalf("accessEnded = %v, want %v (status %q, reason %q)", got, c.want, status, reason)
			}
		})
	}
}
