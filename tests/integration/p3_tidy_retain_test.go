package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// fix/p3-tidy item 2 (§2.9, §7.4): an owner's "retain" applies to the roles
// THAT OWNER owns, never to every subject of the policy. One policy, two
// target roles with different owners; the owner of role A retains sqs
// through the production review route with the production wiring. The next
// version keeps sqs for A only: the real compiler's apply plan for A no
// longer removes sqs, B's still does. A second owner (of B) retaining sqs too
// then removes it from the policy's removals altogether.
func TestP3TidyOwnerRetainIsScopedToTheOwnersTargets(t *testing.T) {
	l := newP3aLab(t, "p3-tidy-retain")
	t.Cleanup(services.InstallGovOwnerReviewWiring(l.db))
	const roleA, roleB = "AROATIDYRETAINA01", "AROATIDYRETAINB01"
	report := map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil, "sns": nil}
	// Names of different lengths: the fake IAM derives a managed policy's
	// PolicyId from its ARN's length and last character.
	l.role("AlphaRetainRole", roleA, report)
	l.role("BravoRetain", roleB, report)
	l.publish()
	ident := func(roleID string) uuid.UUID {
		return bdbID(t, l.p2Lab, `SELECT id FROM iga_identity_accounts WHERE workspace_id = ? AND immutable_key = ?`, l.ws, roleID)
	}
	idA, idB := ident(roleA), ident(roleB)
	ownerA := l.member("owner-a", "read")
	ownerB := l.member("owner-b", "read")
	wireOwner(t, l, models.GovObjectIdentityAccount, idA, ownerA.user)
	wireOwner(t, l, models.GovObjectIdentityAccount, idB, ownerB.user)

	policy, _ := l.proposeTemplate(roleA, roleB)
	l.compile(policy, 1)
	removedOf := func(no int) map[string][]string {
		t.Helper()
		var rows []struct {
			RoleID string
			Impact json.RawMessage
		}
		if err := l.db.Raw(`SELECT c.role_id, p.impact FROM iga_gov_plan p
		                     JOIN iga_gov_control c ON c.workspace_id = p.workspace_id AND c.id = p.control_id
		                    WHERE p.workspace_id = ? AND p.version_id = ? AND p.kind = 'apply' AND p.superseded_at IS NULL`,
			l.ws, l.versionID(policy, no)).Scan(&rows).Error; err != nil {
			t.Fatal(err)
		}
		out := map[string][]string{}
		for _, r := range rows {
			var im igagov.Impact
			if err := json.Unmarshal(r.Impact, &im); err != nil {
				t.Fatal(err)
			}
			for _, s := range im.Removed {
				out[r.RoleID] = append(out[r.RoleID], s.Service)
			}
			sort.Strings(out[r.RoleID])
		}
		return out
	}
	if got := fmt.Sprint(removedOf(1)); got != "map[AROATIDYRETAINA01:[sns sqs] AROATIDYRETAINB01:[sns sqs]]" {
		t.Fatalf("version 1 removals per role: %s", got)
	}

	retain := func(m p3aMember, no int) map[string]any {
		t.Helper()
		review, _ := l.reviewOfVersion(policy, no)
		code, body := l.call(m, http.MethodPost, "/reviews/"+review.String()+"/respond", map[string]any{"response": "retain",
			"retain_items": []any{map[string]any{"service": "sqs", "reason": "the nightly batch reads the DLQ", "review_by": "2027-06-30"}}})
		return l.must(code, body, http.StatusOK, "retain")
	}
	if d := retain(ownerA, 1); fmt.Sprint(d["new_version_id"]) != l.versionID(policy, 2).String() {
		t.Fatalf("retain response %v, want version 2", d)
	}
	var v2 models.IGAGovPolicyVersion
	if err := l.db.Where("workspace_id = ? AND id = ?", l.ws, l.versionID(policy, 2)).Take(&v2).Error; err != nil {
		t.Fatal(err)
	}
	parsed, err := igagov.ParseIntent(v2.Intent)
	if err != nil {
		t.Fatalf("version 2 intent: %v", err)
	}
	in := parsed.RightSize
	stillRemoved := false
	for _, r := range in.Remove {
		stillRemoved = stillRemoved || r.Service == "sqs"
	}
	var sqs []igagov.RetainEntry
	for _, r := range in.Retain {
		if r.Service == "sqs" {
			sqs = append(sqs, r)
		}
	}
	if !stillRemoved || len(sqs) != 1 || sqs[0].Basis != igagov.RetainOwner || fmt.Sprint(sqs[0].Subjects) != fmt.Sprint([]string{idA.String()}) {
		t.Fatalf("version 2: sqs still removed for B = %v, sqs retains %+v (want one owner retain scoped to %s)", stillRemoved, sqs, idA)
	}

	// The real compiler: A keeps sqs, B still loses it.
	l.compile(policy, 2)
	if got := fmt.Sprint(removedOf(2)); got != "map[AROATIDYRETAINA01:[sns] AROATIDYRETAINB01:[sns sqs]]" {
		t.Fatalf("version 2 removals per role: %s, want sqs kept for A only", got)
	}

	// B's owner retains sqs too: no subject removes it any more.
	retain(ownerB, 2)
	var v3 models.IGAGovPolicyVersion
	if err := l.db.Where("workspace_id = ? AND id = ?", l.ws, l.versionID(policy, 3)).Take(&v3).Error; err != nil {
		t.Fatal(err)
	}
	p3, err := igagov.ParseIntent(v3.Intent)
	if err != nil {
		t.Fatalf("version 3 intent: %v", err)
	}
	for _, r := range p3.RightSize.Remove {
		if r.Service == "sqs" {
			t.Fatalf("version 3 still removes sqs although both owners retained it: %+v", p3.RightSize)
		}
	}
	l.compile(policy, 3)
	if got := fmt.Sprint(removedOf(3)); got != "map[AROATIDYRETAINA01:[sns] AROATIDYRETAINB01:[sns]]" {
		t.Fatalf("version 3 removals per role: %s", got)
	}
}
