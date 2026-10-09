package load

// Resource › Access finds its page of holders grant-first, or identity-first
// for a reference named by rdetailAccessDenseAt targets or more (T6.10: "*").
// The switch is a plan choice and must never be an answer: on the fixture's
// references -- "*", the most-named exact resource, typical ones, and an exact
// reference with group-held grants -- both strategies must return the same
// pages, byte for byte, cursor by cursor, with and without ended rows.

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igaread"
)

// TestP2LoadAccessStrategiesAgree walks every page of each reference's Access
// with each strategy forced and compares them.
//
// Safeguards (mutation-checked): the identity-first page's direct probe, its
// member probe (a member of a group holding a grant is a holder, D-18), the
// membership overlap on the member rows, and its cursor predicate.
func TestP2LoadAccessStrategiesAgree(t *testing.T) {
	env := loadEnvFor(t)
	g := env.main
	grantFirst := igaread.NewReader(env.db, loadCursorKey).WithAccessDenseAt(1 << 30)
	identityFirst := igaread.NewReader(env.db, loadCursorKey).WithAccessDenseAt(1)

	refs := []uuid.UUID{g.h.starResource, g.h.hotBucket}
	refs = append(refs, g.h.resources[:10]...)
	if r := loadGroupHeldReference(t, env); r != uuid.Nil {
		refs = append(refs, r)
	} else {
		t.Fatal("fixture: no reference is reached through a group; the member rows would go untested")
	}
	for _, id := range refs {
		for _, ended := range []string{"", "true"} {
			a := loadAccessPages(t, grantFirst, g.ws, id, ended)
			b := loadAccessPages(t, identityFirst, g.ws, id, ended)
			if len(a) != len(b) {
				t.Errorf("resource %s include_ended=%q: grant-first %d pages, identity-first %d", id, ended, len(a), len(b))
				continue
			}
			for i := range a {
				if a[i] != b[i] {
					t.Errorf("resource %s include_ended=%q page %d differs:\ngrant-first    %s\nidentity-first %s",
						id, ended, i+1, loadClip([]byte(a[i])), loadClip([]byte(b[i])))
					break
				}
			}
		}
	}
}

// loadAccessPages is every page of one reference's Access at limit 50 (so the
// hub references page many times), rendered as JSON.
func loadAccessPages(t *testing.T, r *igaread.Reader, ws, id uuid.UUID, includeEnded string) []string {
	t.Helper()
	var pages []string
	cursor := ""
	for n := 0; n < 1000; n++ {
		vals := url.Values{"limit": {"50"}}
		if includeEnded != "" {
			vals.Set("include_ended", includeEnded)
		}
		if cursor != "" {
			vals.Set("cursor", cursor)
		}
		out, err := r.ResourceAccess(context.Background(), ws, id.String(), vals)
		if err != nil {
			t.Fatalf("access %s: %v", id, err)
		}
		raw, err := json.Marshal(out)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		pages = append(pages, string(raw))
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		next, _ := loadDig(body, "meta", "next_cursor").(string)
		if next == "" {
			return pages
		}
		cursor = next
	}
	t.Fatalf("access %s did not end within 1000 pages", id)
	return nil
}

// loadGroupHeldReference is an exact reference a group holds a live grant to
// while one of its members' memberships is live: its Access has member rows.
func loadGroupHeldReference(t *testing.T, env *loadEnv) uuid.UUID {
	t.Helper()
	var ids []uuid.UUID
	if err := env.db.Raw(`SELECT t.resource_id FROM iga_access_edges g
	                         JOIN iga_identity_accounts gr ON gr.workspace_id = g.workspace_id AND gr.id = g.subject_identity_account_id
	                                                      AND gr.account_kind = 'iam_group'
	                         JOIN iga_relationship m ON m.workspace_id = g.workspace_id AND m.relationship_type = 'member_of'
	                                                AND m.target_identity_account_id = gr.id AND m.state <> 'ended'
	                         JOIN iga_entitlement_target t ON t.workspace_id = g.workspace_id AND t.entitlement_id = g.entitlement_id
	                                                      AND t.target_mode = 'resource'
	                         JOIN iga_resources r ON r.workspace_id = t.workspace_id AND r.id = t.resource_id
	                                             AND r.resource_kind <> 'selector'
	                        WHERE g.workspace_id = ? AND g.state <> 'ended'
	                        ORDER BY t.resource_id LIMIT 1`, env.main.ws).Scan(&ids).Error; err != nil {
		t.Fatalf("group-held reference: %v", err)
	}
	if len(ids) == 0 {
		return uuid.Nil
	}
	return ids[0]
}
