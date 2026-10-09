package integration

// D-13's sort orders on /workloads and /identities, walked ONE row per page so
// every keyset arm is exercised: each sort's key, then name, then account
// (identities), then id -- and '-' reversing all of it but the "no value"
// flags. /resources' orders are walked in TestP2ListsResourcesKindsAccountsAndFacets.

import (
	"strings"
	"testing"
)

// listsLabels renders rows as name@account-id.
func listsLabels(rows []any) string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, digs(r, "name")+"@"+digs(r, "account", "id"))
	}
	return strings.Join(out, " ")
}

func TestP2ListsWorkloadAndIdentitySorts(t *testing.T) {
	l := newP2Lab(t, "p2-lists-sorts", true)
	a := l.account(accountA)
	b := l.account(accountB)
	// The same identity name in both accounts, so the name sort's account
	// component (D-13) -- not the random id -- decides between them.
	roleA, roleB := a.role("b-role", "AROABROLEBROLEBROLE1"), b.role("a-role", "AROAAROLEAROLEAROLE1")
	a.role("shared", "AROASHAREDSHAREDSHA1")
	b.role("shared", "AROASHAREDSHAREDSHB1")
	listsFunctions(a, "us-east-1", "b-fn", roleA, "d-fn", roleA)
	listsFunctions(b, "us-east-1", "a-fn", roleB, "c-fn", roleB)
	// A is projected first, so everything of A was last confirmed earlier.
	l.scanAndProject(a)
	l.scanAndProject(b)
	var dfn string
	if err := l.db.Raw(`SELECT id FROM iga_workload WHERE workspace_id = ? AND display_name = 'd-fn'`, l.ws).
		Row().Scan(&dfn); err != nil {
		t.Fatalf("d-fn: %v", err)
	}
	api := l.api()
	listsDecide(t, l.db, l.ws, refUUID(t, "workload:"+dfn))

	A, B := "@"+accountA, "@"+accountB
	for _, tc := range []struct {
		route, sort, want string
	}{
		{"/workloads", "name", "a-fn" + B + " b-fn" + A + " c-fn" + B + " d-fn" + A},
		{"/workloads", "-name", "d-fn" + A + " c-fn" + B + " b-fn" + A + " a-fn" + B},
		// account id, then name (accountA sorts before accountB).
		{"/workloads", "account", "b-fn" + A + " d-fn" + A + " a-fn" + B + " c-fn" + B},
		{"/workloads", "-account", "c-fn" + B + " a-fn" + B + " d-fn" + A + " b-fn" + A},
		// by RANK: the classified agent before the unclassified (D-13).
		{"/workloads", "classification", "d-fn" + A + " a-fn" + B + " b-fn" + A + " c-fn" + B},
		{"/workloads", "-classification", "c-fn" + B + " b-fn" + A + " a-fn" + B + " d-fn" + A},
		// name, then account (D-13, §2.14.6): shared@A before shared@B.
		{"/identities", "name", "a-role" + B + " b-role" + A + " shared" + A + " shared" + B},
		{"/identities", "-name", "shared" + B + " shared" + A + " b-role" + A + " a-role" + B},
		{"/identities", "account", "b-role" + A + " shared" + A + " a-role" + B + " shared" + B},
		{"/identities", "-account", "shared" + B + " a-role" + B + " shared" + A + " b-role" + A},
	} {
		if got := listsLabels(listsWalk(t, api, tc.route, 1, "sort", tc.sort)); got != tc.want {
			t.Errorf("%s sort=%s =\n  %s\nwant\n  %s", tc.route, tc.sort, got, tc.want)
		}
	}

	// D-1's derived last_confirmed_at: A's pass came first, so A's rows lead.
	// Within one pass the projector stamps each row as it writes it, so the
	// order inside an account is the write order, not asserted; '-' must
	// still be the exact reverse (every row has a value: no flag is active).
	for _, route := range []string{"/workloads", "/identities"} {
		asc := listsWalk(t, api, route, 1, "sort", "last_confirmed")
		desc := listsWalk(t, api, route, 1, "sort", "-last_confirmed")
		accts := listsField(asc, "account", "id")
		if len(asc) != 4 || strings.Join(accts, " ") != strings.Join([]string{accountA, accountA, accountB, accountB}, " ") {
			t.Errorf("%s sort=last_confirmed = %s, want A's rows (confirmed first) before B's", route, listsLabels(asc))
		}
		for i := range asc {
			if len(desc) != len(asc) || digs(asc[i], "ref") != digs(desc[len(desc)-1-i], "ref") {
				t.Errorf("%s sort=-last_confirmed = %s, want the exact reverse of %s", route, listsLabels(desc), listsLabels(asc))
				break
			}
		}
	}
}
